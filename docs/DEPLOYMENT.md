# Deployment guide

This is a reference deployment for Debian/Ubuntu systems using initramfs-tools, a PKCS#11 P-256 hardware token, a TPM 2.0 Attestation Key, and an Anduril Lattice Sandbox for endpoint asset reporting.

## 1. Architecture and trust boundaries

The initramfs agent does not patch the running kernel and does not install a kernel hook. It runs in the initramfs after the root volume is discovered/mounted but before initramfs-tools pivots into the real root. The system continues only after the remote service approves the dongle/user/asset binding and verifies a nonce-bound TPM quote.

The trust chain is:

- UEFI Secure Boot -> signed bootloader/kernel/initramfs.
- Kernel lockdown and module signature enforcement -> protect the running kernel.
- Initramfs agent -> asks the authorization service for a fresh challenge.
- PKCS#11 token -> signs a domain-separated challenge using its non-exportable P-256 key.
- TPM 2.0 AK -> quotes the configured PCR selection with the same fresh nonce.
- Authorization service -> verifies token signature, TPM quote, approved PCR baseline, and the registry relationships.
- Lattice -> receives the endpoint asset's authorization status for operator visibility. Lattice reporting is not itself the cryptographic boot trust anchor.

A network outage, unknown key, expired challenge, invalid signature, unregistered TPM, PCR drift, or service error causes a fail-closed boot denial. Provide a separately controlled recovery procedure before enabling this on production systems.

## 2. Build

Build on a supported Linux build host with a Rust toolchain:

    cargo build --release --bins

The default Cargo feature selects aws-lc-rs 1.17.1 with its FIPS feature enabled (AWS-LC-FIPS 3.x). Do not use --no-default-features. Keep the lockfile committed and review crypto dependency changes as controlled security changes.

Install the binaries on the authorization host and boot client as appropriate:

    install -D -m 0755 target/release/dongle-authd /usr/local/sbin/dongle-authd
    install -D -m 0755 target/release/dongle-agent /usr/local/sbin/dongle-agent

The service host needs tpm2-tools so it can run tpm2_checkquote. The client needs tpm2-tools, OpenSC (pkcs11-tool and opensc-pkcs11.so), pcscd, and a working reader.

## 3. Enroll the hardware token

Provision an ECDSA P-256 key in the dongle using your hardware-token vendor's approved provisioning process. The private key must be generated and retained on the token; do not export it. Confirm the token supports the SHA-256/ECDSA PKCS#11 mechanism.

Example OpenSC discovery commands:

    pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-token-slots
    pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --token-label "TOKEN_LABEL" --list-objects

Export only the public-key object (not the private key):

    pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
      --token-label "TOKEN_LABEL" --read-object --type pubkey --id 01 \
      --output-file /tmp/dongle-public.der

Convert the public object to the raw 65-byte uncompressed SEC1 P-256 point:

    scripts/export-sec1-public-key.sh /tmp/dongle-public.der

Put the resulting Base64 string in public_key_sec1_b64 in the server policy. Register the matching user_id and dongle_id. The policy service checks that the dongle is active, belongs to the claimed user, and that the user is explicitly allowed on the target asset.

At boot, dongle-agent invokes pkcs11-tool --login; the token PIN is entered interactively on the initramfs console. The PIN is not passed in argv or environment variables. Do not add PINs to TOML, kernel command lines, systemd environment files, or logs.

## 4. Enroll the computer TPM and PCR baseline

Create a TPM Endorsement Key and Attestation Key on the computer. Follow your platform's TPM provisioning policy; the AK private key/context must remain protected by the TPM and the AK public key must be registered against the asset by a trusted administrator.

A typical tpm2-tools flow is:

    install -d -m 0700 /etc/dongle
    tpm2_createek -c /etc/dongle/ek.ctx -G rsa -u /etc/dongle/ek.pub.pem -f pem
    tpm2_createak -C /etc/dongle/ek.ctx -c /etc/dongle/ak.ctx \
      -G rsa -s rsassa -g sha256 -u /etc/dongle/ak.pub.pem -f pem

Copy the AK public PEM to the authorization host at the path named in the asset policy. Do not copy the TPM private material to the server.

Choose PCRs that match the platform boot chain and policy. The example uses SHA-256 PCRs 0, 2, 4, 7, 10, and 11; validate the meaning and availability of these PCRs on the target firmware, bootloader, kernel, and initramfs. Generate a baseline only from a known-good, administrator-approved boot:

    NONCE=0000000000000000000000000000000000000000000000000000000000000000
    tpm2_quote -c /etc/dongle/ak.ctx -l sha256:0,2,4,7,10,11 \
      -q "$NONCE" -m /tmp/approved.msg -s /tmp/approved.sig \
      -o /tmp/approved.pcrs -g sha256
    sha256sum /tmp/approved.pcrs

Set approved_pcrs_sha256 to the 64-character digest printed by sha256sum. The same PCR selection must be set in both the server asset policy and the initramfs agent config. The service verifies the TPM signature, qualifying nonce, exact registered PCR selection, and PCR data using tpm2_checkquote, then compares the serialized PCR snapshot digest to the registered baseline.

PCR baselines change when measured boot components change. After a kernel, bootloader, Secure Boot database, initramfs, or relevant firmware update, rebaseline only after the new boot chain is reviewed and approved. Never automatically trust the first new PCR value observed after a failed check.

The AK public key is treated as an enrolled trust anchor in this reference build. Production enrollment should additionally verify the TPM's EK certificate/AK credential chain against the manufacturer's or enterprise's approved roots before adding the AK to policy.

## 5. Configure the policy service

Copy the policy example and edit it:

    install -D -m 0600 config/policy.sandbox.example.toml /etc/dongle/policy.toml

Set:
- [users.<id>]: active = true and an explicit allowed_assets list.
- [dongles.<id>]: active = true, the same user ID, and the registered SEC1 public key.
- [assets.<id>]: active = true, the registered TPM AK public-key path, approved PCR digest, and the expected PCR selection.

The example is deny-by-default. Do not set active = true until the corresponding key or asset is actually enrolled.

The service listens on loopback by default at 127.0.0.1:8765. Put it behind a TLS reverse proxy and expose only HTTPS to boot clients. Restrict access to the authorization API at the network layer; do not expose the service directly to an untrusted network. The agent uses normal certificate validation and refuses non-HTTPS URLs.

Create a service account and install the systemd unit:

    useradd --system --home /var/lib/dongle --shell /usr/sbin/nologin dongle
    chown root:dongle /etc/dongle/policy.toml
    chmod 0640 /etc/dongle/policy.toml
    install -D -m 0644 deploy/systemd/dongle-authd.service /etc/systemd/system/dongle-authd.service
    systemctl daemon-reload
    systemctl enable --now dongle-authd

The service requires read access to the AK public-key PEM files referenced by policy. Keep those files public but administrator-controlled.

## 6. Configure the initramfs client

Copy the agent config and edit it for the asset, user, token label, key ID, PKCS#11 module path, TPM AK context, PCR selection, and HTTPS authorization URL:

    install -D -m 0600 config/agent.sandbox.example.toml /etc/dongle/agent.toml
    install -D -m 0755 deploy/initramfs-tools/hooks/dongle-agent /etc/initramfs-tools/hooks/dongle-agent
    install -D -m 0755 deploy/initramfs-tools/scripts/local-bottom/dongle-auth /etc/initramfs-tools/scripts/local-bottom/dongle-auth

The hook includes the agent, OpenSC token utility/module, PC/SC daemon, TPM quote tool, agent config, and system CA bundle in the initramfs. The example module path is Debian/Ubuntu x86-64 specific; adjust PKCS11_MODULE_PATH in the hook for other architectures or token vendors.

Ensure the initramfs brings up networking before local-bottom runs. For DHCP-managed systems, the kernel command line commonly uses ip=dhcp; static environments must configure the interface, DNS, route, and time/CA trust in the initramfs. Confirm that the authorization host is reachable from the initramfs, not merely after the real root has booted.

Rebuild and inspect the initramfs:

    update-initramfs -u -k all
    lsinitramfs /boot/initrd.img-$(uname -r) | grep -E 'dongle-agent|pkcs11-tool|tpm2_quote|agent.toml'

Do not test the enforcement path on your only bootable installation. First test using a disposable host or VM with a working out-of-band recovery path.

## 7. Lattice Sandboxes reporting

Create a Lattice Sandbox environment and note its resource endpoint, environment token, and account-level Sandboxes token. Set the three values on the authorization host, not on every boot client:

    install -d -m 0700 /etc/dongle
    install -m 0600 .env.example /etc/dongle/lattice.env
    editor /etc/dongle/lattice.env

Use these variables:

- LATTICE_ENDPOINT: hostname only, with no https:// prefix or path.
- ENVIRONMENT_TOKEN: the environment's Lattice auth token.
- SANDBOXES_TOKEN: the account-level Sandboxes bearer token.

The reporter sends Authorization: Bearer <ENVIRONMENT_TOKEN> and Anduril-Sandbox-Authorization: Bearer <SANDBOXES_TOKEN> to Lattice's documented PUT /api/v1/entities endpoint. It publishes a stable Linux endpoint asset entity and reports the most recent boot authorization state. It does not send the dongle private key, token PIN, TPM private key, or full quote payload to Lattice. Reporting is best-effort: Lattice being unavailable does not grant access and does not reverse an already verified decision.

The example uses the supported environment-token flow. Rotate environment tokens before expiry. OAuth client-credentials support can be added when it is enabled for the target Sandbox; the Lattice documentation currently describes that flow as beta in some deployments.

## 8. Kernel and secure-boot controls

Use your distribution's supported Secure Boot signing flow for the kernel and initramfs. Keep Secure Boot enabled, enforce signed kernel modules, and retain kernel lockdown. Do not add unsigned kernel patches, disable lockdown, or load unsigned modules to make this agent work.

Recommended kernel configuration controls include:
- CONFIG_MODULE_SIG=y
- CONFIG_MODULE_SIG_FORCE=y
- CONFIG_SECURITY_LOCKDOWN_LSM=y

The exact options and signing workflow are distribution/kernel-build dependent. Secure Boot must cover the bootloader, kernel, and the initramfs containing the gate; otherwise an attacker with physical access may replace or bypass the early-boot script. A measured PCR quote detects unexpected measurements only when the baseline and trust chain have been provisioned correctly.

## 9. Verification and negative tests

Before production, test at least:

1. Registered token + registered user + registered asset + approved PCR baseline -> allow.
2. Unknown dongle ID -> deny.
3. Active dongle associated with a different user -> deny.
4. User not explicitly allowed on the asset -> deny.
5. Altered challenge signature -> deny.
6. Replayed or expired challenge -> deny.
7. Wrong TPM AK -> deny.
8. Wrong nonce/quote -> deny.
9. Changed PCR snapshot or selection -> deny.
10. DNS, TLS, policy-service, or network failure -> initramfs refuses to pivot to the real root.
11. Lattice unavailable -> authorization remains based on local verification and is still fail-closed with respect to the authorization service.

## 10. FIPS 140-3 scope and limitations

The project uses AWS-LC-FIPS 3.x through aws-lc-rs 1.17.1 for the software ECDSA verification path and rustls provider. The AWS-LC 3.x module has CMVP certificates #5298 (dynamic) and #5314 (static). A FIPS claim is valid only when the exact validated module version, build/link mode, approved operating mode, and operating environment satisfy the vendor security policy and applicable CMVP conditions.

This does not certify the whole Dongle application, the hardware token, TPM, OS, kernel, boot chain, or deployment. The token and TPM have their own assurance/validation requirements. Consult the relevant NIST certificate/security policy and an accredited CMVP laboratory or compliance authority before making a compliance assertion.

## 11. Operational considerations

- Keep the policy service on a protected management network and TLS-protect its public endpoint.
- Restrict policy edits to authorized administrators. Back up policy and audit logs securely.
- Provide a documented break-glass process that requires physical/administrative control and leaves an auditable record.
- Re-enroll a dongle immediately when lost, stolen, or suspected compromised by setting active = false.
- Disable a computer asset immediately when retired or compromised.
- The current reference implementation gates boot. It does not implement continuous user-session reauthentication, screen lock on dongle removal, directory-service login integration, or automated enrollment/key rotation.
