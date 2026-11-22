# Deployment guide

This guide covers two client enforcement paths: a pre-OS Rust UEFI application (which runs before the OS loader and initramfs) and the existing Debian/Ubuntu initramfs-tools agent. Both use the same PKCS#11 P-256 enrollment policy, TPM 2.0 Attestation Key, remote authorization service, and optional Anduril Lattice reporting. The UEFI path additionally requires a platform/vendor UEFI driver for the token and TPM evidence.

## 1. Architecture and trust boundaries

The Linux initramfs agent does not patch the running kernel and does not install a kernel hook. It runs after the root volume is discovered/mounted but before initramfs-tools pivots into the real root. The separate UEFI application is earlier: it is started by firmware before the bootloader/kernel/initramfs, configures DHCP through UEFI network protocols, performs the same remote challenge/authorization transaction, and loads the next signed EFI loader only after approval.

The trust chain is:

- UEFI Secure Boot -> signed bootloader/kernel/initramfs.
- Kernel lockdown and module signature enforcement -> protect the running kernel.
- UEFI gate -> only on platforms with the required firmware protocols and signed token-adapter driver; it authorizes before the OS loader.
- Preferred pre-OS path: signed UEFI application -> firmware DHCP/HTTPS and platform token-attestation protocol -> authorization service.
- Alternative Linux enforcement path: initramfs agent -> asks the authorization service for a fresh challenge.
- PKCS#11 token -> signs a domain-separated challenge using its non-exportable P-256 key.
- TPM 2.0 AK -> quotes the configured PCR selection with the same fresh nonce.
- Authorization service -> verifies token signature, TPM quote, approved PCR baseline, and the registry relationships.
- Local policy TOML -> authoritative enrollment registry for users, dongles, assets, and allowed bindings.
- Lattice -> receives the endpoint asset's authorization status for operator visibility. Lattice reporting is not itself the cryptographic boot trust anchor.

A network outage, unknown key, expired challenge, invalid signature, unregistered TPM, PCR drift, or service error causes a fail-closed boot denial. Provide a separately controlled recovery procedure before enabling this on production systems.

## 2. Build

Build on a supported Linux build host with a Rust toolchain:

    cargo build --release --bins

The default Cargo feature pins aws-lc-rs 1.18.1 and enables its FIPS feature, selecting AWS-LC-FIPS 4.x. The code checks AWS-LC FIPS mode at startup and installs the AWS-LC-backed rustls provider before opening HTTPS clients. Do not use --no-default-features. Keep Cargo.lock committed and review crypto dependency changes as controlled security changes.

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

Set approved_pcrs_sha256 to the 64-character digest printed by sha256sum. The same PCR selection must be set in both the server asset policy and the initramfs agent config. The service verifies the TPM signature, qualifying nonce, and quoted PCR data using tpm2_checkquote. The SHA-256 baseline is calculated over the full serialized PCR output from tpm2_quote, which binds both the PCR selection structure and the selected PCR values; a changed selection or measurement therefore fails the baseline comparison.

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

The hook includes the agent, OpenSC token utility/module, PC/SC daemon, TPM quote tool, agent config, the TPM AK context at /etc/dongle/ak.ctx, and the system CA bundle in the initramfs. Protect the AK context and keep the initramfs image signed and access-controlled. The example module path is Debian/Ubuntu x86-64 specific; adjust PKCS11_MODULE_PATH in the hook for other architectures or token vendors.

Ensure the initramfs brings up networking before local-bottom runs. For DHCP-managed systems, the kernel command line commonly uses ip=dhcp; static environments must configure the interface, DNS, route, and time/CA trust in the initramfs. Confirm that the authorization host is reachable from the initramfs, not merely after the real root has booted.

Rebuild and inspect the initramfs:

    update-initramfs -u -k all
    lsinitramfs /boot/initrd.img-$(uname -r) | grep -E 'dongle-agent|pkcs11-tool|tpm2_quote|agent.toml'

Do not test the enforcement path on your only bootable installation. First test using a disposable host or VM with a working out-of-band recovery path.

## 7. Build and install the UEFI pre-OS stage

Use this path when authentication must complete before the OS loader, kernel, and initramfs. It runs under UEFI boot services and does not rely on Linux networking. The authorization server must already be reachable on the managed network.

### Platform prerequisites

The target firmware must expose:
- UEFI IPv4 Config 2 (DHCPv4) and a network interface usable by its HTTP driver.
- UEFI HTTP plus TLS service-binding/configuration protocols.
- Firmware DNS and a correct clock.
- TCG2 protocol with TPM 2.0 and an active SHA-256 PCR bank.
- A Secure-Boot-signed vendor driver that installs the DongleAttestationProtocol defined in uefi-stage/include/dongle_attestation_protocol.h.

UEFI does not provide a universal PKCS#11 API. The adapter is hardware/vendor-specific and is not included in this repository. It must retrieve the signature from the non-exportable dongle key and obtain a TPM quote using the server's nonce as qualifying data. It must not export private keys or PINs. Do not assume an OpenSC-capable dongle automatically has a UEFI driver.

The first version supports DHCPv4 only. Static IPv4, IPv6, Wi-Fi association, 802.1X, and automatic firmware network-driver loading are not implemented. Missing protocols or DHCP failure deny boot.

### Configure and build

Copy the example and set the endpoint identities and the complete next-stage device path:

    cp config/uefi-stage.example.env config/uefi-stage.env
    editor config/uefi-stage.env

DONGLE_UEFI_NEXT_BOOT_DEVICE_PATH must be the complete UEFI device path for the signed OS loader (for example, the firmware device path to shimx64.efi or grubx64.efi). It is not a Linux path such as /boot/efi/EFI/ubuntu/shimx64.efi. Use the target machine's firmware Boot#### record or trusted device-path tooling to obtain it. The example contains a deliberately invalid placeholder; replace it with the exact path for each machine class.

Build with Rust 1.91 or later:

    sh scripts/build-uefi-stage.sh

The output is:

    target/x86_64-unknown-uefi/release/dongle_uefi_stage.efi

Sign the EFI application with the Secure Boot key trusted by the target firmware. A typical sbsign invocation is:

    sbsign --key db.key --cert db.crt \
      --output dongle_uefi_stage.signed.efi \
      target/x86_64-unknown-uefi/release/dongle_uefi_stage.efi

The command above is only an example; use your organization's actual Secure Boot key-management process. Enroll the corresponding signing certificate in firmware db or the applicable shim trust store. Sign and enroll the platform token-adapter driver as well, and ensure firmware loads that driver before the Dongle UEFI application so the protocol is installed.

### Firmware TLS trust configuration

The UEFI application uses the firmware HTTP stack. Before deployment, install the authorization server's trusted CA roots in the firmware TLS trust configuration and verify that the firmware validates the certificate chain, server name, validity period, and permitted TLS versions. The application confirms that TLS protocol interfaces exist, but firmware-specific settings determine whether peer validation is actually enforced. Do not disable peer verification or use a test/accept-any-certificate mode. If the firmware cannot provide strict server authentication, do not deploy this pre-OS client over an untrusted network.

The policy service must expose the UEFI routes through the same HTTPS reverse proxy as the existing client:
- POST /v1/uefi/challenge
- POST /v1/uefi/authorize

They accept raw JSON bodies and reuse the same enrollment, one-time challenge, dongle-signature, TPM quote, and PCR-baseline verification functions as /v1/challenge and /v1/authorize. The UEFI app cannot authenticate if the TLS proxy, DNS, route, or server is unavailable; it halts.

### Install and enforce the boot order

Copy the signed application to an administrator-controlled path on the EFI System Partition, for example:

    install -D -m 0644 dongle_uefi_stage.signed.efi \
      /boot/efi/EFI/Dongle/dongle_uefi_stage.efi

Create a firmware boot entry for the Dongle application and configure it as the mandatory first stage. The application itself loads the configured next-stage EFI loader using the full device path and UEFI LoadImage/StartImage services after receiving an allow decision. UEFI LoadImage applies the firmware Secure Boot image policy to that next loader.

On denial, a missing adapter, DHCP failure, missing TLS/TPM support, invalid quote, or authorization service failure, the application stays halted rather than returning to Boot Manager. This prevents a normal Boot Manager fallback in that boot attempt. It cannot prevent a user with physical access or firmware administration rights from resetting the machine and selecting another boot entry. Restrict setup access, protect BootOrder/boot entries with the platform's available controls, disable unauthenticated alternate boot paths, and test cold boot, warm reboot, watchdog/reset, and recovery behavior. A firmware reset or a reconfigured BootOrder must not provide a direct path to the OS loader.

Keep the initramfs gate available as a second control only when the deployment intentionally wants both checks. If using the UEFI application as the mandatory pre-OS gate, do not configure an alternate boot entry that can bypass it and then rely on the initramfs script to compensate.

### What runs where

- UEFI application: DHCPv4, HTTPS challenge/authorization exchange, handoff to the next-stage EFI loader.
- Vendor UEFI adapter: token-specific PIN/session handling, non-exportable P-256 signature, TPM quote acquisition.
- dongle-authd: authoritative user/dongle/asset policy, dongle signature verification, TPM quote/PCR verification, decision record.
- Lattice reporter: remains on the authorization host. It publishes best-effort asset status after the decision and does not grant boot access. Never place Lattice environment or Sandboxes tokens in the UEFI image.

The UEFI application is a new platform-dependent path. CI can compile it, but successful compilation does not establish compatibility with a particular UEFI firmware, token driver, TPM implementation, TLS stack, or machine's device path. Hardware-in-the-loop validation is mandatory.

## 8. Lattice Sandboxes reporting

Create a Lattice Sandbox environment and note its resource endpoint, environment token, and account-level Sandboxes token. Set the three values on the authorization host, not on every boot client:

    install -d -m 0700 /etc/dongle
    install -m 0600 .env.example /etc/dongle/lattice.env
    editor /etc/dongle/lattice.env

Use these variables:

- LATTICE_ENDPOINT: hostname only, with no https:// prefix or path.
- ENVIRONMENT_TOKEN: the environment's Lattice auth token.
- SANDBOXES_TOKEN: the account-level Sandboxes bearer token.

For each asset you want published, add an `[assets.<id>.lattice_location]` table to the server policy with its real `latitude_degrees`, `longitude_degrees`, and optional `altitude_hae_meters`. The publisher skips an asset without this configured position rather than inventing coordinates. The reporter sends Authorization: Bearer <ENVIRONMENT_TOKEN> and Anduril-Sandbox-Authorization: Bearer <SANDBOXES_TOKEN> to Lattice's documented PUT /api/v1/entities endpoint. It publishes a stable, persistent `TEMPLATE_ASSET` entity with location and `milView` components, plus the latest user/dongle boot authorization status. It does not send the dongle private key, token PIN, TPM private key, or full quote payload to Lattice. Reporting is best-effort: Lattice being unavailable does not grant access and does not reverse an already verified decision.

The local TOML policy remains the authority for the enrolled public keys and user-to-asset permissions; this initial integration publishes status to Lattice but does not yet read authorization policy back from Lattice. The example uses the supported environment-token flow. Rotate environment tokens before expiry. OAuth client-credentials support can be added when it is enabled for the target Sandbox; the Lattice documentation currently describes that flow as beta in some deployments.

## 9. Kernel and secure-boot controls

Use your distribution's supported Secure Boot signing flow for the kernel and initramfs. Keep Secure Boot enabled, enforce signed kernel modules, and retain kernel lockdown. Do not add unsigned kernel patches, disable lockdown, or load unsigned modules to make this agent work.

Recommended kernel configuration controls include:
- CONFIG_MODULE_SIG=y
- CONFIG_MODULE_SIG_FORCE=y
- CONFIG_SECURITY_LOCKDOWN_LSM=y

The exact options and signing workflow are distribution/kernel-build dependent. Secure Boot must cover the bootloader, kernel, and the initramfs containing the gate; otherwise an attacker with physical access may replace or bypass the early-boot script. A measured PCR quote detects unexpected measurements only when the baseline and trust chain have been provisioned correctly.

## 10. Verification and negative tests

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

## 11. FIPS 140-3 scope and limitations

The project pins aws-lc-rs 1.18.1 with the FIPS feature, which selects AWS-LC-FIPS 4.x for the software ECDSA verification path and rustls provider. As of 21 November 2026, NIST lists AWS-LC 4 Cryptographic Module as active under CMVP certificates #5595 (dynamic) and #5596 (static). Both certificates require operation in approved mode and installation, initialization, and configuration as specified in Section 11.1 of the applicable AWS security policy. The startup check confirms that the linked AWS-LC reports FIPS mode; it does not attest that the deployed binary, platform, external dongle/TPM, or operational configuration meets every condition of those certificates. A FIPS compliance claim requires matching the exact validated module build/link mode and operating environment to the certificate security policy.

This does not certify the whole Dongle application, the hardware token, TPM, OS, kernel, boot chain, or deployment. The hardware dongle's own PKCS#11 cryptographic module must separately have an applicable FIPS 140-3 validation and be operated in its approved mode; using a PKCS#11 interface or OpenSC alone does not establish that. The TPM and firmware also have their own assurance and platform-validation requirements. Consult the relevant NIST certificate/security policy and an accredited CMVP laboratory or compliance authority before making a compliance assertion.

## 12. Operational considerations

- Keep the policy service on a protected management network and TLS-protect its public endpoint.
- Restrict policy edits to authorized administrators. Back up policy and audit logs securely.
- Provide a documented break-glass process that requires physical/administrative control and leaves an auditable record.
- Re-enroll a dongle immediately when lost, stolen, or suspected compromised by setting active = false.
- Disable a computer asset immediately when retired or compromised.
- The current reference implementation gates boot. It does not implement continuous user-session reauthentication, screen lock on dongle removal, directory-service login integration, or automated enrollment/key rotation.
