# Dongle

Dongle is a Linux early-boot access-control prototype that combines a registered hardware signing key, TPM 2.0 measured-boot attestation, and an administrator-managed user-to-computer authorization policy. It includes an optional Anduril Lattice Sandboxes integration for publishing endpoint asset status.

The goal is to prevent a managed Linux computer from continuing its boot sequence unless the presented hardware key is authorized for the requested user and computer, and the computer can prove that its measured boot state matches an enrolled baseline.

> [!IMPORTANT]
> **Prototype / security-review status:** this repository is an initial reference implementation, not a production-certified authentication product. It has not been independently security-audited or validated against every target hardware token, TPM, firmware, initramfs, or Lattice environment. Do not enable the boot gate on a primary workstation until it has been built, tested, reviewed, and a tested recovery path is available.
>
> Enabling an AWS-LC FIPS build feature does not make this entire application, operating system, hardware token, TPM, kernel, or deployment FIPS 140-3 validated. See [FIPS 140-3 scope](#fips-140-3-scope-and-validation).

## Contents

- [Goals and design](#goals-and-design)
- [Architecture](#architecture)
- [Authentication sequence](#authentication-sequence)
- [Trust boundaries and security properties](#trust-boundaries-and-security-properties)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Build and test](#build-and-test)
- [Deployment overview](#deployment-overview)
- [Enroll a hardware dongle](#enroll-a-hardware-dongle)
- [Enroll a computer TPM](#enroll-a-computer-tpm)
- [Configure the authorization service](#configure-the-authorization-service)
- [Configure the initramfs agent](#configure-the-initramfs-agent)
- [Configure Lattice Sandboxes](#configure-lattice-sandboxes)
- [API overview](#api-overview)
- [Secure Boot and kernel integration](#secure-boot-and-kernel-integration)
- [Validation checklist](#validation-checklist)
- [Recovery and operations](#recovery-and-operations)
- [FIPS 140-3 scope and validation](#fips-140-3-scope-and-validation)
- [Current limitations and future work](#current-limitations-and-future-work)
- [Further documentation](#further-documentation)

## Goals and design

Dongle is intended to provide a hardware-backed boot authorization decision across three enrolled identities:

| Identity | Proof / policy | Purpose |
|---|---|---|
| **User** | Active local policy entry and explicit asset allow-list | Establishes which user identity is requesting access and which computers that identity may use |
| **Dongle** | Registered P-256 public key; signature produced by a PKCS#11 hardware token | Proves possession of the enrolled hardware-backed private key |
| **Computer asset** | Registered TPM 2.0 Attestation Key (AK) and approved PCR baseline | Binds the request to an enrolled computer and checks its measured boot state |

All three must be active and correctly related in the authorization policy. A key registered to one user must not authorize another user, and a user must not be able to use an enrolled key to access a computer outside that user's explicit allow-list.

The design is deliberately split into two parts:

1. **Local authorization policy** is the source of truth for user, dongle, and asset enrollment. The initial implementation stores that policy in a root-controlled TOML file on the authorization service.
2. **Lattice reporting** is an optional asset-visibility and audit integration. It publishes endpoint status, but it is not the cryptographic trust anchor and does not currently provide the authorization registry.

### Design goals

- Keep dongle private keys non-exportable inside the hardware token.
- Use a fresh server challenge to prevent replay of previously captured signatures and quotes.
- Bind the challenge to the user ID, dongle ID, asset ID, and random nonce.
- Verify a TPM quote against the registered computer Attestation Key.
- Compare the serialized PCR output against a known-good, administrator-approved baseline.
- Fail closed when authorization cannot be established.
- Keep the boot enforcement in the initramfs, before the transition to the real root filesystem.
- Preserve Secure Boot, kernel lockdown, and kernel module-signature enforcement.
- Keep Lattice credentials on the authorization service, never on the client boot image.

### Non-goals of the initial prototype

The current implementation is a boot gate, not a complete enterprise identity-management system. It does not yet provide interactive desktop login, directory-service authentication, continuous session reauthentication, automatic token enrollment, key rotation, remote policy synchronization from Lattice, or a custom patched kernel.

## Architecture

The normal boot chain remains responsible for verifying the signed bootloader, kernel, and initramfs. Dongle adds an authorization check inside the initramfs before the system transitions to its real root filesystem.

    UEFI Secure Boot
          |
          v
    Signed bootloader / kernel / initramfs
          |
          v
    Initramfs networking and device setup
          |
          v
    dongle-agent
       |            \
       |             \---- TPM 2.0 quote
       |                    |
       |                    v
       |              Computer Attestation Key
       |
       +---- PKCS#11 request to hardware dongle
       |        |
       |        v
       |    P-256 signature
       |
       v
    HTTPS authorization request
          |
          v
    TLS reverse proxy / protected network boundary
          |
          v
    dongle-authd
       |      \
       |       \---- Optional Lattice asset status
       |
       +---- Local enrollment policy
       |
       +---- Dongle signature verification
       |
       +---- TPM quote and PCR baseline verification
          |
          v
    Allow / deny
          |
          v
    Continue initramfs boot only on allow
          |
          v
       switch_root

### Components

| Component | Location | Responsibility |
|---|---|---|
| **dongle-agent** | Protected client initramfs | Requests a challenge, prompts for token PIN through OpenSC, signs the challenge, obtains the TPM quote, and submits proof |
| **dongle-authd** | Protected authorization host | Maintains in-memory challenges, loads enrollment policy, verifies dongle signatures and TPM evidence, and returns the decision |
| **PKCS#11 token** | Hardware dongle | Holds the non-exportable P-256 private key used for challenge signing |
| **TPM 2.0** | Managed computer | Holds the Attestation Key and produces a nonce-bound quote for the selected PCRs |
| **tpm2_checkquote** | Authorization host | Checks the TPM quote signature, qualification value, and supplied PCR data |
| **Lattice reporter** | Authorization host | Optionally publishes a persistent endpoint asset entity and the latest authorization result |
| **initramfs-tools hook** | Client build system | Includes the agent and its required files in the generated initramfs |
| **initramfs local-bottom script** | Client initramfs | Runs the agent before the real-root transition and panics on denial or failure |

## Authentication sequence

The current protocol follows this sequence.

1. **Check the requested identity binding.** The client sends the configured user ID, dongle ID, and asset ID to the challenge endpoint. The authorization service rejects missing, inactive, or incorrectly related entries.
2. **Create a fresh challenge.** The server generates a 32-byte nonce using AWS-LC randomness. It creates a challenge identifier, stores the challenge in memory, and gives it a short expiry configured by **server.challenge_ttl_seconds**.
3. **Build the signing transcript.** The transcript is domain-separated with the **ANDURIL-DONGLE-AUTH-V1** protocol label and length-prefixes the challenge ID, user ID, dongle ID, asset ID, and nonce. This prevents ambiguity when fields are concatenated.
4. **Sign with the hardware token.** The client hashes the transcript with SHA-256 through AWS-LC and asks OpenSC's **pkcs11-tool** to perform the ECDSA operation using the registered private-key object. The private key is never exported.
5. **Obtain a TPM quote.** The client invokes **tpm2_quote** using its configured TPM AK context, PCR selection, and the same server nonce as the qualification value.
6. **Submit proof.** The agent sends the dongle signature, TPM quote message, TPM quote signature, and serialized PCR output to the authorization service.
7. **Consume the challenge.** The service removes the pending challenge before validating it. A repeated request cannot reuse the same challenge.
8. **Verify all proofs.** The service checks the challenge expiry and identity binding, verifies the P-256 signature against the enrolled public key, checks the TPM quote with the registered AK public key, and compares the SHA-256 digest of the serialized PCR output with the enrolled asset baseline.
9. **Return the decision.** The server returns an allow or deny response. The initramfs agent exits successfully only when the response explicitly allows boot.
10. **Publish optional asset status.** When Lattice credentials and an operator-supplied asset location are configured, the service attempts to publish the latest authorization result. Lattice reporting does not change the authorization decision.

A network failure, service failure, invalid signature, expired or replayed challenge, incorrect identity binding, failed TPM quote, or PCR baseline mismatch must not be interpreted as authorization.

## Trust boundaries and security properties

### Hardware dongle

The private key is expected to be generated and retained on the hardware token. The server receives only the registered public key. The client uses the PKCS#11 interface through OpenSC and does not place the token PIN in the TOML configuration, process arguments, or environment variables.

The PIN prompt depends on the token, OpenSC version, reader, and initramfs console behaving as expected. Validate this on the exact hardware before relying on it.

### Computer TPM

The TPM Attestation Key is expected to be non-exportable. The server stores only the enrolled AK public key. The AK public key is treated as an enrolled trust anchor by this prototype; the initial code does not perform a full EK certificate and AK credential-chain enrollment ceremony.

The PCR baseline must be generated from a boot that an administrator has independently reviewed and approved. A baseline is not trustworthy merely because it was the first value observed.

### Authorization service

The service's default listener is **127.0.0.1:8765**. It is designed to sit behind a TLS reverse proxy or equivalent protected network boundary. The Rust HTTP service itself does not terminate TLS. The agent uses HTTPS with normal certificate verification and refuses an HTTP service URL.

The current service does not implement its own API bearer-token authentication or mutual TLS. Restrict access to the reverse proxy and authorization host using network policy; for higher-assurance deployments, add and validate client authentication at that boundary.

Pending challenges are held in process memory. Restarting the service invalidates outstanding challenges. A multi-instance deployment would require a shared, atomic challenge store and replay controls; the in-memory implementation is intended for a single service instance.

### Lattice

Lattice is a reporting destination, not the source of truth for authorization. The local policy file remains authoritative. The reporter skips an asset when no real location has been configured, rather than inventing coordinates.

Only endpoint identity/status metadata is sent. The implementation does not intentionally send dongle private keys, token PINs, TPM private material, or full TPM quote payloads to Lattice.

## Repository layout

    .
    ├── Cargo.toml
    ├── README.md
    ├── .env.example
    ├── config/
    │   ├── agent.sandbox.example.toml
    │   └── policy.sandbox.example.toml
    ├── docs/
    │   └── DEPLOYMENT.md
    ├── deploy/
    │   ├── initramfs-tools/
    │   │   ├── hooks/
    │   │   │   └── dongle-agent
    │   │   └── scripts/
    │   │       └── local-bottom/
    │   │           └── dongle-auth
    │   └── systemd/
    │       └── dongle-authd.service
    ├── scripts/
    │   └── export-sec1-public-key.sh
    └── src/
        ├── bin/
        │   ├── dongle-agent.rs
        │   └── dongle-authd.rs
        ├── config.rs
        ├── crypto.rs
        ├── lattice.rs
        ├── lib.rs
        ├── protocol.rs
        └── quote.rs

## Requirements

The example deployment targets Debian/Ubuntu systems using **initramfs-tools** and an x86-64 OpenSC module path. Other distributions, architectures, token providers, and initramfs frameworks require adaptation and testing.

### Build host

- Rust toolchain and Cargo.
- A supported Linux build environment for the AWS-LC build.
- Standard native build dependencies required by AWS-LC and the Rust dependency graph.

### Authorization host

- Linux host running **dongle-authd**.
- **tpm2-tools**, including **tpm2_checkquote**.
- A root-controlled policy TOML file.
- The enrolled TPM AK public-key PEM files for managed assets.
- A TLS reverse proxy or equivalent protected HTTPS ingress.
- Optional Lattice Sandbox environment, environment token, and Sandboxes token.

### Managed client

- UEFI Secure Boot-capable platform with a supported signed boot chain.
- TPM 2.0 and a provisioned Attestation Key.
- Hardware token that supports P-256 ECDSA through PKCS#11.
- OpenSC, including **pkcs11-tool** and a compatible PKCS#11 module.
- PC/SC daemon and a supported smart-card/dongle reader.
- **tpm2-tools**, including **tpm2_quote**.
- Debian/Ubuntu **initramfs-tools** for the supplied hook and script.
- Networking, DNS, routing, time, and trusted CA certificates available inside the initramfs before the gate executes.

## Build and test

The default Cargo feature enables the FIPS feature for AWS-LC and rustls. The library has a compile-time guard against building without the project FIPS feature, and both binaries call the AWS-LC FIPS-mode check at startup.

Build both binaries:

    cargo build --release --bins

Run formatting and tests:

    cargo fmt --all -- --check
    cargo test --all-targets

Do not use **--no-default-features** for a deployment build. Generate and review a Cargo.lock for release builds, commit it to the deployment source, and use locked dependency resolution in controlled release pipelines.

The GitHub Actions workflow runs formatting and tests using the default FIPS feature. A successful CI run validates the code against the runner's build environment; it does not validate the physical token, TPM, UEFI firmware, Secure Boot configuration, initramfs networking, Lattice tenant, or production operating environment.

## Deployment overview

The complete procedure is in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). The outline below describes the intended order.

### 1. Build and install the binaries

Build the two binaries and install them on their respective hosts.

Authorization host:

    install -D -m 0755 target/release/dongle-authd /usr/local/sbin/dongle-authd

Managed client:

    install -D -m 0755 target/release/dongle-agent /usr/local/sbin/dongle-agent

Install the platform dependencies listed above. The service host needs **tpm2_checkquote**; the client needs **tpm2_quote**, OpenSC, the PKCS#11 module, and PC/SC support.

### 2. Enroll the dongle key

Provision a P-256 keypair on the hardware token using the token vendor's approved procedure. Keep the private key on the token. Export the public key, convert it to a 65-byte uncompressed SEC1 point, and register its Base64 encoding in the authorization policy.

See [Enroll a hardware dongle](#enroll-a-hardware-dongle).

### 3. Enroll the computer TPM

Create or provision a TPM AK, copy only its public key to the authorization host, and capture a known-good PCR baseline. The AK context remains on the client and is included in the generated initramfs.

See [Enroll a computer TPM](#enroll-a-computer-tpm).

### 4. Configure and start the authorization service

Copy the example policy to **/etc/dongle/policy.toml**, enter the enrolled identities, and explicitly enable the correct user, dongle, and asset records. Install and start the systemd service. Keep the service bound to loopback and place it behind a TLS ingress that can be reached from the initramfs.

See [Configure the authorization service](#configure-the-authorization-service).

### 5. Configure and build the client initramfs

Copy the agent configuration to **/etc/dongle/agent.toml**. Install the initramfs hook and **local-bottom** script. Configure initramfs networking and ensure the agent's HTTPS service endpoint and CA trust are available before **local-bottom** is run.

Rebuild and inspect the initramfs before testing.

See [Configure the initramfs agent](#configure-the-initramfs-agent).

### 6. Test with a recovery path

Use a disposable computer or a test installation first. Test successful authorization, every deny condition, unavailable network/service, token removal, TPM mismatch, and boot recovery before rolling out to any essential workstation.

## Enroll a hardware dongle

The policy expects a P-256 ECDSA public key encoded as Base64 of a 65-byte uncompressed SEC1 point:

    0x04 || X-coordinate (32 bytes) || Y-coordinate (32 bytes)

The corresponding private key must remain on the dongle.

List token slots and objects:

    pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-token-slots

    pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
      --token-label "TOKEN_LABEL" --list-objects

Export the public-key object only:

    pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
      --token-label "TOKEN_LABEL" --read-object --type pubkey --id 01 \
      --output-file /tmp/dongle-public.der

Convert the public object into the format expected by the policy:

    scripts/export-sec1-public-key.sh /tmp/dongle-public.der

Place the resulting Base64 string in the dongle's **public_key_sec1_b64** policy field. The helper is written for the DER SubjectPublicKeyInfo output expected from the example OpenSC flow; verify the result and key curve before enrollment.

At boot, the client invokes **pkcs11-tool --login**. The PIN should be entered interactively on the initramfs console. Do not put a PIN, private key, or recovery secret in the policy TOML, agent TOML, kernel command line, .env file, or source repository.

The sample policy uses a placeholder token label, key ID, and public key. Replace all three with the values from the actual enrolled token.

## Enroll a computer TPM

The example uses a TPM 2.0 Endorsement Key and RSA Attestation Key. Follow your platform's TPM provisioning and enterprise trust policy; do not assume all systems expose the same PCRs or TPM tooling.

A typical starting point for the supplied example is:

    install -d -m 0700 /etc/dongle

    tpm2_createek -c /etc/dongle/ek.ctx \
      -G rsa -u /etc/dongle/ek.pub.pem -f pem

    tpm2_createak -C /etc/dongle/ek.ctx \
      -c /etc/dongle/ak.ctx \
      -G rsa -s rsassa -g sha256 \
      -u /etc/dongle/ak.pub.pem -f pem

Keep the AK context and all TPM private material on the managed computer. Copy the AK public PEM to the authorization host and set the asset's **ak_public_key_pem_path** to that administrator-controlled file.

### PCR baseline

The example configuration uses SHA-256 PCRs 0, 2, 4, 7, 10, and 11:

    sha256:0,2,4,7,10,11

That selection is only an example. Verify the PCR definitions and availability on the target machine's firmware, bootloader, Secure Boot policy, kernel, and initramfs. Capture the baseline only after the system has booted through a reviewed and approved configuration.

A baseline capture can use a fixed qualification value because the purpose of this step is to capture the serialized PCR output for administrator review:

    NONCE=0000000000000000000000000000000000000000000000000000000000000000

    tpm2_quote -c /etc/dongle/ak.ctx \
      -l sha256:0,2,4,7,10,11 \
      -q "$NONCE" \
      -m /tmp/approved.msg \
      -s /tmp/approved.sig \
      -o /tmp/approved.pcrs \
      -g sha256

    sha256sum /tmp/approved.pcrs

Set **approved_pcrs_sha256** to the SHA-256 digest of the complete serialized PCR output file. The server compares the PCR output received in the authorization request against this enrolled digest and invokes **tpm2_checkquote** to check the TPM quote, its signature, and its qualification value.

The selected PCR list in the client agent configuration and server asset policy must be kept aligned with the process used to capture the approved baseline. A baseline change requires a deliberate administrator review; never automatically accept a new PCR value after a failed check.

The AK public key is an enrolled trust anchor in this prototype. A production enrollment system should additionally validate the TPM's EK certificate and AK credential/attestation chain against an approved manufacturer or enterprise trust root before the AK is registered.

## Configure the authorization service

Copy the sample policy:

    install -d -m 0700 /etc/dongle
    install -D -m 0600 config/policy.sandbox.example.toml /etc/dongle/policy.toml

Edit **/etc/dongle/policy.toml**. The sample records are intentionally inactive. Replace all placeholders and only set **active = true** after the corresponding user, dongle, or computer has been properly enrolled.

The policy has three identity sections.

### Users

Example:

    [users.operator]
    active = true
    allowed_assets = ["linux-workstation-01"]

The allow-list is explicit. A missing asset from this list is a denial.

### Dongles

Example:

    [dongles.operator-key-01]
    active = true
    user_id = "operator"
    public_key_sec1_b64 = "BASE64_ENCODED_SEC1_P256_PUBLIC_POINT"

The dongle's **user_id** must match the user attempting authorization. The public key must be the key exported from the enrolled token, not a software-generated substitute.

### Assets

Example:

    [assets.linux-workstation-01]
    active = true
    ak_public_key_pem_path = "/etc/dongle/ak-linux-workstation-01.pem"
    approved_pcrs_sha256 = "64_HEX_CHARACTER_SHA256_DIGEST"
    pcr_selection = "sha256:0,2,4,7,10,11"

The AK public key file must be readable by the **dongle** service account and must be protected from unauthorized modification. The PCR digest must be computed from the approved TPM PCR output, not chosen manually.

### Run the service

Create the service account:

    useradd --system --home /var/lib/dongle \
      --shell /usr/sbin/nologin dongle

Protect the policy file:

    chown root:dongle /etc/dongle/policy.toml
    chmod 0640 /etc/dongle/policy.toml

Install and start the systemd unit:

    install -D -m 0644 deploy/systemd/dongle-authd.service \
      /etc/systemd/system/dongle-authd.service

    systemctl daemon-reload
    systemctl enable --now dongle-authd

The default service listener is **127.0.0.1:8765**. Configure a TLS reverse proxy on the authorization host and point the client agent to that proxy using an HTTPS URL. Ensure the proxy forwards only the required API routes and is restricted to the managed-client network. The service does not itself terminate TLS or provide API bearer-token authentication.

The service loads its policy file at startup. Restart **dongle-authd** after policy changes.

## Configure the initramfs agent

Copy the sample agent configuration:

    install -D -m 0600 config/agent.sandbox.example.toml \
      /etc/dongle/agent.toml

Edit the file and set:

- **service_url:** the HTTPS URL exposed by the protected reverse proxy.
- **user_id:** the user identity to authorize.
- **dongle_id:** the ID of the enrolled PKCS#11 token key.
- **asset_id:** the computer asset ID from the server policy.
- **pkcs11_module_path:** the actual PKCS#11 provider module on the client.
- **pkcs11_token_label:** the label shown by OpenSC for the token.
- **pkcs11_key_id:** the ID of the enrolled P-256 private-key object.
- **tpm_ak_context_path:** the client-side TPM AK context file.
- **pcr_selection:** the PCR selection used for the approved baseline.

The example module path is specific to Debian/Ubuntu x86-64 OpenSC installations. Adjust it for the target architecture and token vendor. The initramfs hook also accepts **PKCS11_MODULE_PATH** in its build environment to override its default module path.

### Install the initramfs hook and enforcement script

    install -D -m 0755 deploy/initramfs-tools/hooks/dongle-agent \
      /etc/initramfs-tools/hooks/dongle-agent

    install -D -m 0755 deploy/initramfs-tools/scripts/local-bottom/dongle-auth \
      /etc/initramfs-tools/scripts/local-bottom/dongle-auth

The hook includes:

- dongle-agent
- pkcs11-tool
- tpm2_quote
- pcscd
- the configured OpenSC PKCS#11 module
- /etc/dongle/agent.toml
- /etc/dongle/ak.ctx
- the system CA certificate bundle

Place the client AK context at **/etc/dongle/ak.ctx** before generating the initramfs. Protect it as root-owned provisioning material. The generated initramfs must itself be protected by the platform's Secure Boot signing and boot-image controls.

### Initramfs networking

The supplied hook packages files; it does not configure the client's network interface. Configure the initramfs so that networking is available before the **local-bottom** enforcement script runs.

For DHCP-managed systems, the kernel command line commonly uses:

    ip=dhcp

Static network configurations must provide the interface address, route, DNS, and the correct time/certificate trust context inside the initramfs. Validate that the HTTPS authorization host is reachable from the initramfs environment, not merely after the real root filesystem has started.

Rebuild and inspect the image:

    update-initramfs -u -k all

    lsinitramfs /boot/initrd.img-$(uname -r) | \
      grep -E 'dongle-agent|pkcs11-tool|tpm2_quote|agent.toml|ak.ctx'

The enforcement script runs the agent before **switch_root**. If the agent is missing, authorization is denied, or the server cannot be reached, it calls the initramfs panic path rather than continuing the boot.

> [!WARNING]
> A broken initramfs hook or unreachable authorization service can make the computer unable to boot normally. Test on a disposable machine or test installation with a known-good recovery image, alternate boot entry, and out-of-band administrative access. Do not begin by enabling enforcement on your only working computer.

## Configure Lattice Sandboxes

Lattice reporting is optional. If all three Lattice environment variables are absent, the authorization service starts with Lattice reporting disabled. If any one is set, the other required values must also be supplied.

Copy the example environment file to the authorization host:

    install -m 0600 .env.example /etc/dongle/lattice.env

Edit it and configure:

| Variable | Description |
|---|---|
| **LATTICE_ENDPOINT** | Sandbox hostname only; do not include a URL scheme or path |
| **ENVIRONMENT_TOKEN** | Lattice environment authentication token |
| **SANDBOXES_TOKEN** | Account-level Sandboxes authorization token |
| **RUST_LOG** | Optional Rust logging filter |

The systemd service reads **/etc/dongle/lattice.env** through its **EnvironmentFile** setting. Keep the file root-owned and readable only by the service's intended administrators.

The reporter sends:

- **Authorization: Bearer <ENVIRONMENT_TOKEN>**
- **Anduril-Sandbox-Authorization: Bearer <SANDBOXES_TOKEN>**

It uses the Lattice REST Entities endpoint at **/api/v1/entities** and publishes a persistent Linux endpoint asset entity. The entity includes the asset identity, the supplied position, a land/friendly **milView**, authorization status, and integration provenance.

### Configure an asset location

Lattice publication is skipped for an asset unless a real, operator-approved location is configured in the server policy:

    [assets.linux-workstation-01.lattice_location]
    latitude_degrees = 00.000000
    longitude_degrees = 00.000000
    altitude_hae_meters = 0.0

Replace these example values with the actual authorized position. Do not use placeholder coordinates in a production asset feed. The configuration loader checks that latitude, longitude, and altitude are finite and that latitude/longitude are within their valid ranges.

### Lattice trust boundary

The initial integration is **write-only reporting**. Local TOML policy remains authoritative for dongle public keys and user-to-asset permissions. The service does not currently read Lattice entities back to make the authorization decision.

Lattice reporting is best-effort telemetry. A Lattice API outage is logged and does not grant access or reverse a cryptographically verified decision. The reporter does not intentionally send token PINs, dongle private keys, TPM private material, or full TPM quote payloads.

## API overview

The authorization service currently exposes three HTTP routes. Expose them to managed clients only through the protected HTTPS ingress.

| Method | Route | Purpose |
|---|---|---|
| **GET** | **/healthz** | Basic service health response |
| **POST** | **/v1/challenge** | Validate the requested enrollment binding and issue a fresh challenge |
| **POST** | **/v1/authorize** | Consume the challenge and verify dongle and TPM evidence |

### Challenge request

    {
      "userId": "operator",
      "dongleId": "operator-key-01",
      "assetId": "linux-workstation-01"
    }

The service responds with:

    {
      "challengeId": "HEX_ENCODED_RANDOM_CHALLENGE",
      "nonceHex": "HEX_ENCODED_NONCE",
      "signingPayloadB64": "BASE64_ENCODED_PROTOCOL_TRANSCRIPT",
      "expiresInSeconds": 90
    }

The values above are illustrative placeholders, not valid credentials or a real challenge.

### Authorization request

The agent submits the challenge identifier and the matching identity tuple, plus Base64-encoded proof material:

    {
      "challengeId": "CHALLENGE_ID",
      "userId": "operator",
      "dongleId": "operator-key-01",
      "assetId": "linux-workstation-01",
      "dongleSignatureB64": "BASE64_DER_ECDSA_SIGNATURE",
      "quoteMessageB64": "BASE64_TPM_QUOTE_MESSAGE",
      "quoteSignatureB64": "BASE64_TPM_QUOTE_SIGNATURE",
      "pcrValuesB64": "BASE64_SERIALIZED_PCR_OUTPUT"
    }

A successful decision has **allowed** set to true. A denial has **allowed** set to false and a generic reason. Detailed verification failures are recorded in the service log; callers should not rely on internal failure details being exposed through the API.

The authorization endpoint consumes the challenge before verification. A failed attempt therefore requires requesting a new challenge. Unknown, expired, and replayed challenge IDs are denied.

## Secure Boot and kernel integration

Dongle does not patch the running kernel, inject undocumented kernel hooks, or require unsigned kernel modules. It provides an early userspace gate that relies on the platform's boot trust chain.

Use the distribution's supported Secure Boot process and ensure the bootloader, kernel, and initramfs containing the gate are protected against unauthorized replacement. A signed kernel alone is not sufficient if an attacker can replace the initramfs or bypass the configured bootloader policy.

Recommended kernel controls for a managed deployment include:

- **CONFIG_MODULE_SIG=y**
- **CONFIG_MODULE_SIG_FORCE=y**
- **CONFIG_SECURITY_LOCKDOWN_LSM=y**

The exact settings and signing process depend on the Linux distribution and kernel build. Validate the effective runtime state, not merely the presence of a setting in a configuration file.

The measured PCR selection should cover the boot components relevant to the asset policy. Review platform-specific PCR definitions and event logs. The sample PCR list is not a universal secure-boot profile.

## Validation checklist

Before considering an endpoint enrolled, test at least the following cases on representative hardware.

| Test | Expected result |
|---|---|
| Active user, enrolled dongle, enrolled asset, approved PCR state | Allow |
| Unknown dongle ID | Deny |
| Inactive dongle | Deny |
| Dongle bound to another user | Deny |
| User not allow-listed for the asset | Deny |
| Inactive user or asset | Deny |
| Modified or invalid dongle signature | Deny |
| Expired challenge | Deny |
| Replayed challenge | Deny |
| User/dongle/asset fields changed between challenge and authorization | Deny |
| Wrong TPM AK | Deny |
| Wrong TPM quote qualification/nonce | Deny |
| Modified PCR output or unapproved baseline | Deny |
| Authorization service unavailable | Initramfs refuses to continue |
| DNS, routing, or TLS failure | Initramfs refuses to continue |
| Lattice unavailable while core authorization succeeds | Core decision remains based on local verification; Lattice report is logged as failed |

Also validate operational edge cases:

- The reader and token are detected reliably in the initramfs.
- The PIN prompt is visible and accepts input on the target console.
- The TPM AK context is available and usable in the initramfs.
- The client can resolve and reach the TLS authorization endpoint before **local-bottom**.
- The initramfs CA bundle trusts the certificate presented by the HTTPS endpoint.
- A policy change takes effect after the service is restarted.
- A revoked or lost dongle can be disabled in policy before another boot authorization is attempted.
- The administrator can recover a denied machine without weakening Secure Boot or permanently bypassing the gate.

## Recovery and operations

A fail-closed boot gate must have a documented recovery path. Before deployment, decide who can authorize recovery, how recovery is recorded, and how the system is restored to a known-good state.

Recommended operational practices:

- Keep an alternate signed recovery boot entry or trusted recovery image.
- Keep physical or out-of-band administrative access available during rollout.
- Back up the authorization policy and approved PCR baseline records securely.
- Restrict write access to policy files, AK public-key files, and initramfs build inputs.
- Disable a lost or suspected-compromised dongle by setting its policy entry inactive.
- Disable retired or compromised computers by setting their asset entry inactive.
- Rebaseline PCRs only after an administrator has reviewed the changed boot chain.
- Rotate Lattice environment credentials through the supported Lattice process.
- Avoid logging PINs, private keys, TPM context contents, bearer tokens, or full challenge proof payloads.
- Do not make a new PCR measurement trusted automatically after a mismatch.

The service currently loads the policy at startup. Restart it after enrollment or revocation changes. Outstanding challenges are in memory and are lost on service restart.

## FIPS 140-3 scope and validation

The default build enables the FIPS feature for **aws-lc-rs** version **1.18.1** and the AWS-LC-backed rustls provider. Both binaries call the AWS-LC FIPS-mode check at startup and refuse to continue when it fails.

This is a deliberate cryptographic dependency and configuration choice, **not a claim that Dongle is a FIPS 140-3 validated product**.

A FIPS 140-3 claim depends on the exact validated cryptographic module, certificate, security policy, module version, build/link configuration, approved operating mode, and operating environment. An application using a cryptographic module does not inherit validation automatically.

In particular:

- AWS-LC's validation covers the specific AWS-LC module configuration and operating conditions described by its applicable CMVP certificate and security policy.
- The external PKCS#11 hardware token must have its own applicable FIPS 140-3 validation and must be used in its approved mode if that is part of the compliance requirement.
- The TPM, firmware, Secure Boot chain, operating system, kernel, initramfs, service configuration, and deployment environment are not certified by this repository.
- OpenSC and the PKCS#11 API do not themselves prove that the attached token is a validated cryptographic module.
- The startup FIPS-mode check does not perform a complete compliance assessment of the host or hardware.

Before making a compliance assertion, identify the required validation boundary and compare the exact deployed configuration with the current NIST CMVP record and applicable vendor security policy. Have the deployment assessed by the organization's security/compliance authority or an appropriately accredited CMVP laboratory.

## Current limitations and future work

The following are known limitations of this initial implementation and should be addressed before a production rollout.

### Authorization and service hardening

- Pending challenges are held in a process-local in-memory map. There is no persistent or distributed challenge store.
- The service does not currently include API bearer-token authentication or mutual TLS. Protect its listener behind a TLS ingress, network ACLs, and an appropriate client-authentication control.
- There is no built-in request rate limiting, per-token lockout, enrollment administration API, or automated key revocation workflow.
- Policy is loaded at startup; there is no file watcher or live policy reload.
- The service should receive a dedicated security review for concurrency, resource exhaustion, audit integrity, and deployment hardening.

### TPM enrollment and measurement

- The initial enrollment flow treats the registered AK public key as trusted. Full EK certificate and AK credential-chain validation should be implemented as part of a managed enrollment ceremony.
- PCR selection and baselines are platform-specific. Production policy should validate expected PCR selections and measured-boot event logs for each supported platform and update lifecycle.
- The initial policy model stores one approved PCR-output digest per asset. Production environments may need controlled multi-baseline rotation during signed kernel and firmware upgrades.

### User/session authentication

- The initial implementation proves possession of the assigned hardware dongle and verifies its configured user/asset binding. It does not independently authenticate a human through a directory service, password provider, biometric sensor, or interactive operating-system login.
- It does not continuously verify that the dongle remains present after boot.
- It does not lock or terminate an existing user session when the dongle is removed.

### Lattice integration

- Lattice is currently an outbound reporting integration, not the authoritative policy database.
- Entity publication requires an explicitly configured asset location.
- There is no synchronization, reconciliation, or policy read-back from Lattice.
- Lattice entity schema and authorization behavior must be validated against the target Sandbox environment and its API permissions.

### Boot integration

- The provided scripts target Debian/Ubuntu **initramfs-tools**.
- Initramfs networking setup is a deployment responsibility and must run before the enforcement script.
- The supplied example PKCS#11 module path is architecture/package specific.
- The generated initramfs and its bootloader integration must be protected by the platform's Secure Boot chain.
- A separate recovery mode and administrative override process must be designed and tested for each deployment.

## Further documentation

- [Deployment guide](docs/DEPLOYMENT.md) — detailed prerequisites, enrollment, PCR baseline, service installation, initramfs setup, Lattice credentials, and negative tests.
- [Policy example](config/policy.sandbox.example.toml) — deny-by-default user, dongle, and asset enrollment policy.
- [Agent configuration example](config/agent.sandbox.example.toml) — managed-client token, TPM, and HTTPS endpoint settings.
- [Lattice environment example](.env.example) — environment and Sandboxes credential variable names.
- [Initramfs hook](deploy/initramfs-tools/hooks/dongle-agent) — packages the early-boot client and required files.
- [Initramfs enforcement script](deploy/initramfs-tools/scripts/local-bottom/dongle-auth) — invokes the agent before the real-root transition.
- [Authorization service unit](deploy/systemd/dongle-authd.service) — systemd service hardening and environment-file configuration.

---

**Security notice:** This repository is a starting point for engineering and validation. Treat every example identity, key, location, digest, URL, and credential as a placeholder. Do not deploy the enforcement path on production systems until the hardware, boot chain, network boundary, policy lifecycle, recovery process, and compliance scope have been independently reviewed.
