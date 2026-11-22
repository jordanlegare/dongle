# Dongle

A Linux early-boot access gate for registered hardware signing keys, TPM 2.0 measured-boot evidence, and computer/user authorization, with optional Anduril Lattice asset reporting.

> **Status:** initial reference implementation. The repository was empty when this work began. This project is not a certified product and does not, by itself, make a host FIPS 140-3 compliant.

## Security model

1. UEFI Secure Boot verifies the signed kernel and initramfs. Kernel lockdown and module-signature enforcement remain enabled; this project does not patch the running kernel or install undocumented kernel hooks.
2. Before `switch_root`, the initramfs gate requests a single-use authorization challenge from the policy service.
3. A registered P-256 private key in a PKCS#11 hardware token signs the challenge. The private key is never exported.
4. The TPM 2.0 Attestation Key (AK) quotes the configured PCR set using the same server nonce. The service verifies the quote with `tpm2_checkquote` and checks the PCR snapshot against the registered asset baseline.
5. The service checks the dongle-to-user and user-to-asset bindings, consumes the challenge, and issues a short-lived allow/deny response. The initramfs continues boot only on an allow response.
6. When configured with an operator-supplied location, the service publishes the endpoint as a persistent Lattice asset and records the latest user/dongle authorization state. Local TOML remains the enrollment authority; Lattice is an audit/asset-visibility integration, not the root of trust for boot admission.

## FIPS 140-3

The default build pins `aws-lc-rs` 1.18.1 with its `fips` feature, selecting AWS-LC-FIPS 4.x. NIST lists the AWS-LC 4 dynamic and static modules as active under CMVP certificates #5595 and #5596. The binaries check FIPS mode at startup. Validation still applies only when the validated module, approved mode, exact build, and operating environment match the applicable NIST security policy; this does not certify the dongle, TPM, host, kernel, or complete deployment.

## Components

- `dongle-authd`: policy service; issues challenges, verifies token signatures and TPM quotes, and optionally reports asset status to Lattice.
- `dongle-agent`: initramfs client; prompts the hardware token through `pkcs11-tool`, obtains a TPM quote with `tpm2_quote`, and fails closed.
- `config/`: deny-by-default policy and deployment examples.
- `deploy/initramfs-tools/`: Debian/Ubuntu initramfs hook for the pre-`switch_root` gate.
- `deploy/systemd/`: service unit for post-boot health reporting/maintenance.

## Quick start

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for prerequisites, key enrollment, PCR baseline capture, service configuration, initramfs integration, Lattice Sandboxes credentials, and test steps.

Never commit `.env`, private keys, token PINs, Lattice secrets, or generated TPM private material.
