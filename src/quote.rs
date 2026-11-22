use crate::{
    config::AssetPolicy,
    protocol::{decode_b64, AuthorizeRequest},
};
use aws_lc_rs::digest::{digest, SHA256};
use std::{fs, process::Command};
use tempfile::tempdir;

pub fn verify_tpm_quote(
    asset: &AssetPolicy,
    request: &AuthorizeRequest,
    expected_nonce_hex: &str,
    checkquote_path: &str,
) -> anyhow::Result<()> {
    let quote_message = decode_b64(&request.quote_message_b64, "quoteMessage")?;
    let quote_signature = decode_b64(&request.quote_signature_b64, "quoteSignature")?;
    let pcr_values = decode_b64(&request.pcr_values_b64, "pcrValues")?;

    anyhow::ensure!(!quote_message.is_empty(), "TPM quote message is empty");
    anyhow::ensure!(!quote_signature.is_empty(), "TPM quote signature is empty");
    anyhow::ensure!(!pcr_values.is_empty(), "TPM PCR snapshot is empty");
    anyhow::ensure!(
        !asset.pcr_selection.trim().is_empty(),
        "registered asset PCR selection is empty"
    );

    let expected = asset.approved_pcrs_sha256.trim().to_ascii_lowercase();
    anyhow::ensure!(
        expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
        "asset approved_pcrs_sha256 must be 64 hexadecimal characters"
    );

    let pcr_digest = digest(&SHA256, &pcr_values);
    let actual = hex::encode(pcr_digest.as_ref());
    anyhow::ensure!(
        actual == expected,
        "TPM PCR snapshot does not match the approved asset baseline"
    );

    let ak_public_pem = fs::read(&asset.ak_public_key_pem_path)
        .map_err(|e| anyhow::anyhow!("cannot read registered TPM AK public key: {e}"))?;
    let dir = tempdir().map_err(|e| anyhow::anyhow!("cannot create quote workspace: {e}"))?;
    let message_path = dir.path().join("quote.msg");
    let signature_path = dir.path().join("quote.sig");
    let pcr_path = dir.path().join("quote.pcrs");
    let public_path = dir.path().join("ak.pem");

    fs::write(&message_path, quote_message)?;
    fs::write(&signature_path, quote_signature)?;
    fs::write(&pcr_path, pcr_values)?;
    fs::write(&public_path, ak_public_pem)?;

    // Check both quote authenticity/nonce and exact approved PCR selection.
    let output = Command::new(checkquote_path)
        .arg("--public")
        .arg(&public_path)
        .arg("--message")
        .arg(&message_path)
        .arg("--signature")
        .arg(&signature_path)
        .arg("--pcr")
        .arg(&pcr_path)
        .arg("--hash-algorithm")
        .arg("sha256")
        .arg("--qualification")
        .arg(expected_nonce_hex)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to execute tpm2_checkquote: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("TPM quote verification failed: {}", stderr.trim());
    }
    Ok(())
}
