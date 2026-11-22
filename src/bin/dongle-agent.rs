use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use dongle::{
    config::AgentConfig,
    protocol::{decode_b64, AuthorizeRequest, AuthorizeResponse, ChallengeRequest, ChallengeResponse},
};
use reqwest::Client;
use std::{
    env,
    fs,
    process::Command,
    time::Duration,
};
use tempfile::tempdir;

fn ecdsa_raw_p256_to_der(raw: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(raw.len() == 64, "PKCS#11 ECDSA output must be 64-byte P-256 r||s");

    fn append_integer(src: &[u8], dst: &mut Vec<u8>) -> Result<()> {
        let first = src.iter().position(|b| *b != 0).unwrap_or(src.len() - 1);
        let value = &src[first..];
        anyhow::ensure!(value.len() <= 32, "invalid ECDSA integer");
        let needs_zero = value[0] & 0x80 != 0;
        dst.push(0x02);
        dst.push((value.len() + usize::from(needs_zero)) as u8);
        if needs_zero {
            dst.push(0);
        }
        dst.extend_from_slice(value);
        Ok(())
    }

    let mut body = Vec::with_capacity(72);
    append_integer(&raw[..32], &mut body)?;
    append_integer(&raw[32..], &mut body)?;

    let mut der = Vec::with_capacity(body.len() + 2);
    der.push(0x30);
    der.push(body.len() as u8);
    der.extend_from_slice(&body);
    Ok(der)
}

fn sign_with_pkcs11(config: &AgentConfig, payload: &[u8]) -> Result<Vec<u8>> {
    let dir = tempdir().context("creating PKCS#11 workspace")?;
    let input_path = dir.path().join("challenge.bin");
    let output_path = dir.path().join("signature.raw");
    fs::write(&input_path, payload)?;

    // Do not pass the PIN as a command-line argument or environment variable.
    // pkcs11-tool prompts on the initramfs console after --login.
    let status = Command::new(&config.pkcs11_tool_path)
        .arg("--module").arg(&config.pkcs11_module_path)
        .arg("--token-label").arg(&config.pkcs11_token_label)
        .arg("--login")
        .arg("--type").arg("privkey")
        .arg("--id").arg(&config.pkcs11_key_id)
        .arg("--mechanism").arg("ECDSA")
        .arg("--sign")
        .arg("--input-file").arg(&input_path)
        .arg("--output-file").arg(&output_path)
        .status()
        .with_context(|| format!("starting PKCS#11 tool {}", config.pkcs11_tool_path))?;

    anyhow::ensure!(status.success(), "hardware token refused or failed the signing operation");
    let raw_signature = fs::read(&output_path).context("reading PKCS#11 signature")?;
    ecdsa_raw_p256_to_der(&raw_signature)
}

fn create_tpm_quote(config: &AgentConfig, nonce_hex: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let dir = tempdir().context("creating TPM quote workspace")?;
    let message_path = dir.path().join("quote.msg");
    let signature_path = dir.path().join("quote.sig");
    let pcr_path = dir.path().join("quote.pcrs");

    let status = Command::new(&config.tpm2_quote_path)
        .arg("--key-context").arg(&config.tpm_ak_context_path)
        .arg("--pcr-list").arg(&config.pcr_selection)
        .arg("--qualification").arg(nonce_hex)
        .arg("--message").arg(&message_path)
        .arg("--signature").arg(&signature_path)
        .arg("--pcr").arg(&pcr_path)
        .arg("--hash-algorithm").arg("sha256")
        .status()
        .with_context(|| format!("starting TPM quote tool {}", config.tpm2_quote_path))?;

    anyhow::ensure!(status.success(), "TPM 2.0 quote operation failed");
    Ok((
        fs::read(&message_path).context("reading TPM quote message")?,
        fs::read(&signature_path).context("reading TPM quote signature")?,
        fs::read(&pcr_path).context("reading TPM PCR snapshot")?,
    ))
}

async fn run(config: AgentConfig) -> Result<()> {
    let client = Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(25))
        .build()
        .context("building policy-service HTTPS client")?;
    let base = config.service_url.trim_end_matches('/');

    let challenge: ChallengeResponse = client
        .post(format!("{base}/v1/challenge"))
        .json(&ChallengeRequest {
            user_id: config.user_id.clone(),
            dongle_id: config.dongle_id.clone(),
            asset_id: config.asset_id.clone(),
        })
        .send()
        .await
        .context("requesting boot authorization challenge")?
        .error_for_status()
        .context("policy service rejected challenge request")?
        .json()
        .await
        .context("decoding authorization challenge")?;

    let transcript = decode_b64(&challenge.signing_payload_b64, "signingPayload")?;
    let dongle_signature = sign_with_pkcs11(&config, &transcript)?;
    let (quote_message, quote_signature, pcr_values) =
        create_tpm_quote(&config, &challenge.nonce_hex)?;

    let request = AuthorizeRequest {
        challenge_id: challenge.challenge_id,
        user_id: config.user_id,
        dongle_id: config.dongle_id,
        asset_id: config.asset_id,
        dongle_signature_b64: STANDARD.encode(dongle_signature),
        quote_message_b64: STANDARD.encode(quote_message),
        quote_signature_b64: STANDARD.encode(quote_signature),
        pcr_values_b64: STANDARD.encode(pcr_values),
    };

    let response: AuthorizeResponse = client
        .post(format!("{base}/v1/authorize"))
        .json(&request)
        .send()
        .await
        .context("submitting dongle and TPM proof")?
        .error_for_status()
        .context("policy service rejected authorization request")?
        .json()
        .await
        .context("decoding authorization decision")?;

    anyhow::ensure!(response.allowed, "boot authorization denied: {}", response.reason);
    println!("dongle authorization granted for asset {}", request.asset_id);
    Ok(())
}

#[tokio::main]
async fn main() {
    let config_path = env::args().nth(1).unwrap_or_else(|| "/etc/dongle/agent.toml".to_string());
    let result = AgentConfig::load(&config_path).and_then(|config| {
        // Validate that a URL is configured before starting any token interaction.
        if !config.service_url.starts_with("https://") {
            anyhow::bail!("service_url must use HTTPS");
        }
        Ok(config)
    });

    match result {
        Ok(config) => {
            if let Err(error) = run(config).await {
                eprintln!("dongle-agent: {error:#}");
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("dongle-agent: {error:#}");
            std::process::exit(1);
        }
    }
}
