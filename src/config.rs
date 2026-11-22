use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::HashMap, fs, path::Path};

#[derive(Clone, Debug, Deserialize)]
pub struct Policy {
    pub server: ServerPolicy,
    #[serde(default)]
    pub users: HashMap<String, UserPolicy>,
    #[serde(default)]
    pub dongles: HashMap<String, DonglePolicy>,
    #[serde(default)]
    pub assets: HashMap<String, AssetPolicy>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerPolicy {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl_seconds: u64,
    #[serde(default = "default_tpm2_checkquote")]
    pub tpm2_checkquote: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UserPolicy {
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub allowed_assets: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DonglePolicy {
    #[serde(default)]
    pub active: bool,
    pub user_id: String,
    /// Base64-encoded uncompressed SEC1 P-256 public point (65 bytes).
    pub public_key_sec1_b64: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AssetPolicy {
    #[serde(default)]
    pub active: bool,
    /// PEM-encoded TPM 2.0 Attestation Key public portion, readable by authd.
    pub ak_public_key_pem_path: String,
    /// Lowercase SHA-256 digest of the serialized PCR output file from tpm2_quote.
    pub approved_pcrs_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AgentConfig {
    pub service_url: String,
    pub user_id: String,
    pub dongle_id: String,
    pub asset_id: String,
    pub pkcs11_module_path: String,
    pub pkcs11_token_label: String,
    /// PKCS#11 object ID in hexadecimal, e.g. "01".
    pub pkcs11_key_id: String,
    #[serde(default = "default_pkcs11_tool")]
    pub pkcs11_tool_path: String,
    pub tpm_ak_context_path: String,
    pub pcr_selection: String,
    #[serde(default = "default_tpm2_quote")]
    pub tpm2_quote_path: String,
}

impl Policy {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading policy file {}", path.display()))?;
        let policy: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing policy file {}", path.display()))?;
        if policy.server.challenge_ttl_seconds == 0 || policy.server.challenge_ttl_seconds > 300 {
            anyhow::bail!("server.challenge_ttl_seconds must be between 1 and 300");
        }
        Ok(policy)
    }
}

impl AgentConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading agent config {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing agent config {}", path.display()))?;
        if !config.service_url.starts_with("https://") {
            anyhow::bail!("service_url must use HTTPS; do not disable certificate verification");
        }
        for (name, value) in [
            ("user_id", &config.user_id),
            ("dongle_id", &config.dongle_id),
            ("asset_id", &config.asset_id),
            ("pkcs11_module_path", &config.pkcs11_module_path),
            ("pkcs11_token_label", &config.pkcs11_token_label),
            ("pkcs11_key_id", &config.pkcs11_key_id),
            ("tpm_ak_context_path", &config.tpm_ak_context_path),
            ("pcr_selection", &config.pcr_selection),
        ] {
            if value.trim().is_empty() {
                anyhow::bail!("agent config field {name} cannot be empty");
            }
        }
        Ok(config)
    }
}

fn default_listen() -> String {
    "127.0.0.1:8765".to_string()
}
fn default_challenge_ttl() -> u64 {
    90
}
fn default_tpm2_checkquote() -> String {
    "/usr/bin/tpm2_checkquote".to_string()
}
fn default_tpm2_quote() -> String {
    "/usr/bin/tpm2_quote".to_string()
}
fn default_pkcs11_tool() -> String {
    "/usr/bin/pkcs11-tool".to_string()
}
