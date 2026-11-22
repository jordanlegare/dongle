use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use reqwest::Client;
use serde_json::json;
use std::env;
use uuid::Uuid;

#[derive(Clone)]
pub struct LatticeReporter {
    client: Client,
    publish_url: String,
    environment_token: String,
    sandboxes_token: String,
}

/// Lattice is an optional reporting plane. Missing credentials disable reporting;
/// partial configuration is an error so deployment mistakes are visible.
impl LatticeReporter {
    pub fn from_env() -> Result<Option<Self>> {
        let endpoint = env::var("LATTICE_ENDPOINT").ok();
        let environment_token = env::var("ENVIRONMENT_TOKEN").ok();
        let sandboxes_token = env::var("SANDBOXES_TOKEN").ok();

        if endpoint.is_none() && environment_token.is_none() && sandboxes_token.is_none() {
            return Ok(None);
        }

        let endpoint = endpoint.context("LATTICE_ENDPOINT is required when Lattice is enabled")?;
        let environment_token = environment_token.context("ENVIRONMENT_TOKEN is required when Lattice is enabled")?;
        let sandboxes_token = sandboxes_token.context("SANDBOXES_TOKEN is required for Lattice Sandboxes")?;

        anyhow::ensure!(
            !endpoint.contains("://") && !endpoint.contains('/') && !endpoint.trim().is_empty(),
            "LATTICE_ENDPOINT must be the hostname only, without scheme or path"
        );
        anyhow::ensure!(!environment_token.trim().is_empty(), "ENVIRONMENT_TOKEN cannot be empty");
        anyhow::ensure!(!sandboxes_token.trim().is_empty(), "SANDBOXES_TOKEN cannot be empty");

        let client = Client::builder()
            .https_only(true)
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .context("building Lattice HTTPS client")?;

        Ok(Some(Self {
            client,
            publish_url: format!("https://{endpoint}/api/v1/entities"),
            environment_token,
            sandboxes_token,
        }))
    }

    /// Publish an asset entity update using Lattice's documented REST endpoint.
    /// This is best-effort telemetry and never changes the local authorization decision.
    pub async fn publish_asset_status(&self, asset_id: &str, allowed: bool) -> Result<()> {
        let entity_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, format!("dongle-endpoint:{asset_id}").as_bytes());
        let now = Utc::now();
        let activity = if allowed { "BOOT_AUTHORIZATION_GRANTED" } else { "BOOT_AUTHORIZATION_DENIED" };
        let role = "Linux endpoint boot access control";
        let timestamp = now.to_rfc3339_opts(SecondsFormat::Millis, true);

        let entity = json!({
            "entityId": entity_id.to_string(),
            "description": format!("Dongle-managed Linux endpoint {asset_id}"),
            "isLive": true,
            "aliases": { "name": asset_id },
            "ontology": {
                "template": "TEMPLATE_ASSET",
                "platformType": "LINUX_ENDPOINT"
            },
            "status": {
                "platformActivity": activity,
                "role": role
            },
            "provenance": {
                "integrationName": "dongle-auth",
                "dataType": "BOOT_AUTHORIZATION",
                "sourceUpdateTime": timestamp
            }
        });

        let response = self.client
            .put(&self.publish_url)
            .bearer_auth(&self.environment_token)
            .header(
                "Anduril-Sandbox-Authorization",
                format!("Bearer {}", self.sandboxes_token),
            )
            .json(&entity)
            .send()
            .await
            .context("sending endpoint status to Lattice")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Lattice rejected endpoint update ({status}): {}", body.chars().take(512).collect::<String>());
        }
        Ok(())
    }
}
