use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use dongle::{
    config::{AssetPolicy, Policy},
    crypto::verify_dongle_signature,
    lattice::LatticeReporter,
    protocol::{
        encode_payload, make_signing_payload, AuthorizeRequest, AuthorizeResponse,
        ChallengeRequest, ChallengeResponse,
    },
    quote::verify_tpm_quote,
};
use serde_json::json;
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    policy: Arc<Policy>,
    pending: Arc<Mutex<HashMap<String, PendingChallenge>>>,
    lattice: Option<LatticeReporter>,
}

struct PendingChallenge {
    user_id: String,
    dongle_id: String,
    asset_id: String,
    nonce_hex: String,
    transcript: Vec<u8>,
    expires_at: Instant,
}

type ApiError = (StatusCode, Json<serde_json::Value>);

fn api_error(status: StatusCode, message: &str) -> ApiError {
    (status, Json(json!({ "error": message })))
}

fn enrolled_binding(policy: &Policy, user_id: &str, dongle_id: &str, asset_id: &str) -> bool {
    let Some(user) = policy.users.get(user_id) else { return false };
    let Some(dongle) = policy.dongles.get(dongle_id) else { return false };
    let Some(asset) = policy.assets.get(asset_id) else { return false };
    user.active
        && dongle.active
        && asset.active
        && dongle.user_id == user_id
        && user.allowed_assets.iter().any(|allowed| allowed == asset_id)
}

async fn issue_challenge(
    State(state): State<AppState>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    if request.user_id.trim().is_empty()
        || request.dongle_id.trim().is_empty()
        || request.asset_id.trim().is_empty()
        || request.user_id.len() > 256
        || request.dongle_id.len() > 256
        || request.asset_id.len() > 256
    {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid identity binding"));
    }

    if !enrolled_binding(&state.policy, &request.user_id, &request.dongle_id, &request.asset_id) {
        return Err(api_error(StatusCode::FORBIDDEN, "user, dongle, or asset is not enrolled for this binding"));
    }

    let mut nonce = [0u8; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "secure random generation failed"))?;

    let challenge_id = hex::encode(nonce);
    let nonce_hex = challenge_id.clone();
    let transcript = make_signing_payload(
        &challenge_id,
        &request.user_id,
        &request.dongle_id,
        &request.asset_id,
        &nonce,
    );
    let ttl = state.policy.server.challenge_ttl_seconds;
    let challenge = PendingChallenge {
        user_id: request.user_id,
        dongle_id: request.dongle_id,
        asset_id: request.asset_id,
        nonce_hex: nonce_hex.clone(),
        transcript: transcript.clone(),
        expires_at: Instant::now() + Duration::from_secs(ttl),
    };

    {
        let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.retain(|_, item| item.expires_at > Instant::now());
        pending.insert(challenge_id.clone(), challenge);
    }

    Ok(Json(ChallengeResponse {
        challenge_id,
        nonce_hex,
        signing_payload_b64: encode_payload(&transcript),
        expires_in_seconds: ttl,
    }))
}

async fn publish_lattice(state: &AppState, asset_id: &str, allowed: bool) {
    if let Some(reporter) = &state.lattice {
        if let Err(error) = reporter.publish_asset_status(asset_id, allowed).await {
            warn!(asset_id, error = %error, "Lattice status publish failed; access decision is unchanged");
        }
    }
}

async fn authorize(
    State(state): State<AppState>,
    Json(request): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeResponse>, ApiError> {
    let pending = {
        let mut challenges = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        challenges.remove(&request.challenge_id)
    };

    let decision_id = Uuid::new_v4().to_string();
    let Some(challenge) = pending else {
        return Ok(Json(AuthorizeResponse {
            allowed: false,
            decision_id,
            reason: "unknown_or_replayed_challenge".to_string(),
        }));
    };

    let failure = (|| -> anyhow::Result<()> {
        anyhow::ensure!(challenge.expires_at > Instant::now(), "challenge expired");
        anyhow::ensure!(
            request.user_id == challenge.user_id
                && request.dongle_id == challenge.dongle_id
                && request.asset_id == challenge.asset_id,
            "challenge identity binding mismatch"
        );
        anyhow::ensure!(
            enrolled_binding(&state.policy, &challenge.user_id, &challenge.dongle_id, &challenge.asset_id),
            "enrollment is inactive"
        );

        let dongle = state.policy.dongles.get(&challenge.dongle_id)
            .ok_or_else(|| anyhow::anyhow!("dongle is not registered"))?;
        let public_key = STANDARD.decode(&dongle.public_key_sec1_b64)
            .map_err(|_| anyhow::anyhow!("registered dongle public key is not valid base64"))?;
        let signature = STANDARD.decode(&request.dongle_signature_b64)
            .map_err(|_| anyhow::anyhow!("dongle signature is not valid base64"))?;

        verify_dongle_signature(&public_key, &challenge.transcript, &signature)?;

        let asset: &AssetPolicy = state.policy.assets.get(&challenge.asset_id)
            .ok_or_else(|| anyhow::anyhow!("asset is not registered"))?;
        verify_tpm_quote(
            asset,
            &request,
            &challenge.nonce_hex,
            &state.policy.server.tpm2_checkquote,
        )?;
        Ok(())
    })();

    match failure {
        Ok(()) => {
            info!(
                user_id = %challenge.user_id,
                dongle_id = %challenge.dongle_id,
                asset_id = %challenge.asset_id,
                decision_id = %decision_id,
                "boot authorization granted"
            );
            publish_lattice(&state, &challenge.asset_id, true).await;
            Ok(Json(AuthorizeResponse {
                allowed: true,
                decision_id,
                reason: "verified".to_string(),
            }))
        }
        Err(error) => {
            warn!(
                user_id = %challenge.user_id,
                dongle_id = %challenge.dongle_id,
                asset_id = %challenge.asset_id,
                decision_id = %decision_id,
                reason = %error,
                "boot authorization denied"
            );
            publish_lattice(&state, &challenge.asset_id, false).await;
            Ok(Json(AuthorizeResponse {
                allowed: false,
                decision_id,
                reason: "verification_failed".to_string(),
            }))
        }
    }
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .init();

    // Install AWS-LC as rustls' default provider before constructing HTTPS clients.
    // Cargo's default feature set selects the pinned AWS-LC-FIPS 3.x module.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config_path = env::args().nth(1).unwrap_or_else(|| "/etc/dongle/policy.toml".to_string());
    let policy = Arc::new(Policy::load(&config_path)?);
    let lattice = LatticeReporter::from_env()?;
    if lattice.is_none() {
        info!("Lattice reporting disabled (no Lattice environment variables configured)");
    }

    let bind: SocketAddr = policy.server.listen.parse()
        .map_err(|e| anyhow::anyhow!("invalid server.listen address: {e}"))?;
    let state = AppState {
        policy,
        pending: Arc::new(Mutex::new(HashMap::new())),
        lattice,
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/challenge", post(issue_challenge))
        .route("/v1/authorize", post(authorize))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    info!(%bind, "dongle-authd listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
