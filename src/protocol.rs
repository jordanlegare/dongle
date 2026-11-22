use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest {
    pub user_id: String,
    pub dongle_id: String,
    pub asset_id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub nonce_hex: String,
    pub signing_payload_b64: String,
    pub expires_in_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeRequest {
    pub challenge_id: String,
    pub user_id: String,
    pub dongle_id: String,
    pub asset_id: String,
    /// DER-encoded ECDSA P-256/SHA-256 signature over the returned payload.
    pub dongle_signature_b64: String,
    pub quote_message_b64: String,
    pub quote_signature_b64: String,
    pub pcr_values_b64: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeResponse {
    pub allowed: bool,
    pub decision_id: String,
    pub reason: String,
}

pub fn make_signing_payload(
    challenge_id: &str,
    user_id: &str,
    dongle_id: &str,
    asset_id: &str,
    nonce: &[u8],
) -> Vec<u8> {
    let mut out = b"ANDURIL-DONGLE-AUTH-V1\0".to_vec();
    for field in [challenge_id, user_id, dongle_id, asset_id] {
        let bytes = field.as_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    out.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
    out.extend_from_slice(nonce);
    out
}

pub fn encode_payload(payload: &[u8]) -> String {
    STANDARD.encode(payload)
}

pub fn decode_b64(value: &str, field: &str) -> anyhow::Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|e| anyhow::anyhow!("invalid base64 in {field}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::make_signing_payload;

    #[test]
    fn challenge_transcript_binds_all_identity_fields_and_nonce() {
        let nonce = [0x5au8; 32];
        let expected = make_signing_payload("challenge", "alice", "key-1", "host-1", &nonce);

        assert_ne!(
            expected,
            make_signing_payload("challenge", "bob", "key-1", "host-1", &nonce)
        );
        assert_ne!(
            expected,
            make_signing_payload("challenge", "alice", "key-2", "host-1", &nonce)
        );
        assert_ne!(
            expected,
            make_signing_payload("challenge", "alice", "key-1", "host-2", &nonce)
        );
        assert_ne!(
            expected,
            make_signing_payload("challenge", "alice", "key-1", "host-1", &[0x5b; 32])
        );
    }

    #[test]
    fn challenge_transcript_is_domain_separated_and_deterministic() {
        let nonce = [0x01u8; 32];
        let first = make_signing_payload("c", "u", "d", "a", &nonce);
        let second = make_signing_payload("c", "u", "d", "a", &nonce);

        assert_eq!(first, second);
        assert!(first.starts_with(b"ANDURIL-DONGLE-AUTH-V1\0"));
    }
}
