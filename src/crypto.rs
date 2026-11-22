use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};

/// Verify a P-256 ECDSA signature over the exact challenge transcript.
///
/// The registered public key must be a 65-byte uncompressed SEC1 point.
/// The signature must be ASN.1 DER encoded.
pub fn verify_dongle_signature(
    public_key_sec1: &[u8],
    transcript: &[u8],
    signature_der: &[u8],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        public_key_sec1.len() == 65 && public_key_sec1.first() == Some(&0x04),
        "registered dongle key is not an uncompressed P-256 SEC1 point"
    );

    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_sec1)
        .verify(transcript, signature_der)
        .map_err(|_| anyhow::anyhow!("dongle signature verification failed"))
}
