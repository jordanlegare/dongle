#![forbid(unsafe_code)]

#[cfg(not(feature = "fips"))]
compile_error!("dongle requires the aws-lc-rs FIPS feature; build with the default features enabled");

pub mod config;
pub mod crypto;
pub mod lattice;
pub mod protocol;
pub mod quote;

/// Refuse to start unless AWS-LC is built with and reports FIPS mode, then
/// install its rustls provider before any HTTPS client is constructed.
pub fn initialize_crypto() -> anyhow::Result<()> {
    aws_lc_rs::try_fips_mode()
        .map_err(|error| anyhow::anyhow!("AWS-LC FIPS mode check failed: {error}"))?;

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("could not install the AWS-LC rustls crypto provider"))?;

    Ok(())
}
