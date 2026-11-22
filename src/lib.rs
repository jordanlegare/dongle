#![forbid(unsafe_code)]

#[cfg(not(feature = "fips"))]
compile_error!("dongle requires the aws-lc-rs FIPS feature; build with the default features enabled");

pub mod config;
pub mod crypto;
pub mod lattice;
pub mod protocol;
pub mod quote;
