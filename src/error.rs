//! Error and Result module

use std::{io, result};

pub type Result<T> = result::Result<T, Error>;

// General error the crate
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid header protocol")]
    InvalidHeader,
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    JsonError(#[from] serde_json::error::Error),
    #[error("TLS settings not valid: {0}")]
    TlsConfigError(String),
    #[error("tried to encrypt with an \"unencrypted\" TLS config")]
    TlsUnencrypted,
}
