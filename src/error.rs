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
    #[cfg(feature = "_tls_common")]
    #[error(transparent)]
    TlsError(#[from] crate::tls::TlsError),
}
