//! Error and Result module

use std::{io, result};

/// A [std::result::Result] for the [zbx_sender::Error](Error) type
pub type Result<T> = result::Result<T, Error>;

// General error the crate
#[derive(thiserror::Error, Debug)]
/// Errors that occur during configuration of the Zabbix connection or submission of item values to
/// Zabbix
pub enum Error {
    #[error("invalid header protocol")]
    /// The header received from Zabbix Server or Zabbix Proxy was invalid, most likely due to a
    /// non-backwards-compatible change made in future versions of Zabbix.
    InvalidHeader,

    #[error(transparent)]
    /// A system-level IO error, which can occur:
    ///
    /// * During configuration, when reading certificates or keys from the filesystem for TLS
    ///   encryption.
    /// * During sending of values, when there is a network error.
    IoError(#[from] io::Error),

    #[error(transparent)]
    /// An error decoding JSON received from Zabbix Server or Zabbix Proxy.
    JsonError(#[from] serde_json::error::Error),

    #[cfg(feature = "_tls_common")]
    #[error(transparent)]
    /// An error when configuring or establishing the TLS connection to Zabbix.
    TlsError(#[from] crate::tls::TlsError),
}
