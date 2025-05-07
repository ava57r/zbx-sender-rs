//! TLS configuration for [Sender](crate::Sender)
//!
//! Provides common configuration for TLS connection to Zabbix Server and Zabbix Proxy.
//! Implementations are private submodules of this module (e.g. `rustls`, `openssl`).
//!
//! To configure encrypted communication with Zabbix, a [TlsConfig] struct is created, using
//! following methods, depending on which type of encryption is required:
//! * [TlsConfig::new_psk] - PSK encryption with a PSK identity string and key file
//! * [TlsConfig::new_cert] - Certificate encryption with client certificate authentication and
//!   server certificate verification via system trust roots
//! * [TlsConfig::cert_builder] - Same as `new_cert` but creates a [TlsConfigBuilder] with additional methods for
//!   stricter server verification.
use std::path::PathBuf;

use derive_builder::Builder;

#[cfg(feature = "clap")]
mod cli;
#[cfg(feature = "clap")]
pub use cli::ClapArgs;

#[cfg(feature = "tls_rustls")]
mod rustls;
#[cfg(feature = "tls_rustls")]
pub(crate) use self::rustls::{StreamAdapter, TlsError};

#[cfg(feature = "tls_openssl")]
mod openssl;
#[cfg(feature = "tls_openssl")]
pub(crate) use self::openssl::{StreamAdapter, TlsError};

#[derive(serde::Deserialize, Clone, Debug, Default)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
/// Encryption method used for the connection to Zabbix
pub enum EncryptionType {
    #[default]
    /// connect without encryption (default)
    Unencrypted,
    /// connect using TLS and a pre-shared key
    Psk,
    /// connect using TLS and a certificate
    Cert,
}

#[derive(Builder)]
#[builder(
    custom_constructor,
    create_empty = "empty",
    build_fn(private, name = "fallible_build", validate = "Self::validate"),
    pattern = "owned"
)]
/// TLS configuration for [Sender](crate::Sender)
///
/// Provided to [Sender.with_tls()](crate::Sender.with_tls) to set up an encrypted connection.
pub struct TlsConfig {
    #[builder(setter(custom))]
    pub(crate) connect: EncryptionType,

    #[builder(setter(custom))]
    psk_identity: Option<String>,
    #[builder(setter(custom))]
    psk_file: Option<PathBuf>,

    #[builder(setter(custom))]
    cert_file: Option<PathBuf>,
    #[builder(setter(custom))]
    key_file: Option<PathBuf>,

    /// Full pathname of a file containing the top-level CA certificate(s) for
    /// server certificate verification (default is to use system CA trust store)
    #[builder(default, setter(strip_option, into))]
    ca_file: Option<PathBuf>,

    /// An X.509 name that the server certificate's Issuer field must match exactly
    #[builder(default, setter(strip_option, into))]
    server_cert_issuer: Option<String>,

    /// An X.509 name that the server certificate's Subject field must match exactly
    #[builder(default, setter(strip_option, into))]
    server_cert_subject: Option<String>,
}

impl TlsConfigBuilder {
    fn validate(&self) -> Result<(), String> {
        macro_rules! validate_inner_is_none{
            ($obj:expr, $why:expr, $field:ident)=>{
                if $obj.$field.as_ref()
                    .map(|inner| inner.as_ref())
                    .flatten()
                    .is_some()
                {
                    return Err(format!("{} specified, but {}", stringify!($field), $why))
                }
            };
            ($obj:expr, $why:expr, $($field:ident),+)=>{
                $(validate_inner_is_none!($obj, $why, $field));+
            }
        }

        match self.connect {
            Some(EncryptionType::Unencrypted) => {
                validate_inner_is_none!(
                    self,
                    "connection is unencrypted",
                    ca_file,
                    server_cert_issuer,
                    server_cert_subject,
                    cert_file,
                    key_file,
                    psk_identity,
                    psk_file
                );
            }
            Some(EncryptionType::Psk) => {
                validate_inner_is_none!(
                    self,
                    "connection is encrypted by PSK",
                    ca_file,
                    server_cert_issuer,
                    server_cert_subject,
                    cert_file,
                    key_file
                );
            }
            Some(EncryptionType::Cert) => {
                validate_inner_is_none!(
                    self,
                    "connection is encrypted by certificate",
                    psk_identity,
                    psk_file
                );
            }
            None => return Err("connection encryption type not specified".into()),
        };
        Ok(())
    }

    /// Build a new [`TlsConfig`]
    pub fn build(self) -> TlsConfig {
        self.fallible_build()
            .expect("programmer error: should be guaranteed by builder")
    }
}

impl TlsConfig {
    /// Configure TLS for PSK encryption
    ///
    /// ## Arguments
    ///
    /// * `identity` - the identity string for this key expected by Zabbix Server
    /// * `key_file` - the full path to a file containing the pre-shared key, encoded
    ///   as hexadecimal digits
    pub fn new_psk(identity: impl Into<String>, key_file: impl Into<PathBuf>) -> Self {
        // Run this configuration through the builder
        // so that ...Builder::validate() gets run, in case
        // any future changes add value validation.
        TlsConfigBuilder {
            connect: Some(EncryptionType::Psk),
            psk_identity: Some(Some(identity.into())),
            psk_file: Some(Some(key_file.into())),
            cert_file: Some(None),
            key_file: Some(None),
            ..TlsConfigBuilder::empty()
        }
        .fallible_build()
        .expect("Programmer mistake in fields provided for TlsConfigBuilder in Config::new_psk()")
    }

    /// Configure TLS for certificate encryption
    ///
    /// ## Arguments
    ///
    /// * `cert_file` - the full path to a certificate (or certificate chain) in PEM format
    /// * `key_file` - the full path to the certificate's private key in PEM format
    pub fn new_cert(cert_file: impl Into<PathBuf>, key_file: impl Into<PathBuf>) -> Self {
        Self::cert_builder(cert_file, key_file)
            .fallible_build()
            .expect(
                "Programmer mistake in fields provided for TlsConfigBuilder in Config::new_cert()",
            )
    }

    /// Create an instance of [TlsConfigBuilder] to configure certificate encryption with server
    /// authentication
    ///
    /// ## Arguments
    ///
    /// * `cert_file` - the full path to a certificate (or certificate chain) in PEM format
    /// * `key_file` - the full path to the certificate's private key in PEM format
    ///
    /// ## Return
    ///
    /// * An instance of [TlsConfigBuilder] to customize server TLS authentication
    pub fn cert_builder(
        cert_file: impl Into<PathBuf>,
        key_file: impl Into<PathBuf>,
    ) -> TlsConfigBuilder {
        TlsConfigBuilder {
            connect: Some(EncryptionType::Cert),
            cert_file: Some(Some(cert_file.into())),
            key_file: Some(Some(key_file.into())),
            psk_identity: Some(None),
            psk_file: Some(None),
            ..TlsConfigBuilder::empty()
        }
    }
}
