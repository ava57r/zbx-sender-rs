use std::path::PathBuf;

use derive_builder::Builder;

macro_rules! unsupported_options {
    ($obj:expr, $opt:ident)=>{
        if $obj.$opt.is_some() {
            return Err(Self::Error::Unsupported(stringify!($opt).into()));
        }
    };
    ($obj:expr, $($opt:ident),+)=>{
        $(unsupported_options!($obj, $opt));+
    }
}

#[cfg(feature = "clap")]
mod cli;
#[cfg(feature = "clap")]
pub use cli::ZabbixTlsCli;

#[cfg(feature = "tls_rustls")]
mod rustls;
#[cfg(feature = "tls_rustls")]
pub use self::rustls::{StreamAdapter, TlsError};

#[cfg(feature = "tls_openssl")]
mod openssl;
#[cfg(feature = "tls_openssl")]
pub use self::openssl::{StreamAdapter, TlsError};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "clap", derive(clap::ArgEnum))]
pub enum ZabbixTlsConnect {
    /// connect without encryption (default)
    Unencrypted,
    /// connect using TLS and a pre-shared key
    Psk,
    /// connect using TLS and a certificate
    Cert,
}

impl Default for ZabbixTlsConnect {
    fn default() -> Self {
        Self::Unencrypted
    }
}

#[derive(Builder, Default)]
#[builder(
    custom_constructor,
    create_empty = "empty",
    build_fn(validate = "Self::validate")
)]
pub struct ZabbixTlsConfig {
    #[builder(setter(custom))]
    pub(crate) connect: ZabbixTlsConnect,
    #[builder(setter(custom))]
    psk_identity: Option<String>,
    #[builder(setter(custom))]
    psk_file: Option<PathBuf>,
    #[builder(default, setter(strip_option, into))]
    ca_file: Option<PathBuf>,
    #[builder(default, setter(strip_option, into))]
    crl_file: Option<PathBuf>,
    #[builder(default, setter(strip_option, into))]
    server_cert_issuer: Option<String>,
    #[builder(default, setter(strip_option, into))]
    server_cert_subject: Option<String>,
    #[builder(setter(custom))]
    cert_file: Option<PathBuf>,
    #[builder(setter(custom))]
    key_file: Option<PathBuf>,
}

impl ZabbixTlsConfigBuilder {
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
            Some(ZabbixTlsConnect::Unencrypted) => {
                validate_inner_is_none!(
                    self,
                    "connection is unencrypted",
                    ca_file,
                    crl_file,
                    server_cert_issuer,
                    server_cert_subject,
                    cert_file,
                    key_file,
                    psk_identity,
                    psk_file
                );
            }
            Some(ZabbixTlsConnect::Psk) => {
                validate_inner_is_none!(
                    self,
                    "connection is encrypted by PSK",
                    ca_file,
                    crl_file,
                    server_cert_issuer,
                    server_cert_subject,
                    cert_file,
                    key_file
                );
            }
            Some(ZabbixTlsConnect::Cert) => {
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
}

impl ZabbixTlsConfig {
    pub fn new_unencrypted() -> Self {
        Self::default()
    }

    pub fn new_psk(identity: impl Into<String>, key_file: impl Into<PathBuf>) -> Self {
        // Run this configuration through the builder
        // so that ...Builder::validate() gets run, in case
        // any future changes add value validation.
        ZabbixTlsConfigBuilder {
            connect: Some(ZabbixTlsConnect::Psk),
            psk_identity: Some(Some(identity.into())),
            psk_file: Some(Some(key_file.into())),
            cert_file: Some(None),
            key_file: Some(None),
            ..ZabbixTlsConfigBuilder::empty()
        }
        .build()
        .expect("Programmer mistake in fields provided for ZabbixTlsConfigBuilder in ZabbixTlsConfig::new_psk()")
    }

    pub fn new_cert(cert_file: impl Into<PathBuf>, key_file: impl Into<PathBuf>) -> Self {
        Self::cert_builder(cert_file, key_file).build().expect(
            "Programmer mistake in fields provided for ZabbixTlsConfigBuilder in ZabbixTlsConfig::new_cert()",
        )
    }

    pub fn cert_builder(
        cert_file: impl Into<PathBuf>,
        key_file: impl Into<PathBuf>,
    ) -> ZabbixTlsConfigBuilder {
        ZabbixTlsConfigBuilder {
            connect: Some(ZabbixTlsConnect::Cert),
            cert_file: Some(Some(cert_file.into())),
            key_file: Some(Some(key_file.into())),
            psk_identity: Some(None),
            psk_file: Some(None),
            ..ZabbixTlsConfigBuilder::empty()
        }
    }
}
