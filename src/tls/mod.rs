use std::{
    convert::TryFrom,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
};

use derive_builder::Builder;

#[cfg(feature = "clap")]
mod cli;
#[cfg(feature = "clap")]
pub use cli::ZabbixTlsCli;
#[cfg(feature = "tracing")]
use tracing::warn;
use x509_certificate::CapturedX509Certificate;

use crate::Error::TlsConfigError;

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

impl TryFrom<ZabbixTlsConfig> for rustls::ClientConfig {
    type Error = crate::Error;

    fn try_from(zabbix_config: ZabbixTlsConfig) -> Result<Self, Self::Error> {
        match zabbix_config.connect {
            ZabbixTlsConnect::Unencrypted => Err(Self::Error::TlsUnencrypted),
            ZabbixTlsConnect::Psk => todo!(),
            ZabbixTlsConnect::Cert => {
                let root_store = match zabbix_config.ca_file {
                    None => load_system_roots()?,
                    Some(path) => load_ca_file(path)?,
                };
                let verifier = ZabbixServerCertVerifier::new(
                    root_store,
                    zabbix_config.server_cert_subject,
                    zabbix_config.server_cert_issuer,
                );
                let client_key =
                    load_key_file(zabbix_config.key_file.expect("guaranteed by builder"))?;
                let client_cert =
                    load_cert_file(zabbix_config.cert_file.expect("guaranteed by builder"))?;
                // `with_safe_defaults()` includes a set of cipher suites
                // that partially overlaps with Zabbix's default cipher suites
                rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_single_cert(client_cert, client_key)
                    .map_err(|e| {
                        TlsConfigError(format!("error loading client certificate or key: {}", e))
                    })
            }
        }
    }
}

struct ZabbixServerCertVerifier {
    inner: rustls::client::WebPkiVerifier,
    subject: Option<String>,
    issuer: Option<String>,
}

impl ZabbixServerCertVerifier {
    fn new(
        root_store: rustls::RootCertStore,
        subject: Option<String>,
        issuer: Option<String>,
    ) -> Self {
        let verifier = rustls::client::WebPkiVerifier::new(root_store, None);
        Self {
            inner: verifier,
            issuer,
            subject,
        }
    }
}

impl rustls::client::ServerCertVerifier for ZabbixServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &rustls::ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        use rustls::Error;

        let parsed_cert = if self.subject.is_some() || self.issuer.is_some() {
            let parsed_cert = CapturedX509Certificate::from_der(end_entity.0.as_slice())
                .map_err(|e| Error::General(e.to_string()))?;
            Some(parsed_cert)
        } else {
            None
        };

        self.inner
            .verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                scts,
                ocsp_response,
                now,
            )
            .and_then(|ok| {
                if let Some(subject) = &self.subject {
                    let subject_dn = parsed_cert
                        .as_ref()
                        .expect("guaranteed by above if conditions")
                        .subject_name()
                        .user_friendly_str()
                        .map_err(|e| Error::InvalidCertificateData(e.to_string()))?;
                    if &subject_dn != subject {
                        return Err(Error::InvalidCertificateData(format!(
                            "Certificate subject `{}` does not match required \
                                 server_cert_subject from configuration: `{}`",
                            subject_dn, subject
                        )));
                    }
                }
                Ok(ok)
            })
            .and_then(|ok| {
                if let Some(issuer) = &self.issuer {
                    let issuer_dn = parsed_cert
                        .as_ref()
                        .expect("guaranteed by above if conditions")
                        .issuer_name()
                        .user_friendly_str()
                        .map_err(|e| Error::InvalidCertificateData(e.to_string()))?;
                    if &issuer_dn != issuer {
                        return Err(Error::InvalidCertificateData(format!(
                            "Certificate issuer `{}` does not match required \
                                 server_cert_issuer from configuration: `{}`",
                            issuer_dn, issuer
                        )));
                    }
                }
                Ok(ok)
            })
    }
}

fn load_cert_file(path: impl AsRef<Path>) -> Result<Vec<rustls::Certificate>, crate::Error> {
    let path = path.as_ref();
    let mut rdr = BufReader::new(File::open(&path)?);
    let chain: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut rdr)?
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    if chain.is_empty() {
        Err(TlsConfigError(format!(
            "no certificates found in {}",
            path.to_string_lossy()
        )))
    } else {
        Ok(chain)
    }
}

fn load_key_file(path: impl AsRef<Path>) -> Result<rustls::PrivateKey, crate::Error> {
    use rustls_pemfile::Item::*;

    let path = path.as_ref();
    let mut rdr = BufReader::new(File::open(&path)?);
    let mut found_key = None;
    while let Some(item) = rustls_pemfile::read_one(&mut rdr)? {
        match item {
            RSAKey(v) | PKCS8Key(v) | ECKey(v) => {
                if found_key.is_some() {
                    return Err(TlsConfigError(format!(
                        "multiple keys found in {}",
                        path.to_string_lossy()
                    )));
                }
                found_key = Some(rustls::PrivateKey(v));
            }
            _ => {
                #[cfg(feature = "tracing")]
                warn!("certificate found in {}", path.to_string_lossy())
            }
        }
    }
    found_key.ok_or_else(|| TlsConfigError(format!("no keys found in {}", path.to_string_lossy())))
}

fn load_ca_file(path: impl AsRef<Path>) -> Result<rustls::RootCertStore, crate::Error> {
    let mut roots = rustls::RootCertStore::empty();
    let mut rdr = BufReader::new(File::open(path.as_ref())?);
    while let Some(item) = rustls_pemfile::read_one(&mut rdr)? {
        if let rustls_pemfile::Item::X509Certificate(cert) = item {
            let cert = rustls::Certificate(cert);
            roots
                .add(&cert)
                .map_err(|e| TlsConfigError(format!("error loading ca_file: {}", e)))?;
        } else {
            #[cfg(feature = "tracing")]
            warn!(
                "found non-certificate item in {}",
                path.as_ref().to_string_lossy()
            );
        }
    }
    Ok(roots)
}

fn load_system_roots() -> Result<rustls::RootCertStore, crate::Error> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        let cert = rustls::Certificate(cert.0);
        roots.add(&cert).map_err(|e| {
            TlsConfigError(format!(
                "error loading certificate from system roots: {}",
                e
            ))
        })?;
    }
    Ok(roots)
}
