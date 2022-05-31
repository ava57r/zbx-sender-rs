use std::{
    convert::{TryFrom, TryInto},
    fs::File,
    io::BufReader,
    path::Path,
    sync::Arc,
};

use rustls::{client::InvalidDnsNameError, ClientConnection, ServerName, StreamOwned};
use thiserror::Error;
#[cfg(feature = "tracing")]
use tracing::warn;
use x509_certificate::CapturedX509Certificate;

use super::{TlsConfig, EncryptionType};

#[derive(Error, Debug)]
pub enum TlsError {
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    InvalidServerName(#[from] InvalidDnsNameError),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("tried to encrypt with an \"unencrypted\" TLS config")]
    Unencrypted,
    #[error("option not supported: {0}")]
    Unsupported(String),
}

pub struct StreamAdapter {
    config: Arc<rustls::ClientConfig>,
}

impl StreamAdapter {
    pub fn connect(
        &self,
        server_name: impl AsRef<str>,
        stream: std::net::TcpStream,
    ) -> Result<StreamOwned<ClientConnection, std::net::TcpStream>, TlsError> {
        let server_name = server_name.as_ref().try_into()?;
        let conn = ClientConnection::new(Arc::clone(&self.config), server_name)?;
        Ok(StreamOwned::new(conn, stream))
    }

    #[cfg(feature = "async_tokio")]
    pub async fn connect_async(
        &self,
        server_name: impl AsRef<str>,
        stream: tokio::net::TcpStream,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, TlsError> {
        let server_name = server_name.as_ref().try_into()?;
        let conn = tokio_rustls::TlsConnector::from(Arc::clone(&self.config));
        conn.connect(server_name, stream)
            .await
            .map_err(|e| e.into())
    }
}

impl TryFrom<TlsConfig> for StreamAdapter {
    type Error = crate::Error;

    fn try_from(config: TlsConfig) -> Result<Self, Self::Error> {
        let config = config.try_into()?;
        Ok(Self {
            config: Arc::new(config),
        })
    }
}

#[doc(hidden)]
impl TryFrom<TlsConfig> for rustls::ClientConfig {
    type Error = TlsError;

    fn try_from(zabbix_config: TlsConfig) -> Result<Self, Self::Error> {
        unsupported_options!(zabbix_config, crl_file, psk_identity, psk_file);
        match zabbix_config.connect {
            EncryptionType::Unencrypted => Err(Self::Error::Unencrypted),
            EncryptionType::Psk => Err(Self::Error::Unsupported(
                "rustls does not yet support PSK encryption".into(),
            )),
            EncryptionType::Cert => {
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
                    .map_err(|e| e.into())
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
        server_name: &ServerName,
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

fn load_cert_file(path: impl AsRef<Path>) -> Result<Vec<rustls::Certificate>, TlsError> {
    let path = path.as_ref();
    let mut rdr = BufReader::new(File::open(&path)?);
    let chain: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut rdr)?
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    if chain.is_empty() {
        Err(TlsError::Config(format!(
            "no certificates found in {}",
            path.to_string_lossy()
        )))
    } else {
        Ok(chain)
    }
}

fn load_key_file(path: impl AsRef<Path>) -> Result<rustls::PrivateKey, TlsError> {
    use rustls_pemfile::Item::*;

    let path = path.as_ref();
    let mut rdr = BufReader::new(File::open(&path)?);
    let mut found_key = None;
    while let Some(item) = rustls_pemfile::read_one(&mut rdr)? {
        match item {
            RSAKey(v) | PKCS8Key(v) | ECKey(v) => {
                if found_key.is_some() {
                    return Err(TlsError::Config(format!(
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
    found_key
        .ok_or_else(|| TlsError::Config(format!("no keys found in {}", path.to_string_lossy())))
}

fn load_ca_file(path: impl AsRef<Path>) -> Result<rustls::RootCertStore, TlsError> {
    let mut roots = rustls::RootCertStore::empty();
    let mut rdr = BufReader::new(File::open(path.as_ref())?);
    while let Some(item) = rustls_pemfile::read_one(&mut rdr)? {
        if let rustls_pemfile::Item::X509Certificate(cert) = item {
            let cert = rustls::Certificate(cert);
            roots
                .add(&cert)
                .map_err(|e| TlsError::Config(format!("error loading ca_file: {}", e)))?;
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

fn load_system_roots() -> Result<rustls::RootCertStore, TlsError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        let cert = rustls::Certificate(cert.0);
        roots.add(&cert).map_err(|e| {
            TlsError::Config(format!(
                "error loading certificate from system roots: {}",
                e
            ))
        })?;
    }
    Ok(roots)
}
