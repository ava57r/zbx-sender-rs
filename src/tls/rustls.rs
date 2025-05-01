use std::{
    convert::{TryFrom, TryInto},
    fs::File,
    io::BufReader,
    path::Path,
    sync::Arc,
};

use rustls::{client::danger::{ServerCertVerified, ServerCertVerifier}, pki_types::{CertificateDer, InvalidDnsNameError, PrivateKeyDer, ServerName}, ClientConnection, StreamOwned};
use thiserror::Error;
#[cfg(feature = "tracing")]
use tracing::warn;
use x509_certificate::CapturedX509Certificate;

use super::{EncryptionType, TlsConfig};

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
        server_name: &str,
        stream: std::net::TcpStream,
    ) -> Result<StreamOwned<ClientConnection, std::net::TcpStream>, TlsError> {
        let server_name = server_name.to_owned().try_into()?;
        let conn = ClientConnection::new(Arc::clone(&self.config), server_name)?;
        Ok(StreamOwned::new(conn, stream))
    }

    #[cfg(feature = "async_tokio")]
    pub async fn connect_async(
        &self,
        server_name: &str,
        stream: tokio::net::TcpStream,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, TlsError> {
        let server_name = server_name.to_owned().try_into()?;
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
        unsupported_options!(zabbix_config, psk_identity, psk_file);
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
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_client_auth_cert(client_cert, client_key)
                    .map_err(|e| e.into())
            }
        }
    }
}

#[derive(Debug)]
struct ZabbixServerCertVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    subject: Option<String>,
    issuer: Option<String>,
}

impl ZabbixServerCertVerifier {
    fn new(
        root_store: rustls::RootCertStore,
        subject: Option<String>,
        issuer: Option<String>,
    ) -> Self {
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .expect("root_store should never be empty");
        Self {
            inner: verifier,
            issuer,
            subject,
        }
    }
}

fn certificate_config_error(s: impl ToString) -> rustls::Error {
    rustls::Error::InvalidCertificate(
        rustls::CertificateError::Other(
            rustls::OtherError(Arc::new(TlsError::Config(s.to_string())))
        )
    )
}

impl ServerCertVerifier for ZabbixServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed_cert = if self.subject.is_some() || self.issuer.is_some() {
            let parsed_cert = CapturedX509Certificate::from_der(end_entity.as_ref())
                .map_err(certificate_config_error)?;
            Some(parsed_cert)
        } else {
            None
        };

        self.inner
            .verify_server_cert(
                end_entity,
                intermediates,
                server_name,
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
                        .map_err(certificate_config_error)?;
                    if &subject_dn != subject {
                        return Err(certificate_config_error(format!(
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
                        .map_err(certificate_config_error)?;
                    if &issuer_dn != issuer {
                        return Err(certificate_config_error(format!(
                            "Certificate issuer `{}` does not match required \
                                 server_cert_issuer from configuration: `{}`",
                            issuer_dn, issuer
                        )));
                    }
                }
                Ok(ok)
            })
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn load_cert_file(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let path = path.as_ref();
    let mut rdr = BufReader::new(File::open(path)?);
    let chain: Vec<_> = rustls_pemfile::certs(&mut rdr)
        .collect::<Result<_, _>>()?;
    if chain.is_empty() {
        Err(TlsError::Config(format!(
            "no certificates found in {}",
            path.display()
        )))
    } else {
        Ok(chain)
    }
}

fn load_key_file(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>, TlsError> {
    let path = path.as_ref();
    let mut rdr = BufReader::new(File::open(path)?);
    let mut found_key = None;
    while let Some(key) = rustls_pemfile::private_key(&mut rdr)? {
        if found_key.is_some() {
            return Err(TlsError::Config(format!(
                "multiple keys found in {}",
                path.display()
            )));
        }
        found_key = Some(key);
    }
    found_key
        .ok_or_else(|| TlsError::Config(format!("no keys found in {}", path.display())))
}

fn load_ca_file(path: impl AsRef<Path>) -> Result<rustls::RootCertStore, TlsError> {
    let path = path.as_ref();
    let mut roots = rustls::RootCertStore::empty();
    let mut rdr = BufReader::new(File::open(path)?);
    let root_certs: Vec<_> = rustls_pemfile::certs(&mut rdr).collect::<Result<_, _>>()?;
    let (_, _n_ignored) = roots.add_parsable_certificates(root_certs);
    #[cfg(feature = "tracing")]
    if _n_ignored > 0 {
        warn!("Could not parse {_n_ignored} certs in {}", path.display());
    }
    Ok(roots)
}

fn load_system_roots() -> Result<rustls::RootCertStore, TlsError> {
    let mut roots = rustls::RootCertStore::empty();
    let system_roots = rustls_native_certs::load_native_certs();
    if let Some(err) = system_roots.errors.first() {
        return Err(TlsError::Config(format!("could not load system trust store: {}", err)));
    }
    let (_, _n_ignored) = roots.add_parsable_certificates(system_roots.expect("errors checked above"));
    #[cfg(feature = "tracing")]
    if _n_ignored > 0 {
        warn!("Could not parse {_n_ignored} certs from system trust store");
    }
    Ok(roots)
}
