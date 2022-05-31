use std::{
    convert::{TryFrom, TryInto},
    fs::File,
    io::{Read, Write},
    path::Path,
};

use openssl::{
    ec::EcKey,
    error::ErrorStack,
    nid::Nid,
    ssl::{
        HandshakeError, SslConnector, SslConnectorBuilder, SslFiletype, SslMethod, SslOptions,
        SslSessionCacheMode, SslStream, SslVerifyMode,
    },
    x509::{X509NameEntries, X509StoreContextRef},
};
use openssl_errors::{openssl_errors, put_error};
use thiserror::Error;
#[cfg(feature = "async_tokio")]
use tokio_openssl::SslStream as AsyncSslStream;
#[cfg(feature = "tracing")]
use tracing::error;

use super::{TlsConfig, EncryptionType};

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Stack(#[from] ErrorStack),
    #[error(transparent)]
    Handshake(#[from] HandshakeError<std::net::TcpStream>),
    #[error(transparent)]
    AsyncHandshake(#[from] openssl::ssl::Error),
    #[error("tried to encrypt with an \"unencrypted\" TLS config")]
    Unencrypted,
    #[error("option not supported: {0}")]
    Unsupported(String),
}

pub struct StreamAdapter {
    connector: SslConnector,
}

const CIPHERS_CERT_ECDHE: &str = "EECDH+aRSA+AES128:";
const CIPHERS_CERT: &str = "RSA+aRSA+AES128";
const CIPHERS_PSK_ECDHE: &str = "kECDHEPSK+AES128";
const CIPHERS_PSK: &str = "kPSK+AES128";
const CIPHERS_PSK_PRE110: &str = "PSK-AES128-CBC-SHA";
const CIPHERS_PSK_TLS13: &str = "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

impl StreamAdapter {
    pub fn connect(
        &self,
        server_name: impl AsRef<str>,
        stream: std::net::TcpStream,
    ) -> Result<SslStream<std::net::TcpStream>, TlsError> {
        let stream = self.connector.connect(server_name.as_ref(), stream)?;
        Ok(stream)
    }

    #[cfg(feature = "async_tokio")]
    pub async fn connect_async(
        &self,
        server_name: impl AsRef<str>,
        stream: tokio::net::TcpStream,
    ) -> Result<AsyncSslStream<tokio::net::TcpStream>, TlsError> {
        use std::pin::Pin;

        let mut stream = self
            .connector
            .configure()
            .and_then(|c| c.into_ssl(server_name.as_ref()))
            .and_then(move |s| AsyncSslStream::new(s, stream))?;
        let mut pinned_stream = Pin::new(&mut stream);
        pinned_stream.as_mut().connect().await?;
        Ok(stream)
    }
}

impl TryFrom<TlsConfig> for StreamAdapter {
    type Error = crate::Error;

    fn try_from(config: TlsConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            connector: config.try_into()?,
        })
    }
}

#[doc(hidden)]
impl TryFrom<TlsConfig> for SslConnector {
    type Error = TlsError;

    fn try_from(zabbix_config: TlsConfig) -> Result<Self, Self::Error> {
        use EncryptionType::*;

        unsupported_options!(zabbix_config, crl_file);
        if let EncryptionType::Unencrypted = zabbix_config.connect {
            return Err(Self::Error::Unencrypted);
        }
        // Do some stuff common to PSK and certificate encryption
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
        builder.set_options(SslOptions::CIPHER_SERVER_PREFERENCE);
        builder.set_options(SslOptions::NO_TICKET);
        set_openssl_ciphers(&mut builder, &zabbix_config.connect)?;

        match &zabbix_config.connect {
            Unencrypted => unreachable!("early return above"),
            Psk => {
                let psk_identity = zabbix_config.psk_identity.expect("guaranteed by builder");
                let psk_key = load_psk_key(zabbix_config.psk_file.expect("guaranteed by builder"))?;

                builder.set_psk_client_callback(
                    move |_ssl, _hint, mut identity_buffer, mut psk_buffer| {
                        use ZbxSenderOpenSSLError as E;
                        identity_buffer
                            .write_all(psk_identity.as_bytes())
                            .map_err(|err| {
                                put_error!(E::CONNECT_WRITE_ID, E::IO_ERROR, "{}", err);
                                ErrorStack::get()
                            })?;
                        psk_buffer.write_all(&psk_key).map_err(|err| {
                            put_error!(E::CONNECT_WRITE_KEY, E::IO_ERROR, "{}", err);
                            ErrorStack::get()
                        })?;
                        Ok(psk_key.len())
                    },
                );

                Ok(builder.build())
            }
            Cert => {
                if let Some(path) = &zabbix_config.ca_file {
                    builder.set_ca_file(path)?;
                }
                builder.set_private_key_file(
                    zabbix_config
                        .key_file
                        .as_ref()
                        .expect("guaranteed by builder"),
                    SslFiletype::PEM,
                )?;
                builder.set_certificate_chain_file(
                    zabbix_config
                        .cert_file
                        .as_ref()
                        .expect("guaranteed by builder"),
                )?;
                if zabbix_config.server_cert_issuer.is_some()
                    || zabbix_config.server_cert_subject.is_some()
                {
                    builder.set_verify_callback(
                        SslVerifyMode::PEER,
                        move |is_valid_cert: bool, ctx: &mut X509StoreContextRef| {
                            let required_subject = zabbix_config.server_cert_subject.as_deref();
                            let required_issuer = zabbix_config.server_cert_issuer.as_deref();
                            verify_subject_issuer(
                                required_subject,
                                required_issuer,
                                is_valid_cert,
                                ctx,
                            )
                        },
                    );
                }
                Ok(builder.build())
            }
        }
    }
}

fn set_openssl_ciphers(
    builder: &mut SslConnectorBuilder,
    mode: &EncryptionType,
) -> Result<(), ErrorStack> {
    use EncryptionType::*;

    let openssl_version_number = openssl::version::number();
    if matches!(mode, Psk) && openssl_version_number >= 0x1010100f {
        // OpenSSL >=1.1.1
        builder.set_ciphersuites(CIPHERS_PSK_TLS13)?;
    }
    let ciphers = if openssl_version_number >= 0x1010000f {
        // OpenSSL >=1.1.0
        let ecdhe_res = set_ecdhe_params(builder);
        match (mode, ecdhe_res) {
            (Psk, Ok(_)) => format!("{}:{}", CIPHERS_PSK_ECDHE, CIPHERS_PSK),
            (Cert, Ok(_)) => format!("{}:{}", CIPHERS_CERT_ECDHE, CIPHERS_CERT),
            (Psk, Err(_)) => CIPHERS_PSK.into(),
            (Cert, Err(_)) => CIPHERS_CERT.into(),
            _ => unreachable!("never called for Unencrypted variant"),
        }
    } else {
        match mode {
            Psk => CIPHERS_PSK_PRE110.into(),
            Cert => CIPHERS_CERT.into(),
            _ => unreachable!("never called for Unencrypted variant"),
        }
    };
    builder.set_cipher_list(&ciphers)
}

fn verify_subject_issuer(
    required_subject: Option<&str>,
    required_issuer: Option<&str>,
    is_valid_cert: bool,
    ctx: &mut X509StoreContextRef,
) -> bool {
    fn entries_to_string(entries: X509NameEntries) -> String {
        use std::fmt::Write as _;
        let mut out = String::default();
        for part in entries {
            let key = if let Ok(k) = part.object().nid().short_name() {
                k
            } else {
                continue;
            };
            let value = if let Ok(v) = part.data().as_utf8() {
                v
            } else {
                continue;
            };
            if !out.is_empty() {
                write!(out, ", ").unwrap();
            }
            write!(out, "{}={}", key, value).unwrap();
        }
        out
    }

    if !is_valid_cert {
        return false;
    }
    let cert = ctx.chain().and_then(|ch| ch.into_iter().next());
    match cert {
        None => {
            #[cfg(feature = "tracing")]
            error!("Certificate could not be found in server response");
            return false;
        }
        Some(cert) => {
            if let Some(subject) = required_subject {
                let cert_subject = entries_to_string(cert.subject_name().entries());
                if cert_subject != subject {
                    #[cfg(feature = "tracing")]
                    error!(
                        "Certificate subject (\"{}\") does not match configured subject (\"{}\")",
                        cert_subject, subject
                    );
                    return false;
                }
            }
            if let Some(issuer) = required_issuer {
                let cert_issuer = entries_to_string(cert.issuer_name().entries());
                if cert_issuer != issuer {
                    #[cfg(feature = "tracing")]
                    error!(
                        "Certificate issuer (\"{}\") does not match configured issuer (\"{}\")",
                        cert_issuer, issuer
                    );
                    return false;
                }
            }
        }
    }

    true
}

fn set_ecdhe_params(builder: &mut SslConnectorBuilder) -> Result<(), openssl::error::ErrorStack> {
    let openssl_version_number = openssl::version::number();
    let ec_curve = Nid::X9_62_PRIME256V1;
    if openssl_version_number >= 0x3000000f {
        builder.set_groups_list(ec_curve.short_name()?)?;
    } else {
        let ecdh = EcKey::from_curve_name(ec_curve)?;
        builder.set_options(SslOptions::SINGLE_ECDH_USE);
        builder.set_tmp_ecdh(&ecdh)?; // todo?: set this at connection time instead of at init?
    }
    Ok(())
}

fn load_psk_key(path: impl AsRef<Path>) -> Result<Vec<u8>, TlsError> {
    let path = path.as_ref();

    let mut buffer = Vec::new();
    let mut rdr = File::open(&path)?;
    rdr.read_to_end(&mut buffer)?;
    buffer = buffer.into_iter().filter(u8::is_ascii_hexdigit).collect();

    buffer = hex::decode(buffer)
        .map_err(|_| TlsError::Config("unable to decode PSK key as hexidecimal digits".into()))?;

    Ok(buffer)
}

openssl_errors! {
    pub library ZbxSenderOpenSSLError("Zabbix Sender Library") {
        functions {
            CONNECT_WRITE_ID("set_psk_client_callback:identity_buffer.write_all");
            CONNECT_WRITE_KEY("set_psk_client_callback:psk_buffer.write_all");
        }

        reasons {
            IO_ERROR("An IO error occurred");
        }
    }
}
