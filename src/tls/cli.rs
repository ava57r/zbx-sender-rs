use std::{convert::TryFrom, path::PathBuf};

use super::ZabbixTlsConnect;

#[derive(clap::Args)]
pub struct ZabbixTlsCli {
    /// How to connect to server or proxy
    #[clap(long, arg_enum, default_value_t)]
    pub tls_connect: ZabbixTlsConnect,

    /// PSK-identity string
    #[clap(long, required_if_eq("tls-connect", "psk"), conflicts_with_all(&["tls-cert-file","tls-key-file"]))]
    pub tls_psk_identity: Option<String>,

    /// Full pathname of a file containing the pre-shared key
    #[clap(long, required_if_eq("tls-connect", "psk"), conflicts_with_all(&["tls-cert-file","tls-key-file"]))]
    pub tls_psk_file: Option<PathBuf>,

    /// Full pathname of a file containing the top-level CA(s) certificates for peer certificate verification
    /// (default is to use system CA trust store)
    #[clap(long)]
    pub tls_ca_file: Option<PathBuf>,

    /// Full pathname of a file containing revoked certificates
    /// (default is to use system CRL)
    #[clap(long)]
    pub tls_crl_file: Option<PathBuf>,

    /// Allowed server certificate issuer
    #[clap(long)]
    pub tls_server_cert_issuer: Option<String>,

    /// Allowed server certificate subject
    #[clap(long)]
    pub tls_server_cert_subject: Option<String>,

    /// Full pathname of a file containing the certificate or certificate chain
    #[clap(long, required_if_eq("tls-connect", "cert"))]
    pub tls_cert_file: Option<PathBuf>,

    /// Full pathname of a file containing the private key
    #[clap(long, required_if_eq("tls-connect", "cert"))]
    pub tls_key_file: Option<PathBuf>,
}

impl TryFrom<ZabbixTlsCli> for super::ZabbixTlsConfig {
    // Returns a clap::Error so that conversion errors
    // can be handled and displayed during clap argument
    // validation, if desired. clap::Error implements
    // std::error::Error as well, so can also be used in
    // other error contexts.
    type Error = clap::Error;

    fn try_from(args: ZabbixTlsCli) -> Result<Self, Self::Error> {
        let builder = super::ZabbixTlsConfigBuilder {
            connect: Some(args.tls_connect),
            psk_identity: Some(args.tls_psk_identity),
            psk_file: Some(args.tls_psk_file),
            ca_file: Some(args.tls_ca_file),
            crl_file: Some(args.tls_crl_file),
            server_cert_issuer: Some(args.tls_server_cert_issuer),
            server_cert_subject: Some(args.tls_server_cert_subject),
            cert_file: Some(args.tls_cert_file),
            key_file: Some(args.tls_key_file),
        };

        // Apply validation logic of builder to generate argument
        // conflicts (e.g. cert arguments when tls_connect=psk)
        builder
            .build()
            .map_err(|e| Self::Error::raw(clap::ErrorKind::ArgumentConflict, e))
    }
}
