use std::{convert::TryFrom, path::PathBuf};

use super::EncryptionType;

#[derive(clap::Args)]
/// Implementation of [`clap::Args`](https://docs.rs/clap/3/clap/trait.Args.html) that mirrors
/// the [Zabbix native tool TLS configuration
/// options](https://www.zabbix.com/documentation/current/en/manpages/zabbix_sender).
pub struct ClapArgs {
    /// How to encrypt the connection to Zabbix Server or Proxy
    #[clap(long, arg_enum, default_value = "unencrypted")]
    pub tls_connect: EncryptionType,

    /// PSK-identity string
    ///
    /// Mutually exclusive with all certificate-related arguments (i.e. `--tls-cert-file`,
    /// `--tls-ca-file`, *etc.*)
    #[clap(
        long,
        required_if_eq("tls-connect", "psk"),
        conflicts_with_all(Self::CERT_ARGS)
    )]
    pub tls_psk_identity: Option<String>,

    /// Full pathname of a file containing the pre-shared key
    ///
    /// Mutually exclusive with all certificate-related arguments (i.e. `--tls-cert-file`,
    /// `--tls-ca-file`, *etc.*)
    #[clap(
        long,
        required_if_eq("tls-connect", "psk"),
        conflicts_with_all(Self::CERT_ARGS)
    )]
    pub tls_psk_file: Option<PathBuf>,

    /// Full pathname of a file containing the top-level CA(s) certificates for
    /// peer certificate verification (default is to use system CA trust store)
    #[clap(long)]
    pub tls_ca_file: Option<PathBuf>,

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

impl ClapArgs {
    const CERT_ARGS: &'static [&'static str] = &[
        "tls-cert-file",
        "tls-key-file",
        "tls-ca-file",
        "tls-server-cert-issuer",
        "tls-server-cert-subject",
    ];
}

impl TryFrom<ClapArgs> for super::TlsConfig {
    type Error = clap::Error;

    /// Converts command-line arguments into [TlsConfig](super::TlsConfig) using the [TryFrom] trait.
    ///
    /// Applies the validation logic of [TlsConfigBuilder](super::TlsConfigBuilder).
    ///
    /// ## Return Value
    ///
    /// Returns a [clap::Error] so that conversion errors
    /// can be handled and displayed during clap argument
    /// validation, if desired. [clap::Error] implements
    /// [std::error::Error] as well, so can also be used in
    /// other error contexts.
    fn try_from(args: ClapArgs) -> Result<Self, Self::Error> {
        let builder = super::TlsConfigBuilder {
            connect: Some(args.tls_connect),
            psk_identity: Some(args.tls_psk_identity),
            psk_file: Some(args.tls_psk_file),
            ca_file: Some(args.tls_ca_file),
            server_cert_issuer: Some(args.tls_server_cert_issuer),
            server_cert_subject: Some(args.tls_server_cert_subject),
            cert_file: Some(args.tls_cert_file),
            key_file: Some(args.tls_key_file),
        };

        // Apply validation logic of builder to generate argument
        // conflicts (e.g. cert arguments when tls_connect=psk)
        builder
            .fallible_build()
            .map_err(|e| Self::Error::raw(clap::ErrorKind::ArgumentConflict, e))
    }
}
