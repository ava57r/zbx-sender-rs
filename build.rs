use std::{env, process};

fn main() {
    if env::var_os("CARGO_FEATURE_ASYNC_TOKIO").is_some() {
        match (env::var_os("CARGO_FEATURE_TLS_OPENSSL"), env::var_os("CARGO_FEATURE_TLS_OPENSSL_TOKIO")) {
            (Some(_), None) => { fatal("to enable the features `tls_openssl` and `async_tokio` together, you must also enable the `tls_openssl_tokio` feature") },
            (None, Some(_)) => { fatal("feature `tls_openssl_tokio` enabled without `tls_openssl`") },
            _ => {},
        }
        match (env::var_os("CARGO_FEATURE_TLS_RUSTLS"), env::var_os("CARGO_FEATURE_TLS_RUSTLS_TOKIO")) {
            (Some(_), None) => { fatal("to enable the features `tls_rustls` and `async_tokio` together, you must also enable the `tls_rustls_tokio` feature") },
            (None, Some(_)) => { fatal("feature `tls_rustls_tokio` enabled without `tls_rustls`") },
            _ => {},
        }
    }
}

fn fatal(msg: &str) {
    eprintln!("error: {}", msg);
    process::exit(1);
}
