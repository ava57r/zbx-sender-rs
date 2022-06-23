extern crate zbx_sender;

#[cfg(unix)]
use std::os::unix::prelude::*;
#[cfg(windows)]
use std::os::windows::prelude::*;
use std::{ffi::OsStr, io::Read, path::PathBuf};

use anyhow::{anyhow, bail};
use clap::Parser;

use csv::ReaderBuilder;
use zbx_sender::{Response, Sender, ToMessage};

#[cfg(feature = "_tls_common")]
use {
    std::convert::TryInto,
    zbx_sender::tls::{ClapArgs, TlsConfig},
};

#[derive(Parser)]
#[clap(setting = clap::AppSettings::DeriveDisplayOrder)]
struct Cli {
    /// Hostname or IP address of the Zabbix Server or Zabbix Proxy
    #[clap(short = 'z', long = "zabbix-server")]
    server: String,

    /// Port number that Zabbix accepts traps / sender values on
    #[clap(short, long, default_value = "10051")]
    port: u16,

    /// Host name the item belongs to in Zabbix. Host IP address and DNS name will not work.
    #[clap(short = 's', long, requires = "key", requires = "value")]
    host: Option<String>,

    /// Item key in Zabbix
    #[clap(short, long, requires = "host", requires = "value")]
    key: Option<String>,

    /// Specify to exit with an error status if any items failed to be processed by Zabbix.
    #[clap(short = 'f', long = "status-on-fail")]
    fail: bool,

    /// Item value
    #[clap(short = 'o', long, requires = "host", requires = "key")]
    value: Option<String>,

    /// Load values from input file. Specify - as <input-file> to read values from standard input.
    /// Each line of file contains, delimited by a single space:
    ///
    /// <hostname> <key> <value>
    ///
    /// Each value must be specified on its own line. Each line must contain 3 whitespace delimited
    /// entries: <hostname> <key> <value>. Entries must be quoted with double quotes (") if they
    /// contain spaces. Double quotes and backslashes in entries can be escaped with a backslash
    /// (\).
    ///
    /// This is a similar format to the native zabbix_sender, but not identical: notably, this
    /// tool does not accept tabs or multiple spaces between entries.
    #[clap(short, long)]
    input_file: Option<PathBuf>,

    #[cfg(feature = "_tls_common")]
    #[clap(flatten)]
    tls: ClapArgs,
}

/// This function handles generic csv::Reader<R> to abstract over
/// whether a File or Stdin is being used as input.
/// It returns owned data, because the lifetime of the read data
/// must outlive the references to it taken by Sender.send()
fn records_from_input<R: Read>(mut reader: csv::Reader<R>) -> csv::Result<Vec<csv::StringRecord>> {
    // No Iterator.try_map(), so we have to iterate
    // and handle errors by for loop.
    let mut records = Vec::new();
    for record in reader.records() {
        records.push(record?);
    }
    Ok(records)
}

fn send_wrapper(sender: &Sender, message: impl ToMessage) -> zbx_sender::Result<Response> {
    #[cfg(not(feature = "async_tokio"))]
    let result = sender.send(message);

    // This is not the idiomatic way to run this function. See the documentation for send_async.
    // This is done this way to simplify the code in main(), rather than have both a sync and async
    // version.
    #[cfg(feature = "async_tokio")]
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap()
        .block_on(sender.send_async(message));

    result
}

fn main() -> Result<(), anyhow::Error> {
    let args = Cli::parse();
    let sender = Sender::new(args.server.to_owned(), args.port);
    #[cfg(feature = "_tls_common")]
    let sender = {
        let tls_config: TlsConfig = args.tls.try_into().unwrap();
        sender.with_tls(tls_config).unwrap()
    };

    let response = if let Some(path) = args.input_file {
        let mut rdr = ReaderBuilder::new();
        rdr.delimiter(b' ')
            .double_quote(false)
            .escape(Some(b'\\'))
            .has_headers(false)
            .trim(csv::Trim::All);

        // The lifetime of `records` must exceed the lifetime of the
        // references taken in `items`, then passed to `Sender.send()`
        let records = if path == OsStr::from_bytes(&[b'-']) {
            records_from_input(rdr.from_reader(std::io::stdin()))
        } else {
            records_from_input(rdr.from_path(path)?)
        }?;
        let items: Vec<(&str, &str, &str)> = records
            .iter()
            .map(|item| (&item[0], &item[1], &item[2]))
            .collect();

        send_wrapper(&sender, items)?
    } else if let Some(host) = args.host {
        send_wrapper(
            &sender,
            (
                host.as_str(),
                args.key.expect("Guaranteed by Cli").as_str(),
                args.value.expect("Guaranteed by Cli").as_str(),
            ),
        )?
    } else {
        bail!("You must specify either --input-file or --host, --key, and --value");
    };

    if response.success() {
        println!("{:?}", response);
        if args.fail {
            let n_failed = response
                .failed_cnt()
                .ok_or_else(|| anyhow!("Could not parse failed items count"))?;
            if n_failed > 0 {
                bail!("{} items failed", n_failed);
            }
        }
        Ok(())
    } else {
        Err(anyhow!("{:?}", response))
    }
}
