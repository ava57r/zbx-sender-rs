extern crate zbx_sender;

use std::convert::TryInto;

use clap::Parser;

use zbx_sender::{
    tls::{ZabbixTlsCli, ZabbixTlsConfig},
    Response, Result, Sender,
};

#[derive(Parser)]
struct Cli {
    #[clap(short, long)]
    server: String,
    #[clap(short, long, default_value = "10051")]
    port: u16,
    #[clap(flatten)]
    tls: ZabbixTlsCli,
}

fn send_one_value(sender: &Sender) -> Result<Response> {
    sender.send(("host1", "key1", "value"))
}

fn main() {
    let args = Cli::parse();
    let tls_config: ZabbixTlsConfig = args.tls.try_into().unwrap();
    let sender = Sender::new(args.server.to_owned(), args.port)
        .with_tls(tls_config)
        .unwrap();

    match send_one_value(&sender) {
        Ok(response) => println!("{:?} is success {} ", response, response.success()),
        Err(e) => println!("Error {}", e),
    }
}
