extern crate zbx_sender;

use std::convert::TryInto;

use clap::Parser;

use zbx_sender::{
    tls::{ClapArgs, TlsConfig},
    Response, Result, Sender,
};

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    server: String,
    #[arg(short, long, default_value = "10051")]
    port: u16,
    #[command(flatten)]
    tls: ClapArgs,
}

async fn send_one_value(sender: &Sender) -> Result<Response> {
    sender.send_async(("host1", "key1", "value")).await
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Cli::parse();
    let tls_config: TlsConfig = args.tls.try_into().unwrap();
    let sender = Sender::new(args.server.to_owned(), args.port)
        .with_tls(tls_config)
        .unwrap();

    match send_one_value(&sender).await {
        Ok(response) => println!("{:?} is success {} ", response, response.success()),
        Err(e) => println!("Error {}", e),
    }
}
