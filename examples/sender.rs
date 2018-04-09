extern crate zbx_sender;

use zbx_sender::{Response, Result, Sender};
use std::env;

fn send_one_value(command: &str) -> Result<Response> {
    let sender = Sender::new(command.to_owned(), 10051);
    sender.send_value("host1".to_owned(), "key1".to_owned(), "value".to_owned())
}

fn main() {
    let command = match env::args().nth(1) {
        Some(cmd) => cmd,
        None => {
            let name = env::args().nth(0).unwrap();
            panic!("Usage: {} [command]", name)
        }
    };

    match send_one_value(&command) {
        Ok(response) => println!("{:?}", response),
        Err(e) => println!("Error {}", e),
    }
}
