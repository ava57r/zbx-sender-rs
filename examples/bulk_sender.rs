extern crate zbx_sender;

use std::env;
use zbx_sender::{Response, Result, SendValue, Sender};

fn send(command: &str) -> Result<Response> {
    let sender = Sender::new(command.to_owned(), 10051);
    let collection: Vec<SendValue> = vec![
        ("host1", "key1", "value").into(),
        ("host1", "key1", "value2").into(),
    ];

    sender.send(collection)
}

fn main() {
    let command = match env::args().nth(1) {
        Some(cmd) => cmd,
        None => {
            let name = env::args().nth(0).unwrap();
            panic!("Usage: {} [command]", name)
        }
    };

    match send(&command) {
        Ok(response) => {
            println!("{:?}", response);
            println!(
                "processed: {}; failed: {}; total: {}; seconds spent: {}",
                response.processed_cnt().unwrap(),
                response.failed_cnt().unwrap(),
                response.total_cnt().unwrap(),
                response.seconds_spent().unwrap()
            );
        }
        Err(e) => println!("Error {}", e),
    }
}
