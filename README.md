# zbx-sender

[![](https://img.shields.io/crates/v/zbx_sender.svg)](https://crates.io/crates/zbx_sender)

## Synopsis

Modern Rust implementation of Zabbix Sender Client.
Working with Zabbix 2.0.8 and 2.1.7+ versions.


## Code Example
Easy to use:

```rust
extern crate zbx_sender;

use zbx_sender::{Response, Result, Sender};
use std::env;

fn send_one_value(command: &str) -> Result<Response> {
    let sender = Sender::new(command.to_owned(), 10051);
    sender.send(("host1", "key1", "value"))
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
```

See examples/sender.rs

## License

[The MIT License (MIT)](LICENSE)
