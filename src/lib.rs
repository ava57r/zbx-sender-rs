//! The library implementation Zabbix sender protocol
//! more details:
//! [Zabbix Documentation - 4 Trapper items](https://www.zabbix.com/documentation/3.0/manual/appendix/items/trapper).
//! [Docs/protocols/zabbix sender/2.0](https://www.zabbix.org/wiki/Docs/protocols/zabbix_sender/2.0).
//!

use byteorder;
use regex;
use serde::{Deserialize, Serialize};
use serde_json;
#[macro_use]
extern crate lazy_static;
use failure;

mod error;

pub use crate::error::Result;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;
use std::io::prelude::*;
use std::net::TcpStream;

const ZBX_HEADER: usize = 5;
const ZBX_HDR: &'static [u8; ZBX_HEADER] = b"ZBXD\x01";
const ZBX_HDR_SIZE: usize = 13;

/// implementation Zabbix sender protocol.
pub struct Sender {
    server: String,
    port: u16,
}

impl Sender {
    /// Creates a new instance of the client zabbix.
    pub fn new(server: String, port: u16) -> Sender {
        Sender { server, port }
    }

    /// Sends data to the server according to Protocol rules
    pub fn send<T>(&self, msg: T) -> Result<Response>
    where
        T: ToMessage,
    {
        let byte_msg = serde_json::to_string(&msg.to_message())?;
        let data = byte_msg.as_bytes();

        let mut send_data: Vec<u8> = Vec::with_capacity(ZBX_HDR_SIZE + data.len());
        send_data.extend(ZBX_HDR);
        send_data.write_u32::<LittleEndian>(data.len() as u32)?;
        send_data.extend(&[0, 0, 0, 0]);
        send_data.extend(data.iter());

        let addr = format!("{0}:{1}", self.server, self.port);
        let mut stream = TcpStream::connect(addr)?;
        stream.write(&send_data)?;

        let mut zbx_hdr = [0; ZBX_HDR_SIZE];
        stream.read(&mut zbx_hdr)?;
        if ZBX_HDR != &zbx_hdr[..ZBX_HEADER] {
            return Err(error::Error::InvalidHeader);
        }

        let mut rdr = io::Cursor::new(zbx_hdr);
        rdr.set_position(ZBX_HEADER as u64);
        let data_length = rdr.read_u64::<LittleEndian>()?;
        if data_length == 0 {
            return Err(error::Error::InvalidHeader);
        }

        let mut read_data = Vec::with_capacity(data_length as usize);
        stream.take(data_length).read_to_end(&mut read_data)?;
        let response: Response = serde_json::from_slice(&read_data)?;

        Ok(response)
    }
}

/// Data item sent to the server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SendValue {
    host: String,
    key: String,
    value: String,
}

impl<'a> From<(&'a str, &'a str, &'a str)> for SendValue {
    fn from(msg: (&'a str, &'a str, &'a str)) -> SendValue {
        let (host, key, value) = msg;
        SendValue {
            host: host.to_owned(),
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }
}

/// The message that is sent to the Zabbix server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    request: &'static str,
    data: Vec<SendValue>,
}

impl Message {
    /// Constant request header to the server.
    const REQUEST: &'static str = "sender data";

    /// Creating a new instance of the Message structure from SendValue.
    pub fn new(value: SendValue) -> Message {
        Message {
            request: Message::REQUEST,
            data: vec![value],
        }
    }

    /// Adds an entry to send a composed message.
    pub fn add(&mut self, value: SendValue) {
        self.data.push(value)
    }
}

impl Default for Message {
    fn default() -> Message {
        Message {
            request: Message::REQUEST,
            data: vec![],
        }
    }
}

/// Contract for types that provide the ability to cast to a `Message` type.
pub trait ToMessage {
    fn to_message(self) -> Message;
}

impl ToMessage for Message {
    fn to_message(self) -> Message {
        self
    }
}

impl<'a> ToMessage for (&'a str, &'a str, &'a str) {
    fn to_message(self) -> Message {
        Message::new(SendValue::from(self))
    }
}

impl<'a> From<(&'a str, &'a str, &'a str)> for Message {
    fn from(msg: (&'a str, &'a str, &'a str)) -> Message {
        Message::new(SendValue::from(msg))
    }
}

impl ToMessage for Vec<SendValue> {
    fn to_message(self) -> Message {
        let mut msg = Message::default();
        msg.data.extend(self.into_iter());

        msg
    }
}

/// Structure of Zabbix server's response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Response {
    response: String,
    info: String,
}

impl Response {
    /// Verifies if the date successful send to the zabbix server
    pub fn success(&self) -> bool {
        self.response == "success"
    }

    /// return the number of successful processed commands
    pub fn processed_cnt(&self) -> Option<i32> {
        self.get_value_from_info("processed")
            .and_then(|result| result.parse::<i32>().ok())
    }

    /// return the number of failed commands
    pub fn failed_cnt(&self) -> Option<i32> {
        self.get_value_from_info("failed")
            .and_then(|result| result.parse::<i32>().ok())
    }

    /// return the number total number of commands send
    pub fn total_cnt(&self) -> Option<i32> {
        self.get_value_from_info("total")
            .and_then(|result| result.parse::<i32>().ok())
    }

    /// return the time spent to send the command
    pub fn seconds_spent(&self) -> Option<f32> {
        self.get_value_from_info("seconds_spent")
            .and_then(|result| result.parse::<f32>().ok())
    }

    fn get_value_from_info(&self, name: &str) -> Option<String> {
        lazy_static! {
            static ref RE: regex::Regex = regex::Regex::new(r"processed: (?P<processed>\d+); failed: (?P<failed>\d+); total: (?P<total>\d+); seconds spent: (?P<seconds_spent>\d.\d+)").unwrap();
        }
        match RE.captures(&self.info) {
            Some(x) => Some(x[name].to_string()),
            None => None,
        }
    }
}
