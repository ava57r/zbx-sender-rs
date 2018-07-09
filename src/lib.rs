//! The library implementation Zabbix sender protocol
//! more details:
//! [Zabbix Documentation - 4 Trapper items](https://www.zabbix.com/documentation/3.0/manual/appendix/items/trapper).
//! [Docs/protocols/zabbix sender/2.0](https://www.zabbix.org/wiki/Docs/protocols/zabbix_sender/2.0).
//!

#[macro_use]
extern crate serde_derive;
extern crate byteorder;
extern crate serde_json;
extern crate regex;

#[macro_use]
extern crate failure;

mod error;

pub use error::Result;

use std::io::prelude::*;
use std::io;
use std::net::TcpStream;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

const ZBX_HDR: &'static [u8; 5] = b"ZBXD\x01";
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
        if ZBX_HDR != &zbx_hdr[..5] {
            return Err(error::Error::InvalidHeader);
        }

        let mut rdr = io::Cursor::new(zbx_hdr);
        rdr.set_position(5);
        let data_length = rdr.read_u64::<LittleEndian>()?;
        if data_length == 0 {
            return Err(error::Error::InvalidHeader);
        }

        let mut read_data = vec![];
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
    pub fn processed_cnt(&self) -> i32 {
        if let Some(result) = self.get_value_from_info("processed") {
            if let Ok(int_value) = result.parse::<i32>() {
                return int_value
            }
        }
        -1 //Return a invalid number
    }

    /// return the number of failed commands
    pub fn failed_cnt(&self) -> i32 {
        if let Some(result) = self.get_value_from_info("failed") {
            if let Ok(int_value) = result.parse::<i32>() {
                return int_value
            }
        }
        -1 //Return a invalid number
    }

    /// return the number total number of commands send
    pub fn total_cnt(&self) -> i32 {
        if let Some(result) = self.get_value_from_info("total") {
            if let Ok(int_value) = result.parse::<i32>() {
                return int_value
            }
        }
        -1 //Return a invalid number
    }

    /// return the time spent to send the command
    pub fn seconds_spent(&self) -> f32 {
        if let Some(result) = self.get_value_from_info("seconds_spent") {
            if let Ok(float_value) = result.parse::<f32>() {
                return float_value
            }
        }
        -1.0 //Return a invalid number
    }

    fn get_value_from_info(&self, name: &str) -> Option<String> {

        let reg = regex::Regex::new(r"processed: (?P<processed>\d+); failed: (?P<failed>\d+); total: (?P<total>\d+); seconds spent: (?P<seconds_spent>\d.\d+)").unwrap();
        match reg.captures(&self.info) {
            Some(x) => Some(x[name].to_string()),
            None => None,
        }

    }
}
