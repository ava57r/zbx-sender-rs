#[macro_use]
extern crate serde_derive;
extern crate byteorder;
extern crate serde_json;

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

pub struct Sender {
    server: String,
    port: u16,
}

impl Sender {
    pub fn new(server: String, port: u16) -> Sender {
        Sender { server, port }
    }

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    request: &'static str,
    data: Vec<SendValue>,
}

impl Message {
    const REQUEST: &'static str = "sender data";

    pub fn new(value: SendValue) -> Message {
        Message {
            request: Message::REQUEST,
            data: vec![value],
        }
    }

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Response {
    response: String,
    info: String,
}
