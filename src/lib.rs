#[macro_use]
extern crate serde_derive;
extern crate byteorder;
extern crate serde_json;

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

    pub fn send(&self, host: String, key: String, value: String) -> io::Result<Response> {
        let msg = Message::new(SendValue { host, key, value });

        let byte_msg = serde_json::to_string(&msg).unwrap();
        let data = byte_msg.as_bytes();

        let mut send_data: Vec<u8> = Vec::with_capacity(ZBX_HDR_SIZE + data.len());
        send_data.extend(ZBX_HDR);
        send_data
            .write_u32::<LittleEndian>(data.len() as u32)
            .unwrap();
        send_data.extend(&[0, 0, 0, 0]);
        send_data.extend(data.iter());

        let addr = format!("{0}:{1}", self.server, self.port);
        let mut stream = TcpStream::connect(addr)?;
        stream.write(&send_data)?;

        let mut zbx_hdr = [0; ZBX_HDR_SIZE];
        stream.read(&mut zbx_hdr)?;
        assert_eq!(ZBX_HDR, &zbx_hdr[..5]);

        let mut rdr = io::Cursor::new(zbx_hdr);
        rdr.set_position(5);
        let data_length = rdr.read_u32::<LittleEndian>().unwrap();
        if data_length == 0 {
            panic!("Invalid response");
        }

        let mut read_data = vec![];
        stream.read_to_end(&mut read_data).unwrap();
        let response: Response = serde_json::from_slice(&read_data).unwrap();

        Ok(response)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SendValue {
    host: String,
    key: String,
    value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Message {
    request: String,
    data: Vec<SendValue>,
}

impl Message {
    const REQUEST: &'static str = "sender data";

    pub fn new(value: SendValue) -> Message {
        Message {
            request: Message::REQUEST.to_owned(),
            data: vec![value],
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Response {
    response: String,
    info: String,
}

mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
