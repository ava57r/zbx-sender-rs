//! The library implementation Zabbix sender protocol
//! more details:
//! [Zabbix Documentation - 4 Trapper items](https://www.zabbix.com/documentation/3.0/manual/appendix/items/trapper).
//! [Docs/protocols/zabbix sender/2.0](https://www.zabbix.org/wiki/Docs/protocols/zabbix_sender/2.0).
//!
//! ## Package feature
//!
//! `async_tokio` - enables tokio async requests.

use serde::{Deserialize, Serialize};
#[macro_use]
extern crate lazy_static;
#[cfg(feature = "tracing")]
use tracing::{debug, trace};

mod error;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "tls")]
use {std::sync::Arc, tls::ZabbixTlsConfig};

trait Stream: std::io::Read + std::io::Write {}

impl<T> Stream for T where T: std::io::Read + std::io::Write {}

#[cfg(feature = "async_tls")]
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}

#[cfg(feature = "async_tls")]
impl<T> AsyncStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}

pub use crate::error::{Error, Result};

use std::convert::TryInto;
use std::io;
use std::io::prelude::*;
use std::net::TcpStream;

const ZBX_HEADER: usize = 5;
const ZBX_HDR: &[u8; ZBX_HEADER] = b"ZBXD\x01";
const ZBX_HDR_SIZE: usize = 13;

/// implementation Zabbix sender protocol.
pub struct Sender {
    server: String,
    port: u16,
    #[cfg(feature = "tls")]
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl Sender {
    /// Creates a new instance of the client zabbix.
    pub fn new(server: String, port: u16) -> Self {
        Self {
            server,
            port,
            #[cfg(feature = "tls")]
            tls: None,
        }
    }

    #[cfg(feature = "tls")]
    pub fn with_tls(self, tls: ZabbixTlsConfig) -> Result<Self> {
        let tls_config = tls.try_into().map_or_else(
            |e| {
                if let Error::TlsUnencrypted = e {
                    Ok(None)
                } else {
                    Err(e)
                }
            },
            |c| Ok(Some(Arc::new(c))),
        )?;
        Ok(Self {
            tls: tls_config,
            ..self
        })
    }

    /// Sends data to the server according to Protocol rules
    pub fn send<T>(&self, msg: T) -> Result<Response>
    where
        T: ToMessage,
    {
        // This use statement must be scoped to the function body
        // or the methods provided by `byteorder` (e.g. `read_u64`)
        // conflict with the same methods provided by
        // `tokio::io::AsyncReadExt` when the `async_tokio` feature
        // is enabled, because `AsyncReadExt` is implemented for
        // `AsyncRead`, which is implemented for `std::io::Cursor<T>`.
        use byteorder::{LittleEndian, ReadBytesExt};

        let msg = msg.to_message();
        let send_data = Self::encode_request(&msg)?;

        #[cfg_attr(feature = "tls", allow(unused_mut))]
        let mut stream = TcpStream::connect((self.server.as_str(), self.port))?;
        #[cfg(feature = "tracing")]
        {
            debug!(?stream, "connected to Zabbix");
            trace!(data = ?send_data, "request bytes");
        }
        #[cfg(feature = "tls")]
        let mut stream = {
            use rustls::ClientConnection;

            if let Some(config) = &self.tls {
                let server_name = self.server.as_str().try_into().map_err(
                    |e: rustls::client::InvalidDnsNameError| Error::TlsConfigError(e.to_string()),
                )?;
                let conn = ClientConnection::new(Arc::clone(config), server_name)
                    .map_err(|e| Error::TlsConfigError(e.to_string()))?;
                Box::new(rustls::StreamOwned::new(conn, stream)) as Box<dyn Stream>
            } else {
                Box::new(stream) as Box<dyn Stream>
            }
        };
        stream.write_all(&send_data)?;
        #[cfg(feature = "tracing")]
        debug!(
            message = serde_json::to_string(&msg)?.as_str(),
            "sent trap to Zabbix"
        );

        let mut zbx_hdr = [0; ZBX_HDR_SIZE];
        stream.read_exact(&mut zbx_hdr)?;
        if ZBX_HDR != &zbx_hdr[..ZBX_HEADER] {
            return Err(Error::InvalidHeader);
        }

        let mut rdr = io::Cursor::new(zbx_hdr);
        rdr.set_position(ZBX_HEADER as u64);
        let data_length = rdr.read_u64::<LittleEndian>()?;
        if data_length == 0 {
            return Err(Error::InvalidHeader);
        }
        #[cfg(feature = "tracing")]
        trace!(header = ?zbx_hdr, data_length, "got valid response header");

        let mut read_data = Vec::with_capacity(data_length as usize);
        stream.take(data_length).read_to_end(&mut read_data)?;
        #[cfg(feature = "tracing")]
        trace!(data = ?read_data, "read response bytes");

        let response: Response = serde_json::from_slice(&read_data)?;
        #[cfg(feature = "tracing")]
        debug!(?response, "decoded valid response");

        Ok(response)
    }

    #[cfg(feature = "async_tokio")]
    pub async fn send_async<T>(&self, msg: T) -> Result<Response>
    where
        T: ToMessage,
    {
        // This use statement must be scoped to the function body.
        // See explanation in comment at `fn send()`.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let msg = msg.to_message();
        let send_data = Self::encode_request(&msg)?;

        #[cfg_attr(feature = "tls", allow(unused_mut))]
        let mut stream = tokio::net::TcpStream::connect((self.server.as_str(), self.port)).await?;
        #[cfg(feature = "tracing")]
        {
            debug!(?stream, "connected to Zabbix");
            trace!(data = ?send_data, "request bytes");
        }
        #[cfg(all(feature = "tls", not(feature = "async_tls")))]
        compile_error!("To enable the features `tls` and `async_tokio` together, you must also enable the `async_tls` feature");

        #[cfg(all(feature = "tls", feature = "async_tls"))]
        let mut stream = if let Some(config) = &self.tls {
            let server_name = self.server.as_str().try_into().map_err(
                |e: rustls::client::InvalidDnsNameError| Error::TlsConfigError(e.to_string()),
            )?;
            let conn = tokio_rustls::TlsConnector::from(Arc::clone(config));
            Box::new(conn.connect(server_name, stream).await?) as Box<dyn AsyncStream>
        } else {
            Box::new(stream)
        };

        stream.write_all(&send_data).await?;
        #[cfg(feature = "tracing")]
        debug!(
            message = serde_json::to_string(&msg)?.as_str(),
            "sent trap to Zabbix"
        );

        let mut zbx_hdr = [0; ZBX_HDR_SIZE];
        stream.read_exact(&mut zbx_hdr).await?;
        if ZBX_HDR != &zbx_hdr[..ZBX_HEADER] {
            return Err(Error::InvalidHeader);
        }

        let mut rdr = io::Cursor::new(zbx_hdr);
        rdr.set_position(ZBX_HEADER as u64);
        let data_length = rdr.read_u64_le().await?;
        if data_length == 0 {
            return Err(Error::InvalidHeader);
        }
        #[cfg(feature = "tracing")]
        trace!(header = ?zbx_hdr, data_length, "got valid response header");

        let mut read_data = Vec::with_capacity(data_length as usize);
        stream.take(data_length).read_to_end(&mut read_data).await?;
        #[cfg(feature = "tracing")]
        trace!(data = ?read_data, "read response bytes");

        let response: Response = serde_json::from_slice(&read_data)?;
        #[cfg(feature = "tracing")]
        debug!(?response, "decoded valid response");

        Ok(response)
    }

    fn encode_request(msg: &Message) -> Result<Vec<u8>> {
        // This use statement must be scoped to the function body.
        // See explanation in comment at `fn send()`.
        use byteorder::{LittleEndian, WriteBytesExt};

        let msg_json = serde_json::to_string(msg)?;
        let data = msg_json.as_bytes();

        let mut send_data: Vec<u8> = Vec::with_capacity(ZBX_HDR_SIZE + data.len());
        send_data.extend(ZBX_HDR);
        send_data.write_u32::<LittleEndian>(data.len() as u32)?;
        send_data.extend(&[0, 0, 0, 0]);
        send_data.extend(data.iter());

        Ok(send_data)
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
        // This is not public API, so the following should panic
        // if an invalid regex capture is requested.
        RE.captures(&self.info).map(|x| x[name].to_string())
    }
}
