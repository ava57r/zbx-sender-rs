#![warn(missing_docs)]
//! Zabbix Sender Protocol implementation to transmit metrics to Zabbix Server.
//!
//! Provides sync (and optional async) methods to send key-value pairs to Zabbix Server and Zabbix
//! Proxy. Can communicate unencrypted or via TLS with certificates or pre-shared key (PSK). Also
//! provides a [`clap`](https://crates.io/crates/clap) command line parser that can be used to
//! configure a TLS connection to Zabbix for crates that use this library.
//!
//! ## Crate Features
//!
//! - `tracing` - enable logging via the `tracing` crate.
//! - `async_tokio` - enable the async method `Sender.send_async()` to send values
//!   asynchronously using `tokio::net::TcpStream`
//! - `tls_rustls` - use the `rustls` crate to enable TLS certificate encryption with Zabbix
//!   Server. As of version 0.20, `rustls` does **NOT** support PSK encryption.
//! - `tls_openssl` - use the `openssl` crate to enable TLS certificate encryption or PSK
//!   encryption with Zabbix Server.
//! - `tls_rustls_tokio` - **MUST** be enabled when both `async_tokio` and `tls_rustls` are
//!   enabled, because Cargo does not support conditional feature enablement (i.e.
//!   <https://github.com/rust-lang/cargo/issues/1839>).
//! - `tls_openssl_tokio` - **MUST** be enabled when both `async_tokio` and `tls_openssl` are
//!   enabled.
//! - `clap` - Include the struct that implements `clap::Args`, which can be included in downstream
//!   users of this library to get command line argument parsing that mirrors Zabbix native TLS
//!   configuration.
#![cfg_attr(
    all(feature = "_tls_common", feature = "clap"),
    doc = r##"
      See details in the documentation for [tls::ClapArgs].
"##
)]

use serde::{Deserialize, Serialize};
#[macro_use]
extern crate lazy_static;
#[cfg(feature = "tracing")]
use tracing::{debug, trace};

mod error;
#[cfg(feature = "_tls_common")]
pub mod tls;
#[cfg(feature = "_tls_common")]
use tls::TlsConfig;

trait Stream: std::io::Read + std::io::Write {}

impl<T: std::io::Read + std::io::Write> Stream for T {}

#[cfg(feature = "async_tokio")]
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {}

#[cfg(feature = "async_tokio")]
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> AsyncStream for T {}

pub use crate::error::{Error, Result};

#[cfg(feature = "_tls_common")]
use std::convert::TryInto;
use std::io;
use std::io::prelude::*;
use std::net::TcpStream;

const ZBX_HEADER: usize = 5;
const ZBX_HDR: &[u8; ZBX_HEADER] = b"ZBXD\x01";
const ZBX_HDR_SIZE: usize = 13;

/// Implementation of Zabbix Sender protocol.
pub struct Sender {
    server: String,
    port: u16,
    #[cfg(feature = "_tls_common")]
    tls: Option<tls::StreamAdapter>,
}

impl Sender {
    /// Creates a new instance of the Zabbix client.
    ///
    /// ## Arguments
    ///
    /// * `server` - the hostname or IP address of the Zabbix Server or Zabbix Proxy.
    /// * `port` - the Zabbix trapper port (also referred to as "Active Checks"). The Zabbix
    ///   default is 10051.
    ///
    /// ## Examples
    /// ```
    /// use zbx_sender::Sender;
    ///
    /// let zabbix = Sender::new("zabbix.example.com", 10051);
    /// ```
    pub fn new(server: impl Into<String>, port: u16) -> Self {
        Self {
            server: server.into(),
            port,
            #[cfg(feature = "_tls_common")]
            tls: None,
        }
    }

    #[cfg(feature = "_tls_common")]
    /// Configure the client to connect via TLS
    ///
    /// ## Arguments
    ///
    /// * `tls` - an instance of [TlsConfig]
    ///
    /// ## Examples
    /// ```no_run
    /// use zbx_sender::{Sender, tls::TlsConfig};
    ///
    /// let tls_config = TlsConfig::new_cert(
    ///     "/etc/zabbix/sender.crt",
    ///     "/etc/zabbix/sender.key",
    /// );
    /// let zabbix = Sender::new("zabbix.example.com", 10051).with_tls(tls_config);
    /// ```
    pub fn with_tls(self, tls: TlsConfig) -> Result<Self> {
        use crate::tls::TlsError::Unencrypted;

        let tls_config = tls.try_into().map_or_else(
            |e| {
                if let Error::TlsError(Unencrypted) = e {
                    Ok(None)
                } else {
                    Err(e)
                }
            },
            |c| Ok(Some(c)),
        )?;
        Ok(Self {
            tls: tls_config,
            ..self
        })
    }

    /// Send data to Zabbix server
    ///
    /// ## Arguments
    ///
    /// * `msg` - Any value for which the trait [ToMessage] is implemented
    ///
    /// ## Examples
    /// ```no_run
    /// # use zbx_sender::{Error, Sender};
    /// # let zabbix = Sender::new("zabbix.example.com", 10051);
    /// zabbix.send(("hostname", "item_key", "value"))?;
    /// # Ok::<(), Error>(())
    /// ```
    ///
    pub fn send<T>(&self, msg: T) -> Result<Response>
    where
        T: ToMessage,
    {
        let conn = self.connect()?;
        self.send_to(msg, conn)
    }

    fn connect(&self) -> Result<Box<dyn Stream>> {
        #[cfg_attr(feature = "_tls_common", allow(unused_mut))]
        let stream = Box::new(TcpStream::connect((self.server.as_str(), self.port))?);

        #[cfg(feature = "tracing")]
        debug!(?stream, "connected to Zabbix");

        #[cfg(feature = "_tls_common")]
        let stream = if let Some(t) = &self.tls {
            Box::new(t.connect(&self.server, *stream)?) as Box<dyn Stream>
        } else {
            stream
        };

        Ok(stream)
    }

    fn send_to<T, S>(&self, msg: T, mut stream: S) -> Result<Response>
    where
        T: ToMessage,
        S: Stream,
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

        #[cfg(feature = "tracing")]
        trace!(data = ?send_data, "request bytes");
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
    /// Async version of `Sender.send()`
    ///
    /// ## Arguments
    ///
    /// * `msg` - Any value for which the trait [ToMessage] is implemented
    ///
    /// ## Examples
    /// ```no_run
    /// # use zbx_sender::{Error, Sender};
    /// # let zabbix = Sender::new("zabbix.example.com", 10051);
    /// # tokio_test::block_on(async {
    /// zabbix.send_async(("hostname", "item_key", "value")).await?;
    /// # Ok::<(), Error>(())
    /// # });
    /// # Ok::<(), Error>(())
    /// ```
    pub async fn send_async<T>(&self, msg: T) -> Result<Response>
    where
        T: ToMessage,
    {
        let conn = self.connect_async().await?;
        self.send_async_to(msg, conn).await
    }

    #[cfg(feature = "async_tokio")]
    async fn connect_async(&self) -> Result<Box<dyn AsyncStream>> {
        #[cfg_attr(feature = "_tls_common", allow(unused_mut))]
        let stream =
            Box::new(tokio::net::TcpStream::connect((self.server.as_str(), self.port)).await?);

        #[cfg(feature = "tracing")]
        debug!(?stream, "connected to Zabbix");

        #[cfg(feature = "_tls_common")]
        let stream = if let Some(t) = &self.tls {
            Box::new(t.connect_async(&self.server, *stream).await?) as Box<dyn AsyncStream>
        } else {
            stream
        };

        Ok(stream)
    }

    #[cfg(feature = "async_tokio")]
    async fn send_async_to<T, S>(&self, msg: T, mut stream: S) -> Result<Response>
    where
        T: ToMessage,
        S: AsyncStream,
    {
        // This use statement must be scoped to the function body.
        // See explanation in comment at `fn send()`.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let msg = msg.to_message();
        let send_data = Self::encode_request(&msg)?;

        #[cfg(feature = "tracing")]
        trace!(data = ?send_data, "request bytes");
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
///
/// ## Official Zabbix Documentation
///
/// - [Zabbix Sender Protocol](https://www.zabbix.com/documentation/current/en/manual/appendix/protocols/header_datalen)
/// - [Message format](https://www.zabbix.com/documentation/current/en/manual/appendix/items/trapper)
///
/// ## Protocol Details
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            "ZBXD"                             |     Flags     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Data Length (Little Endian)                 |  Reserved ... |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Reserved (continued) [zero-filled]       | JSON Message Data (UTF-8) ... |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                       ...                                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// For Zabbix Sender, the Flags field is always `0x01`. Other documented flag values are for
/// Zabbix Server-Proxy communication.
///
/// ## Message Format
///
/// ```json
/// {
///     "request": "sender data",
///     "data": [
///         {
///             "host": "<Host Name in Zabbix Server>",
///             "key": "<Item Key in Zabbix Server>",
///             "value": "<Item Value>",
///             "clock": <Unix timestamp>,
///             "ns": <Nanosecond fraction>
///         }
///     ]
/// }
/// ```
///
/// `clock` and `ns` are optional fields that are not currently implemented by the `zbx_sender`
/// crate.
///
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
    /// Convert the type to a [Message]
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

impl<'a> ToMessage for Vec<(&'a str, &'a str, &'a str)> {
    fn to_message(self) -> Message {
        let mut msg = Message::default();
        msg.data.extend(self.into_iter().map(SendValue::from));

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

#[cfg(test)]
mod test {
    use mock_io::sync::{MockListener, MockStream};

    use super::*;

    fn json_to_packet(json: impl AsRef<[u8]>) -> Vec<u8> {
        let body = json.as_ref();
        let len: u32 = body.len().try_into().unwrap();
        let mut packet: Vec<u8> = Vec::new();
        packet.extend_from_slice(ZBX_HDR);
        packet.extend_from_slice(&len.to_le_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(body);
        packet
    }

    fn verify_request(mut stream: impl Read, expected: impl AsRef<[u8]>) {
        let expected = expected.as_ref();
        let hdr = &mut [0u8; ZBX_HDR_SIZE];
        stream.read_exact(&mut hdr[..]).unwrap();
        assert_eq!(hdr, &expected[..ZBX_HDR_SIZE]);

        let len_end = ZBX_HEADER + std::mem::size_of::<u32>();
        let len = u32::from_le_bytes((&hdr[ZBX_HEADER..len_end]).try_into().unwrap());

        let mut body = vec![0u8; len as usize];
        stream.read_exact(&mut body[..]).unwrap();
        assert_eq!(body, &expected[ZBX_HDR_SIZE..]);
    }

    fn verify_response(response: &Response, n_values_sent: i32) {
        assert!(response.success());
        let n_processed = response.processed_cnt().expect("processed_cnt missing");
        assert_eq!(n_processed, n_values_sent);
        let n_failed = response.failed_cnt().expect("failed_cnt missing");
        assert!(n_failed == 0);
        let n_total = response.total_cnt().expect("total_cnt missing");
        assert_eq!(n_total, n_values_sent);
        let n_seconds = response.seconds_spent().expect("seconds_spent missing");
        assert!(n_seconds > 0.0);
    }

    #[test]
    fn single_value() {
        let expected_packet = json_to_packet(concat!(
            r#"{"request":"sender data","data":["#,
            r#"{"host":"test_host","key":"test_key","value":"12345678"}"#,
            r#"]}"#
        ));

        let (listener, handle) = MockListener::new();

        let h_client = std::thread::spawn(move || {
            let stream = MockStream::connect(&handle).unwrap();
            let sender = Sender::new("test_server", 10051);
            let response = sender.send_to(("test_host", "test_key", "12345678"), stream).unwrap();
            verify_response(&response, 1);
        });

        // Accept just one connection
        let mut stream = listener.accept().unwrap();
        verify_request(Read::by_ref(&mut stream), &expected_packet);
        let response = json_to_packet(
            r#"{"response":"success","info":"processed: 1; failed: 0; total: 1; seconds spent: 0.1"}"#
        );
        stream.write_all(&response[..]).unwrap();

        // This serves two purposes:
        // 
        // 1. Ensures the client thread didn't panic
        // 2. Ensures the client did close the "connection",
        //    or this line would block forever, because the
        //    above test server code doesn't.
        h_client.join().unwrap();
    }

    #[test]
    fn multiple_values() {
        let expected_packet = json_to_packet(concat!(
            r#"{"request":"sender data","data":["#,
            r#"{"host":"test_host","key":"test_key","value":"12345678"},"#,
            r#"{"host":"test_host","key":"test_key2","value":"87654321"}"#,
            r#"]}"#
        ));

        let (listener, handle) = MockListener::new();

        let h_client = std::thread::spawn(move || {
            let stream = MockStream::connect(&handle).unwrap();
            let sender = Sender::new("test_server", 10051);
            let message = vec![("test_host", "test_key", "12345678"), ("test_host", "test_key2", "87654321")].to_message();
            let response = sender.send_to(message, stream).unwrap();
            verify_response(&response, 2);
        });

        // Accept just one connection
        let mut stream = listener.accept().unwrap();
        verify_request(Read::by_ref(&mut stream), &expected_packet);
        let response = json_to_packet(
            r#"{"response":"success","info":"processed: 2; failed: 0; total: 2; seconds spent: 0.1"}"#
        );
        stream.write_all(&response[..]).unwrap();

        // This serves two purposes:
        // 
        // 1. Ensures the client thread didn't panic
        // 2. Ensures the client did close the "connection",
        //    or this line would block forever, because the
        //    above test server code doesn't.
        h_client.join().unwrap();
    }

    #[cfg(feature = "async_tokio")]
    mod async_tokio {
        use mock_io::tokio::{
            MockListener as AsyncMockListener,
            MockStream as AsyncMockStream
        };
        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
        
        use super::*;

        #[tokio::test]
        async fn single_value() {
            let expected_packet = json_to_packet(concat!(
                r#"{"request":"sender data","data":["#,
                r#"{"host":"test_host","key":"test_key","value":"12345678"}"#,
                r#"]}"#
            ));

            let (mut listener, handle) = AsyncMockListener::new();

            let h_client = tokio::spawn(async move {
                let stream = AsyncMockStream::connect(&handle).unwrap();
                let sender = Sender::new("test_server", 10051);
                let response = sender.send_async_to(("test_host", "test_key", "12345678"), stream).await.unwrap();
                verify_response(&response, 1);
            });

            // Accept just one connection
            let stream = listener.accept().await.unwrap();
            let (stream_r, mut stream_w) = stream.split(); 
            verify_request(stream_r, &expected_packet).await;
            let response = json_to_packet(
                r#"{"response":"success","info":"processed: 1; failed: 0; total: 1; seconds spent: 0.1"}"#
            );
            stream_w.write_all(&response[..]).await.unwrap();

            // This serves two purposes:
            // 
            // 1. Ensures the client thread didn't panic
            // 2. Ensures the client did close the "connection",
            //    or this line would block forever, because the
            //    above test server code doesn't.
            h_client.await.unwrap();
        }

        #[tokio::test]
        async fn multiple_values() {
            let expected_packet = json_to_packet(concat!(
                r#"{"request":"sender data","data":["#,
                r#"{"host":"test_host","key":"test_key","value":"12345678"},"#,
                r#"{"host":"test_host","key":"test_key2","value":"87654321"}"#,
                r#"]}"#
            ));

            let (mut listener, handle) = AsyncMockListener::new();

            let h_client = tokio::spawn(async move {
                let stream = AsyncMockStream::connect(&handle).unwrap();
                let sender = Sender::new("test_server", 10051);
                let message = vec![("test_host", "test_key", "12345678"), ("test_host", "test_key2", "87654321")].to_message();
                let response = sender.send_async_to(message, stream).await.unwrap();
                verify_response(&response, 2);
            });

            // Accept just one connection
            let stream = listener.accept().await.unwrap();
            let (stream_r, mut stream_w) = stream.split(); 
            verify_request(stream_r, &expected_packet).await;
            let response = json_to_packet(
                r#"{"response":"success","info":"processed: 2; failed: 0; total: 2; seconds spent: 0.1"}"#
            );
            stream_w.write_all(&response[..]).await.unwrap();

            // This serves two purposes:
            // 
            // 1. Ensures the client thread didn't panic
            // 2. Ensures the client did close the "connection",
            //    or this line would block forever, because the
            //    above test server code doesn't.
            h_client.await.unwrap();
        }
        async fn verify_request<S>(mut stream: S, expected: impl AsRef<[u8]>)
        where
            S: AsyncRead + Unpin,
        {
            let expected = expected.as_ref();
            let hdr = &mut [0u8; ZBX_HDR_SIZE];
            stream.read_exact(&mut hdr[..]).await.unwrap();
            assert_eq!(hdr, &expected[..ZBX_HDR_SIZE]);

            let len_end = ZBX_HEADER + std::mem::size_of::<u32>();
            let len = u32::from_le_bytes((&hdr[ZBX_HEADER..len_end]).try_into().unwrap());

            let mut body = vec![0u8; len as usize];
            stream.read_exact(&mut body[..]).await.unwrap();
            assert_eq!(body, &expected[ZBX_HDR_SIZE..]);
        }
    }
}
