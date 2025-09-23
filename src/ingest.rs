//! A protocol implementation for sending raw events to the Giganto server.

pub mod log;
pub mod netflow;
pub mod network;
pub mod statistics;
pub mod sysmon;
pub mod timeseries;

use std::fmt::Display;

use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::frame::{self, RecvError, SendError};
use crate::RawEventKind;

/// Time format pattern for Zeek-compatible timestamp format ("%s%.9f")
const TIME_FORMAT: &str = "%s%.9f";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Packet {
    pub packet_timestamp: i64,
    pub packet: Vec<u8>,
}

/// Sends the record type. (`RawEventKind`)
///
/// # Errors
///
/// * `SendError::WriteError` if the record header could not be written
pub async fn send_record_header(
    send: &mut SendStream,
    record_type: RawEventKind,
) -> Result<(), SendError> {
    frame::send_bytes(send, &u32::from(record_type).to_le_bytes()).await?;
    Ok(())
}

/// Sends the record data. (timestamp / record structure)
///
/// # Errors
///
/// * `SendError::SerializationFailure`: if the event data could not be serialized
/// * `SendError::MessageTooLarge`: if the event data is too large
/// * `SendError::WriteError`: if the event data could not be written
pub async fn send_event<T>(
    send: &mut SendStream,
    timestamp: i64,
    record_data: T,
) -> Result<(), SendError>
where
    T: Serialize,
{
    frame::send_bytes(send, &timestamp.to_le_bytes()).await?;
    let mut buf = Vec::new();
    frame::send(send, &mut buf, record_data).await?;
    Ok(())
}

/// Receives the record type. (`RawEventKind`)
///
/// # Errors
///
/// * `RecvError::ReadError`: if the record header could not be read
pub async fn receive_record_header(recv: &mut RecvStream, buf: &mut [u8]) -> Result<(), RecvError> {
    frame::recv_bytes(recv, buf).await?;
    Ok(())
}

/// Receives the record data. (timestamp / record structure)
///
/// # Errors
///
/// * `RecvError::ReadError`: if the event data could not be read
pub async fn receive_event(recv: &mut RecvStream) -> Result<(Vec<u8>, i64), RecvError> {
    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    frame::recv_bytes(recv, &mut ts_buf).await?;
    let timestamp = i64::from_le_bytes(ts_buf);

    let mut record_buf = Vec::new();
    frame::recv_raw(recv, &mut record_buf).await?;
    Ok((record_buf, timestamp))
}

/// Receives the ack timestamp. (big-endian)
///
/// # Errors
///
/// * `RecvError::ReadError`: if the ack timestamp data could not be read
pub async fn receive_ack_timestamp(recv: &mut RecvStream) -> Result<i64, RecvError> {
    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    frame::recv_bytes(recv, &mut ts_buf).await?;
    let timestamp = i64::from_be_bytes(ts_buf);
    Ok(timestamp)
}

/// Converts a timestamp to a string in the format of "%s%.9f", which is the format used by Zeek.
#[must_use]
fn convert_time_format(timestamp: i64) -> String {
    const A_BILLION: i64 = 1_000_000_000;

    if timestamp > 0 {
        format!("{}.{:09}", timestamp / A_BILLION, timestamp % A_BILLION)
    } else {
        format!("{}.{:09}", timestamp / A_BILLION, -timestamp % A_BILLION)
    }
}

fn as_str_or_default(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

pub(crate) fn sanitize_csv_field(s: &str) -> String {
    if s.is_empty() {
        "-".to_string()
    } else {
        s.replace(['\t', '\n', '\r'], " ")
    }
}

pub(crate) fn sanitize_csv_field_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "-".to_string()
    } else {
        std::str::from_utf8(bytes)
            .unwrap_or_default()
            .replace(['\t', '\n', '\r'], " ")
    }
}

fn vec_to_string_or_default<T>(vec: &[T]) -> String
where
    T: Display,
{
    if vec.is_empty() {
        "-".to_string()
    } else {
        vec.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn to_string_or_empty<T: Display>(option: Option<T>) -> String {
    match option {
        Some(val) => val.to_string(),
        None => "-".to_string(),
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn ingest_send_recv() {
        use std::{mem, net::IpAddr};

        use jiff::Timestamp;

        use crate::test::{channel, TOKEN};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // send/recv event type
        super::send_record_header(&mut channel.client.send, super::RawEventKind::Conn)
            .await
            .unwrap();

        let mut buf = vec![0; mem::size_of::<u32>()];
        super::receive_record_header(&mut channel.server.recv, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, u32::from(super::RawEventKind::Conn).to_le_bytes());

        // send/recv event data
        let conn = super::network::Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: String::new(),
            start_time: Timestamp::from_nanosecond(500).expect("valid timestamp"),
            end_time: Timestamp::from_nanosecond(1000).expect("valid timestamp"),
            duration: 500,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 21515,
            resp_l2_bytes: 27889,
        };
        super::send_event(&mut channel.client.send, 9999, conn.clone())
            .await
            .unwrap();
        let (data, timestamp) = super::receive_event(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(timestamp, 9999);
        assert_eq!(data, crate::bincode_utils::encode_legacy(&conn).unwrap());

        // recv ack timestamp
        crate::frame::send_bytes(&mut channel.client.send, &8888_i64.to_be_bytes())
            .await
            .unwrap();
        let timestamp = super::receive_ack_timestamp(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(timestamp, 8888);
    }

    #[test]
    fn convert_time_format() {
        use jiff::Timestamp;

        let sec = 2;
        let nsec = 123;
        let ndt = Timestamp::from_nanosecond(sec * 1_000_000_000 + nsec).expect("valid timestamp");

        let ts = ndt.as_nanosecond();
        let ts_fmt = super::convert_time_format(ts.try_into().unwrap());
        assert_eq!(ts_fmt, "2.000000123");

        let sec = -1;
        let nsec = 0;
        let ndt = Timestamp::from_nanosecond(sec * 1_000_000_000 + nsec).expect("valid timestamp");

        let ts = ndt.as_nanosecond();
        let ts_fmt = super::convert_time_format(ts.try_into().unwrap());
        assert_eq!(ts_fmt, "-1.000000000");
    }

    #[test]
    fn sanitize_csv_field() {
        // Test empty string
        assert_eq!(super::sanitize_csv_field(""), "-");

        // Test normal string without special characters
        assert_eq!(super::sanitize_csv_field("normal text"), "normal text");

        // Test string with horizontal tab (0x09)
        assert_eq!(
            super::sanitize_csv_field("text\twith\ttabs"),
            "text with tabs"
        );

        // Test string with line feed (0x0a)
        assert_eq!(
            super::sanitize_csv_field("text\nwith\nlines"),
            "text with lines"
        );

        // Test string with carriage return (0x0d)
        assert_eq!(
            super::sanitize_csv_field("text\rwith\rcarriage"),
            "text with carriage"
        );

        // Test string with all special characters combined
        assert_eq!(
            super::sanitize_csv_field("text\t\n\rwith\tall\tspecial"),
            "text   with all special"
        );
    }

    #[test]
    fn sanitize_csv_field_bytes() {
        // Test empty bytes
        assert_eq!(super::sanitize_csv_field_bytes(&[]), "-");

        // Test normal bytes without special characters
        assert_eq!(
            super::sanitize_csv_field_bytes(b"normal text"),
            "normal text"
        );

        // Test bytes with horizontal tab (0x09)
        assert_eq!(
            super::sanitize_csv_field_bytes(b"text\twith\ttabs"),
            "text with tabs"
        );

        // Test bytes with line feed (0x0a)
        assert_eq!(
            super::sanitize_csv_field_bytes(b"text\nwith\nlines"),
            "text with lines"
        );

        // Test bytes with carriage return (0x0d)
        assert_eq!(
            super::sanitize_csv_field_bytes(b"text\rwith\rcarriage"),
            "text with carriage"
        );

        // Test bytes with all special characters combined
        assert_eq!(
            super::sanitize_csv_field_bytes(b"text\t\n\rwith\tall\tspecial"),
            "text   with all special"
        );

        // Test invalid UTF-8 bytes
        let invalid_utf8 = vec![0xff, 0xfe, 0xfd];
        assert_eq!(super::sanitize_csv_field_bytes(&invalid_utf8), "");
    }
}
