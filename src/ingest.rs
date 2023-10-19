//! A protocol implementation for sending raw events to the Giganto server.

pub mod log;
pub mod netflow;
pub mod network;
pub mod statistics;
pub mod sysmon;
pub mod timeseries;

use crate::frame::{self, RecvError, SendError};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(
    Clone, Copy, Debug, Hash, Deserialize, Eq, IntoPrimitive, PartialEq, Serialize, TryFromPrimitive,
)]
#[repr(u32)]
#[non_exhaustive]
pub enum RecordType {
    Conn = 0,
    Dns = 1,
    Log = 2,
    Http = 3,
    Rdp = 4,
    PeriodicTimeSeries = 5,
    Smtp = 6,
    Ntlm = 7,
    Kerberos = 8,
    Ssh = 9,
    DceRpc = 10,
    Statistics = 11,
    Oplog = 12,
    Packet = 13,
    Ftp = 14,
    Mqtt = 15,
    Ldap = 16,
    Tls = 17,
    Smb = 18,
    Nfs = 19,

    // Windows Sysmon
    ProcessCreate = 31,
    FileCreateTime = 32,
    NetworkConnect = 33,
    ProcessTerminate = 35,
    ImageLoad = 37,
    FileCreate = 41,
    RegistryValueSet = 43,
    RegistryKeyRename = 44,
    FileCreateStreamHash = 45,
    PipeEvent = 47,
    DnsQuery = 52,
    FileDelete = 53,
    ProcessTamper = 55,
    FileDeleteDetected = 56,

    Netflow5 = 60,
    Netflow9 = 61,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Packet {
    pub packet_timestamp: i64,
    pub packet: Vec<u8>,
}

/// Sends the record type. (`RecordType`)
///
/// # Errors
///
/// * `SendError::WriteError` if the record header could not be written
pub async fn send_record_header(
    send: &mut SendStream,
    record_type: RecordType,
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

/// Receives the record type. (`RecordType`)
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

fn vec_to_string_or_default<T>(vec: &Vec<T>) -> String
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

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn ingest_send_recv() {
        use crate::test::{channel, TOKEN};
        use std::{mem, net::IpAddr};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // send/recv event type
        super::send_record_header(&mut channel.client.send, super::RecordType::Conn)
            .await
            .unwrap();

        let mut buf = Vec::new();
        buf.resize(mem::size_of::<u32>(), 0);
        super::receive_record_header(&mut channel.server.recv, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, u32::from(super::RecordType::Conn).to_le_bytes());

        // send/recv event data
        let conn = super::network::Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            duration: 1000,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
        };
        super::send_event(&mut channel.client.send, 9999, conn.clone())
            .await
            .unwrap();
        let (data, timestamp) = super::receive_event(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(timestamp, 9999);
        assert_eq!(data, bincode::serialize(&conn).unwrap());

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
        use chrono::NaiveDateTime;

        let sec = 2;
        let nsec = 123;
        let ndt = NaiveDateTime::from_timestamp_opt(sec, nsec).unwrap();

        let ts = ndt.timestamp_nanos_opt().unwrap();
        let ts_fmt = super::convert_time_format(ts);
        assert_eq!(ts_fmt, "2.000000123");

        let sec = -1;
        let nsec = 0;
        let ndt = NaiveDateTime::from_timestamp_opt(sec, nsec).unwrap();

        let ts = ndt.timestamp_nanos_opt().unwrap();
        let ts_fmt = super::convert_time_format(ts);
        assert_eq!(ts_fmt, "-1.000000000");
    }
}
