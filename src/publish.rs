//! A protocol implementation for fetching raw events from the Giganto server.

pub mod range;
pub mod stream;

use std::{mem, net::IpAddr};

use anyhow::Result;
use chrono::{DateTime, Utc};
use quinn::{Connection, ConnectionError, RecvStream, SendStream};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use self::{
    range::{MessageCode, ResponseRangeData},
    stream::{RequestStreamRecord, StreamRequestPayload},
};
use crate::bincode_utils;
use crate::frame::{self, recv_bytes, recv_raw, send_bytes, send_raw, RecvError, SendError};

/// The error type for a publish failure.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Error)]
pub enum PublishError {
    #[error("Connection closed by peer")]
    ConnectionClosed,
    #[error("Connection lost")]
    ConnectionLost(#[from] ConnectionError),
    #[error("Cannot receive a publish message")]
    ReadError(#[from] quinn::ReadError),
    #[error("Cannot send a publish message")]
    WriteError(#[from] quinn::WriteError),
    #[error("Cannot call close request redundantly")]
    CloseStreamError(#[from] quinn::ClosedStream),
    #[error("Cannot serialize a publish message")]
    SerializationError(#[from] bincode::error::EncodeError),
    #[error("Cannot deserialize a publish message")]
    DeserializationError(#[from] bincode::error::DecodeError),
    #[error("Message is too large, so type casting failed")]
    MessageTooLarge,
    #[error("Invalid message type")]
    InvalidMessageType,
    #[error("Invalid message data")]
    InvalidMessageData,
    #[error("Pcap request failed, because {0}")]
    PcapRequestFail(String),
}

impl From<frame::RecvError> for PublishError {
    fn from(e: frame::RecvError) -> Self {
        match e {
            RecvError::DeserializationFailure(e) => PublishError::DeserializationError(e),
            RecvError::ReadError(e) => match e {
                quinn::ReadExactError::FinishedEarly(_) => PublishError::ConnectionClosed,
                quinn::ReadExactError::ReadError(e) => PublishError::ReadError(e),
            },
            RecvError::MessageTooLarge(_) => PublishError::MessageTooLarge,
        }
    }
}

impl From<frame::SendError> for PublishError {
    fn from(e: frame::SendError) -> Self {
        match e {
            SendError::SerializationFailure(e) => PublishError::SerializationError(e),
            SendError::MessageTooLarge(_) => PublishError::MessageTooLarge,
            SendError::WriteError(e) => PublishError::WriteError(e),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PcapFilter {
    pub start_time: DateTime<Utc>,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: DateTime<Utc>,
}

/// Sends the stream request to giganto's publish module.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the stream-request data could not be serialized
/// * `PublishError::MessageTooLarge`: if the stream-request data is too large
/// * `PublishError::WriteError`: if the stream-request data could not be written
pub async fn send_stream_request(
    send: &mut SendStream,
    payload: StreamRequestPayload,
) -> Result<(), PublishError> {
    // send payload
    let mut buf = Vec::new();
    frame::send(send, &mut buf, payload).await?;
    Ok(())
}

/// Sends the semi-supervised stream start message from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::WriteError`: if the semi-supervised's stream start message could not be written
pub async fn send_semi_supervised_stream_start_message(
    send: &mut SendStream,
    start_msg: RequestStreamRecord,
) -> Result<(), PublishError> {
    let record: u32 = start_msg.into();
    send_bytes(send, &record.to_le_bytes()).await?;
    Ok(())
}

/// Sends the range data request to giganto's publish module.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the range-request data could not be serialized
/// * `PublishError::MessageTooLarge`: if the range-request data is too large
/// * `PublishError::WriteError`: if the range-request data could not be written
pub async fn send_range_data_request<T>(
    send: &mut SendStream,
    msg: MessageCode,
    request: T,
) -> Result<(), PublishError>
where
    T: Serialize,
{
    //send MessageCode
    let msg_code: u32 = msg.into();
    send_bytes(send, &msg_code.to_le_bytes()).await?;

    //send RequestRange
    let mut buf = Vec::new();
    frame::send(send, &mut buf, request).await?;
    Ok(())
}

/// Sends the range data from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the range data could not be serialized
/// * `PublishError::MessageTooLarge`: if the range data is too large
/// * `PublishError::WriteError`: if the range data could not be written
pub async fn send_range_data<T>(
    send: &mut SendStream,
    data: Option<(T, i64, &str)>,
) -> Result<(), PublishError>
where
    T: ResponseRangeData,
{
    let send_buf = if let Some((val, timestamp, sensor)) = data {
        val.response_data(timestamp, sensor)
            .map_err(PublishError::SerializationError)?
    } else {
        T::response_done().map_err(PublishError::SerializationError)?
    };
    send_raw(send, &send_buf).await?;
    Ok(())
}

/// Sends the data `Vec<(timestamp, sensor, raw_events)>` from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the data could not be serialized
/// * `PublishError::MessageTooLarge`: if the data is too large
/// * `PublishError::WriteError`: if the data could not be written
pub async fn send_raw_events(
    send: &mut SendStream,
    raw_events: Vec<(i64, String, Vec<u8>)>,
) -> Result<(), PublishError> {
    let mut buf = Vec::new();
    frame::send(send, &mut buf, &raw_events).await?;
    Ok(())
}

/// Receives the stream request sent to giganto's publish module.
///
/// # Errors
///
/// * `PublishError::ReadError`: if the stream-request data could not be read
/// * `PublishError::SerialDeserialFailure`: if the stream-request data could not be deserialized
pub async fn receive_stream_request(
    recv: &mut RecvStream,
) -> Result<StreamRequestPayload, PublishError> {
    let mut buf = Vec::new();
    Ok(frame::recv::<StreamRequestPayload>(recv, &mut buf).await?)
}

/// Receives the semi-supervised stream start message sent from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::ReadError`: if the semi-supervised's stream start data could not be read
/// * `PublishError::InvalidMessageType`: if the semi-supervised's stream start data could not be
///   converted to valid type
pub async fn receive_semi_supervised_stream_start_message(
    recv: &mut RecvStream,
) -> Result<RequestStreamRecord, PublishError> {
    let mut record_buf = [0; mem::size_of::<u32>()];
    recv_bytes(recv, &mut record_buf).await?;
    let start_msg = RequestStreamRecord::try_from(u32::from_le_bytes(record_buf))
        .map_err(|_| PublishError::InvalidMessageType)?;
    Ok(start_msg)
}

/// Receives the time series generator stream start message sent from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::ReadError`: if the time-series-generator's stream start data could not be read
/// * `PublishError::InvalidMessageData`: if the time-series-generator's stream start data could not
///   be converted to valid data
pub async fn receive_time_series_generator_stream_start_message(
    recv: &mut RecvStream,
) -> Result<u32, PublishError> {
    let mut buf = Vec::new();
    recv_raw(recv, &mut buf).await?;
    let start_msg = String::from_utf8(buf)
        .map_err(|_| PublishError::InvalidMessageData)?
        .parse::<u32>()
        .map_err(|_| PublishError::InvalidMessageData)?;
    Ok(start_msg)
}

/// Receives the record data. (timestamp / record structure)
///
/// # Errors
///
/// * `PublishError::ReadError`: if the stream record data could not be read
pub async fn receive_time_series_generator_data(
    recv: &mut RecvStream,
) -> Result<(Vec<u8>, i64), PublishError> {
    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    frame::recv_bytes(recv, &mut ts_buf).await?;
    let timestamp = i64::from_le_bytes(ts_buf);

    let mut record_buf = Vec::new();
    frame::recv_raw(recv, &mut record_buf).await?;
    Ok((record_buf, timestamp))
}

/// Receives the timestamp/sensor/record data from giganto's publish module.
/// If you want to receive record data, sensor and timestamp separately,
/// use `publish::receive_time_series_generator_data`
///
/// # Errors
///
/// * `PublishError::ReadError`: if the stream record data could not be read
pub async fn receive_semi_supervised_data(recv: &mut RecvStream) -> Result<Vec<u8>, PublishError> {
    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    frame::recv_bytes(recv, &mut ts_buf).await?;

    let mut sensor_buf = Vec::new();
    frame::recv_raw(recv, &mut sensor_buf).await?;

    let mut record_buf = Vec::new();
    frame::recv_raw(recv, &mut record_buf).await?;

    let mut result_buf: Vec<u8> = Vec::new();
    result_buf.extend_from_slice(&ts_buf);
    result_buf.extend_from_slice(&sensor_buf);
    result_buf.extend_from_slice(&record_buf);

    Ok(result_buf)
}

/// Receives the range data request sent to giganto's publish module.
///
/// # Errors
///
/// * `PublishError::ReadError`: if the range data could not be read
/// * `PublishError::InvalidMessageType`: if the range data could not be converted to valid type
pub async fn receive_range_data_request(
    recv: &mut RecvStream,
) -> Result<(MessageCode, Vec<u8>), PublishError> {
    // receive message code
    let mut buf = [0; mem::size_of::<u32>()];
    recv_bytes(recv, &mut buf).await?;
    let msg_type = MessageCode::try_from(u32::from_le_bytes(buf))
        .map_err(|_| PublishError::InvalidMessageType)?;

    // receive request info
    let mut buf = Vec::new();
    recv_raw(recv, &mut buf).await?;
    Ok((msg_type, buf))
}

/// Receives the range data sent from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the range data could not be
///   deserialized
/// * `PublishError::ReadError`: if the range data could not be read
pub async fn receive_range_data<T>(recv: &mut RecvStream) -> Result<T, PublishError>
where
    T: DeserializeOwned,
{
    let mut buf = Vec::new();
    Ok(frame::recv::<T>(recv, &mut buf).await?)
}

/// Receives the data `Vec<(timestamp, sensor, raw_events)>` sent from giganto's publish module.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the data could not be
///   deserialized
/// * `PublishError::ReadError`: if the data could not be read
pub async fn receive_raw_events(
    recv: &mut RecvStream,
) -> Result<Vec<(i64, String, Vec<u8>)>, PublishError> {
    let mut buf = Vec::new();
    Ok(frame::recv::<Vec<(i64, String, Vec<u8>)>>(recv, &mut buf).await?)
}

/// Sends pcap extract request to sensor and receives request acknowledge from sensor
///
/// # Errors
///
/// * `PublishError::ConnectionLost`: if quinn connection is lost
/// * `PublishError::MessageTooLarge`: if the extract request data is too large
/// * `PublishError::WriteError`: if the extract request data could not be written
/// * `PublishError::ReadError`: if the extract request ack data could not be read
/// * `PublishError::SerialDeserialFailure`: if the extract request ack data could not be deserialized
/// * `PublishError::RequestFail`: if the extract request ack data is Err
/// * `PublishError::CloseStreamError`: if duplicate stream close calls are requested.
pub async fn pcap_extract_request(
    conn: &Connection,
    pcap_filter: &PcapFilter,
) -> Result<(), PublishError> {
    //open target sensor's channel
    let (mut send, mut recv) = conn.open_bi().await?;

    // serialize pcapfilter data
    let filter =
        bincode_utils::encode_legacy(pcap_filter).map_err(PublishError::SerializationError)?;

    // send pacp extract request to sensor
    send_raw(&mut send, &filter).await?;
    send.finish()?;

    // receive pcap extract acknowledge from sensor
    recv_ack_response(&mut recv).await?;
    Ok(())
}

/// Receives pcap extract request from giganto and sends request acknowledge to giganto
///
/// # Errors
///
/// * `PublishError::ConnectionLost`: if quinn connection is lost
/// * `PublishError::SerialDeserialFailure`: if the extract request data could not be deserialized
/// * `PublishError::MessageTooLarge`: if the extract request data is too large
/// * `PublishError::ReadError`: if the extract request data could not be read
/// * `PublishError::WriteError`: if the extract ack data could not be written
pub async fn pcap_extract_response(
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<PcapFilter, PublishError> {
    // Recieve pcap extract request filter
    let mut buf = Vec::new();
    match frame::recv::<PcapFilter>(&mut recv, &mut buf).await {
        Ok(filter) => {
            // Send ack response (Ok())
            send_ok(&mut send, &mut buf, ()).await?;
            Ok(filter)
        }
        Err(err) => {
            // Send ack response (Err())
            let err_msg = format!("{err:#}");
            send_err(&mut send, &mut buf, err).await?;
            Err(PublishError::PcapRequestFail(err_msg))
        }
    }
}

/// Sends an `Ok` response.
///
/// `buf` will be cleared after the response is sent.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the response data could not be serialized
/// * `PublishError::WriteError`: if the response data could not be written
pub async fn send_ok<T: Serialize>(
    send: &mut SendStream,
    buf: &mut Vec<u8>,
    body: T,
) -> Result<(), PublishError> {
    frame::send(send, buf, Ok(body) as Result<T, String>).await?;
    Ok(())
}

/// Sends an `Err` response.
///
/// `buf` will be cleared after the response is sent.
///
/// # Errors
///
/// * `PublishError::SerialDeserialFailure`: if the response data could not be serialized
/// * `PublishError::WriteError`: if the response data could not be written
pub async fn send_err<E: std::fmt::Display>(
    send: &mut SendStream,
    buf: &mut Vec<u8>,
    e: E,
) -> Result<(), PublishError> {
    frame::send(send, buf, Err(format!("{e:#}")) as Result<(), String>).await?;
    Ok(())
}

/// Receive an `Ok`/`Err` response.
///
/// # Errors
///
/// * `PublishError::ReadError`: if the response data could not be read
/// * `PublishError::MessageTooLarge`: if the response data is too large
/// * `PublishError::SerialDeserialFailure`: if the response data could not be deserialized
/// * `PublishError::PcapRequestFail`: if the response data could not be read
pub async fn recv_ack_response(recv: &mut RecvStream) -> Result<(), PublishError> {
    let mut ack_buf = Vec::new();
    recv_raw(recv, &mut ack_buf).await?;
    bincode_utils::decode_legacy::<Result<(), String>>(&ack_buf)
        .map_err(PublishError::DeserializationError)?
        .map_err(PublishError::PcapRequestFail)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::hash::{DefaultHasher, Hash, Hasher};

    use serde_json::json;

    use super::PcapFilter;
    use crate::bincode_utils::{decode_legacy, encode_legacy};

    /// Ensures the derived `Serialize`/`Deserialize` impl for `PcapFilter` is lossless and stable.
    #[test]
    fn pcap_filter_binary_round_trip() {
        let filter: PcapFilter = serde_json::from_value(json!({
            "start_time": "2024-08-10T12:00:00Z",
            "sensor": "roundtrip-sensor",
            "src_addr": "198.51.100.10",
            "src_port": 5000,
            "dst_addr": "203.0.113.20",
            "dst_port": 6000,
            "proto": 17,
            "end_time": "2024-08-10T12:05:00Z",
        }))
        .expect("valid PcapFilter payload");

        let encoded = encode_legacy(&filter).expect("serializable filter");
        // Ensure decode->encode produces identical bytes so wire format changes are caught immediately.
        let decoded: PcapFilter = decode_legacy(&encoded).expect("deserializable filter");

        assert_eq!(decoded, filter);
        let reencoded = encode_legacy(&decoded).expect("re-serializable filter");
        assert_eq!(reencoded, encoded, "binary round-trip must be stable");
    }

    #[test]
    fn pcap_filter_handles_millisecond_precision_timestamps() {
        let filter_json = json!({
            "start_time": "2015-11-11T14:23:45.123Z",
            "sensor": "sensor-millis",
            "src_addr": "10.0.0.1",
            "src_port": 1000,
            "dst_addr": "10.0.0.2",
            "dst_port": 1001,
            "proto": 6,
            "end_time": "2015-11-11T14:33:45.987Z"
        });

        let filter: PcapFilter =
            serde_json::from_value(filter_json).expect("valid millisecond filter");
        assert!(filter.start_time < filter.end_time);

        let serialized_json =
            serde_json::to_value(&filter).expect("serializable millisecond filter");
        assert_eq!(
            serialized_json.get("start_time").and_then(|v| v.as_str()),
            Some("2015-11-11T14:23:45.123Z")
        );
        assert_eq!(
            serialized_json.get("end_time").and_then(|v| v.as_str()),
            Some("2015-11-11T14:33:45.987Z")
        );
    }

    #[test]
    fn pcap_filter_handles_microsecond_precision_timestamps() {
        let filter_json = json!({
            "start_time": "2015-11-11T14:23:45.123456Z",
            "sensor": "sensor-micros",
            "src_addr": "2001:db8::10",
            "src_port": 2000,
            "dst_addr": "2001:db8::20",
            "dst_port": 2001,
            "proto": 17,
            "end_time": "2015-11-11T14:33:45.654321Z"
        });

        let filter: PcapFilter =
            serde_json::from_value(filter_json).expect("valid microsecond filter");
        assert!(filter.start_time < filter.end_time);

        let serialized_json =
            serde_json::to_value(&filter).expect("serializable microsecond filter");
        assert_eq!(
            serialized_json.get("start_time").and_then(|v| v.as_str()),
            Some("2015-11-11T14:23:45.123456Z")
        );
        assert_eq!(
            serialized_json.get("end_time").and_then(|v| v.as_str()),
            Some("2015-11-11T14:33:45.654321Z")
        );
    }

    #[test]
    fn pcap_filter_handles_nanosecond_precision_timestamps() {
        let filter_json = json!({
            "start_time": "2015-11-11T14:23:45.123456789Z",
            "sensor": "sensor-nanos",
            "src_addr": "192.0.2.50",
            "src_port": 3000,
            "dst_addr": "198.51.100.60",
            "dst_port": 3001,
            "proto": 1,
            "end_time": "2015-11-11T14:33:45.987654321Z"
        });

        let filter: PcapFilter =
            serde_json::from_value(filter_json).expect("valid nanosecond filter");
        assert!(filter.start_time < filter.end_time);

        let serialized_json =
            serde_json::to_value(&filter).expect("serializable nanosecond filter");
        assert_eq!(
            serialized_json.get("start_time").and_then(|v| v.as_str()),
            Some("2015-11-11T14:23:45.123456789Z")
        );
        assert_eq!(
            serialized_json.get("end_time").and_then(|v| v.as_str()),
            Some("2015-11-11T14:33:45.987654321Z")
        );
    }

    /// Tests that `PcapFilter` correctly implements `Eq` trait.
    #[test]
    fn pcap_filter_eq_trait() {
        let a: PcapFilter = serde_json::from_value(json!({
            "start_time": "1970-01-01T00:00:00Z",
            "end_time": "1970-01-01T00:00:00.001Z",
            "sensor": "s",
            "src_addr": "1.1.1.1",
            "src_port": 1111,
            "dst_addr": "2.2.2.2",
            "dst_port": 2222,
            "proto": 17
        }))
        .unwrap();

        let b = a.clone();
        let c = a.clone();

        // reflexivity
        assert_eq!(a, a);
        // symmetry
        assert!(a == b);
        assert!(b == a);
        // transitivity
        assert!(a == b);
        assert!(b == c);
        assert!(a == c);

        // unequal case
        let mut d = a.clone();
        d.dst_port += 1;
        assert_ne!(a, d);
    }

    /// Tests that `PcapFilter` correctly implements `Hash` trait.
    #[test]
    fn pcap_filter_hash_trait() {
        let a: PcapFilter = serde_json::from_value(json!({
            "start_time": "1970-01-01T00:00:00Z",
            "end_time": "1970-01-01T00:00:00.001Z",
            "sensor": "s",
            "src_addr": "1.1.1.1",
            "src_port": 1111,
            "dst_addr": "2.2.2.2",
            "dst_port": 2222,
            "proto": 17
        }))
        .unwrap();
        let b = a.clone();

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let hash_a = ha.finish();

        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        let hash_b = hb.finish();

        assert_eq!(a, b);
        assert_eq!(hash_a, hash_b, "equal values must produce identical hashes");
    }

    /// `HashSet` semantics rely on `Eq` and `Hash` being implemented consistently for `PcapFilter`.
    #[test]
    fn pcap_filter_hashset_behavior() {
        let a: PcapFilter = serde_json::from_value(json!({
            "start_time": "1970-01-01T00:00:00Z",
            "end_time": "1970-01-01T00:00:00.001Z",
            "sensor": "s",
            "src_addr": "1.1.1.1",
            "src_port": 1111,
            "dst_addr": "2.2.2.2",
            "dst_port": 2222,
            "proto": 17
        }))
        .unwrap();
        let mut b = a.clone();

        let mut set = HashSet::new();
        assert!(set.insert(a));
        assert!(!set.insert(b.clone())); // equal -> insertion failed
        assert_eq!(set.len(), 1);

        b.dst_port += 1; // make it unequal
        assert!(set.insert(b));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn pcap_filter_debug_trait_smoke() {
        // We only perform a *weak* assertion on Debug output.
        // Rationale:
        // - `Debug` is intended for human-readable diagnostics, not a stable wire format.
        // - Exact string matching (including field order/spacing) makes tests brittle:
        //   adding a field or changing derive implementation can break tests without
        //   indicating a real behavioral regression.
        // - Therefore we assert the presence of key tokens to ensure the output is useful,
        //   while keeping the test resilient to benign format changes.

        let a: PcapFilter = serde_json::from_value(serde_json::json!({
            "start_time": "1970-01-01T00:00:00Z",
            "end_time":   "1970-01-01T00:00:00.001Z",
            "sensor":     "sensor-alpha",
            "src_addr":   "1.1.1.1",
            "src_port":   1234,
            "dst_addr":   "2.2.2.2",
            "dst_port":   5678,
            "proto":      17
        }))
        .unwrap();

        let compact = format!("{a:?}");
        // Type name appears
        assert!(compact.contains("PcapFilter"));
        // A few representative field names appear
        assert!(compact.contains("start_time"));
        assert!(compact.contains("dst_port"));
        assert!(compact.contains("proto"));
        assert!(compact.contains("sensor"));
        // Representative values show up (string/number)
        assert!(compact.contains("1970-01-01T00:00:00Z"));
        assert!(compact.contains("5678"));
        assert!(compact.contains("17"));
        assert!(compact.contains("sensor-alpha"));

        // Pretty Debug should introduce newlines/indentation, but we do not lock exact layout.
        let pretty = format!("{a:#?}");
        assert!(pretty.contains('\n'));
        assert!(pretty.contains("start_time:"));
    }
}
