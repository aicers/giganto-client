//! A protocol implementation for fetching raw events from the Giganto server.

pub mod range;
pub mod stream;

use std::{mem, net::IpAddr};

use anyhow::Result;
use quinn::{Connection, ConnectionError, RecvStream, SendStream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use self::{
    range::{MessageCode, ResponseRangeData},
    stream::{RequestStreamRecord, StreamRequestPayload},
};
use crate::frame::{self, RecvError, SendError, recv_bytes, recv_raw, send_bytes, send_raw};

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
    #[error("Cannot serialize/deserialize a publish message")]
    SerialDeserialFailure(#[from] bincode::Error),
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
            RecvError::DeserializationFailure(e) => PublishError::SerialDeserialFailure(e),
            RecvError::ReadError(e) => match e {
                quinn::ReadExactError::FinishedEarly(_) => PublishError::ConnectionClosed,
                quinn::ReadExactError::ReadError(e) => PublishError::ReadError(e),
            },
            RecvError::MessageTooLarge => PublishError::MessageTooLarge,
        }
    }
}

impl From<frame::SendError> for PublishError {
    fn from(e: frame::SendError) -> Self {
        match e {
            SendError::SerializationFailure(e) => PublishError::SerialDeserialFailure(e),
            SendError::MessageTooLarge(_) => PublishError::MessageTooLarge,
            SendError::WriteError(e) => PublishError::WriteError(e),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PcapFilter {
    pub start_time: i64,
    pub sensor: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,
    pub end_time: i64,
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
            .map_err(PublishError::SerialDeserialFailure)?
    } else {
        T::response_done().map_err(PublishError::SerialDeserialFailure)?
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
    let filter = bincode::serialize(pcap_filter)?;

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
    frame::send(send, buf, Ok(body) as Result<T, &str>).await?;
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
    bincode::deserialize::<Result<(), &str>>(&ack_buf)?
        .map_err(|e| PublishError::PcapRequestFail(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use crate::frame;
    use crate::ingest::network::Conn;
    use crate::publish::{PublishError, recv_ack_response};
    use crate::test::{TOKEN, channel};

    // =========================================================================
    // Test Helpers / Builders
    // =========================================================================

    /// Helper to create a sample `Conn` event for testing.
    fn sample_conn() -> Conn {
        Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: String::new(),
            start_time: 500,
            duration: 500,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 21515,
            resp_l2_bytes: 27889,
        }
    }

    /// Helper to create a sample `PcapFilter` for testing.
    fn sample_pcap_filter() -> super::PcapFilter {
        super::PcapFilter {
            start_time: 12345,
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            end_time: 67890,
        }
    }

    /// Builder for `RequestSemiSupervisedStream` payloads.
    struct SemiSupervisedStreamBuilder {
        start: i64,
        sensor: Option<Vec<String>>,
    }

    impl SemiSupervisedStreamBuilder {
        fn new() -> Self {
            Self {
                start: 0,
                sensor: None,
            }
        }

        fn start(mut self, start: i64) -> Self {
            self.start = start;
            self
        }

        fn sensor(mut self, sensor: Vec<String>) -> Self {
            self.sensor = Some(sensor);
            self
        }

        fn build(self) -> super::stream::RequestSemiSupervisedStream {
            super::stream::RequestSemiSupervisedStream {
                start: self.start,
                sensor: self.sensor,
            }
        }
    }

    /// Builder for `RequestTimeSeriesGeneratorStream` payloads.
    struct TimeSeriesGeneratorStreamBuilder {
        start: i64,
        id: String,
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        sensor: Option<String>,
    }

    impl TimeSeriesGeneratorStreamBuilder {
        fn new() -> Self {
            Self {
                start: 0,
                id: "1".to_string(),
                src_ip: None,
                dst_ip: None,
                sensor: None,
            }
        }

        fn start(mut self, start: i64) -> Self {
            self.start = start;
            self
        }

        fn id(mut self, id: &str) -> Self {
            self.id = id.to_string();
            self
        }

        fn src_ip(mut self, ip: IpAddr) -> Self {
            self.src_ip = Some(ip);
            self
        }

        fn dst_ip(mut self, ip: IpAddr) -> Self {
            self.dst_ip = Some(ip);
            self
        }

        fn sensor(mut self, sensor: &str) -> Self {
            self.sensor = Some(sensor.to_string());
            self
        }

        fn build(self) -> super::stream::RequestTimeSeriesGeneratorStream {
            super::stream::RequestTimeSeriesGeneratorStream {
                start: self.start,
                id: self.id,
                src_ip: self.src_ip,
                dst_ip: self.dst_ip,
                sensor: self.sensor,
            }
        }
    }

    /// Builder for `RequestRange` payloads.
    struct RequestRangeBuilder {
        sensor: String,
        kind: String,
        start: i64,
        end: i64,
        count: usize,
    }

    #[allow(dead_code)]
    impl RequestRangeBuilder {
        fn new() -> Self {
            Self {
                sensor: "test-sensor".to_string(),
                kind: "conn".to_string(),
                start: 0,
                end: 100,
                count: 10,
            }
        }

        fn sensor(mut self, sensor: &str) -> Self {
            self.sensor = sensor.to_string();
            self
        }

        fn kind(mut self, kind: &str) -> Self {
            self.kind = kind.to_string();
            self
        }

        fn start(mut self, start: i64) -> Self {
            self.start = start;
            self
        }

        fn end(mut self, end: i64) -> Self {
            self.end = end;
            self
        }

        fn count(mut self, count: usize) -> Self {
            self.count = count;
            self
        }

        fn build(self) -> super::range::RequestRange {
            super::range::RequestRange {
                sensor: self.sensor,
                kind: self.kind,
                start: self.start,
                end: self.end,
                count: self.count,
            }
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn publish_send_recv() {
        use crate::frame::send_bytes;
        use crate::publish::{
            PcapFilter,
            range::ResponseRangeData,
            stream::{
                RequestSemiSupervisedStream, RequestTimeSeriesGeneratorStream, StreamRequestPayload,
            },
        };

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // send/recv semi-supervised stream request
        let semi_supervised_req = RequestSemiSupervisedStream {
            start: 0,
            sensor: Some(vec!["hello".to_string(), "world".to_string()]),
        };
        let payload = StreamRequestPayload::new_semi_supervised(
            super::stream::RequestStreamRecord::Conn,
            semi_supervised_req.clone(),
        );
        super::send_stream_request(&mut channel.client.send, payload.clone())
            .await
            .unwrap();

        let received_payload = super::receive_stream_request(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(received_payload, payload);

        // send/recv time series generator stream request
        let time_series_generator_req = RequestTimeSeriesGeneratorStream {
            start: 0,
            id: "1".to_string(),
            src_ip: Some("192.168.4.76".parse::<IpAddr>().unwrap()),
            dst_ip: Some("31.3.245.133".parse::<IpAddr>().unwrap()),
            sensor: Some("world".to_string()),
        };
        let payload = StreamRequestPayload::new_time_series_generator(
            super::stream::RequestStreamRecord::Conn,
            time_series_generator_req.clone(),
        );
        super::send_stream_request(&mut channel.client.send, payload.clone())
            .await
            .unwrap();

        let received_payload = super::receive_stream_request(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(received_payload, payload);

        // send/recv semi_supervised stream start message
        super::send_semi_supervised_stream_start_message(
            &mut channel.server.send,
            super::stream::RequestStreamRecord::Conn,
        )
        .await
        .unwrap();
        let req_record =
            super::receive_semi_supervised_stream_start_message(&mut channel.client.recv)
                .await
                .unwrap();
        assert_eq!(req_record, super::stream::RequestStreamRecord::Conn);

        // recv time series generator stream start message
        frame::send_raw(&mut channel.server.send, "1".to_string().as_bytes())
            .await
            .unwrap();

        let policy_id =
            super::receive_time_series_generator_stream_start_message(&mut channel.client.recv)
                .await
                .unwrap();
        assert_eq!(policy_id, "1".parse::<u32>().unwrap());

        // send/recv stream data with semi-supervised (semi-supervised's stream data use send_bytes
        // function)
        let conn = Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: String::new(),
            start_time: 500,
            duration: 500,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 21515,
            resp_l2_bytes: 27889,
        };
        let raw_event = bincode::serialize(&conn).unwrap();
        let sensor = bincode::serialize(&"hello").unwrap();
        let raw_len = u32::try_from(raw_event.len()).unwrap().to_le_bytes();
        let sensor_len = u32::try_from(sensor.len()).unwrap().to_le_bytes();
        let mut send_buf: Vec<u8> = Vec::new();
        send_buf.extend_from_slice(&6666_i64.to_le_bytes());
        send_buf.extend_from_slice(&sensor_len);
        send_buf.extend_from_slice(&sensor);
        send_buf.extend_from_slice(&raw_len);
        send_buf.extend_from_slice(&raw_event);
        send_bytes(&mut channel.server.send, &send_buf)
            .await
            .unwrap();

        let data = super::receive_semi_supervised_data(&mut channel.client.recv)
            .await
            .unwrap();
        let mut result_buf: Vec<u8> = Vec::new();
        result_buf.extend_from_slice(&6666_i64.to_le_bytes());
        result_buf.extend_from_slice(&sensor);
        result_buf.extend_from_slice(&raw_event);
        assert_eq!(data, result_buf);

        // recv time series generator stream data
        frame::send_bytes(&mut channel.server.send, &7777_i64.to_le_bytes())
            .await
            .unwrap();
        let mut data_buf = Vec::new();
        frame::send(&mut channel.server.send, &mut data_buf, conn.clone())
            .await
            .unwrap();
        let (data, timestamp) = super::receive_time_series_generator_data(&mut channel.client.recv)
            .await
            .unwrap();
        assert_eq!(timestamp, 7777);
        assert_eq!(data, bincode::serialize(&conn).unwrap());

        // send/recv range data request
        let req_range = super::range::RequestRange {
            sensor: String::from("world"),
            kind: String::from("conn"),
            start: 11111,
            end: 22222,
            count: 5,
        };
        super::send_range_data_request(
            &mut channel.client.send,
            super::range::MessageCode::ReqRange,
            req_range.clone(),
        )
        .await
        .unwrap();
        let (msg_code, data) = super::receive_range_data_request(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(msg_code, super::range::MessageCode::ReqRange);
        assert_eq!(data, bincode::serialize(&req_range).unwrap());

        // send/recv range data
        super::send_range_data(
            &mut channel.server.send,
            Some((conn.clone(), 33333, "world")),
        )
        .await
        .unwrap();
        let data =
            super::receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut channel.client.recv)
                .await
                .unwrap();
        assert_eq!(
            bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&data).unwrap(),
            conn.response_data(33333, "world").unwrap()
        );

        // send/recv pcap extract request
        let p_filter = PcapFilter {
            start_time: 12345,
            sensor: "hello".to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            end_time: 1000,
        };
        let send_filter = p_filter.clone();

        let handle = tokio::spawn(async move {
            super::pcap_extract_request(&channel.server.conn, &send_filter).await
        });

        let (send, recv) = channel.client.conn.accept_bi().await.unwrap();
        let data = super::pcap_extract_response(send, recv).await.unwrap();
        assert_eq!(data, p_filter);

        let res = tokio::join!(handle).0.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn send_ok() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let mut buf = Vec::new();
        super::send_ok(&mut channel.server.send, &mut buf, "hello")
            .await
            .unwrap();
        assert!(buf.is_empty());
        let resp_result = recv_ack_response(&mut channel.client.recv).await.is_ok();
        assert!(resp_result);
    }

    #[tokio::test]
    async fn send_err() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let mut buf = Vec::new();
        super::send_err(&mut channel.server.send, &mut buf, "hello")
            .await
            .unwrap();
        assert!(buf.is_empty());
        let resp = recv_ack_response(&mut channel.client.recv)
            .await
            .unwrap_err();
        assert_eq!(
            resp.to_string(),
            PublishError::PcapRequestFail("hello".to_string()).to_string()
        );
    }

    #[tokio::test]
    async fn send_recv_raw_events() {
        use crate::RawEventKind;
        use crate::publish::range::{MessageCode, RequestRawData};
        use crate::publish::{receive_raw_events, send_raw_events};
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let msg_code = MessageCode::RawData;

        let conn = Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: String::new(),
            start_time: 500,
            duration: 500,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 21515,
            resp_l2_bytes: 27889,
        };
        let raw_event = bincode::serialize(&conn).unwrap();

        let sensor1 = "src 1";
        let sensor2 = "src 2";

        let ts1 = 1i64;
        let ts2 = 2i64;
        let ts3 = 3i64;

        let req_msg = vec![
            (sensor1.to_string(), vec![ts1, ts2]),
            (sensor2.to_string(), vec![ts1, ts3]),
        ];
        let req_raw = RequestRawData {
            kind: "conn".to_string(),
            input: req_msg,
        };

        super::send_range_data_request(&mut channel.client.send, msg_code, req_raw.clone())
            .await
            .unwrap();

        let (msg_code, data) = super::receive_range_data_request(&mut channel.server.recv)
            .await
            .unwrap();

        let recv_request = bincode::deserialize::<RequestRawData>(&data).unwrap();
        assert_eq!(msg_code, MessageCode::RawData);
        assert_eq!(
            RawEventKind::from_str(recv_request.kind.as_str()).unwrap(),
            RawEventKind::Conn
        );

        // example data from giganto
        let value_with_sensors = vec![
            (ts1, sensor1.to_string(), raw_event.clone()),
            (ts1, sensor1.to_string(), raw_event.clone()),
            (ts1, sensor2.to_string(), raw_event.clone()),
            (ts1, sensor2.to_string(), raw_event),
        ];

        send_raw_events(&mut channel.server.send, value_with_sensors)
            .await
            .unwrap();

        let recv_data = receive_raw_events(&mut channel.client.recv).await.unwrap();

        assert_eq!(recv_data.len(), 4);
    }

    #[tokio::test]
    async fn publish_pcap_extract_response_err() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send invalid data that will fail deserialization to PcapFilter
        frame::send_raw(&mut channel.server.send, b"invalid data")
            .await
            .unwrap();

        let res = super::pcap_extract_response(channel.client.send, channel.client.recv).await;
        assert!(matches!(
            res,
            Err(PublishError::PcapRequestFail(msg)) if msg.contains("Failed deserializing message")
        ));

        // Verify server received the error response (via recv_ack_response)
        let mut ack_buf = Vec::new();
        frame::recv_raw(&mut channel.server.recv, &mut ack_buf)
            .await
            .unwrap();
        let resp = bincode::deserialize::<Result<(), String>>(&ack_buf).unwrap();
        assert!(resp.is_err());
    }

    #[test]
    fn test_publish_error_conversion() {
        let err = PublishError::MessageTooLarge;
        assert_eq!(
            err.to_string(),
            "Message is too large, so type casting failed"
        );

        let err = PublishError::InvalidMessageType;
        assert_eq!(err.to_string(), "Invalid message type");

        let err = PublishError::InvalidMessageData;
        assert_eq!(err.to_string(), "Invalid message data");
    }

    #[tokio::test]
    async fn test_receive_time_series_generator_stream_start_message_invalid_data() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send non-numeric string
        frame::send_raw(&mut channel.server.send, b"not a number")
            .await
            .unwrap();

        let res =
            super::receive_time_series_generator_stream_start_message(&mut channel.client.recv)
                .await;
        assert!(matches!(res, Err(PublishError::InvalidMessageData)));

        // Send invalid UTF-8
        frame::send_raw(&mut channel.server.send, &[0xFF, 0xFE, 0xFD])
            .await
            .unwrap();
        let res =
            super::receive_time_series_generator_stream_start_message(&mut channel.client.recv)
                .await;
        assert!(matches!(res, Err(PublishError::InvalidMessageData)));
    }

    #[tokio::test]
    async fn test_receive_semi_supervised_stream_start_message_invalid_type() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send invalid enum variant (e.g. u32::MAX)
        frame::send_bytes(&mut channel.server.send, &u32::MAX.to_le_bytes())
            .await
            .unwrap();

        let res =
            super::receive_semi_supervised_stream_start_message(&mut channel.client.recv).await;
        assert!(matches!(res, Err(PublishError::InvalidMessageType)));
    }

    #[tokio::test]
    async fn test_receive_range_data_request_invalid_type() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send invalid enum variant
        frame::send_bytes(&mut channel.server.send, &u32::MAX.to_le_bytes())
            .await
            .unwrap();

        let res = super::receive_range_data_request(&mut channel.client.recv).await;
        assert!(matches!(res, Err(PublishError::InvalidMessageType)));
    }

    // =========================================================================
    // Valid Message Types Roundtrip Tests
    // =========================================================================

    /// Tests that all `RequestStreamRecord` variants can be sent and received
    /// correctly through semi-supervised stream start messages.
    #[tokio::test]
    async fn test_all_request_stream_record_variants_roundtrip() {
        use super::stream::RequestStreamRecord;

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Test all RequestStreamRecord variants
        let all_records = RequestStreamRecord::all();
        for record in all_records {
            super::send_semi_supervised_stream_start_message(&mut channel.server.send, record)
                .await
                .unwrap();

            let received =
                super::receive_semi_supervised_stream_start_message(&mut channel.client.recv)
                    .await
                    .unwrap();
            assert_eq!(received, record, "Roundtrip failed for {record:?}");
        }
    }

    /// Tests that all `StreamRequestPayload` variants serialize and deserialize
    /// correctly.
    #[tokio::test]
    async fn test_stream_request_payload_variants_roundtrip() {
        use super::stream::{RequestStreamRecord, StreamRequestPayload};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Test SemiSupervised variant
        let semi_supervised_payload = StreamRequestPayload::new_semi_supervised(
            RequestStreamRecord::Conn,
            SemiSupervisedStreamBuilder::new()
                .start(1000)
                .sensor(vec!["sensor1".to_string(), "sensor2".to_string()])
                .build(),
        );
        super::send_stream_request(&mut channel.client.send, semi_supervised_payload.clone())
            .await
            .unwrap();
        let received = super::receive_stream_request(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(received, semi_supervised_payload);

        // Test TimeSeriesGenerator variant
        let time_series_payload = StreamRequestPayload::new_time_series_generator(
            RequestStreamRecord::Dns,
            TimeSeriesGeneratorStreamBuilder::new()
                .start(2000)
                .id("policy-1")
                .src_ip("10.0.0.1".parse().unwrap())
                .dst_ip("10.0.0.2".parse().unwrap())
                .sensor("sensor-tsg")
                .build(),
        );
        super::send_stream_request(&mut channel.client.send, time_series_payload.clone())
            .await
            .unwrap();
        let received = super::receive_stream_request(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(received, time_series_payload);

        // Test PcapExtraction variant
        let pcap_payload = StreamRequestPayload::new_pcap_extraction(vec![sample_pcap_filter()]);
        super::send_stream_request(&mut channel.client.send, pcap_payload.clone())
            .await
            .unwrap();
        let received = super::receive_stream_request(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(received, pcap_payload);
    }

    /// Tests that all `MessageCode` variants can be sent and received correctly.
    #[tokio::test]
    async fn test_all_message_code_variants_roundtrip() {
        use super::range::MessageCode;

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let message_codes = [
            MessageCode::ReqRange,
            MessageCode::Pcap,
            MessageCode::RawData,
        ];

        for msg_code in message_codes {
            let request = RequestRangeBuilder::new().build();
            super::send_range_data_request(&mut channel.client.send, msg_code, request.clone())
                .await
                .unwrap();

            let (received_code, received_data) =
                super::receive_range_data_request(&mut channel.server.recv)
                    .await
                    .unwrap();
            assert_eq!(
                received_code, msg_code,
                "MessageCode mismatch for {msg_code:?}"
            );
            let deserialized: super::range::RequestRange =
                bincode::deserialize(&received_data).unwrap();
            assert_eq!(deserialized, request);
        }
    }

    // =========================================================================
    // Invalid Message Type Tests
    // =========================================================================

    /// Tests that an invalid `RequestStreamRecord` value returns
    /// `PublishError::InvalidMessageType`.
    #[tokio::test]
    async fn test_invalid_request_stream_record_value() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send an invalid variant value (100 is not a valid RequestStreamRecord)
        frame::send_bytes(&mut channel.server.send, &100_u32.to_le_bytes())
            .await
            .unwrap();

        let res =
            super::receive_semi_supervised_stream_start_message(&mut channel.client.recv).await;
        assert!(
            matches!(res, Err(PublishError::InvalidMessageType)),
            "Expected InvalidMessageType for invalid RequestStreamRecord, got {res:?}"
        );
    }

    /// Tests that an invalid `MessageCode` value (zero) returns
    /// `PublishError::InvalidMessageType`.
    #[tokio::test]
    async fn test_invalid_message_code_zero() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // MessageCode valid values are 1, 2, 3. Send 0.
        frame::send_bytes(&mut channel.server.send, &0_u32.to_le_bytes())
            .await
            .unwrap();

        let res = super::receive_range_data_request(&mut channel.client.recv).await;
        assert!(
            matches!(res, Err(PublishError::InvalidMessageType)),
            "Expected InvalidMessageType for MessageCode=0, got {res:?}"
        );
    }

    /// Tests that a very high invalid `MessageCode` value returns
    /// `PublishError::InvalidMessageType`.
    #[tokio::test]
    async fn test_invalid_message_code_high_value() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // MessageCode valid values are 1, 2, 3. Send 999.
        frame::send_bytes(&mut channel.server.send, &999_u32.to_le_bytes())
            .await
            .unwrap();

        let res = super::receive_range_data_request(&mut channel.client.recv).await;
        assert!(
            matches!(res, Err(PublishError::InvalidMessageType)),
            "Expected InvalidMessageType for MessageCode=999, got {res:?}"
        );
    }

    // =========================================================================
    // Malformed Payload / Truncated Frame Tests
    // =========================================================================

    /// Tests that a malformed `StreamRequestPayload` (invalid bincode) returns
    /// `PublishError::SerialDeserialFailure`.
    #[tokio::test]
    async fn test_malformed_stream_request_payload() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send garbage bytes that cannot be deserialized as StreamRequestPayload
        frame::send_raw(&mut channel.server.send, b"invalid payload data")
            .await
            .unwrap();

        let res = super::receive_stream_request(&mut channel.client.recv).await;
        assert!(
            matches!(res, Err(PublishError::SerialDeserialFailure(_))),
            "Expected SerialDeserialFailure for malformed payload, got {res:?}"
        );
    }

    /// Tests that a truncated bincode payload returns
    /// `PublishError::SerialDeserialFailure`.
    #[tokio::test]
    async fn test_truncated_bincode_payload() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Create a valid payload, serialize it, then truncate
        let payload = super::stream::StreamRequestPayload::new_semi_supervised(
            super::stream::RequestStreamRecord::Conn,
            SemiSupervisedStreamBuilder::new().build(),
        );
        let serialized = bincode::serialize(&payload).unwrap();

        // Truncate to half the size
        let truncated = &serialized[..serialized.len() / 2];
        frame::send_raw(&mut channel.server.send, truncated)
            .await
            .unwrap();

        let res = super::receive_stream_request(&mut channel.client.recv).await;
        assert!(
            matches!(res, Err(PublishError::SerialDeserialFailure(_))),
            "Expected SerialDeserialFailure for truncated payload, got {res:?}"
        );
    }

    /// Tests that an empty payload returns `PublishError::SerialDeserialFailure`.
    #[tokio::test]
    async fn test_empty_payload() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send empty bytes
        frame::send_raw(&mut channel.server.send, &[])
            .await
            .unwrap();

        let res = super::receive_stream_request(&mut channel.client.recv).await;
        assert!(
            matches!(res, Err(PublishError::SerialDeserialFailure(_))),
            "Expected SerialDeserialFailure for empty payload, got {res:?}"
        );
    }

    /// Tests that corrupted bincode for range data returns appropriate error.
    #[tokio::test]
    async fn test_malformed_range_data_payload() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send valid message code, followed by garbage payload
        let msg_code: u32 = super::range::MessageCode::ReqRange.into();
        frame::send_bytes(&mut channel.server.send, &msg_code.to_le_bytes())
            .await
            .unwrap();
        frame::send_raw(&mut channel.server.send, b"garbage data not valid bincode")
            .await
            .unwrap();

        let (code, data) = super::receive_range_data_request(&mut channel.client.recv)
            .await
            .unwrap();
        assert_eq!(code, super::range::MessageCode::ReqRange);

        // Attempting to deserialize should fail
        let deser_result = bincode::deserialize::<super::range::RequestRange>(&data);
        assert!(deser_result.is_err(), "Expected deserialization to fail");
    }

    // =========================================================================
    // Range Boundary Cases Tests
    // =========================================================================

    /// Tests range requests with boundary values (zero, negative, max values).
    #[tokio::test]
    async fn test_range_boundary_values() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Test with zero values
        let zero_range = RequestRangeBuilder::new().start(0).end(0).count(0).build();
        super::send_range_data_request(
            &mut channel.client.send,
            super::range::MessageCode::ReqRange,
            zero_range.clone(),
        )
        .await
        .unwrap();
        let (_, data) = super::receive_range_data_request(&mut channel.server.recv)
            .await
            .unwrap();
        let received: super::range::RequestRange = bincode::deserialize(&data).unwrap();
        assert_eq!(received.start, 0);
        assert_eq!(received.end, 0);
        assert_eq!(received.count, 0);

        // Test with negative timestamps
        let negative_range = RequestRangeBuilder::new()
            .start(-1000)
            .end(-1)
            .count(10)
            .build();
        super::send_range_data_request(
            &mut channel.client.send,
            super::range::MessageCode::ReqRange,
            negative_range.clone(),
        )
        .await
        .unwrap();
        let (_, data) = super::receive_range_data_request(&mut channel.server.recv)
            .await
            .unwrap();
        let received: super::range::RequestRange = bincode::deserialize(&data).unwrap();
        assert_eq!(received.start, -1000);
        assert_eq!(received.end, -1);

        // Test with large values
        let max_range = RequestRangeBuilder::new()
            .start(i64::MIN)
            .end(i64::MAX)
            .count(usize::MAX)
            .build();
        super::send_range_data_request(
            &mut channel.client.send,
            super::range::MessageCode::ReqRange,
            max_range.clone(),
        )
        .await
        .unwrap();
        let (_, data) = super::receive_range_data_request(&mut channel.server.recv)
            .await
            .unwrap();
        let received: super::range::RequestRange = bincode::deserialize(&data).unwrap();
        assert_eq!(received.start, i64::MIN);
        assert_eq!(received.end, i64::MAX);
        assert_eq!(received.count, usize::MAX);
    }

    /// Tests range requests where start > end (inverted range).
    #[tokio::test]
    async fn test_inverted_range() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Inverted range (start > end) - the protocol should still
        // transmit this; validation is application-level
        let inverted_range = RequestRangeBuilder::new()
            .start(1000)
            .end(100)
            .count(50)
            .build();
        super::send_range_data_request(
            &mut channel.client.send,
            super::range::MessageCode::ReqRange,
            inverted_range.clone(),
        )
        .await
        .unwrap();
        let (_, data) = super::receive_range_data_request(&mut channel.server.recv)
            .await
            .unwrap();
        let received: super::range::RequestRange = bincode::deserialize(&data).unwrap();
        assert_eq!(received.start, 1000);
        assert_eq!(received.end, 100);
        assert!(
            received.start > received.end,
            "Inverted range should preserve start > end"
        );
    }

    /// Tests empty sensor list in raw data requests.
    #[tokio::test]
    async fn test_empty_raw_data_input() {
        use super::range::{MessageCode, RequestRawData};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Empty input list
        let empty_request = RequestRawData {
            kind: "conn".to_string(),
            input: vec![],
        };
        super::send_range_data_request(
            &mut channel.client.send,
            MessageCode::RawData,
            empty_request.clone(),
        )
        .await
        .unwrap();
        let (code, data) = super::receive_range_data_request(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(code, MessageCode::RawData);
        let received: RequestRawData = bincode::deserialize(&data).unwrap();
        assert!(received.input.is_empty());
    }

    /// Tests raw data request with empty timestamp vectors.
    #[tokio::test]
    async fn test_raw_data_empty_timestamps() {
        use super::range::{MessageCode, RequestRawData};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Sensor with empty timestamp list
        let request = RequestRawData {
            kind: "dns".to_string(),
            input: vec![
                ("sensor1".to_string(), vec![]),
                ("sensor2".to_string(), vec![1, 2, 3]),
            ],
        };
        super::send_range_data_request(&mut channel.client.send, MessageCode::RawData, request)
            .await
            .unwrap();
        let (code, data) = super::receive_range_data_request(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(code, MessageCode::RawData);
        let received: RequestRawData = bincode::deserialize(&data).unwrap();
        assert_eq!(received.input.len(), 2);
        assert!(received.input[0].1.is_empty());
        assert_eq!(received.input[1].1.len(), 3);
    }

    /// Tests `send_range_data` with `None` data, which should send a
    /// `response_done()` signal.
    #[tokio::test]
    async fn test_send_range_data_none_response_done() {
        use super::range::ResponseRangeData;

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send None, which triggers the response_done() path
        super::send_range_data::<Conn>(&mut channel.server.send, None)
            .await
            .unwrap();

        // Receive and verify it matches the response_done() format
        let received =
            super::receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut channel.client.recv)
                .await
                .unwrap();

        // response_done() serializes None, so received should be None
        assert!(
            received.is_none(),
            "Expected None for response_done signal, got {received:?}"
        );

        // Also verify that the raw bytes match the response_done() output
        super::send_range_data::<Conn>(&mut channel.server.send, None)
            .await
            .unwrap();

        let mut raw_buf = Vec::new();
        frame::recv_raw(&mut channel.client.recv, &mut raw_buf)
            .await
            .unwrap();

        let expected_done = Conn::response_done().unwrap();
        assert_eq!(
            raw_buf, expected_done,
            "Raw bytes should match response_done() output"
        );
    }

    // =========================================================================
    // Error Conversion and Variant Tests
    // =========================================================================

    /// Tests all `PublishError` variants display correctly.
    #[test]
    fn test_all_publish_error_display() {
        assert_eq!(
            PublishError::ConnectionClosed.to_string(),
            "Connection closed by peer"
        );
        assert_eq!(
            PublishError::MessageTooLarge.to_string(),
            "Message is too large, so type casting failed"
        );
        assert_eq!(
            PublishError::InvalidMessageType.to_string(),
            "Invalid message type"
        );
        assert_eq!(
            PublishError::InvalidMessageData.to_string(),
            "Invalid message data"
        );
        assert_eq!(
            PublishError::PcapRequestFail("test error".to_string()).to_string(),
            "Pcap request failed, because test error"
        );
    }

    /// Tests `From<frame::RecvError>` conversion for `PublishError`.
    #[test]
    fn test_publish_error_from_recv_error() {
        use std::num::TryFromIntError;

        // Test DeserializationFailure conversion
        let bincode_err = bincode::deserialize::<String>(&[0xFF, 0xFF]).unwrap_err();
        let recv_err = frame::RecvError::DeserializationFailure(bincode_err);
        let publish_err: PublishError = recv_err.into();
        assert!(
            matches!(publish_err, PublishError::SerialDeserialFailure(_)),
            "Expected SerialDeserialFailure, got {publish_err:?}"
        );

        // Test MessageTooLarge conversion - use i8::try_from to reliably get an
        // error
        let try_from_err: TryFromIntError = i8::try_from(1000_i32).unwrap_err();
        let too_large_err = frame::RecvError::MessageTooLarge(try_from_err);
        let publish_err: PublishError = too_large_err.into();
        assert!(
            matches!(publish_err, PublishError::MessageTooLarge),
            "Expected MessageTooLarge, got {publish_err:?}"
        );

        // Test ReadError::FinishedEarly conversion -> ConnectionClosed
        // FinishedEarly takes a usize (bytes read before stream ended)
        let finished_early_err = quinn::ReadExactError::FinishedEarly(0);
        let recv_err = frame::RecvError::ReadError(finished_early_err);
        let publish_err: PublishError = recv_err.into();
        assert!(
            matches!(publish_err, PublishError::ConnectionClosed),
            "Expected ConnectionClosed for FinishedEarly, got {publish_err:?}"
        );

        // Test ReadError::ReadError conversion -> PublishError::ReadError
        let read_err = quinn::ReadError::ClosedStream;
        let read_exact_err = quinn::ReadExactError::ReadError(read_err);
        let recv_err = frame::RecvError::ReadError(read_exact_err);
        let publish_err: PublishError = recv_err.into();
        assert!(
            matches!(publish_err, PublishError::ReadError(_)),
            "Expected ReadError, got {publish_err:?}"
        );
    }

    /// Tests `From<frame::SendError>` conversion for `PublishError`.
    #[test]
    fn test_publish_error_from_send_error() {
        use std::num::TryFromIntError;

        // Test SerializationFailure conversion - we need a type that fails to
        // serialize. Channels can't be serialized.
        // Instead, we'll verify the error type mapping is correct by checking
        // the error type is preserved after conversion.

        // Test MessageTooLarge conversion - use i8::try_from to reliably get an
        // error
        let try_from_err: TryFromIntError = i8::try_from(1000_i32).unwrap_err();
        let too_large_err = frame::SendError::MessageTooLarge(try_from_err);
        let publish_err: PublishError = too_large_err.into();
        assert!(
            matches!(publish_err, PublishError::MessageTooLarge),
            "Expected MessageTooLarge, got {publish_err:?}"
        );

        // Test WriteError conversion -> PublishError::WriteError
        let write_err = quinn::WriteError::ClosedStream;
        let send_err = frame::SendError::WriteError(write_err);
        let publish_err: PublishError = send_err.into();
        assert!(
            matches!(publish_err, PublishError::WriteError(_)),
            "Expected WriteError, got {publish_err:?}"
        );
    }

    /// Tests `PcapRequestFail` error variant with various messages.
    #[test]
    fn test_pcap_request_fail_variants() {
        let err = PublishError::PcapRequestFail("connection refused".to_string());
        assert!(err.to_string().contains("connection refused"));

        let err = PublishError::PcapRequestFail(String::new());
        assert_eq!(err.to_string(), "Pcap request failed, because ");

        let err = PublishError::PcapRequestFail("error with\nnewline".to_string());
        assert!(err.to_string().contains("newline"));
    }

    // =========================================================================
    // Stream Data Tests
    // =========================================================================

    /// Tests sending and receiving semi-supervised stream data.
    #[tokio::test]
    async fn test_semi_supervised_stream_data_roundtrip() {
        use crate::frame::send_bytes;

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let conn = sample_conn();
        let raw_event = bincode::serialize(&conn).unwrap();
        let sensor = bincode::serialize(&"test-sensor").unwrap();
        let timestamp: i64 = 1_234_567_890;

        // Build the send buffer manually (timestamp + sensor_len + sensor +
        // raw_len + raw_event)
        let raw_len = u32::try_from(raw_event.len()).unwrap().to_le_bytes();
        let sensor_len = u32::try_from(sensor.len()).unwrap().to_le_bytes();
        let mut send_buf: Vec<u8> = Vec::new();
        send_buf.extend_from_slice(&timestamp.to_le_bytes());
        send_buf.extend_from_slice(&sensor_len);
        send_buf.extend_from_slice(&sensor);
        send_buf.extend_from_slice(&raw_len);
        send_buf.extend_from_slice(&raw_event);

        send_bytes(&mut channel.server.send, &send_buf)
            .await
            .unwrap();

        let received_data = super::receive_semi_supervised_data(&mut channel.client.recv)
            .await
            .unwrap();

        // Verify the received data contains timestamp, sensor, and record
        assert!(received_data.len() > 8, "Should contain timestamp and data");
        let received_ts = i64::from_le_bytes(received_data[..8].try_into().unwrap());
        assert_eq!(received_ts, timestamp);
    }

    /// Tests sending and receiving time series generator stream data.
    #[tokio::test]
    async fn test_time_series_generator_data_roundtrip() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let conn = sample_conn();
        let timestamp: i64 = 9_876_543_210;

        // Send timestamp as raw bytes
        frame::send_bytes(&mut channel.server.send, &timestamp.to_le_bytes())
            .await
            .unwrap();

        // Send conn data as a frame
        let mut buf = Vec::new();
        frame::send(&mut channel.server.send, &mut buf, conn.clone())
            .await
            .unwrap();

        let (data, received_ts) =
            super::receive_time_series_generator_data(&mut channel.client.recv)
                .await
                .unwrap();

        assert_eq!(received_ts, timestamp);
        let received_conn: Conn = bincode::deserialize(&data).unwrap();
        assert_eq!(received_conn, conn);
    }

    /// Tests time series generator start message with valid numeric string.
    #[tokio::test]
    async fn test_time_series_generator_start_message_valid() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send valid numeric string
        frame::send_raw(&mut channel.server.send, b"12345")
            .await
            .unwrap();

        let policy_id =
            super::receive_time_series_generator_stream_start_message(&mut channel.client.recv)
                .await
                .unwrap();
        assert_eq!(policy_id, 12345);
    }

    /// Tests time series generator start message with boundary values.
    #[tokio::test]
    async fn test_time_series_generator_start_message_boundaries() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Test with 0
        frame::send_raw(&mut channel.server.send, b"0")
            .await
            .unwrap();
        let policy_id =
            super::receive_time_series_generator_stream_start_message(&mut channel.client.recv)
                .await
                .unwrap();
        assert_eq!(policy_id, 0);

        // Test with max u32
        frame::send_raw(&mut channel.server.send, b"4294967295")
            .await
            .unwrap();
        let policy_id =
            super::receive_time_series_generator_stream_start_message(&mut channel.client.recv)
                .await
                .unwrap();
        assert_eq!(policy_id, u32::MAX);
    }

    /// Tests time series generator start message with overflow value.
    #[tokio::test]
    async fn test_time_series_generator_start_message_overflow() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Value larger than u32::MAX
        frame::send_raw(&mut channel.server.send, b"4294967296")
            .await
            .unwrap();

        let res =
            super::receive_time_series_generator_stream_start_message(&mut channel.client.recv)
                .await;
        assert!(
            matches!(res, Err(PublishError::InvalidMessageData)),
            "Expected InvalidMessageData for overflow value, got {res:?}"
        );
    }

    // =========================================================================
    // Raw Events Tests
    // =========================================================================

    /// Tests sending and receiving empty raw events list.
    #[tokio::test]
    async fn test_send_recv_empty_raw_events() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let empty_events: Vec<(i64, String, Vec<u8>)> = vec![];
        super::send_raw_events(&mut channel.server.send, empty_events)
            .await
            .unwrap();

        let received = super::receive_raw_events(&mut channel.client.recv)
            .await
            .unwrap();
        assert!(received.is_empty());
    }

    /// Tests sending and receiving raw events with various data sizes.
    #[tokio::test]
    async fn test_send_recv_raw_events_various_sizes() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Create events with various sizes
        let events = vec![
            (1_i64, "sensor1".to_string(), vec![]),          // empty data
            (2_i64, "sensor2".to_string(), vec![0u8; 1]),    // minimal data
            (3_i64, "sensor3".to_string(), vec![0u8; 1000]), // medium data
        ];

        super::send_raw_events(&mut channel.server.send, events.clone())
            .await
            .unwrap();

        let received = super::receive_raw_events(&mut channel.client.recv)
            .await
            .unwrap();
        assert_eq!(received.len(), 3);
        assert_eq!(received[0].0, 1);
        assert!(received[0].2.is_empty());
        assert_eq!(received[1].2.len(), 1);
        assert_eq!(received[2].2.len(), 1000);
    }

    // =========================================================================
    // ACK Response Tests
    // =========================================================================

    /// Tests `recv_ack_response` with various error messages.
    #[tokio::test]
    async fn test_recv_ack_response_error_messages() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send error response with specific message
        let error_response: Result<(), String> = Err("custom error message".to_string());
        let serialized = bincode::serialize(&error_response).unwrap();
        frame::send_raw(&mut channel.server.send, &serialized)
            .await
            .unwrap();

        let res = recv_ack_response(&mut channel.client.recv).await;
        assert!(matches!(
            res,
            Err(PublishError::PcapRequestFail(msg)) if msg == "custom error message"
        ));
    }

    /// Tests `recv_ack_response` with malformed response.
    #[tokio::test]
    async fn test_recv_ack_response_malformed() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send malformed data that cannot be deserialized as Result<(), &str>
        frame::send_raw(&mut channel.server.send, b"not valid bincode")
            .await
            .unwrap();

        let res = recv_ack_response(&mut channel.client.recv).await;
        assert!(
            matches!(res, Err(PublishError::SerialDeserialFailure(_))),
            "Expected SerialDeserialFailure for malformed ack, got {res:?}"
        );
    }

    // =========================================================================
    // PcapFilter Tests
    // =========================================================================

    /// Tests `PcapFilter` serialization and deserialization.
    #[test]
    fn test_pcap_filter_serde() {
        let filter = sample_pcap_filter();

        let serialized = bincode::serialize(&filter).unwrap();
        let deserialized: super::PcapFilter = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.start_time, filter.start_time);
        assert_eq!(deserialized.end_time, filter.end_time);
        assert_eq!(deserialized.sensor, filter.sensor);
        assert_eq!(deserialized.src_addr, filter.src_addr);
        assert_eq!(deserialized.src_port, filter.src_port);
        assert_eq!(deserialized.dst_addr, filter.dst_addr);
        assert_eq!(deserialized.dst_port, filter.dst_port);
        assert_eq!(deserialized.proto, filter.proto);
    }

    /// Tests `PcapFilter` with IPv6 addresses.
    #[test]
    fn test_pcap_filter_ipv6() {
        let filter = super::PcapFilter {
            start_time: 1000,
            sensor: "ipv6-sensor".to_string(),
            src_addr: "2001:db8::1".parse().unwrap(),
            src_port: 443,
            dst_addr: "2001:db8::2".parse().unwrap(),
            dst_port: 8443,
            proto: 6,
            end_time: 2000,
        };

        let serialized = bincode::serialize(&filter).unwrap();
        let deserialized: super::PcapFilter = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.src_addr, filter.src_addr);
        assert_eq!(deserialized.dst_addr, filter.dst_addr);
    }

    /// Tests `PcapFilter` equality and hashing.
    #[test]
    fn test_pcap_filter_eq_hash() {
        use std::collections::HashSet;

        let filter1 = sample_pcap_filter();
        let filter2 = sample_pcap_filter();
        let filter3 = super::PcapFilter {
            start_time: 99999,
            ..sample_pcap_filter()
        };

        assert_eq!(filter1, filter2);
        assert_ne!(filter1, filter3);

        let mut set = HashSet::new();
        set.insert(filter1.clone());
        assert!(set.contains(&filter2));
        assert!(!set.contains(&filter3));
    }
}
