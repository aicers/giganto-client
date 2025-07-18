//! A protocol implementation for fetching raw events from the Giganto server.

pub mod range;
pub mod stream;

use std::{mem, net::IpAddr};

use anyhow::Result;
use quinn::{Connection, ConnectionError, RecvStream, SendStream};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use self::{
    range::{MessageCode, ResponseRangeData},
    stream::{RequestStreamRecord, StreamRequestPayload},
};
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
            RecvError::MessageTooLarge(_) => PublishError::MessageTooLarge,
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
    pub timestamp: i64,
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
    use crate::publish::{recv_ack_response, PublishError};
    use crate::test::{channel, TOKEN};

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn publish_send_recv() {
        use crate::frame::send_bytes;
        use crate::publish::{
            range::ResponseRangeData,
            stream::{
                RequestSemiSupervisedStream, RequestTimeSeriesGeneratorStream, StreamRequestPayload,
            },
            PcapFilter,
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
            end_time: 1000,
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
            timestamp: 12345,
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
        use crate::publish::range::{MessageCode, RequestRawData};
        use crate::publish::{receive_raw_events, send_raw_events};
        use crate::RawEventKind;
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
            end_time: 1000,
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
}
