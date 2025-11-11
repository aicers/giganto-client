#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;
use std::net::IpAddr;
use std::str::FromStr;

use common::{channel, decode_legacy, encode_legacy, sample_conn, TOKEN};
use giganto_client::{
    frame,
    frame::send_bytes,
    publish::{
        pcap_extract_request, pcap_extract_response,
        range::{MessageCode, RequestRange, RequestRawData, ResponseRangeData},
        receive_range_data, receive_range_data_request, receive_raw_events,
        receive_semi_supervised_data, receive_semi_supervised_stream_start_message,
        receive_stream_request, receive_time_series_generator_data,
        receive_time_series_generator_stream_start_message, recv_ack_response, send_err, send_ok,
        send_range_data, send_range_data_request, send_raw_events,
        send_semi_supervised_stream_start_message, send_stream_request,
        stream::{
            RequestSemiSupervisedStream, RequestStreamRecord, RequestTimeSeriesGeneratorStream,
            StreamRequestPayload,
        },
        PcapFilter, PublishError,
    },
    RawEventKind,
};
use serde_json::json;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn publish_send_recv() {
    let _lock = TOKEN.lock().await;
    let mut channel = channel().await;

    // send/recv semi-supervised stream request
    let semi_supervised_req = RequestSemiSupervisedStream {
        start: 0,
        sensor: Some(vec!["hello".to_string(), "world".to_string()]),
    };
    let payload = StreamRequestPayload::new_semi_supervised(
        RequestStreamRecord::Conn,
        semi_supervised_req.clone(),
    );
    send_stream_request(&mut channel.client.send, payload.clone())
        .await
        .unwrap();

    let received_payload = receive_stream_request(&mut channel.server.recv)
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
        RequestStreamRecord::Conn,
        time_series_generator_req.clone(),
    );
    send_stream_request(&mut channel.client.send, payload.clone())
        .await
        .unwrap();

    let received_payload = receive_stream_request(&mut channel.server.recv)
        .await
        .unwrap();
    assert_eq!(received_payload, payload);

    // send/recv semi_supervised stream start message
    send_semi_supervised_stream_start_message(&mut channel.server.send, RequestStreamRecord::Conn)
        .await
        .unwrap();
    let req_record = receive_semi_supervised_stream_start_message(&mut channel.client.recv)
        .await
        .unwrap();
    assert_eq!(req_record, RequestStreamRecord::Conn);

    // recv time series generator stream start message
    giganto_client::frame::send_raw(&mut channel.server.send, "1".to_string().as_bytes())
        .await
        .unwrap();

    let policy_id = receive_time_series_generator_stream_start_message(&mut channel.client.recv)
        .await
        .unwrap();
    assert_eq!(policy_id, "1".parse::<u32>().unwrap());

    // send/recv stream data with semi-supervised
    let conn = sample_conn();
    let raw_event = encode_legacy(&conn).unwrap();
    let sensor = encode_legacy(&"hello").unwrap();
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

    let data = receive_semi_supervised_data(&mut channel.client.recv)
        .await
        .unwrap();
    let mut result_buf: Vec<u8> = Vec::new();
    result_buf.extend_from_slice(&6666_i64.to_le_bytes());
    result_buf.extend_from_slice(&sensor);
    result_buf.extend_from_slice(&raw_event);
    assert_eq!(data, result_buf);

    // recv time series generator stream data
    giganto_client::frame::send_bytes(&mut channel.server.send, &7777_i64.to_le_bytes())
        .await
        .unwrap();
    let mut data_buf = Vec::new();
    giganto_client::frame::send(&mut channel.server.send, &mut data_buf, conn.clone())
        .await
        .unwrap();
    let (data, timestamp) = receive_time_series_generator_data(&mut channel.client.recv)
        .await
        .unwrap();
    assert_eq!(timestamp, 7777);
    assert_eq!(data, encode_legacy(&conn).unwrap());

    // send/recv range data request
    let req_range = RequestRange {
        sensor: String::from("world"),
        kind: String::from("conn"),
        start: 11111,
        end: 22222,
        count: 5,
    };
    send_range_data_request(
        &mut channel.client.send,
        MessageCode::ReqRange,
        req_range.clone(),
    )
    .await
    .unwrap();
    let (msg_code, data) = receive_range_data_request(&mut channel.server.recv)
        .await
        .unwrap();
    assert_eq!(msg_code, MessageCode::ReqRange);
    assert_eq!(data, encode_legacy(&req_range).unwrap());

    // send/recv range data
    send_range_data(
        &mut channel.server.send,
        Some((conn.clone(), 33333, "world")),
    )
    .await
    .unwrap();
    let data = receive_range_data::<Option<(i64, String, Vec<u8>)>>(&mut channel.client.recv)
        .await
        .unwrap();
    assert_eq!(
        encode_legacy::<Option<(i64, String, Vec<u8>)>>(&data).unwrap(),
        conn.response_data(33333, "world").unwrap()
    );

    // send/recv pcap extract request
    let p_filter: PcapFilter = serde_json::from_value(json!({
        "start_time": "1970-01-01T00:00:00.000012345Z",
        "sensor": "hello",
        "src_addr": "192.168.4.76",
        "src_port": 46378,
        "dst_addr": "192.168.4.76",
        "dst_port": 80,
        "proto": 6,
        "end_time": "1970-01-01T00:00:00.000001000Z",
    }))
    .expect("valid PcapFilter payload");
    let send_filter = p_filter.clone();

    let handle =
        tokio::spawn(async move { pcap_extract_request(&channel.server.conn, &send_filter).await });

    let (send, recv) = channel.client.conn.accept_bi().await.unwrap();
    let data = pcap_extract_response(send, recv).await.unwrap();
    assert_eq!(data, p_filter);

    let res = tokio::join!(handle).0.unwrap();
    assert!(res.is_ok());
}

#[tokio::test]
async fn send_ok_response() {
    let _lock = TOKEN.lock().await;
    let mut channel = channel().await;

    let mut buf = Vec::new();
    send_ok(&mut channel.server.send, &mut buf, "hello")
        .await
        .unwrap();
    assert!(buf.is_empty());
    let resp_result = recv_ack_response(&mut channel.client.recv).await.is_ok();
    assert!(resp_result);
}

#[tokio::test]
async fn send_err_response() {
    let _lock = TOKEN.lock().await;
    let mut channel = channel().await;

    let mut buf = Vec::new();
    send_err(&mut channel.server.send, &mut buf, "hello")
        .await
        .unwrap();
    assert!(buf.is_empty());
    let resp = recv_ack_response(&mut channel.client.recv)
        .await
        .unwrap_err();
    assert_eq!(
        resp.to_string(),
        giganto_client::publish::PublishError::PcapRequestFail("hello".to_string()).to_string()
    );
}

#[tokio::test]
async fn send_recv_raw_events() {
    let _lock = TOKEN.lock().await;
    let mut channel = channel().await;

    let msg_code = MessageCode::RawData;

    let conn = sample_conn();
    let raw_event = encode_legacy(&conn).unwrap();

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

    send_range_data_request(&mut channel.client.send, msg_code, req_raw.clone())
        .await
        .unwrap();

    let (recv_msg_code, data) = receive_range_data_request(&mut channel.server.recv)
        .await
        .unwrap();

    let recv_request = decode_legacy::<RequestRawData>(&data).unwrap();
    assert_eq!(recv_msg_code, MessageCode::RawData);
    assert_eq!(
        RawEventKind::from_str(recv_request.kind.as_str()).unwrap(),
        RawEventKind::Conn
    );

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
async fn pcap_extract_request_success() {
    let _lock = TOKEN.lock().await;
    let channel = channel().await;

    let send_filter: PcapFilter = serde_json::from_value(json!({
        "start_time": "1970-01-01T00:00:00.000012345Z",
        "sensor": "test-sensor",
        "src_addr": "192.168.1.1",
        "src_port": 8080,
        "dst_addr": "192.168.1.2",
        "dst_port": 443,
        "proto": 6,
        "end_time": "1970-01-01T00:00:01.000000000Z",
    }))
    .expect("valid PcapFilter payload");

    // Spawn a task to accept bidirectional stream from server and respond with OK
    let client_conn = channel.client.conn.clone();
    let handle = tokio::spawn(async move {
        let (mut server_send, mut server_recv) = client_conn.accept_bi().await.unwrap();
        // Receive the filter
        let mut buf = Vec::new();
        let received_filter: PcapFilter = frame::recv(&mut server_recv, &mut buf).await.unwrap();
        // Send OK response
        let mut ack_buf = Vec::new();
        send_ok(&mut server_send, &mut ack_buf, ()).await.unwrap();
        received_filter
    });

    // Call pcap_extract_request from server side
    let result = pcap_extract_request(&channel.server.conn, &send_filter).await;

    // Verify it completes successfully
    assert!(result.is_ok());

    // Wait for the receive task to complete and verify the filter was received correctly
    let received_filter = handle.await.unwrap();
    assert_eq!(received_filter, send_filter);
}

/// Ensures the `pcap_extract_request` function returns an `PublishError::PcapRequestFail` error
/// when the received data cannot be deserialized as `PcapFilter`.
#[tokio::test]
async fn pcap_extract_request_error_pcap_request_fail() {
    let _lock = TOKEN.lock().await;
    let channel = channel().await;

    let send_filter: PcapFilter = serde_json::from_value(json!({
        "start_time": "1970-01-01T00:00:00.000012345Z",
        "sensor": "test-sensor",
        "src_addr": "192.168.1.1",
        "src_port": 8080,
        "dst_addr": "192.168.1.2",
        "dst_port": 443,
        "proto": 6,
        "end_time": "1970-01-01T00:00:01.000000000Z",
    }))
    .expect("valid PcapFilter payload");

    // Spawn a task to accept bidirectional stream from server and respond with Err
    let client_conn = channel.client.conn.clone();
    let handle = tokio::spawn(async move {
        let (mut server_send, mut server_recv) = client_conn.accept_bi().await.unwrap();
        // Receive the filter
        let mut buf = Vec::new();
        let _received_filter: PcapFilter = frame::recv(&mut server_recv, &mut buf).await.unwrap();
        // Send Err response
        let mut ack_buf = Vec::new();
        send_err(&mut server_send, &mut ack_buf, "test error message")
            .await
            .unwrap();
    });

    // Call pcap_extract_request from server side
    let result = pcap_extract_request(&channel.server.conn, &send_filter).await;

    // Verify it returns an `PublishError::PcapRequestFail` error
    assert!(result.is_err_and(|e| matches!(e, PublishError::PcapRequestFail(_))));

    // Wait for the send task to complete
    handle.await.unwrap();
}

#[tokio::test]
async fn pcap_extract_response_success() {
    let _lock = TOKEN.lock().await;
    let channel = channel().await;

    let send_filter: PcapFilter = serde_json::from_value(json!({
        "start_time": "1970-01-01T00:00:00.000012345Z",
        "sensor": "test-sensor",
        "src_addr": "192.168.1.1",
        "src_port": 8080,
        "dst_addr": "192.168.1.2",
        "dst_port": 443,
        "proto": 6,
        "end_time": "1970-01-01T00:00:01.000000000Z",
    }))
    .expect("valid PcapFilter payload");

    // Spawn a task to open bidirectional stream from client and send the filter
    let send_filter_clone = send_filter.clone();
    let client_conn = channel.client.conn.clone();
    let handle = tokio::spawn(async move {
        let (mut client_send, client_recv) = client_conn.open_bi().await.unwrap();
        let mut buf = Vec::new();
        frame::send(&mut client_send, &mut buf, send_filter_clone)
            .await
            .unwrap();
        client_send.finish().unwrap();
        client_recv
    });

    // Accept the bidirectional stream on server side and call pcap_extract_response
    let (server_send, server_recv) = channel.server.conn.accept_bi().await.unwrap();
    let received_filter = pcap_extract_response(server_send, server_recv)
        .await
        .unwrap();

    // Verify the received filter matches the sent filter
    assert_eq!(received_filter, send_filter);

    // Wait for the send task to complete and verify the ack response was sent (Ok)
    let mut client_recv = handle.await.unwrap();
    let mut ack_buf = Vec::new();
    frame::recv_raw(&mut client_recv, &mut ack_buf)
        .await
        .unwrap();
    let ack_result: Result<(), String> = decode_legacy(&ack_buf).unwrap();
    assert!(ack_result.is_ok());
}

/// Ensures the `pcap_extract_response` function returns an `PublishError::PcapRequestFail` error
/// when the received data cannot be deserialized as `PcapFilter`.
#[tokio::test]
async fn pcap_extract_response_error_pcap_request_fail() {
    let _lock = TOKEN.lock().await;
    let channel = channel().await;

    // Spawn a task to open bidirectional stream from client and send invalid data
    let client_conn = channel.client.conn.clone();
    let handle = tokio::spawn(async move {
        let (mut client_send, client_recv) = client_conn.open_bi().await.unwrap();
        // Send invalid data that cannot be deserialized as PcapFilter
        let invalid_data = b"invalid pcap filter data";
        frame::send_raw(&mut client_send, invalid_data)
            .await
            .unwrap();
        client_send.finish().unwrap();
        client_recv
    });

    // Accept the bidirectional stream on server side and call pcap_extract_response
    let (server_send, server_recv) = channel.server.conn.accept_bi().await.unwrap();
    let result = pcap_extract_response(server_send, server_recv).await;

    // Verify it returns an `PublishError::PcapRequestFail` error
    assert!(result.is_err_and(|e| matches!(e, PublishError::PcapRequestFail(_))));

    // Wait for the send task to complete and verify the ack response was sent (Err)
    let mut client_recv = handle.await.unwrap();
    let mut ack_buf = Vec::new();
    frame::recv_raw(&mut client_recv, &mut ack_buf)
        .await
        .unwrap();
    let ack_result: Result<(), String> = decode_legacy(&ack_buf).unwrap();
    assert!(ack_result.is_err());
}
