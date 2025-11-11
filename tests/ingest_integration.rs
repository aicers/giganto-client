#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;
use std::mem;

use common::{channel, encode_legacy, sample_conn, TOKEN};
use giganto_client::{
    frame,
    ingest::{
        receive_ack_timestamp, receive_event, receive_record_header, send_event, send_record_header,
    },
    RawEventKind,
};

#[tokio::test]
async fn ingest_send_recv() {
    let _lock = TOKEN.lock().await;
    let mut channel = channel().await;

    // send/recv event type
    send_record_header(&mut channel.client.send, RawEventKind::Conn)
        .await
        .unwrap();

    let mut buf = vec![0; mem::size_of::<u32>()];
    receive_record_header(&mut channel.server.recv, &mut buf)
        .await
        .unwrap();
    assert_eq!(buf, u32::from(RawEventKind::Conn).to_le_bytes());

    // send/recv event data
    let conn = sample_conn();
    send_event(&mut channel.client.send, 9999, conn.clone())
        .await
        .unwrap();
    let (data, timestamp) = receive_event(&mut channel.server.recv).await.unwrap();
    assert_eq!(timestamp, 9999);
    assert_eq!(data, encode_legacy(&conn).unwrap());

    // recv ack timestamp
    frame::send_bytes(&mut channel.client.send, &8888_i64.to_be_bytes())
        .await
        .unwrap();
    let timestamp = receive_ack_timestamp(&mut channel.server.recv)
        .await
        .unwrap();
    assert_eq!(timestamp, 8888);
}
