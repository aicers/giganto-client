#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;
use common::{channel, TOKEN};
use giganto_client::frame::{
    recv, recv_bytes, recv_handshake, recv_raw, send, send_bytes, send_handshake, send_raw,
};

#[tokio::test]
async fn frame_send_and_recv() {
    let _lock = TOKEN.lock().await;
    let mut channel = channel().await;

    let mut buf = Vec::new();
    send(&mut channel.server.send, &mut buf, "hello")
        .await
        .unwrap();
    assert_eq!(buf.len(), 0);
    recv_raw(&mut channel.client.recv, &mut buf).await.unwrap();
    assert_eq!(buf[0] as usize, "hello".len());
    assert_eq!(&buf[8..], b"hello");

    send_raw(&mut channel.server.send, b"world").await.unwrap();
    recv_raw(&mut channel.client.recv, &mut buf).await.unwrap();
    assert_eq!(buf, b"world");

    send_bytes(&mut channel.server.send, b"hello")
        .await
        .unwrap();
    recv_bytes(&mut channel.client.recv, &mut buf)
        .await
        .unwrap();
    assert_eq!(buf, b"hello");

    send_handshake(&mut channel.server.send, b"hello")
        .await
        .unwrap();
    recv_handshake(&mut channel.client.recv, &mut buf)
        .await
        .unwrap();
    assert_eq!(buf, b"hello");

    send(&mut channel.server.send, &mut buf, "hello")
        .await
        .unwrap();
    assert!(buf.is_empty());
    let received = recv::<String>(&mut channel.client.recv, &mut buf)
        .await
        .unwrap();
    assert_eq!(received, "hello");
}
