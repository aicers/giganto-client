#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;
use common::{channel, TOKEN};
use giganto_client::connection::{client_handshake, server_handshake};

#[tokio::test]
async fn handshake() {
    const VERSION_REQ: &str = ">=0.7.0, <=0.8.0-alpha.1";
    const VERSION_STD: &str = "0.7.0";

    let _lock = TOKEN.lock().await;
    let channel = channel().await;
    let (server, client) = (channel.server, channel.client);

    let handle = tokio::spawn(async move { client_handshake(&client.conn, VERSION_STD).await });

    server_handshake(&server.conn, VERSION_REQ).await.unwrap();

    let res = tokio::join!(handle).0.unwrap();
    assert!(res.is_ok());
}

#[tokio::test]
async fn handshake_version_incompatible_err() {
    const VERSION_REQ: &str = ">=0.7.0, <=0.8.0-alpha.1";
    const VERSION_STD: &str = "0.9.0";

    let _lock = TOKEN.lock().await;
    let channel = channel().await;
    let (server, client) = (channel.server, channel.client);

    let handle = tokio::spawn(async move { client_handshake(&client.conn, VERSION_STD).await });

    let res = server_handshake(&server.conn, VERSION_REQ).await;
    assert!(res.is_err());

    let res = tokio::join!(handle).0.unwrap();
    assert!(res.is_err());
}
