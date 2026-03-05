//! Functions and errors for handling messages.

use quinn::{Connection, ConnectionError, RecvStream, SendStream};
use semver::{Version, VersionReq};
use thiserror::Error;

use crate::frame::{self, RecvError, SendError, recv_handshake, send_handshake};

/// The error type for a handshake failure.
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("Connection closed by peer")]
    ConnectionClosed,
    #[error("Connection lost")]
    ConnectionLost(#[from] ConnectionError),
    #[error("Cannot receive a message")]
    ReadError(#[from] quinn::ReadError),
    #[error("Cannot send a message")]
    WriteError(#[from] quinn::WriteError),
    #[error("Cannot serialize a message")]
    SerializationFailure(#[from] bincode::Error),
    #[error("Message is too large, so type casting failed")]
    MessageTooLarge,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Protocol version {0} is not supported")]
    IncompatibleProtocol(String),
}

impl From<SendError> for HandshakeError {
    fn from(e: SendError) -> Self {
        match e {
            SendError::SerializationFailure(e) => HandshakeError::SerializationFailure(e),
            SendError::MessageTooLarge(_) => HandshakeError::MessageTooLarge,
            SendError::WriteError(e) => HandshakeError::WriteError(e),
        }
    }
}

/// Sends a handshake request and processes the response.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
pub async fn client_handshake(
    conn: &Connection,
    protocol_version: &str,
) -> Result<(SendStream, RecvStream), HandshakeError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut buf = Vec::new();
    if let Err(e) = frame::send_handshake(&mut send, protocol_version.as_bytes()).await {
        match e {
            SendError::SerializationFailure(e) => {
                return Err(HandshakeError::SerializationFailure(e));
            }
            SendError::MessageTooLarge(_) => return Err(HandshakeError::MessageTooLarge),
            SendError::WriteError(e) => return Err(HandshakeError::WriteError(e)),
        }
    }

    match frame::recv_handshake(&mut recv, &mut buf).await {
        Err(RecvError::ReadError(error)) => match error {
            quinn::ReadExactError::FinishedEarly(_) => {
                return Err(HandshakeError::ConnectionClosed);
            }
            quinn::ReadExactError::ReadError(e) => {
                return Err(HandshakeError::ReadError(e));
            }
        },
        Err(RecvError::MessageTooLarge) => {
            return Err(HandshakeError::MessageTooLarge);
        }
        Ok(()) | Err(_) => {}
    }

    bincode::deserialize::<Option<&str>>(&buf)
        .map_err(|_| HandshakeError::InvalidMessage)?
        .ok_or_else(|| HandshakeError::IncompatibleProtocol(protocol_version.to_string()))?;

    Ok((send, recv))
}

/// Processes a handshake message and sends a response.
///
/// # Errors
///
/// Returns `HandshakeError` if the handshake failed.
#[allow(clippy::missing_panics_doc)]
pub async fn server_handshake(
    conn: &Connection,
    std_version: &str,
) -> Result<(SendStream, RecvStream), HandshakeError> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(HandshakeError::ConnectionLost)?;

    let mut buf = Vec::new();
    recv_handshake(&mut recv, &mut buf)
        .await
        .map_err(|_| HandshakeError::InvalidMessage)?;

    let recv_version = String::from_utf8(buf).map_err(|_| HandshakeError::InvalidMessage)?;
    let version_req = VersionReq::parse(std_version).expect("valid version requirement");
    let protocol_version = Version::parse(&recv_version)
        .map_err(|_| HandshakeError::IncompatibleProtocol(recv_version))?;
    if version_req.matches(&protocol_version) {
        let resp_data = bincode::serialize::<Option<&str>>(&Some(std_version))?;
        send_handshake(&mut send, &resp_data)
            .await
            .map_err(HandshakeError::from)?;
        return Ok((send, recv));
    }
    let resp_data = bincode::serialize::<Option<&str>>(&None)?;
    send_handshake(&mut send, &resp_data)
        .await
        .map_err(HandshakeError::from)?;
    send.finish().ok();
    Err(HandshakeError::IncompatibleProtocol(
        protocol_version.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use quinn::VarInt;
    use tokio::{
        sync::oneshot,
        time::{Duration, timeout},
    };

    use super::{HandshakeError, client_handshake, server_handshake};
    use crate::frame;
    mod fixture {
        use std::future::Future;

        use quinn::{Connection, ReadError, RecvStream, SendStream, VarInt};
        use tokio::{sync::MutexGuard, task::JoinHandle};

        use super::{HandshakeError, client_handshake};
        use crate::{
            frame,
            test::{Channel, TOKEN, channel},
        };

        pub(super) type HandshakeResult = Result<(SendStream, RecvStream), HandshakeError>;

        pub(super) const DEFAULT_SERVER_VERSION_REQ: &str = ">=0.7.0, <=0.8.0-alpha.1";
        pub(super) const DEFAULT_CLIENT_VERSION: &str = "0.7.0";

        pub(super) async fn setup_channel() -> (MutexGuard<'static, u32>, Channel) {
            let lock = TOKEN.lock().await;
            let channel = channel().await;
            (lock, channel)
        }

        pub(super) fn spawn_client_handshake(
            conn: Connection,
            version: &'static str,
        ) -> JoinHandle<HandshakeResult> {
            tokio::spawn(async move { client_handshake(&conn, version).await })
        }

        pub(super) fn spawn_client_open_bi_send_handshake(
            conn: Connection,
            payload: Vec<u8>,
            stop_code: Option<VarInt>,
        ) -> JoinHandle<()> {
            tokio::spawn(async move {
                let (mut send, mut recv) = conn.open_bi().await.unwrap();
                if let Some(code) = stop_code {
                    recv.stop(code).unwrap();
                }
                frame::send_handshake(&mut send, &payload).await.unwrap();
            })
        }

        pub(super) fn spawn_client_open_bi_raw_write_and_finish(
            conn: Connection,
            payload: Vec<u8>,
        ) -> JoinHandle<()> {
            tokio::spawn(async move {
                let (mut send, _recv) = conn.open_bi().await.unwrap();
                send.write_all(&payload).await.unwrap();
                send.finish().unwrap();
            })
        }

        pub(super) fn spawn_client_open_bi_raw_write_without_finish(
            conn: Connection,
            payload: Vec<u8>,
        ) -> JoinHandle<()> {
            tokio::spawn(async move {
                let (mut send, _recv) = conn.open_bi().await.unwrap();
                send.write_all(&payload).await.unwrap();
            })
        }

        pub(super) fn spawn_server_accept_bi_recv_handshake_then<F, Fut>(
            conn: Connection,
            then: F,
        ) -> JoinHandle<()>
        where
            F: FnOnce(SendStream) -> Fut + Send + 'static,
            Fut: Future<Output = ()> + Send + 'static,
        {
            tokio::spawn(async move {
                let (send, mut recv) = conn.accept_bi().await.unwrap();
                let mut buf = Vec::new();
                frame::recv_handshake(&mut recv, &mut buf).await.unwrap();
                then(send).await;
            })
        }

        pub(super) fn is_incompatible_protocol(result: &HandshakeResult, expected: &str) -> bool {
            match result {
                Err(HandshakeError::IncompatibleProtocol(version)) => version == expected,
                _ => false,
            }
        }

        pub(super) fn is_connection_closed(result: &HandshakeResult) -> bool {
            matches!(result, Err(HandshakeError::ConnectionClosed))
        }

        pub(super) fn is_invalid_message(result: &HandshakeResult) -> bool {
            matches!(result, Err(HandshakeError::InvalidMessage))
        }

        pub(super) fn is_message_too_large(result: &HandshakeResult) -> bool {
            matches!(result, Err(HandshakeError::MessageTooLarge))
        }

        pub(super) fn is_read_error_reset(result: &HandshakeResult, code: VarInt) -> bool {
            matches!(result, Err(HandshakeError::ReadError(ReadError::Reset(reset_code))) if *reset_code == code)
        }

        pub(super) fn is_write_error_stopped(result: &HandshakeResult, code: VarInt) -> bool {
            matches!(result, Err(HandshakeError::WriteError(quinn::WriteError::Stopped(stop_code))) if *stop_code == code)
        }
    }

    use fixture::{
        DEFAULT_CLIENT_VERSION, DEFAULT_SERVER_VERSION_REQ, is_connection_closed,
        is_incompatible_protocol, is_invalid_message, is_message_too_large, is_read_error_reset,
        is_write_error_stopped, setup_channel, spawn_client_handshake,
        spawn_client_open_bi_raw_write_and_finish, spawn_client_open_bi_raw_write_without_finish,
        spawn_client_open_bi_send_handshake, spawn_server_accept_bi_recv_handshake_then,
    };

    #[tokio::test]
    #[allow(clippy::similar_names)]
    async fn handshake_success_roundtrip_streams() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let client_task = spawn_client_handshake(client.conn, DEFAULT_CLIENT_VERSION);
        let server_result = server_handshake(&server.conn, DEFAULT_SERVER_VERSION_REQ).await;
        assert!(
            server_result.is_ok(),
            "Server handshake should succeed, got {server_result:?}"
        );
        let (mut server_send, mut server_recv) = server_result.unwrap();

        let client_result = client_task.await.unwrap();
        assert!(
            client_result.is_ok(),
            "Client handshake should succeed, got {client_result:?}"
        );
        let (mut client_send, mut client_recv) = client_result.unwrap();

        let ping = b"handshake-validation-ping";
        client_send.write_all(ping).await.unwrap();
        let mut ping_recv = vec![0u8; ping.len()];
        server_recv.read_exact(&mut ping_recv).await.unwrap();
        assert_eq!(&ping_recv, ping, "Server did not receive the ping payload");

        let pong = b"handshake-validation-pong";
        server_send.write_all(pong).await.unwrap();
        let mut pong_recv = vec![0u8; pong.len()];
        client_recv.read_exact(&mut pong_recv).await.unwrap();
        assert_eq!(&pong_recv, pong, "Client did not receive the pong payload");
    }

    #[tokio::test]
    async fn handshake_error_incompatible_protocol_on_version_mismatch() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let client_task = spawn_client_handshake(client.conn, "0.9.0");
        let server_result = server_handshake(&server.conn, DEFAULT_SERVER_VERSION_REQ).await;
        assert!(
            is_incompatible_protocol(&server_result, "0.9.0"),
            "Expected IncompatibleProtocol(\"0.9.0\"), got {server_result:?}"
        );

        let client_result = client_task.await.unwrap();
        assert!(
            is_incompatible_protocol(&client_result, "0.9.0"),
            "Expected client IncompatibleProtocol(\"0.9.0\"), got {client_result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_connection_closed_on_server_invalid_version() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let server_task =
            tokio::spawn(async move { server_handshake(&server.conn, ">=0.7.0").await });
        let client_result = client_handshake(&client.conn, "not-a-version").await;
        let server_result = server_task.await.unwrap();

        assert!(
            is_connection_closed(&client_result),
            "Expected client ConnectionClosed, got {client_result:?}"
        );
        assert!(
            is_incompatible_protocol(&server_result, "not-a-version"),
            "Expected server IncompatibleProtocol(\"not-a-version\"), got {server_result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_connection_closed_on_server_early_finish() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let server_task = tokio::spawn(async move {
            let (mut send, _recv) = server.conn.accept_bi().await.unwrap();
            send.finish().unwrap();
        });

        let client_result = client_handshake(&client.conn, DEFAULT_CLIENT_VERSION).await;
        server_task.await.unwrap();

        assert!(
            is_connection_closed(&client_result),
            "Expected ConnectionClosed when server finishes immediately, got {client_result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_connection_closed_on_server_finish_after_read() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let server_task =
            spawn_server_accept_bi_recv_handshake_then(server.conn, |mut send| async move {
                send.finish().unwrap();
            });

        let client_result = client_handshake(&client.conn, DEFAULT_CLIENT_VERSION).await;
        server_task.await.unwrap();

        assert!(
            is_connection_closed(&client_result),
            "Expected ConnectionClosed when server sends no response, got {client_result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_connection_lost_on_client_drop_before_accept() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);
        drop(client);

        let result = server_handshake(&server.conn, ">=0.7.0").await;
        assert!(
            matches!(result, Err(HandshakeError::ConnectionLost(_))),
            "Expected ConnectionLost, got {result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_invalid_message_on_non_utf8_version() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let client_task =
            spawn_client_open_bi_send_handshake(client.conn, vec![0x80, 0x81, 0x82, 0xff], None);

        let result = server_handshake(&server.conn, ">=0.7.0").await;
        client_task.await.unwrap();

        assert!(
            is_invalid_message(&result),
            "Expected InvalidMessage for non-UTF8 payload, got {result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_invalid_message_on_malformed_server_response() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let server_task =
            spawn_server_accept_bi_recv_handshake_then(server.conn, |mut send| async move {
                let malformed_response: &[u8] =
                    &[0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
                frame::send_handshake(&mut send, malformed_response)
                    .await
                    .unwrap();
            });

        let result = client_handshake(&client.conn, DEFAULT_CLIENT_VERSION).await;
        server_task.await.unwrap();

        assert!(
            is_invalid_message(&result),
            "Expected InvalidMessage for malformed server response, got {result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_invalid_message_on_truncated_handshake_body() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let mut payload = Vec::new();
        payload.extend_from_slice(&100u64.to_le_bytes());
        payload.extend_from_slice(b"short");
        let client_task = spawn_client_open_bi_raw_write_and_finish(client.conn, payload);

        let result = server_handshake(&server.conn, ">=0.7.0").await;
        client_task.await.unwrap();

        assert!(
            is_invalid_message(&result),
            "Expected InvalidMessage for truncated handshake, got {result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_read_reset_on_stream_reset() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let (header_written_tx, header_written_rx) = oneshot::channel::<()>();
        let (reset_now_tx, reset_now_rx) = oneshot::channel::<()>();

        let server_task =
            spawn_server_accept_bi_recv_handshake_then(server.conn, move |mut send| async move {
                let len_header: u64 = 1;
                send.write_all(&len_header.to_le_bytes()).await.unwrap();
                let _ = header_written_tx.send(());
                let _ = reset_now_rx.await;
                send.reset(VarInt::from_u32(1)).unwrap();
            });

        let client_task =
            tokio::spawn(
                async move { client_handshake(&client.conn, DEFAULT_CLIENT_VERSION).await },
            );
        let _ = header_written_rx.await;
        let _ = reset_now_tx.send(());
        let result = client_task.await.unwrap();
        server_task.await.unwrap();

        assert!(
            is_read_error_reset(&result, VarInt::from_u32(1)),
            "Expected ReadError::Reset when stream is reset, got {result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_read_connection_lost_on_server_close_during_response() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);
        let close_conn = server.conn.clone();

        let server_task =
            spawn_server_accept_bi_recv_handshake_then(server.conn, move |_send| async move {
                close_conn.close(VarInt::from_u32(99), b"close-during-handshake-response");
            });

        let result = client_handshake(&client.conn, DEFAULT_CLIENT_VERSION).await;
        server_task.await.unwrap();

        assert!(
            matches!(
                result,
                Err(HandshakeError::ReadError(quinn::ReadError::ConnectionLost(
                    _
                )))
            ),
            "Expected ReadError::ConnectionLost when server closes connection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_write_stopped_on_peer_stop() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let server_task = tokio::spawn(async move {
            let (_send, mut recv) = server.conn.accept_bi().await.unwrap();
            recv.stop(VarInt::from_u32(7)).unwrap();
        });

        let (mut send, _recv) = client.conn.open_bi().await.unwrap();
        // Make the stream visible to the peer before waiting on `stopped()`.
        let _ = send.write_all(b"probe").await;

        let stopped = timeout(Duration::from_secs(3), send.stopped())
            .await
            .expect("Timed out waiting for STOP_SENDING")
            .unwrap();
        assert_eq!(
            stopped,
            Some(VarInt::from_u32(7)),
            "Expected STOP_SENDING code 7, got {stopped:?}"
        );

        let send_result = frame::send_handshake(&mut send, DEFAULT_CLIENT_VERSION.as_bytes()).await;
        assert!(
            matches!(
                send_result,
                Err(frame::SendError::WriteError(quinn::WriteError::Stopped(code)))
                    if code == VarInt::from_u32(7)
            ),
            "Expected SendError::WriteError after STOP_SENDING, got {send_result:?}"
        );

        let handshake_error: HandshakeError = send_result.unwrap_err().into();
        assert!(
            matches!(
                handshake_error,
                HandshakeError::WriteError(quinn::WriteError::Stopped(code))
                    if code == VarInt::from_u32(7)
            ),
            "Expected HandshakeError::WriteError conversion, got {handshake_error:?}"
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_error_message_too_large_on_huge_server_header() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let server_task =
            spawn_server_accept_bi_recv_handshake_then(server.conn, |mut send| async move {
                let huge_len: u64 = u64::MAX;
                send.write_all(&huge_len.to_le_bytes()).await.unwrap();
            });

        let result = client_handshake(&client.conn, DEFAULT_CLIENT_VERSION).await;
        server_task.await.unwrap();

        assert!(
            is_message_too_large(&result),
            "Expected MessageTooLarge for huge server response header, got {result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_write_stopped_on_client_stop_before_server_reply() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let server_task = tokio::spawn(async move {
            // Control stream synchronization:
            // wait for "go" from client, then run server_handshake on the next bi stream.
            let (_control_send, mut control_recv) = server.conn.accept_bi().await.unwrap();
            let mut go = [0u8; 2];
            control_recv.read_exact(&mut go).await.unwrap();
            assert_eq!(&go, b"go");
            server_handshake(&server.conn, ">=0.7.0").await
        });

        let (mut control_send, _control_recv) = client.conn.open_bi().await.unwrap();
        let client_data_task = spawn_client_open_bi_send_handshake(
            client.conn,
            DEFAULT_CLIENT_VERSION.as_bytes().to_vec(),
            Some(VarInt::from_u32(11)),
        );
        client_data_task.await.unwrap();
        control_send.write_all(b"go").await.unwrap();

        let server_result = server_task.await.unwrap();
        assert!(
            is_write_error_stopped(&server_result, VarInt::from_u32(11)),
            "Expected server WriteError when client stops response stream, got {server_result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_invalid_message_on_huge_length_header() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let client_task = spawn_client_open_bi_raw_write_without_finish(
            client.conn,
            u64::MAX.to_le_bytes().to_vec(),
        );

        let result = server_handshake(&server.conn, ">=0.7.0").await;
        client_task.await.unwrap();

        assert!(
            is_invalid_message(&result),
            "Expected InvalidMessage (from oversized length header), got {result:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_connection_lost_on_open_bi_after_close() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        server
            .conn
            .close(VarInt::from_u32(42), b"test-close-before-open-bi");
        let _ = client.conn.closed().await;

        let result = client_handshake(&client.conn, DEFAULT_CLIENT_VERSION).await;
        assert!(
            matches!(result, Err(HandshakeError::ConnectionLost(_))),
            "Expected ConnectionLost from open_bi on closed connection, got {result:?}"
        );
    }

    #[test]
    fn handshake_error_serialization_failure_from_send_error() {
        let bincode_error: bincode::Error = Box::new(bincode::ErrorKind::SizeLimit);
        let send_error = frame::SendError::SerializationFailure(bincode_error);
        let handshake_error: HandshakeError = send_error.into();

        assert!(
            matches!(handshake_error, HandshakeError::SerializationFailure(_)),
            "SendError::SerializationFailure should convert to HandshakeError::SerializationFailure"
        );
    }

    #[tokio::test]
    async fn handshake_error_incompatible_protocol_on_empty_version() {
        let (_lock, channel) = setup_channel().await;
        let (server, client) = (channel.server, channel.client);

        let client_task = spawn_client_open_bi_send_handshake(client.conn, Vec::new(), None);

        let result = server_handshake(&server.conn, ">=0.7.0").await;
        client_task.await.unwrap();

        assert!(
            matches!(result, Err(HandshakeError::IncompatibleProtocol(ref version)) if version.is_empty()),
            "Expected IncompatibleProtocol with an empty version, got {result:?}"
        );
    }

    #[test]
    fn handshake_error_from_send_error_message_too_large() {
        use std::num::TryFromIntError;

        let try_error: TryFromIntError = u8::try_from(u16::MAX).unwrap_err();
        let send_error = frame::SendError::MessageTooLarge(try_error);
        let handshake_error: HandshakeError = send_error.into();

        assert!(
            matches!(handshake_error, HandshakeError::MessageTooLarge),
            "SendError::MessageTooLarge should convert to HandshakeError::MessageTooLarge"
        );
    }
}
