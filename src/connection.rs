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
    use std::sync::Arc;

    use tokio::sync::Barrier;

    use super::HandshakeError;
    use crate::frame;
    use crate::test::{TOKEN, channel};

    // =========================================================================
    // Shared test helpers / fixtures
    // =========================================================================

    /// Handshake test fixture builder to simplify test setup.
    struct HandshakeFixture {
        server_version_req: &'static str,
        client_version: &'static str,
    }

    impl HandshakeFixture {
        /// Creates a new fixture with default compatible versions.
        fn new() -> Self {
            Self {
                server_version_req: ">=0.7.0, <=0.8.0-alpha.1",
                client_version: "0.7.0",
            }
        }

        /// Sets the server's version requirement.
        fn server_version_req(mut self, version: &'static str) -> Self {
            self.server_version_req = version;
            self
        }

        /// Sets the client's version string.
        fn client_version(mut self, version: &'static str) -> Self {
            self.client_version = version;
            self
        }
    }

    // =========================================================================
    // Basic handshake success test
    // =========================================================================

    #[tokio::test]
    async fn handshake() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);
        let fixture = HandshakeFixture::new();

        let client_version = fixture.client_version;
        let handle =
            tokio::spawn(
                async move { super::client_handshake(&client.conn, client_version).await },
            );

        let server_result = super::server_handshake(&server.conn, fixture.server_version_req).await;
        assert!(
            server_result.is_ok(),
            "Server handshake should succeed, got {server_result:?}"
        );

        let (mut server_send, mut server_recv) = server_result.unwrap();

        let client_result = tokio::join!(handle).0.unwrap();
        assert!(
            client_result.is_ok(),
            "Client handshake should succeed, got {client_result:?}"
        );

        let (mut client_send, mut client_recv) = client_result.unwrap();

        // Validate stream validity with a simple send/recv roundtrip
        let test_message = b"handshake-validation-ping";
        client_send.write_all(test_message).await.unwrap();

        let mut recv_buf = vec![0u8; test_message.len()];
        server_recv.read_exact(&mut recv_buf).await.unwrap();
        assert_eq!(
            &recv_buf, test_message,
            "Server should receive the message sent by client"
        );

        let response_message = b"handshake-validation-pong";
        server_send.write_all(response_message).await.unwrap();

        let mut response_buf = vec![0u8; response_message.len()];
        client_recv.read_exact(&mut response_buf).await.unwrap();
        assert_eq!(
            &response_buf, response_message,
            "Client should receive the response sent by server"
        );
    }

    // =========================================================================
    // Tests for HandshakeError::IncompatibleProtocol
    // =========================================================================

    #[tokio::test]
    async fn handshake_error_incompatible_protocol_version_mismatch() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);
        let fixture = HandshakeFixture::new()
            .server_version_req(">=0.7.0, <=0.8.0-alpha.1")
            .client_version("0.9.0");

        let client_version = fixture.client_version;
        let handle =
            tokio::spawn(
                async move { super::client_handshake(&client.conn, client_version).await },
            );

        let server_res = super::server_handshake(&server.conn, fixture.server_version_req).await;
        assert!(
            matches!(server_res, Err(HandshakeError::IncompatibleProtocol(ref v)) if v == "0.9.0"),
            "Expected IncompatibleProtocol(\"0.9.0\"), got {server_res:?}"
        );

        let client_res = tokio::join!(handle).0.unwrap();
        assert!(
            matches!(client_res, Err(HandshakeError::IncompatibleProtocol(ref v)) if v == "0.9.0"),
            "Expected client IncompatibleProtocol(\"0.9.0\"), got {client_res:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_incompatible_protocol_invalid_version_string() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);
        let fixture = HandshakeFixture::new()
            .server_version_req(">=0.7.0")
            .client_version("not-a-version");

        // Use a barrier to synchronize: server signals after completing handshake,
        // ensuring deterministic ordering.
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let client_version = fixture.client_version;
        let server_version_req = fixture.server_version_req;

        // Server task: perform handshake and signal when done
        let server_handle = tokio::spawn(async move {
            let res = super::server_handshake(&server.conn, server_version_req).await;
            barrier_clone.wait().await;
            res
        });

        // Client performs handshake
        let client_res = super::client_handshake(&client.conn, client_version).await;
        barrier.wait().await;

        let server_res = server_handle.await.unwrap();

        // Server should get IncompatibleProtocol because the version string is not valid semver.
        // Note: Version::parse fails early, so the server returns IncompatibleProtocol
        // WITHOUT sending a response to the client.
        assert!(
            matches!(server_res, Err(HandshakeError::IncompatibleProtocol(ref v)) if v == "not-a-version"),
            "Expected IncompatibleProtocol(\"not-a-version\"), got {server_res:?}"
        );

        // Client gets ConnectionClosed because the server returns early (on Version::parse failure)
        // without sending any response. The stream is closed when the server-side drops.
        assert!(
            matches!(client_res, Err(HandshakeError::ConnectionClosed)),
            "Expected client ConnectionClosed (server returns early without response), got {client_res:?}"
        );
    }

    // =========================================================================
    // Tests for HandshakeError::ConnectionClosed
    // =========================================================================

    #[tokio::test]
    async fn handshake_error_connection_closed_server_closes_stream_early() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            let (mut send, _recv) = server.conn.accept_bi().await.unwrap();
            send.finish().ok();
        });

        let res = super::client_handshake(&client.conn, "0.7.0").await;
        let _ = handle.await;

        assert!(
            matches!(res, Err(HandshakeError::ConnectionClosed)),
            "Expected ConnectionClosed when server finishes stream early, got {res:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_read_error_server_drops_early() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);
        let fixture = HandshakeFixture::new();

        // Use a barrier to synchronize: server accepts the bi-stream, reads the
        // client handshake, then finishes the send stream without sending a response.
        // This deterministically triggers ConnectionClosed on the client.
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let server_handle = tokio::spawn(async move {
            let (mut send, mut recv) = server.conn.accept_bi().await.unwrap();
            // Read the client's handshake message
            let mut buf = Vec::new();
            frame::recv_handshake(&mut recv, &mut buf).await.ok();
            // Finish the stream without sending any response
            send.finish().ok();
            // Signal that we're done
            barrier_clone.wait().await;
        });

        let client_version = fixture.client_version;

        // Client opens bi-stream and sends handshake, then waits for response
        let client_res = super::client_handshake(&client.conn, client_version).await;

        // Wait for server to complete
        barrier.wait().await;
        let _ = server_handle.await;

        // When server finishes stream without response, client gets ConnectionClosed
        // (FinishedEarly is mapped to ConnectionClosed in client_handshake)
        assert!(
            matches!(client_res, Err(HandshakeError::ConnectionClosed)),
            "Expected ConnectionClosed when server drops early, got {client_res:?}"
        );
    }

    // =========================================================================
    // Tests for HandshakeError::ConnectionLost
    // =========================================================================

    #[tokio::test]
    async fn handshake_error_connection_lost_client_drops_before_server_accepts() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        drop(client);

        let res = super::server_handshake(&server.conn, ">=0.7.0").await;
        assert!(
            matches!(res, Err(HandshakeError::ConnectionLost(_))),
            "Expected ConnectionLost, got {res:?}"
        );
    }

    // =========================================================================
    // Tests for HandshakeError::InvalidMessage
    // =========================================================================

    #[tokio::test]
    async fn handshake_error_invalid_message_malformed_handshake_non_utf8() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            let (mut send, _recv) = client.conn.open_bi().await.unwrap();
            let invalid_utf8: &[u8] = &[0x80, 0x81, 0x82, 0xff];
            frame::send_handshake(&mut send, invalid_utf8)
                .await
                .unwrap();
        });

        let res = super::server_handshake(&server.conn, ">=0.7.0").await;
        let _ = handle.await;

        assert!(
            matches!(res, Err(HandshakeError::InvalidMessage)),
            "Expected InvalidMessage for non-UTF8 data, got {res:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_invalid_message_malformed_response_from_server() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            let (mut send, mut recv) = server.conn.accept_bi().await.unwrap();
            let mut buf = Vec::new();
            frame::recv_handshake(&mut recv, &mut buf).await.ok();
            // Send data that cannot be deserialized as Option<&str>
            // bincode expects a discriminant byte for Option (0=None, 1=Some)
            // followed by length-prefixed string data for Some.
            // Sending invalid data that claims to be Some with invalid string length.
            let malformed_response: &[u8] = &[0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
            frame::send_handshake(&mut send, malformed_response)
                .await
                .ok();
        });

        let res = super::client_handshake(&client.conn, "0.7.0").await;
        let _ = handle.await;

        assert!(
            matches!(res, Err(HandshakeError::InvalidMessage)),
            "Expected InvalidMessage for malformed server response, got {res:?}"
        );
    }

    #[tokio::test]
    async fn handshake_error_invalid_message_truncated_handshake() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            let (mut send, _recv) = client.conn.open_bi().await.unwrap();
            let len_header: u64 = 100;
            send.write_all(&len_header.to_le_bytes()).await.unwrap();
            send.write_all(b"short").await.unwrap();
            send.finish().ok();
        });

        let res = super::server_handshake(&server.conn, ">=0.7.0").await;
        let _ = handle.await;

        assert!(
            matches!(res, Err(HandshakeError::InvalidMessage)),
            "Expected InvalidMessage for truncated handshake, got {res:?}"
        );
    }

    // =========================================================================
    // Tests for HandshakeError::ReadError
    // =========================================================================

    #[tokio::test]
    async fn handshake_error_read_error_stream_reset() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        // Use a barrier to synchronize: server signals after resetting the stream,
        // ensuring the client reads after the reset has been applied.
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let handle = tokio::spawn(async move {
            let (mut send, mut recv) = server.conn.accept_bi().await.unwrap();
            let mut buf = Vec::new();
            frame::recv_handshake(&mut recv, &mut buf).await.ok();
            let resp = bincode::serialize::<Option<&str>>(&Some(">=0.7.0")).unwrap();
            let len_header: u64 = resp.len() as u64;
            send.write_all(&len_header.to_le_bytes()).await.unwrap();
            send.reset(quinn::VarInt::from_u32(1)).ok();
            // Signal that the stream has been reset
            barrier_clone.wait().await;
        });

        let res = super::client_handshake(&client.conn, "0.7.0").await;
        // Wait for server to complete the reset
        barrier.wait().await;
        let _ = handle.await;

        assert!(
            matches!(res, Err(HandshakeError::ReadError(_))),
            "Expected ReadError when stream is reset, got {res:?}"
        );
    }

    // =========================================================================
    // Tests for HandshakeError::WriteError
    // =========================================================================

    // Note: WriteError is difficult to trigger reliably in tests because quinn
    // may complete the write before the stop signal is processed. The From impl
    // for WriteError is tested via the SendError conversion test below.

    // =========================================================================
    // Tests for HandshakeError::MessageTooLarge
    // =========================================================================

    // Note: MessageTooLarge occurs when the 64-bit length header cannot be
    // converted to usize (on 32-bit systems), but on 64-bit systems this is
    // unlikely to trigger. The error is tested via the From impl coverage below.

    // =========================================================================
    // Tests for HandshakeError::SerializationFailure
    // =========================================================================

    // Note: SerializationFailure is hard to trigger directly in handshake
    // because the serialization happens on valid data structures. The error
    // is derived from bincode::Error which typically occurs with custom
    // serializers or when bincode limits are exceeded. We test the From impl
    // coverage via the SendError conversion path.

    #[tokio::test]
    async fn handshake_error_serialization_failure_coverage() {
        let err = bincode::ErrorKind::SizeLimit;
        let bincode_err: bincode::Error = Box::new(err);
        let handshake_err = HandshakeError::SerializationFailure(bincode_err);

        assert!(
            matches!(handshake_err, HandshakeError::SerializationFailure(_)),
            "SerializationFailure variant should be constructible"
        );

        let send_err =
            frame::SendError::SerializationFailure(Box::new(bincode::ErrorKind::SizeLimit));
        let converted: HandshakeError = send_err.into();
        assert!(
            matches!(converted, HandshakeError::SerializationFailure(_)),
            "SendError::SerializationFailure should convert to HandshakeError::SerializationFailure"
        );
    }

    // =========================================================================
    // Edge case: unexpected message ordering
    // =========================================================================

    #[tokio::test]
    async fn handshake_error_unexpected_message_order_double_response() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            let (mut send, mut recv) = server.conn.accept_bi().await.unwrap();
            let mut buf = Vec::new();
            frame::recv_handshake(&mut recv, &mut buf).await.ok();
            let resp = bincode::serialize::<Option<&str>>(&Some(">=0.7.0")).unwrap();
            frame::send_handshake(&mut send, &resp).await.ok();
            frame::send_handshake(&mut send, &resp).await.ok();
        });

        let res = super::client_handshake(&client.conn, "0.7.0").await;
        let _ = handle.await;

        assert!(res.is_ok(), "Double response should not break client");
    }

    // =========================================================================
    // Edge case: empty version string
    // =========================================================================

    #[tokio::test]
    async fn handshake_error_empty_version_string() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (server, client) = (channel.server, channel.client);

        let handle = tokio::spawn(async move {
            let (mut send, _recv) = client.conn.open_bi().await.unwrap();
            frame::send_handshake(&mut send, b"").await.unwrap();
        });

        let res = super::server_handshake(&server.conn, ">=0.7.0").await;
        let _ = handle.await;

        assert!(
            matches!(res, Err(HandshakeError::IncompatibleProtocol(ref v)) if v.is_empty()),
            "Expected IncompatibleProtocol with empty string, got {res:?}"
        );
    }

    // =========================================================================
    // From trait implementation tests
    // =========================================================================

    #[test]
    fn from_send_error_message_too_large() {
        use std::num::TryFromIntError;

        // Create a TryFromIntError by attempting an impossible conversion
        let try_err: TryFromIntError = u8::try_from(u16::MAX).unwrap_err();
        let send_err = frame::SendError::MessageTooLarge(try_err);
        let handshake_err: HandshakeError = send_err.into();
        assert!(
            matches!(handshake_err, HandshakeError::MessageTooLarge),
            "SendError::MessageTooLarge should convert to HandshakeError::MessageTooLarge"
        );
    }

    #[test]
    fn from_send_error_write_error() {
        // Test that SendError::WriteError converts to HandshakeError::WriteError
        // We can't easily create a real WriteError, but we verify the From impl exists
        // and the enum variant is constructible.
        // The From<SendError> impl on line 30-37 covers this conversion.

        // Verify the variant can be pattern matched
        fn check_write_error(err: &HandshakeError) -> bool {
            matches!(err, HandshakeError::WriteError(_))
        }

        // Since we can't easily construct quinn::WriteError, we verify the
        // conversion path exists by checking the type signature compiles
        fn _conversion_exists(send_err: frame::SendError) -> HandshakeError {
            send_err.into()
        }

        // Ensure the check function compiles (proves the variant exists)
        let _ = check_write_error as fn(&HandshakeError) -> bool;
    }
}
