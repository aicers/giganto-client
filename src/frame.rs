//! Functions and errors for handling length-delimited frames.

use std::{mem, num::TryFromIntError};

use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The error type for receiving and deserializing a frame.
#[derive(Debug, Error)]
pub enum RecvError {
    #[error("Failed deserializing message")]
    DeserializationFailure(#[from] bincode::Error),
    #[error("Receive message is too large")]
    MessageTooLarge,
    #[error("Failed to read from a stream")]
    ReadError(#[from] quinn::ReadExactError),
}

/// The error type for sending a message as a frame.
#[derive(Debug, Error)]
pub enum SendError {
    #[error("Failed serializing message")]
    SerializationFailure(#[from] bincode::Error),
    #[error("Send message is too large, so type casting failed")]
    MessageTooLarge(#[from] TryFromIntError),
    #[error("Failed to write to a stream")]
    WriteError(#[from] quinn::WriteError),
}

/// Receives and deserializes a message with a little-endian 4-byte length header.
///
/// # Errors
///
/// * `RecvError::DeserializationFailure`: if the message could not be
///   deserialized
/// * `RecvError::ReadError`: if the message could not be read
/// * `RecvError::MessageTooLarge`: if the message exceeds the maximum size
pub async fn recv<'b, T>(recv: &mut RecvStream, buf: &'b mut Vec<u8>) -> Result<T, RecvError>
where
    T: Deserialize<'b>,
{
    recv_raw(recv, buf).await?;
    Ok(bincode::deserialize(buf)?)
}

/// Receives a sequence of bytes with a little-endian 4-byte length header.
///
/// `buf` will be filled with the message data excluding the 4-byte length
/// header.
///
/// # Errors
///
/// * `RecvError::ReadError`: if the message could not be read
/// * `RecvError::MessageTooLarge`: if the message exceeds the maximum size
pub async fn recv_raw(recv: &mut RecvStream, buf: &mut Vec<u8>) -> Result<(), RecvError> {
    let mut len_buf = [0; mem::size_of::<u32>()];
    recv.read_exact(&mut len_buf).await?;
    prepare_buf(buf, u32::from_le_bytes(len_buf).into())?;
    recv.read_exact(buf.as_mut_slice()).await?;
    Ok(())
}

/// Receives a sequence of bytes with a little-endian 8-byte length header for handshake.
///
/// `buf` will be filled with the message data excluding the 8-byte length
/// header.
///
/// # Errors
///
/// * `RecvError::ReadError`: if the message could not be read
/// * `RecvError::MessageTooLarge`: if the message is too large
pub async fn recv_handshake(recv: &mut RecvStream, buf: &mut Vec<u8>) -> Result<(), RecvError> {
    let mut len_buf = [0; mem::size_of::<u64>()];
    recv.read_exact(&mut len_buf).await?;
    prepare_buf(buf, u64::from_le_bytes(len_buf))?;
    recv.read_exact(buf.as_mut_slice()).await?;
    Ok(())
}

/// Receives a sequence of bytes.
///
/// # Errors
///
/// * `RecvError::ReadError`: if the message could not be read
pub async fn recv_bytes(recv: &mut RecvStream, buf: &mut [u8]) -> Result<(), RecvError> {
    recv.read_exact(buf).await?;
    Ok(())
}

/// Sends a message as a stream of bytes with a little-endian 4-byte length header.
///
/// `buf` will be cleared after the message is sent.
///
/// # Errors
///
/// * `SendError::SerializationFailure`: if the message could not be serialized
/// * `SendError::MessageTooLarge`: if the message is too large
/// * `SendError::WriteError`: if the message could not be written
pub async fn send<T>(send: &mut SendStream, buf: &mut Vec<u8>, msg: T) -> Result<(), SendError>
where
    T: Serialize,
{
    buf.resize(mem::size_of::<u32>(), 0);
    bincode::serialize_into(&mut *buf, &msg)?;
    let len = u32::try_from(buf.len() - mem::size_of::<u32>())?;
    buf[..mem::size_of::<u32>()].clone_from_slice(&len.to_le_bytes());
    send.write_all(buf).await?;
    buf.clear();
    Ok(())
}

/// Sends a sequence of bytes with a little-endian 4-byte length header.
///
/// # Errors
///
/// * `SendError::MessageTooLarge`: if the message is too large
/// * `SendError::WriteError`: if the message could not be written
pub async fn send_raw(send: &mut SendStream, buf: &[u8]) -> Result<(), SendError> {
    let len = u32::try_from(buf.len())?;
    send.write_all(&len.to_le_bytes()).await?;
    send.write_all(buf).await?;
    Ok(())
}

/// Sends a sequence of bytes.
///
/// # Errors
///
/// * `SendError::WriteError`: if the message could not be written
pub async fn send_bytes(send: &mut SendStream, buf: &[u8]) -> Result<(), SendError> {
    send.write_all(buf).await?;
    Ok(())
}

/// Sends a sequence of bytes with a little-endian 8-byte length header for handshake.
///
/// # Errors
///
/// * `SendError::MessageTooLarge`: if the message is too large
/// * `SendError::WriteError`: if the message could not be written
pub async fn send_handshake(send: &mut SendStream, buf: &[u8]) -> Result<(), SendError> {
    let len = u64::try_from(buf.len())?;
    send.write_all(&len.to_le_bytes()).await?;
    send.write_all(buf).await?;
    Ok(())
}

fn prepare_buf(buf: &mut Vec<u8>, len: u64) -> Result<(), RecvError> {
    let len = usize::try_from(len).map_err(|_| RecvError::MessageTooLarge)?;
    if len > buf.len() {
        buf.try_reserve(len - buf.len())
            .map_err(|_| RecvError::MessageTooLarge)?;
    }
    buf.resize(len, 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RecvError, SendError};

    /// Asserts that the result is a specific `RecvError` variant.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_recv_err!(result, RecvError::ReadError(_));
    /// assert_recv_err!(result, RecvError::DeserializationFailure(_));
    /// ```
    macro_rules! assert_recv_err {
        ($res:expr, $pat:pat $(if $guard:expr)?) => {
            match $res {
                Err(ref e) => assert!(
                    matches!(e, $pat $(if $guard)?),
                    "expected {}, got {:?}",
                    stringify!($pat),
                    e
                ),
                Ok(ref v) => panic!("expected RecvError::{}, got Ok({:?})", stringify!($pat), v),
            }
        };
    }

    /// Asserts that the result is a specific `SendError` variant.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_send_err!(result, SendError::WriteError(_));
    /// assert_send_err!(result, SendError::SerializationFailure(_));
    /// ```
    macro_rules! assert_send_err {
        ($res:expr, $pat:pat $(if $guard:expr)?) => {
            match $res {
                Err(ref e) => assert!(
                    matches!(e, $pat $(if $guard)?),
                    "expected {}, got {:?}",
                    stringify!($pat),
                    e
                ),
                Ok(ref v) => panic!("expected SendError::{}, got Ok({:?})", stringify!($pat), v),
            }
        };
    }

    #[tokio::test]
    async fn frame_send_and_recv() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let mut buf = Vec::new();
        super::send(&mut channel.server.send, &mut buf, "hello")
            .await
            .unwrap();
        assert_eq!(buf.len(), 0);
        super::recv_raw(&mut channel.client.recv, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf[0] as usize, "hello".len());
        assert_eq!(&buf[8..], b"hello");

        super::send_raw(&mut channel.server.send, b"world")
            .await
            .unwrap();
        super::recv_raw(&mut channel.client.recv, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, b"world");

        super::send_bytes(&mut channel.server.send, b"hello")
            .await
            .unwrap();
        super::recv_bytes(&mut channel.client.recv, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, b"hello");

        super::send_handshake(&mut channel.server.send, b"hello")
            .await
            .unwrap();
        super::recv_handshake(&mut channel.client.recv, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, b"hello");

        super::send(&mut channel.server.send, &mut buf, "hello")
            .await
            .unwrap();
        assert!(buf.is_empty());
        let received = super::recv::<&str>(&mut channel.client.recv, &mut buf)
            .await
            .unwrap();
        assert_eq!(received, "hello");
    }

    #[test]
    fn prepare_buf_success() {
        let mut buf = Vec::new();
        let len = 1024;
        super::prepare_buf(&mut buf, len).unwrap();
        assert_eq!(buf.len(), 1024);
        assert!(buf.capacity() >= 1024);
    }

    #[test]
    fn prepare_buf_too_large() {
        let mut buf = Vec::new();
        // On 64-bit, this tries to allocate u64::MAX bytes, which fails.
        // On 32-bit, this fails integer conversion.
        let len = u64::MAX;
        let result = super::prepare_buf(&mut buf, len);
        assert!(matches!(result, Err(super::RecvError::MessageTooLarge)));
    }

    #[test]
    fn prepare_buf_allocation_failure() {
        let mut buf = Vec::new();
        // This fits in usize, so it passes the integer conversion check.
        // However, allocating usize::MAX bytes is practically impossible, so try_reserve fails.
        let len = usize::MAX as u64;
        let result = super::prepare_buf(&mut buf, len);
        assert!(matches!(result, Err(super::RecvError::MessageTooLarge)));
    }

    #[tokio::test]
    async fn frame_error_cases() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Test RecvError::DeserializationFailure
        let mut buf = Vec::new();
        // Send a message that is clearly not a valid bincode for a complex struct.
        // Let's try to deserialize into a Vec<u32> from a single byte.
        super::send_raw(&mut channel.server.send, b"1")
            .await
            .unwrap();
        let result = super::recv::<Vec<u32>>(&mut channel.client.recv, &mut buf).await;
        assert!(matches!(
            result,
            Err(super::RecvError::DeserializationFailure(_))
        ));

        // Test MessageTooLarge during recv
        // Let's try a reliable way to trigger MessageTooLarge:
        // 8-byte length in recv_handshake with u64::MAX.
        let huge_len_buf_64 = [255u8; 8];
        channel
            .server
            .send
            .write_all(&huge_len_buf_64)
            .await
            .unwrap();
        let result = super::recv_handshake(&mut channel.client.recv, &mut buf).await;
        assert!(matches!(result, Err(super::RecvError::MessageTooLarge)));

        // Test Empty Message
        super::send_raw(&mut channel.server.send, b"")
            .await
            .unwrap();
        super::recv_raw(&mut channel.client.recv, &mut buf)
            .await
            .unwrap();
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn recv_raw_returns_read_error_when_stream_closed_before_header() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Close the send stream without sending any data
        channel.server.send.finish().unwrap();

        // Attempt to receive - should fail because stream closed before header
        let mut buf = Vec::new();
        let result = super::recv_raw(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::ReadError(_));

        // Verify it's a FinishedEarly error (stream ended before header bytes)
        if let Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(bytes_read))) = result
        {
            assert_eq!(bytes_read, 0, "expected 0 bytes read before stream ended");
        }
    }

    #[tokio::test]
    async fn recv_raw_returns_read_error_when_stream_closed_during_header() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send only 2 bytes of a 4-byte header then close
        channel.server.send.write_all(&[0x05, 0x00]).await.unwrap();
        channel.server.send.finish().unwrap();

        // Attempt to receive - should fail because stream closed mid-header
        let mut buf = Vec::new();
        let result = super::recv_raw(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::ReadError(_));

        // Verify it's a FinishedEarly error with partial header read
        if let Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(bytes_read))) = result
        {
            assert_eq!(bytes_read, 2, "expected 2 bytes read before stream ended");
        }
    }

    #[tokio::test]
    async fn recv_raw_returns_read_error_when_payload_truncated() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send a header indicating 10 bytes but only provide 3 bytes of payload
        let len: u32 = 10;
        channel
            .server
            .send
            .write_all(&len.to_le_bytes())
            .await
            .unwrap();
        channel.server.send.write_all(b"abc").await.unwrap();
        channel.server.send.finish().unwrap();

        // Attempt to receive - should fail because payload is truncated
        let mut buf = Vec::new();
        let result = super::recv_raw(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::ReadError(_));

        // Verify it's a FinishedEarly error with partial payload read
        if let Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(bytes_read))) = result
        {
            assert_eq!(
                bytes_read, 3,
                "expected 3 bytes of payload read before stream ended"
            );
        }
    }

    #[tokio::test]
    async fn recv_bytes_returns_read_error_when_stream_closed() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Close the send stream without sending any data
        channel.server.send.finish().unwrap();

        // Attempt to receive 5 bytes - should fail because stream closed
        let mut buf = [0u8; 5];
        let result = super::recv_bytes(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::ReadError(_));

        // Verify it's a FinishedEarly error
        if let Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(bytes_read))) = result
        {
            assert_eq!(bytes_read, 0, "expected 0 bytes read before stream ended");
        }
    }

    #[tokio::test]
    async fn recv_handshake_returns_read_error_when_stream_closed_before_header() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Close the send stream without sending any data
        channel.server.send.finish().unwrap();

        // Attempt to receive handshake - should fail because stream closed
        let mut buf = Vec::new();
        let result = super::recv_handshake(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::ReadError(_));
    }

    #[tokio::test]
    async fn recv_handshake_returns_read_error_when_payload_truncated() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send an 8-byte header indicating 100 bytes, but only send 10
        let len: u64 = 100;
        channel
            .server
            .send
            .write_all(&len.to_le_bytes())
            .await
            .unwrap();
        channel.server.send.write_all(b"0123456789").await.unwrap();
        channel.server.send.finish().unwrap();

        // Attempt to receive handshake - should fail because payload truncated
        let mut buf = Vec::new();
        let result = super::recv_handshake(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::ReadError(_));

        // Verify it's a FinishedEarly error with partial read
        if let Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(bytes_read))) = result
        {
            assert_eq!(
                bytes_read, 10,
                "expected 10 bytes of payload read before stream ended"
            );
        }
    }

    #[tokio::test]
    async fn recv_returns_deserialization_failure_for_invalid_data() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send raw bytes that cannot be deserialized as the expected type
        // We'll try to receive a String but send invalid bincode data
        let invalid_data = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // Invalid bincode for String
        super::send_raw(&mut channel.server.send, &invalid_data)
            .await
            .unwrap();

        // Attempt to receive and deserialize as String - should fail
        let mut buf = Vec::new();
        let result = super::recv::<String>(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::DeserializationFailure(_));
    }

    #[tokio::test]
    async fn recv_returns_deserialization_failure_for_truncated_serialized_data() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send a truncated serialized string - missing the actual string bytes
        // bincode format for String: 8 bytes length + string bytes
        // We send length=5 but only provide 2 chars worth
        let truncated_data = [
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // length = 5
            b'a', b'b', // only 2 bytes instead of 5
        ];
        super::send_raw(&mut channel.server.send, &truncated_data)
            .await
            .unwrap();

        // Attempt to receive as String - should fail deserialization
        let mut buf = Vec::new();
        let result = super::recv::<String>(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::DeserializationFailure(_));
    }

    #[tokio::test]
    async fn send_returns_write_error_when_stream_stopped() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Have the client stop the server's send stream with an error code
        channel
            .client
            .recv
            .stop(quinn::VarInt::from_u32(42))
            .unwrap();

        // Give the stop signal time to propagate
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Attempt to send - should fail because stream was stopped
        let mut buf = Vec::new();
        let result = super::send(&mut channel.server.send, &mut buf, "hello").await;

        assert_send_err!(result, SendError::WriteError(_));

        // Verify it's a Stopped error with the correct code
        if let Err(SendError::WriteError(quinn::WriteError::Stopped(code))) = result {
            assert_eq!(code.into_inner(), 42, "expected stop code 42");
        }
    }

    #[tokio::test]
    async fn send_raw_returns_write_error_when_stream_stopped() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Have the client stop the server's send stream
        channel
            .client
            .recv
            .stop(quinn::VarInt::from_u32(100))
            .unwrap();

        // Give the stop signal time to propagate
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Attempt to send raw - should fail
        let result = super::send_raw(&mut channel.server.send, b"hello world").await;

        assert_send_err!(result, SendError::WriteError(_));
    }

    #[tokio::test]
    async fn send_bytes_returns_write_error_when_stream_stopped() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Have the client stop the server's send stream
        channel
            .client
            .recv
            .stop(quinn::VarInt::from_u32(200))
            .unwrap();

        // Give the stop signal time to propagate
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Attempt to send bytes - should fail
        let result = super::send_bytes(&mut channel.server.send, b"hello").await;

        assert_send_err!(result, SendError::WriteError(_));
    }

    #[tokio::test]
    async fn send_handshake_returns_write_error_when_stream_stopped() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Have the client stop the server's send stream
        channel
            .client
            .recv
            .stop(quinn::VarInt::from_u32(300))
            .unwrap();

        // Give the stop signal time to propagate
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Attempt to send handshake - should fail
        let result = super::send_handshake(&mut channel.server.send, b"handshake data").await;

        assert_send_err!(result, SendError::WriteError(_));
    }

    #[tokio::test]
    async fn send_returns_write_error_when_connection_closed() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Close the client connection entirely
        channel
            .client
            .conn
            .close(quinn::VarInt::from_u32(0), b"closing");

        // Give the close signal time to propagate
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Attempt to send - should fail because connection closed
        let mut buf = Vec::new();
        let result = super::send(&mut channel.server.send, &mut buf, "hello").await;

        assert_send_err!(result, SendError::WriteError(_));

        // Verify it's a ConnectionLost error
        assert!(
            matches!(
                result,
                Err(SendError::WriteError(quinn::WriteError::ConnectionLost(_)))
            ),
            "expected ConnectionLost, got {result:?}"
        );
    }

    #[tokio::test]
    async fn recv_raw_returns_read_error_when_connection_closed() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Close the server connection entirely
        channel
            .server
            .conn
            .close(quinn::VarInt::from_u32(0), b"closing");

        // Give the close signal time to propagate
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Attempt to receive - should fail because connection closed
        let mut buf = Vec::new();
        let result = super::recv_raw(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::ReadError(_));
    }

    #[tokio::test]
    async fn recv_bytes_returns_read_error_for_partial_data() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send only 3 bytes then close
        channel.server.send.write_all(b"abc").await.unwrap();
        channel.server.send.finish().unwrap();

        // Attempt to receive 10 bytes - should fail with FinishedEarly
        let mut buf = [0u8; 10];
        let result = super::recv_bytes(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::ReadError(_));

        // Verify it's a FinishedEarly error showing we only got 3 bytes
        if let Err(RecvError::ReadError(quinn::ReadExactError::FinishedEarly(bytes_read))) = result
        {
            assert_eq!(bytes_read, 3, "expected 3 bytes read before stream ended");
        }
    }

    #[tokio::test]
    async fn recv_returns_read_error_when_empty_stream() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Close the stream immediately without sending anything
        channel.server.send.finish().unwrap();

        // Attempt to receive - should fail because stream is empty
        let mut buf = Vec::new();
        let result = super::recv::<String>(&mut channel.client.recv, &mut buf).await;

        // This should be a ReadError (FinishedEarly) since we can't even read the header
        assert_recv_err!(result, RecvError::ReadError(_));
    }

    /// Tests that `recv_handshake` returns `RecvError::MessageTooLarge` when
    /// the 8-byte length header contains a value that exceeds allocatable capacity.
    #[tokio::test]
    async fn recv_handshake_returns_message_too_large_for_oversized_length() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send an 8-byte length header with u64::MAX, which exceeds any allocatable size
        let oversized_len: u64 = u64::MAX;
        channel
            .server
            .send
            .write_all(&oversized_len.to_le_bytes())
            .await
            .unwrap();

        // Attempt to receive - should fail with MessageTooLarge
        let mut buf = Vec::new();
        let result = super::recv_handshake(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::MessageTooLarge);
    }

    /// Tests that `TryFromIntError` correctly converts to `SendError::MessageTooLarge`.
    ///
    /// This verifies the `From<TryFromIntError>` implementation that `send_raw` relies on
    /// when `buf.len()` exceeds `u32::MAX`. We cannot practically allocate >4GB in a unit
    /// test, so we test the conversion mechanism directly. The actual `send_raw` behavior
    /// with oversized buffers is covered by the next test using an unsafe mock buffer.
    #[test]
    fn send_error_message_too_large_from_try_from_int_error() {
        use std::num::TryFromIntError;

        // Simulate the same conversion that send_raw performs: u32::try_from(buf.len())
        let large_len: usize = u32::MAX as usize + 1;
        let err: Result<u32, TryFromIntError> = large_len.try_into();
        let try_err = err.unwrap_err();

        // Verify the conversion to SendError::MessageTooLarge works
        let send_err: SendError = try_err.into();
        assert!(
            matches!(send_err, SendError::MessageTooLarge(_)),
            "expected MessageTooLarge, got {send_err:?}"
        );
    }

    /// Tests that `send_raw` returns `SendError::MessageTooLarge` when provided
    /// a buffer with length exceeding `u32::MAX`.
    ///
    /// This test uses an unsafe mock slice with a fabricated length to simulate
    /// an oversized buffer without actually allocating >4GB of memory.
    #[tokio::test]
    async fn send_raw_returns_message_too_large_for_oversized_buffer() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Create a mock slice with a length exceeding u32::MAX.
        // SAFETY: We never actually read from or dereference this slice;
        // send_raw will fail at the length check before any I/O occurs.
        let small_buf = [0u8; 8];
        let oversized_slice: &[u8] =
            unsafe { std::slice::from_raw_parts(small_buf.as_ptr(), u32::MAX as usize + 1) };

        // Attempt to send - should fail with MessageTooLarge before any I/O
        let result = super::send_raw(&mut channel.server.send, oversized_slice).await;

        assert_send_err!(result, SendError::MessageTooLarge(_));
    }

    /// Tests that `send` returns `SerializationFailure` when bincode cannot
    /// serialize the provided data.
    #[tokio::test]
    async fn send_returns_serialization_failure_for_unserializable_data() {
        use serde::ser::{Serialize, Serializer};

        use crate::test::{TOKEN, channel};

        // Define a type that always fails to serialize
        struct AlwaysFailsToSerialize;

        impl Serialize for AlwaysFailsToSerialize {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                // Simulate a serialization failure
                Err(serde::ser::Error::custom(
                    "intentional serialization failure",
                ))
            }
        }

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let mut buf = Vec::new();
        let result = super::send(&mut channel.server.send, &mut buf, AlwaysFailsToSerialize).await;

        assert_send_err!(result, SendError::SerializationFailure(_));
    }

    /// Tests that `recv` returns `DeserializationFailure` when trying to
    /// deserialize into a type with different structure than what was sent.
    #[tokio::test]
    async fn recv_returns_deserialization_failure_for_type_mismatch() {
        use serde::Deserialize;

        use crate::test::{TOKEN, channel};

        // Define a struct that expects specific fields
        #[derive(Debug, Deserialize)]
        struct ExpectedStruct {
            _field1: u64,
            _field2: String,
            _field3: Vec<u8>,
        }

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Send a simple u32 value
        let mut buf = Vec::new();
        super::send(&mut channel.server.send, &mut buf, 42u32)
            .await
            .unwrap();

        // Try to receive as a complex struct - should fail deserialization
        let result = super::recv::<ExpectedStruct>(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::DeserializationFailure(_));
    }

    /// Tests `ReadError` variant wrapping `quinn::ReadExactError::ReadError`.
    #[tokio::test]
    async fn recv_raw_returns_read_error_with_read_error_variant_when_reset() {
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Reset the stream with an error code instead of finishing cleanly
        channel
            .server
            .send
            .reset(quinn::VarInt::from_u32(123))
            .unwrap();

        // Attempt to receive - should fail with a ReadError containing ReadError
        let mut buf = Vec::new();
        let result = super::recv_raw(&mut channel.client.recv, &mut buf).await;

        assert_recv_err!(result, RecvError::ReadError(_));

        // Verify it's specifically a ReadError (not FinishedEarly)
        if let Err(RecvError::ReadError(quinn::ReadExactError::ReadError(read_err))) = result {
            // The inner error should be a Reset error
            assert!(
                matches!(read_err, quinn::ReadError::Reset(_)),
                "expected Reset error, got {read_err:?}"
            );
        }
    }

    /// Tests that error Display implementations provide useful messages.
    #[test]
    fn error_display_messages_are_descriptive() {
        use std::num::TryFromIntError;

        // Test RecvError::MessageTooLarge display
        // RecvError::MessageTooLarge is a unit variant
        let recv_err = RecvError::MessageTooLarge;
        let msg = recv_err.to_string();
        assert!(
            msg.contains("too large"),
            "RecvError::MessageTooLarge message should mention size: {msg}"
        );

        // Test SendError::MessageTooLarge display
        // Use a conversion that always fails regardless of platform
        let result: Result<u8, TryFromIntError> = 256u16.try_into();
        let send_err: SendError = result.unwrap_err().into();
        let msg = send_err.to_string();
        assert!(
            msg.contains("too large") || msg.contains("type casting"),
            "SendError::MessageTooLarge message should mention size: {msg}"
        );
    }

    /// Tests error source chain for `RecvError::ReadError`.
    #[tokio::test]
    async fn recv_error_source_chain_is_accessible() {
        use std::error::Error;

        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Close the stream to trigger ReadError
        channel.server.send.finish().unwrap();

        let mut buf = Vec::new();
        let result = super::recv_raw(&mut channel.client.recv, &mut buf).await;

        if let Err(ref recv_err) = result {
            // Verify the error has a source (the underlying quinn error)
            assert!(
                recv_err.source().is_some(),
                "RecvError should have an underlying source error"
            );
        } else {
            panic!("expected error, got Ok");
        }
    }
}
