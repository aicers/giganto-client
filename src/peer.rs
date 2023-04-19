use crate::frame::{self, recv_bytes, recv_raw, send_bytes, RecvError, SendError};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use quinn::{ConnectionError, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::{mem, net::SocketAddr};
use thiserror::Error;

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub address: SocketAddr,
    pub host_name: String,
}

#[allow(clippy::module_name_repetitions)]
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, IntoPrimitive, PartialEq, Serialize, TryFromPrimitive,
)]
#[repr(u32)]
pub enum PeerCode {
    UpdatePeerList = 0,
    UpdateSourceList = 1,
}

/// The error type for a publish failure.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Error)]
pub enum PeerError {
    #[error("Connection closed by peer")]
    ConnectionClosed,
    #[error("Connection lost")]
    ConnectionLost(#[from] ConnectionError),
    #[error("Cannot receive a peer message")]
    ReadError(#[from] quinn::ReadError),
    #[error("Cannot send a peer message")]
    WriteError(#[from] quinn::WriteError),
    #[error("Cannot serialize/deserialize a peer message")]
    SerialDeserialFailure(#[from] bincode::Error),
    #[error("Message is too large, so type casting failed")]
    MessageTooLarge,
    #[error("Invalid message type")]
    InvalidMessageType,
    #[error("Invalid message data")]
    InvalidMessageData,
}

impl From<frame::RecvError> for PeerError {
    fn from(e: frame::RecvError) -> Self {
        match e {
            RecvError::DeserializationFailure(e) => PeerError::SerialDeserialFailure(e),
            RecvError::ReadError(e) => match e {
                quinn::ReadExactError::FinishedEarly => PeerError::ConnectionClosed,
                quinn::ReadExactError::ReadError(e) => PeerError::ReadError(e),
            },
            RecvError::MessageTooLarge(_) => PeerError::MessageTooLarge,
        }
    }
}

impl From<frame::SendError> for PeerError {
    fn from(e: frame::SendError) -> Self {
        match e {
            SendError::SerializationFailure(e) => PeerError::SerialDeserialFailure(e),
            SendError::MessageTooLarge(_) => PeerError::MessageTooLarge,
            SendError::WriteError(e) => PeerError::WriteError(e),
        }
    }
}

/// Send the peer data to be updated (peer list/source).
///
/// # Errors
///
/// * `PeerError::SerialDeserialFailure`: if the data to sent could not be serialized,
/// * `PeerError::MessageTooLarge`: if the data to sent is too large
/// * `PeerError::WriteError`: if the the data to sent could not be written
pub async fn send_peer_data<T>(
    send: &mut SendStream,
    msg: PeerCode,
    update_data: T,
) -> Result<(), PeerError>
where
    T: Serialize,
{
    // send PeerCode
    let msg_type: u32 = msg.into();
    send_bytes(send, &msg_type.to_le_bytes()).await?;

    // send the peer data to be updated
    let mut buf = Vec::new();
    frame::send(send, &mut buf, update_data).await?;
    Ok(())
}

/// Receives the peer data to be updated (peer list/source).
///
/// # Errors
///
/// * `PeerError::ReadError`: if the data to received could not be read
/// * `PeerError::InvalidMessageType`: if the data to received could not be converted to valid type
pub async fn receive_peer_data(recv: &mut RecvStream) -> Result<(PeerCode, Vec<u8>), PeerError> {
    // receive PeerCode
    let mut buf = [0; mem::size_of::<u32>()];
    recv_bytes(recv, &mut buf).await?;
    let msg_type =
        PeerCode::try_from(u32::from_le_bytes(buf)).map_err(|_| PeerError::InvalidMessageType)?;

    // receive the peer data to be updated
    let mut buf = Vec::new();
    recv_raw(recv, &mut buf).await?;
    Ok((msg_type, buf))
}

#[cfg(test)]
mod tests {
    use crate::{
        peer::{PeerCode, PeerInfo},
        test::{channel, TOKEN},
    };

    #[tokio::test]
    async fn peer_send_recv() {
        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let peer_data = PeerInfo {
            address: "127.0.0.1:8080".parse().unwrap(),
            host_name: "einsis".to_string(),
        };

        super::send_peer_data::<PeerInfo>(
            &mut channel.client.send,
            PeerCode::UpdatePeerList,
            peer_data.clone(),
        )
        .await
        .unwrap();

        let (msg_type, msg_data) = super::receive_peer_data(&mut channel.server.recv)
            .await
            .unwrap();

        assert_eq!(msg_type, PeerCode::UpdatePeerList);
        assert_eq!(msg_data, bincode::serialize(&peer_data).unwrap());
    }
}
