// Utility functions to help with bincode v1 to v2 migration
use serde::{Serialize, de::DeserializeOwned};

/// Serialize data using bincode v2 with legacy configuration
pub fn encode_legacy<T: Serialize>(data: &T) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(data, bincode::config::legacy())
}

/// Deserialize data using bincode v2 with legacy configuration
pub fn decode_legacy<T: DeserializeOwned>(data: &[u8]) -> Result<T, bincode::error::DecodeError> {
    let (result, _len) = bincode::serde::decode_from_slice(data, bincode::config::legacy())?;
    Ok(result)
}

/// Serialize data into an existing writer using bincode v2 with legacy configuration
pub fn encode_into<W: std::io::Write, T: Serialize>(
    writer: &mut W,
    data: &T,
) -> Result<usize, bincode::error::EncodeError> {
    bincode::serde::encode_into_std_write(data, writer, bincode::config::legacy())
}
