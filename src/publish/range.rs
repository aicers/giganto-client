use anyhow::Result;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

use crate::bincode_utils;

pub trait ResponseRangeData {
    /// # Errors
    ///
    /// Will return `Err` if response data's serialize faild.
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError>;

    /// # Errors
    ///
    /// Will return `Err` if serialize faild.
    fn response_done() -> Result<Vec<u8>, bincode::error::EncodeError> {
        bincode_utils::encode_legacy(&None::<(i64, String, Vec<u8>)>)
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, IntoPrimitive, PartialEq, Serialize, TryFromPrimitive,
)]
#[repr(u32)]
pub enum MessageCode {
    ReqRange = 1,
    Pcap = 2,
    RawData = 3,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RequestRange {
    pub sensor: String, //network event: certification name, time_series: sampling policy id
    pub kind: String,
    pub start: i64,
    pub end: i64,
    pub count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestRawData {
    pub kind: String,
    pub input: Vec<(String, Vec<i64>)>,
}
