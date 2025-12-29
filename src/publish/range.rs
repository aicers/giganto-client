use anyhow::Result;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

pub trait ResponseRangeData {
    /// # Errors
    ///
    /// Will return `Err` if response data's serialize faild.
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error>;

    /// # Errors
    ///
    /// Will return `Err` if serialize faild.
    fn response_done() -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize::<Option<(i64, String, Vec<u8>)>>(&None)
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

#[cfg(test)]
mod tests {
    use super::*;

    struct MockResponseRangeData;

    impl ResponseRangeData for MockResponseRangeData {
        fn response_data(&self, _timestamp: i64, _sensor: &str) -> Result<Vec<u8>, bincode::Error> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_message_code_conversion() {
        assert_eq!(u32::from(MessageCode::ReqRange), 1);
        assert_eq!(u32::from(MessageCode::Pcap), 2);
        assert_eq!(u32::from(MessageCode::RawData), 3);

        assert_eq!(MessageCode::try_from(1).unwrap(), MessageCode::ReqRange);
        assert_eq!(MessageCode::try_from(2).unwrap(), MessageCode::Pcap);
        assert_eq!(MessageCode::try_from(3).unwrap(), MessageCode::RawData);
    }

    #[test]
    fn test_mock_response_data() {
        let mock = MockResponseRangeData;
        let res = mock.response_data(100, "sensor").unwrap();
        assert_eq!(res, vec![]);
    }

    #[test]
    fn test_response_done() {
        let done = MockResponseRangeData::response_done().unwrap();
        let decoded: Option<(i64, String, Vec<u8>)> = bincode::deserialize(&done).unwrap();
        assert!(decoded.is_none());
    }
}
