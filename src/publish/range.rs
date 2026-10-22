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
    /// Multi-source range read; the body is a [`RequestMultiSourceRange`].
    ///
    /// The response is zero or more event frames, the terminator frame and
    /// exactly one [`RangeStatus`] frame, as described on
    /// [`RequestMultiSourceRange`].
    MultiSourceRange = 4,
    /// Re-read of given events with per-source status; the body is a
    /// [`RequestRawData`].
    ///
    /// The response is framed as for [`MessageCode::MultiSourceRange`]: zero
    /// or more event frames, the terminator frame and exactly one
    /// [`RangeStatus`] frame.
    RawDataWithStatus = 5,
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

/// A range read over several sources of one event kind, sent with
/// [`MessageCode::MultiSourceRange`].
///
/// Each source is read from its own `start` up to the shared `end`, and
/// `count` bounds the number of events across all sources.
///
/// # Response framing
///
/// The server answers on the request's bidirectional stream with:
///
/// 1. zero or more event frames in time order, each written by
///    `send_range_data(send, Some((value, timestamp, source)))`, that is
///    `Option<(i64, String, Vec<u8>)>`, or `Option<(i64, String, Vec<f64>)>`
///    for time series;
/// 2. one terminator frame, written by `send_range_data::<T>(send, None)`;
/// 3. exactly one [`RangeStatus`] frame, written by
///    [`send_range_status`](crate::publish::send_range_status);
///
/// and then finishes the stream. A response that ends before its
/// [`RangeStatus`] frame is incomplete, and the client treats it as a failure
/// of the whole request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestMultiSourceRange {
    /// Event kind, spelled as in `RequestRange::kind`.
    pub kind: String,
    /// `(source, start)` pairs, non-empty, each source at most once. A
    /// source is a sensor name, or a sampling-policy ID when `kind` is a
    /// time-series kind. `start` is inclusive, in nanoseconds.
    pub sources: Vec<(String, i64)>,
    /// Shared exclusive end, in nanoseconds.
    pub end: i64,
    /// Total number of events across all sources, before the boundary rule.
    pub count: usize,
}

/// The status of one source in a [`RangeStatus`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SourceStatus {
    /// A node in charge of the source (or, for time series, the local store) answered.
    Served,
    /// No node is in charge of the source.
    NoNode,
    /// The source could not be served; the reason is human-readable.
    Failed(String),
}

/// Outcome of a multi-source range read or a re-read with status:
/// `Ok` lists one `(source, status)` per distinct requested source, in
/// request order; `Err` is a failure of the whole request, with its reason.
///
/// It is the last frame of a response to [`MessageCode::MultiSourceRange`] or
/// [`MessageCode::RawDataWithStatus`], sent after the terminator frame.
pub type RangeStatus = Result<Vec<(String, SourceStatus)>, String>;

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

        assert_eq!(u32::from(MessageCode::MultiSourceRange), 4);
        assert_eq!(u32::from(MessageCode::RawDataWithStatus), 5);
        assert_eq!(
            MessageCode::try_from(4).unwrap(),
            MessageCode::MultiSourceRange
        );
        assert_eq!(
            MessageCode::try_from(5).unwrap(),
            MessageCode::RawDataWithStatus
        );

        assert!(MessageCode::try_from(0).is_err());
        assert!(MessageCode::try_from(6).is_err());
    }

    #[test]
    fn test_request_multi_source_range_bincode_roundtrip() {
        let request = RequestMultiSourceRange {
            kind: "conn".to_string(),
            sources: vec![("sensor1".to_string(), 100), ("sensor2".to_string(), 250)],
            end: 1_000,
            count: 30,
        };
        let encoded = bincode::serialize(&request).unwrap();
        let decoded: RequestMultiSourceRange = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn test_source_status_bincode_roundtrip() {
        for status in [
            SourceStatus::Served,
            SourceStatus::NoNode,
            SourceStatus::Failed("peer unreachable".to_string()),
        ] {
            let encoded = bincode::serialize(&status).unwrap();
            let decoded: SourceStatus = bincode::deserialize(&encoded).unwrap();
            assert_eq!(decoded, status);
        }
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
