//! A protocol implementation for sending raw events to the Giganto server.

pub mod log;
pub mod netflow;
pub mod network;
pub mod statistics;
pub mod sysmon;
pub mod timeseries;

use std::fmt::Display;

use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::RawEventKind;
use crate::frame::{self, RecvError, SendError};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Packet {
    pub packet_timestamp: i64,
    pub packet: Vec<u8>,
}

/// Sends the record type. (`RawEventKind`)
///
/// # Errors
///
/// * `SendError::WriteError` if the record header could not be written
pub async fn send_record_header(
    send: &mut SendStream,
    record_type: RawEventKind,
) -> Result<(), SendError> {
    frame::send_bytes(send, &u32::from(record_type).to_le_bytes()).await?;
    Ok(())
}

/// Sends the record data. (timestamp / record structure)
///
/// # Errors
///
/// * `SendError::SerializationFailure`: if the event data could not be serialized
/// * `SendError::MessageTooLarge`: if the event data is too large
/// * `SendError::WriteError`: if the event data could not be written
pub async fn send_event<T>(
    send: &mut SendStream,
    timestamp: i64,
    record_data: T,
) -> Result<(), SendError>
where
    T: Serialize,
{
    frame::send_bytes(send, &timestamp.to_le_bytes()).await?;
    let mut buf = Vec::new();
    frame::send(send, &mut buf, record_data).await?;
    Ok(())
}

/// Receives the record type. (`RawEventKind`)
///
/// # Errors
///
/// * `RecvError::ReadError`: if the record header could not be read
pub async fn receive_record_header(recv: &mut RecvStream, buf: &mut [u8]) -> Result<(), RecvError> {
    frame::recv_bytes(recv, buf).await?;
    Ok(())
}

/// Receives the record data. (timestamp / record structure)
///
/// # Errors
///
/// * `RecvError::ReadError`: if the event data could not be read
pub async fn receive_event(recv: &mut RecvStream) -> Result<(Vec<u8>, i64), RecvError> {
    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    frame::recv_bytes(recv, &mut ts_buf).await?;
    let timestamp = i64::from_le_bytes(ts_buf);

    let mut record_buf = Vec::new();
    frame::recv_raw(recv, &mut record_buf).await?;
    Ok((record_buf, timestamp))
}

/// Receives the ack timestamp. (big-endian)
///
/// # Errors
///
/// * `RecvError::ReadError`: if the ack timestamp data could not be read
pub async fn receive_ack_timestamp(recv: &mut RecvStream) -> Result<i64, RecvError> {
    let mut ts_buf = [0; std::mem::size_of::<u64>()];
    frame::recv_bytes(recv, &mut ts_buf).await?;
    let timestamp = i64::from_be_bytes(ts_buf);
    Ok(timestamp)
}

/// Canonical strftime format for range-data datetime fields.
///
/// Serialized values are RFC 3339 with a fixed `+00:00` UTC offset (not `Z`).
/// Sub-second digits use variable width (`%.f`): trailing zeros are trimmed and
/// the fractional part is omitted entirely when the sub-second value is zero.
pub const RFC3339_RANGE_DATA_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.f%:z";

/// Converts a nanosecond timestamp to the canonical range-data RFC 3339 string.
#[must_use]
pub(crate) fn convert_time_format(timestamp: i64) -> String {
    jiff::Timestamp::from_nanosecond(i128::from(timestamp)).map_or_else(
        |_| format!("INVALID_TIMESTAMP({timestamp})"),
        |ts| ts.strftime(RFC3339_RANGE_DATA_FORMAT).to_string(),
    )
}

fn as_str_or_default(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

pub(crate) fn sanitize_csv_field(s: &str) -> String {
    if s.is_empty() {
        "-".to_string()
    } else {
        s.replace(['\t', '\n', '\r'], " ")
    }
}

pub(crate) fn sanitize_csv_field_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "-".to_string()
    } else {
        std::str::from_utf8(bytes)
            .unwrap_or_default()
            .replace(['\t', '\n', '\r'], " ")
    }
}

fn vec_to_string_or_default<T>(vec: &[T]) -> String
where
    T: Display,
{
    if vec.is_empty() {
        "-".to_string()
    } else {
        vec.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn to_string_or_empty<T: Display>(option: Option<T>) -> String {
    match option {
        Some(val) => val.to_string(),
        None => "-".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;
    #[tokio::test]
    async fn ingest_send_recv() {
        use std::{mem, net::IpAddr};

        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // send/recv event type
        super::send_record_header(&mut channel.client.send, super::RawEventKind::Conn)
            .await
            .unwrap();

        let mut buf = vec![0; mem::size_of::<u32>()];
        super::receive_record_header(&mut channel.server.recv, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, u32::from(super::RawEventKind::Conn).to_le_bytes());

        // send/recv event data
        let conn = super::network::Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: String::new(),
            start_time: 500,
            duration: 500,
            service: "-".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 21515,
            resp_l2_bytes: 27889,
        };
        super::send_event(&mut channel.client.send, 9999, conn.clone())
            .await
            .unwrap();
        let (data, timestamp) = super::receive_event(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(timestamp, 9999);
        assert_eq!(data, bincode::serialize(&conn).unwrap());

        // recv ack timestamp
        crate::frame::send_bytes(&mut channel.client.send, &8888_i64.to_be_bytes())
            .await
            .unwrap();
        let timestamp = super::receive_ack_timestamp(&mut channel.server.recv)
            .await
            .unwrap();
        assert_eq!(timestamp, 8888);
    }

    #[tokio::test]
    async fn send_record_header_write_error_returns_error() {
        use crate::frame::SendError;
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        // Finish the stream to force a write error.
        channel.client.send.finish().ok();

        let err = super::send_record_header(&mut channel.client.send, super::RawEventKind::Conn)
            .await
            .expect_err("expected send_record_header to fail after finish");
        assert!(matches!(err, SendError::WriteError(_)));
    }

    #[tokio::test]
    async fn receive_record_header_short_read_returns_error() {
        use crate::frame::RecvError;
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        channel
            .server
            .send
            .write_all(&u32::from(super::RawEventKind::Conn).to_le_bytes()[..2])
            .await
            .unwrap();
        channel.server.send.finish().ok();

        let mut buf = [0; std::mem::size_of::<u32>()];
        let err = super::receive_record_header(&mut channel.client.recv, &mut buf)
            .await
            .expect_err("expected short read to fail");
        assert!(matches!(err, RecvError::ReadError(_)));
    }

    #[tokio::test]
    async fn receive_event_short_read_returns_error() {
        use crate::frame::RecvError;
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        channel
            .server
            .send
            .write_all(&1234_i64.to_le_bytes()[..4])
            .await
            .unwrap();
        channel.server.send.finish().ok();

        let err = super::receive_event(&mut channel.client.recv)
            .await
            .expect_err("expected short read to fail");
        assert!(matches!(err, RecvError::ReadError(_)));
    }

    #[tokio::test]
    async fn receive_ack_timestamp_short_read_returns_error() {
        use crate::frame::RecvError;
        use crate::test::{TOKEN, channel};

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        channel
            .server
            .send
            .write_all(&8888_i64.to_be_bytes()[..4])
            .await
            .unwrap();
        channel.server.send.finish().ok();

        let err = super::receive_ack_timestamp(&mut channel.client.recv)
            .await
            .expect_err("expected short read to fail");
        assert!(matches!(err, RecvError::ReadError(_)));
    }

    // ==================== Edge Case Tests ====================
    // `%.f` emits variable-width sub-seconds: trailing zeros are trimmed and the
    // fractional part is dropped entirely when the sub-second value is zero.
    const CONVERT_TIME_FORMAT_CASES: &[(i64, &str)] = &[
        (0, "1970-01-01T00:00:00+00:00"),
        (1, "1970-01-01T00:00:00.000000001+00:00"),
        (-1, "1969-12-31T23:59:59.999999999+00:00"),
        (999_999_999, "1970-01-01T00:00:00.999999999+00:00"),
        (1_000_000_000, "1970-01-01T00:00:01+00:00"),
        (1_000_000_001, "1970-01-01T00:00:01.000000001+00:00"),
        (-999_999_999, "1969-12-31T23:59:59.000000001+00:00"),
        (-1_000_000_000, "1969-12-31T23:59:59+00:00"),
        (-1_000_000_001, "1969-12-31T23:59:58.999999999+00:00"),
        (1_999_999_999, "1970-01-01T00:00:01.999999999+00:00"),
        (2_000_000_001, "1970-01-01T00:00:02.000000001+00:00"),
        (-1_999_999_999, "1969-12-31T23:59:58.000000001+00:00"),
        (-2_000_000_001, "1969-12-31T23:59:57.999999999+00:00"),
        (123_456_789_000_000_000, "1973-11-29T21:33:09+00:00"),
        (-123_456_789_000_000_000, "1966-02-02T02:26:51+00:00"),
        (
            1_773_586_804_043_577_000,
            "2026-03-15T15:00:04.043577+00:00",
        ),
    ];

    #[test]
    fn convert_time_format_edge_cases() {
        for (input, expected) in CONVERT_TIME_FORMAT_CASES {
            let result = super::convert_time_format(*input);
            assert_eq!(result, *expected);
            assert!(
                result.ends_with("+00:00"),
                "expected numeric UTC offset, got {result}"
            );
            assert!(!result.ends_with('Z'), "expected +00:00 offset, not Z");
        }
    }

    #[test]
    fn convert_time_format_extreme_values_do_not_panic() {
        for input in [i64::MAX, i64::MIN] {
            let result = super::convert_time_format(input);
            assert!(result.ends_with("+00:00") || result.starts_with("INVALID_TIMESTAMP"));
        }
    }

    #[test]
    fn convert_time_format_round_trip_chrono() {
        let cases: &[i64] = &[
            0,
            1,
            -1,
            999_999_999,
            1_000_000_000,
            1_000_000_001,
            -999_999_999,
            -1_000_000_000,
            -1_000_000_001,
            1_773_586_804_043_577_000,
            i64::MAX,
            i64::MIN,
        ];

        for input in cases {
            let formatted = super::convert_time_format(*input);
            if formatted.starts_with("INVALID_TIMESTAMP") {
                continue;
            }

            let parsed = DateTime::parse_from_rfc3339(&formatted)
                .unwrap_or_else(|err| panic!("failed to parse {formatted} with chrono: {err}"));
            assert_eq!(
                parsed.timestamp_nanos_opt().unwrap(),
                *input,
                "chrono round-trip failed for {input}"
            );
        }
    }

    #[test]
    fn convert_time_format_round_trip_jiff() {
        let cases: &[i64] = &[
            0,
            1,
            -1,
            999_999_999,
            1_000_000_000,
            1_000_000_001,
            -999_999_999,
            -1_000_000_000,
            -1_000_000_001,
            1_773_586_804_043_577_000,
            i64::MAX,
            i64::MIN,
        ];

        for input in cases {
            let formatted = super::convert_time_format(*input);
            if formatted.starts_with("INVALID_TIMESTAMP") {
                continue;
            }

            let parsed: jiff::Timestamp = formatted
                .parse()
                .unwrap_or_else(|err| panic!("failed to parse {formatted} with jiff: {err}"));
            assert_eq!(
                i64::try_from(parsed.as_nanosecond()).unwrap(),
                *input,
                "jiff round-trip failed for {input}"
            );
        }
    }

    /// Table-driven tests for `as_str_or_default`
    #[test]
    fn as_str_or_default_edge_cases() {
        // Static test cases
        let static_cases: &[(&str, &str, &str)] = &[
            ("empty string", "", "-"),
            ("single character", "a", "a"),
            ("whitespace only", " ", " "),
            ("tab only", "\t", "\t"),
            ("dash string", "-", "-"),
            ("unicode string", "日本語", "日本語"),
        ];

        for (name, input, expected) in static_cases {
            let result = super::as_str_or_default(input);
            assert_eq!(result, *expected, "Test case '{name}' failed");
        }
    }

    /// Table-driven tests for `sanitize_csv_field`
    #[test]
    fn sanitize_csv_field_edge_cases() {
        struct TestCase {
            name: &'static str,
            input: &'static str,
            expected: &'static str,
        }

        let test_cases = [
            TestCase {
                name: "empty string",
                input: "",
                expected: "-",
            },
            TestCase {
                name: "normal text",
                input: "normal text",
                expected: "normal text",
            },
            TestCase {
                name: "mixed special characters",
                input: "text\t\n\rwith\tall\tspecial",
                expected: "text   with all special",
            },
            TestCase {
                name: "unicode with special chars",
                input: "日本語\t中文\n한국어",
                expected: "日本語 中文 한국어",
            },
            TestCase {
                name: "spaces preserved",
                input: "  multiple  spaces  ",
                expected: "  multiple  spaces  ",
            },
        ];

        for tc in test_cases {
            let result = super::sanitize_csv_field(tc.input);
            assert_eq!(result, tc.expected, "Test case '{}' failed", tc.name);
        }
    }

    /// Table-driven tests for `sanitize_csv_field_bytes`
    #[test]
    fn sanitize_csv_field_bytes_edge_cases() {
        struct TestCase {
            name: &'static str,
            input: &'static [u8],
            expected: &'static str,
        }

        let test_cases = [
            TestCase {
                name: "empty bytes",
                input: &[],
                expected: "-",
            },
            TestCase {
                name: "normal text",
                input: b"normal text",
                expected: "normal text",
            },
            TestCase {
                name: "binary data with valid UTF-8",
                input: b"hello\x00world",
                expected: "hello\0world",
            },
            TestCase {
                name: "valid 3-byte UTF-8 with special chars",
                input: "日\t本".as_bytes(),
                expected: "日 本",
            },
            TestCase {
                name: "invalid UTF-8 bytes",
                input: &[0xff, 0xfe, 0xfd],
                expected: "",
            },
        ];

        for tc in test_cases {
            let result = super::sanitize_csv_field_bytes(tc.input);
            assert_eq!(result, tc.expected, "Test case '{}' failed", tc.name);
        }
    }

    /// Table-driven tests for `vec_to_string_or_default` with various types and edge cases
    #[test]
    fn vec_to_string_or_default_edge_cases() {
        let cases_i32: &[(&str, &[i32], &str)] = &[
            ("empty -> dash", &[], "-"),
            ("single element", &[42], "42"),
            ("multiple preserves order", &[-1, 0, 1], "-1,0,1"),
        ];

        for (name, input, expected) in cases_i32 {
            let out = super::vec_to_string_or_default(input);
            assert_eq!(out, *expected, "i32 case '{name}' failed: input={input:?}");
        }

        let cases_str: &[(&str, &[&str], &str)] = &[
            ("single element", &["single"], "single"),
            ("string elements join", &["hello", "world"], "hello,world"),
            (
                "comma inside element is not escaped",
                &["with,comma", "normal"],
                "with,comma,normal",
            ),
        ];

        for (name, input, expected) in cases_str {
            let out = super::vec_to_string_or_default(input);
            assert_eq!(out, *expected, "&str case '{name}' failed: input={input:?}");
        }
    }

    /// Table-driven tests for `to_string_or_empty` with various types and edge cases
    #[test]
    fn to_string_or_empty_edge_cases() {
        use std::net::IpAddr;

        // 1) None path
        assert_eq!(super::to_string_or_empty::<i64>(None), "-");

        // 2) Some path (numeric)
        assert_eq!(super::to_string_or_empty(Some(0_i64)), "0");

        // 3) Some path (String)
        assert_eq!(super::to_string_or_empty(Some("test".to_string())), "test");

        // 4) Some path (non-numeric Display type)
        assert_eq!(
            super::to_string_or_empty(Some("127.0.0.1".parse::<IpAddr>().unwrap())),
            "127.0.0.1"
        );
    }
}
