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

/// Converts a timestamp to a string in the format of "%s%.9f", which is the format used by Zeek.
#[must_use]
fn convert_time_format(timestamp: i64) -> String {
    const A_BILLION: u64 = 1_000_000_000;

    // Keep the sign, but format using absolute magnitude.
    let neg = timestamp < 0;

    // Use unsigned_abs() to avoid overflow on i64::MIN
    let abs: u64 = timestamp.unsigned_abs();

    let secs: u64 = abs / A_BILLION;
    let nanos: u64 = abs % A_BILLION;

    if neg {
        format!("-{secs}.{nanos:09}")
    } else {
        format!("{secs}.{nanos:09}")
    }
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
    #[test]
    #[allow(clippy::too_many_lines)]
    fn convert_time_format_edge_cases() {
        struct TestCase {
            name: &'static str,
            input: i64,
            expected: &'static str,
        }

        let test_cases = [
            TestCase {
                name: "zero",
                input: 0,
                expected: "0.000000000",
            },
            TestCase {
                name: "one nanosecond",
                input: 1,
                expected: "0.000000001",
            },
            TestCase {
                name: "max nanoseconds in one second",
                input: 999_999_999,
                expected: "0.999999999",
            },
            TestCase {
                name: "one second exactly",
                input: 1_000_000_000,
                expected: "1.000000000",
            },
            TestCase {
                name: "one second plus one nanosecond",
                input: 1_000_000_001,
                expected: "1.000000001",
            },
            TestCase {
                name: "small negative",
                input: -1,
                expected: "-0.000000001",
            },
            TestCase {
                name: "negative max nanoseconds in one second",
                input: -999_999_999,
                expected: "-0.999999999",
            },
            TestCase {
                name: "negative one second",
                input: -1_000_000_000,
                expected: "-1.000000000",
            },
            TestCase {
                name: "negative one second minus one nanosecond",
                input: -1_000_000_001,
                expected: "-1.000000001",
            },
            TestCase {
                name: "boundary just below two seconds",
                input: 1_999_999_999,
                expected: "1.999999999",
            },
            TestCase {
                name: "two seconds exactly",
                input: 2_000_000_000,
                expected: "2.000000000",
            },
            TestCase {
                name: "two seconds plus one nanosecond",
                input: 2_000_000_001,
                expected: "2.000000001",
            },
            TestCase {
                name: "negative boundary just below two seconds",
                input: -1_999_999_999,
                expected: "-1.999999999",
            },
            TestCase {
                name: "negative two seconds exactly",
                input: -2_000_000_000,
                expected: "-2.000000000",
            },
            TestCase {
                name: "negative two seconds minus one nanosecond",
                input: -2_000_000_001,
                expected: "-2.000000001",
            },
            TestCase {
                name: "large exact seconds",
                input: 123_456_789_000_000_000,
                expected: "123456789.000000000",
            },
            TestCase {
                name: "large exact seconds negative",
                input: -123_456_789_000_000_000,
                expected: "-123456789.000000000",
            },
            TestCase {
                name: "i64::MAX",
                input: i64::MAX,
                expected: "9223372036.854775807",
            },
            TestCase {
                name: "i64::MIN",
                input: i64::MIN,
                expected: "-9223372036.854775808",
            },
        ];

        for tc in test_cases {
            let result = super::convert_time_format(tc.input);
            assert_eq!(result, tc.expected, "Test case '{}' failed", tc.name);
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

        // Test long string separately (dynamic allocation)
        let long_input = "a".repeat(500);
        let result = super::as_str_or_default(&long_input);
        assert_eq!(result, long_input, "Test case 'long string' failed");
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
                name: "CRLF sequence",
                input: "\r\n",
                expected: "  ",
            },
            TestCase {
                name: "multiple consecutive tabs",
                input: "\t\t\t",
                expected: "   ",
            },
            TestCase {
                name: "tabs at start and end",
                input: "\ttext\t",
                expected: " text ",
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
            TestCase {
                name: "mixed whitespace",
                input: " \t \n \r ",
                expected: "       ",
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
                name: "single null byte",
                input: &[0x00],
                expected: "\0",
            },
            TestCase {
                name: "binary data with valid UTF-8",
                input: b"hello\x00world",
                expected: "hello\0world",
            },
            TestCase {
                name: "high ASCII values",
                input: &[0x7f],
                expected: "\x7f",
            },
            TestCase {
                name: "valid 2-byte UTF-8",
                input: &[0xc3, 0xa9],
                expected: "é",
            },
            TestCase {
                name: "valid 3-byte UTF-8 with special chars",
                input: "日\t本".as_bytes(),
                expected: "日 本",
            },
            TestCase {
                name: "mixed valid and special chars",
                input: b"line1\nline2\rline3\tend",
                expected: "line1 line2 line3 end",
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
