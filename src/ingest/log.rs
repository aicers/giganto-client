use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    ingest::{
        bytes_to_hex, convert_time_format,
        endpoint::{EndpointHeader, endpoint_columns},
        replace_csv_separators, sanitize_csv_field, to_string_or_empty,
    },
    publish::range::ResponseRangeData,
};

/// The separator between the elements of a list column of an endpoint log.
const LOG_LIST_SEPARATOR: &str = ";";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Log {
    pub kind: String,
    pub log: Vec<u8>,
}

impl Display for Log {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}",
            sanitize_csv_field(&self.kind),
            String::from_utf8_lossy(&self.log)
        )
    }
}

impl ResponseRangeData for Log {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(&Some((timestamp, sensor, &self.log)))
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpLog {
    pub sensor: String,
    pub service_name: String,
    pub log_level: OpLogLevel,
    pub contents: String,
    // Category, id
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OpLogLevel {
    Info,
    Warn,
    Error,
}

impl Display for OpLog {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{:?}\t{}",
            sanitize_csv_field(&self.sensor),
            sanitize_csv_field(&self.service_name),
            self.log_level,
            sanitize_csv_field(&self.contents)
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecuLog {
    pub kind: String,
    pub log_type: String,
    pub version: String,
    pub orig_addr: Option<IpAddr>,
    pub orig_port: Option<u16>,
    pub resp_addr: Option<IpAddr>,
    pub resp_port: Option<u16>,
    pub proto: Option<u8>,
    pub contents: String,
}

impl Display for SecuLog {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.kind),
            sanitize_csv_field(&self.log_type),
            sanitize_csv_field(&self.version),
            to_string_or_empty(self.orig_addr),
            to_string_or_empty(self.orig_port),
            to_string_or_empty(self.resp_addr),
            to_string_or_empty(self.resp_port),
            to_string_or_empty(self.proto),
            sanitize_csv_field(&self.contents)
        )
    }
}

/// A Windows event log record from an endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowsEventLog {
    pub channel: Option<String>,
    pub provider: Option<String>,
    pub event_id: Option<u16>,
    pub version: Option<u8>,
    pub level: Option<u8>,
    pub task: Option<u16>,
    pub opcode: Option<u8>,
    pub keywords: Option<u64>,
    pub record_id: Option<u64>,
    pub computer: Option<String>,
    pub user_sid: Option<String>,
    pub event_data: Option<Vec<EventData>>,
    pub user_data_xml: Option<String>,
    pub endpoint: EndpointHeader,
}

/// An `EventData` element of a Windows event log record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventData {
    pub name: Option<String>,
    pub value: String,
}

/// A systemd journal entry from an endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Journald {
    pub fields: Option<Vec<LogField>>,
    pub endpoint: EndpointHeader,
}

/// A Linux audit event from an endpoint, made of the audit records that
/// share one serial number.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Auditd {
    pub serial: Option<u64>,
    pub records: Option<Vec<AuditRecord>>,
    pub endpoint: EndpointHeader,
}

/// A single audit record of an [`Auditd`] event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditRecord {
    pub record_type: String,
    pub fields: Vec<LogField>,
}

/// A named field of an endpoint log record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogField {
    pub name: String,
    pub value: LogValue,
}

/// A value of a [`LogField`]: text, or bytes that are not text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum LogValue {
    Text(String),
    Bytes(Vec<u8>),
}

impl Display for LogValue {
    /// Writes the text, or the bytes as lowercase hexadecimal.
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::Text(text) => f.write_str(&replace_csv_separators(text)),
            Self::Bytes(bytes) => f.write_str(&bytes_to_hex(bytes)),
        }
    }
}

impl Display for LogField {
    /// Writes `name=value`.
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}={}", replace_csv_separators(&self.name), self.value)
    }
}

impl Display for EventData {
    /// Writes `name=value`, or `=value` when the element has no name.
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}={}",
            replace_csv_separators(self.name.as_deref().unwrap_or_default()),
            replace_csv_separators(&self.value)
        )
    }
}

impl Display for AuditRecord {
    /// Writes `record_type:` followed by the fields, separated by spaces.
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            replace_csv_separators(&self.record_type),
            join_or_default(&self.fields, " ")
        )
    }
}

/// Joins the elements' `Display` with `separator`, giving an empty string for
/// no elements.
fn join_or_default<T: Display>(items: &[T], separator: &str) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(separator)
}

/// Formats an optional list column of an endpoint log, or `-` when the list
/// is absent or empty.
fn log_list_or_default<T: Display>(items: Option<&[T]>) -> String {
    match items {
        Some(items) if !items.is_empty() => join_or_default(items, LOG_LIST_SEPARATOR),
        _ => "-".to_string(),
    }
}

/// Formats an optional string column, or `-` when it is absent or empty.
fn optional_str_or_default(value: Option<&str>) -> String {
    sanitize_csv_field(value.unwrap_or_default())
}

impl Display for WindowsEventLog {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            optional_str_or_default(self.channel.as_deref()),
            optional_str_or_default(self.provider.as_deref()),
            to_string_or_empty(self.event_id),
            to_string_or_empty(self.version),
            to_string_or_empty(self.level),
            to_string_or_empty(self.task),
            to_string_or_empty(self.opcode),
            to_string_or_empty(self.keywords),
            to_string_or_empty(self.record_id),
            optional_str_or_default(self.computer.as_deref()),
            optional_str_or_default(self.user_sid.as_deref()),
            log_list_or_default(self.event_data.as_deref()),
            optional_str_or_default(self.user_data_xml.as_deref()),
            endpoint_columns(Some(&self.endpoint)),
        )
    }
}

impl ResponseRangeData for WindowsEventLog {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let windows_event_log_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((
            timestamp,
            sensor,
            &windows_event_log_csv.as_bytes(),
        )))
    }
}

impl Display for Journald {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}",
            log_list_or_default(self.fields.as_deref()),
            endpoint_columns(Some(&self.endpoint)),
        )
    }
}

impl ResponseRangeData for Journald {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let journald_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &journald_csv.as_bytes())))
    }
}

impl Display for Auditd {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}",
            to_string_or_empty(self.serial),
            log_list_or_default(self.records.as_deref()),
            endpoint_columns(Some(&self.endpoint)),
        )
    }
}

impl ResponseRangeData for Auditd {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let auditd_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &auditd_csv.as_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_display() {
        let log = Log {
            kind: "test".to_string(),
            log: b"test log".to_vec(),
        };
        assert_eq!(format!("{log}"), "test\ttest log");
    }

    #[test]
    fn test_log_response_data() {
        let log = Log {
            kind: "test".to_string(),
            log: b"test log".to_vec(),
        };
        let res = log.response_data(100, "sensor").unwrap();
        let decoded: Option<(i64, String, Vec<u8>)> = bincode::deserialize(&res).unwrap();
        let (timestamp, sensor, log_data) = decoded.unwrap();
        assert_eq!(timestamp, 100);
        assert_eq!(sensor, "sensor");
        assert_eq!(log_data, b"test log".to_vec());
    }

    #[test]
    fn test_op_log_display() {
        let op_log = OpLog {
            sensor: "sensor".to_string(),
            service_name: "giganto".to_string(),
            log_level: OpLogLevel::Info,
            contents: "content".to_string(),
        };
        assert_eq!(format!("{op_log}"), "sensor\tgiganto\tInfo\tcontent");
    }

    #[test]
    fn test_op_log_display_sanitizes_string_fields() {
        let op_log = OpLog {
            sensor: "sensor\tname".to_string(),
            service_name: String::new(),
            log_level: OpLogLevel::Warn,
            contents: "first\nsecond\r\nlast".to_string(),
        };

        let output = op_log.to_string();
        assert_eq!(output, "sensor name\t-\tWarn\tfirst second  last");
        assert_eq!(output.split('\t').count(), 4);
        assert_eq!(output.lines().count(), 1);
        assert!(!output.contains('\r'));
    }

    #[test]
    fn test_secu_log_display() {
        let secu_log = SecuLog {
            kind: "kind".to_string(),
            log_type: "type".to_string(),
            version: "v1".to_string(),
            orig_addr: Some(IpAddr::from([127, 0, 0, 1])),
            orig_port: Some(8080),
            resp_addr: None,
            resp_port: None,
            proto: Some(6),
            contents: "content".to_string(),
        };
        assert_eq!(
            format!("{secu_log}"),
            "kind\ttype\tv1\t127.0.0.1\t8080\t-\t-\t6\tcontent"
        );
    }

    // ==================== Endpoint logs ====================

    use serde::de::DeserializeOwned;

    use crate::ingest::endpoint::{
        ENDPOINT_HEADER_COLUMNS,
        fixtures::{ENDPOINT_HEADER_CSV, endpoint_header},
    };

    fn assert_round_trip<T>(value: &T)
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let bytes = bincode::serialize(value).unwrap();
        let decoded: T = bincode::deserialize(&bytes).unwrap();
        assert_eq!(&decoded, value);
    }

    fn assert_response_data<T>(value: &T, timestamp: i64, sensor: &str)
    where
        T: ResponseRangeData + Display,
    {
        let res = value.response_data(timestamp, sensor).unwrap();
        let decoded: Option<(i64, String, Vec<u8>)> = bincode::deserialize(&res).unwrap();
        let (decoded_ts, decoded_sensor, decoded_csv) = decoded.expect("expected Some payload");
        assert_eq!(decoded_ts, timestamp);
        assert_eq!(decoded_sensor, sensor);
        let expected_csv = format!("{}\t{sensor}\t{value}", convert_time_format(timestamp));
        assert_eq!(decoded_csv, expected_csv.as_bytes());
        let csv = String::from_utf8(decoded_csv).unwrap();
        crate::test::assert_canonical_time(csv.split('\t').next().unwrap(), timestamp);
    }

    /// Asserts that `output` is `fields`, then the 15 header columns.
    fn assert_fields_then_header(output: &str, fields: &str) {
        assert_eq!(output, format!("{fields}\t{ENDPOINT_HEADER_CSV}"));
        assert_eq!(
            output.split('\t').count(),
            fields.split('\t').count() + ENDPOINT_HEADER_COLUMNS
        );
        assert_eq!(output.lines().count(), 1);
    }

    fn text(name: &str, value: &str) -> LogField {
        LogField {
            name: name.to_string(),
            value: LogValue::Text(value.to_string()),
        }
    }

    fn windows_event_log() -> WindowsEventLog {
        WindowsEventLog {
            channel: Some("Security".to_string()),
            provider: Some("Microsoft-Windows-Security-Auditing".to_string()),
            event_id: Some(4624),
            version: Some(2),
            level: Some(0),
            task: Some(12544),
            opcode: Some(0),
            keywords: Some(0x8020_0000_0000_0000),
            record_id: Some(123_456),
            computer: Some("host-01".to_string()),
            user_sid: Some("S-1-5-18".to_string()),
            event_data: Some(vec![
                EventData {
                    name: Some("SubjectUserName".to_string()),
                    value: "SYSTEM".to_string(),
                },
                EventData {
                    name: None,
                    value: "unnamed".to_string(),
                },
                EventData {
                    name: Some("Empty".to_string()),
                    value: String::new(),
                },
            ]),
            user_data_xml: Some("<UserData>\n  <x/>\n</UserData>".to_string()),
            endpoint: endpoint_header(),
        }
    }

    fn empty_windows_event_log() -> WindowsEventLog {
        WindowsEventLog {
            channel: None,
            provider: None,
            event_id: None,
            version: None,
            level: None,
            task: None,
            opcode: None,
            keywords: None,
            record_id: None,
            computer: None,
            user_sid: None,
            event_data: None,
            user_data_xml: None,
            endpoint: endpoint_header(),
        }
    }

    fn journald() -> Journald {
        Journald {
            fields: Some(vec![
                text("MESSAGE", "Started\tsession"),
                LogField {
                    name: "BINARY".to_string(),
                    value: LogValue::Bytes(vec![0x00, 0x1f, 0xa0, 0xff]),
                },
                text("_PID", "1"),
            ]),
            endpoint: endpoint_header(),
        }
    }

    fn auditd() -> Auditd {
        Auditd {
            serial: Some(8_731),
            records: Some(vec![
                AuditRecord {
                    record_type: "SYSCALL".to_string(),
                    fields: vec![text("arch", "c000003e"), text("syscall", "59")],
                },
                AuditRecord {
                    record_type: "EXECVE".to_string(),
                    fields: vec![
                        text("argc", "1"),
                        LogField {
                            name: "a0".to_string(),
                            value: LogValue::Bytes(b"ls".to_vec()),
                        },
                    ],
                },
                AuditRecord {
                    record_type: "EOE".to_string(),
                    fields: Vec::new(),
                },
            ]),
            endpoint: endpoint_header(),
        }
    }

    #[test]
    fn test_log_value_round_trips_text_and_bytes() {
        for value in [
            LogValue::Text("text".to_string()),
            LogValue::Text(String::new()),
            LogValue::Bytes(vec![0x00, 0xff, 0x10]),
            LogValue::Bytes(Vec::new()),
        ] {
            assert_round_trip(&value);
        }
    }

    #[test]
    fn test_log_value_display() {
        assert_eq!(LogValue::Text("a b".to_string()).to_string(), "a b");
        assert_eq!(LogValue::Text("a\tb\n".to_string()).to_string(), "a b ");
        assert_eq!(
            LogValue::Bytes(vec![0x00, 0x0a, 0xab, 0xff]).to_string(),
            "000aabff"
        );
        assert_eq!(LogValue::Bytes(Vec::new()).to_string(), "");
    }

    #[test]
    fn test_windows_event_log_round_trips() {
        assert_round_trip(&windows_event_log());
        assert_round_trip(&empty_windows_event_log());
        assert_round_trip(&WindowsEventLog {
            event_data: Some(Vec::new()),
            ..empty_windows_event_log()
        });
    }

    #[test]
    fn test_journald_round_trips() {
        assert_round_trip(&journald());
        assert_round_trip(&Journald {
            fields: None,
            endpoint: endpoint_header(),
        });
    }

    #[test]
    fn test_auditd_round_trips() {
        assert_round_trip(&auditd());
        assert_round_trip(&Auditd {
            serial: None,
            records: None,
            endpoint: endpoint_header(),
        });
    }

    #[test]
    fn test_windows_event_log_display() {
        assert_fields_then_header(
            &windows_event_log().to_string(),
            "Security\tMicrosoft-Windows-Security-Auditing\t4624\t2\t0\t12544\t0\
             \t9232379236109516800\t123456\thost-01\tS-1-5-18\
             \tSubjectUserName=SYSTEM;=unnamed;Empty=\t<UserData>   <x/> </UserData>",
        );
        assert_fields_then_header(
            &empty_windows_event_log().to_string(),
            "-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-",
        );
        let empty_strings = WindowsEventLog {
            channel: Some(String::new()),
            event_data: Some(Vec::new()),
            ..empty_windows_event_log()
        };
        assert_fields_then_header(
            &empty_strings.to_string(),
            "-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-",
        );
    }

    #[test]
    fn test_journald_display() {
        assert_fields_then_header(
            &journald().to_string(),
            "MESSAGE=Started session;BINARY=001fa0ff;_PID=1",
        );
        assert_fields_then_header(
            &Journald {
                fields: None,
                endpoint: endpoint_header(),
            }
            .to_string(),
            "-",
        );
    }

    #[test]
    fn test_auditd_display() {
        assert_fields_then_header(
            &auditd().to_string(),
            "8731\tSYSCALL:arch=c000003e syscall=59;EXECVE:argc=1 a0=6c73;EOE:",
        );
        assert_fields_then_header(
            &Auditd {
                serial: None,
                records: Some(Vec::new()),
                endpoint: endpoint_header(),
            }
            .to_string(),
            "-\t-",
        );
    }

    #[test]
    fn test_endpoint_log_response_data() {
        assert_response_data(&windows_event_log(), 13_000, "endpoint-sensor");
        assert_response_data(&journald(), 14_000, "endpoint-sensor");
        assert_response_data(&auditd(), 15_000, "endpoint-sensor");
    }
}
