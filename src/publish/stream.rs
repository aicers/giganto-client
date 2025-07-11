use std::net::IpAddr;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumString};

use crate::publish::PcapFilter;

pub const STREAM_REQUEST_ALL_SENSOR: &str = "all";

#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    IntoPrimitive,
    PartialEq,
    Serialize,
    TryFromPrimitive,
    EnumString,
    Display,
    EnumIter,
)]
#[repr(u32)]
#[strum(serialize_all = "snake_case")]
pub enum RequestStreamRecord {
    Conn = 0,
    Dns = 1,
    Rdp = 2,
    Http = 3,
    Log = 4,
    Smtp = 5,
    Ntlm = 6,
    Kerberos = 7,
    Ssh = 8,
    #[strum(serialize = "dce rpc")]
    DceRpc = 9,
    Pcap = 10,
    Ftp = 11,
    Mqtt = 12,
    Ldap = 13,
    Tls = 14,
    Smb = 15,
    Nfs = 16,
    Bootp = 17,
    Dhcp = 18,

    // sysmon
    FileCreate = 31,
    FileDelete = 32,
}

impl RequestStreamRecord {
    #[must_use]
    pub fn all() -> Vec<RequestStreamRecord> {
        RequestStreamRecord::iter().collect()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RequestSemiSupervisedStream {
    pub start: i64,
    pub sensor: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RequestTimeSeriesGeneratorStream {
    pub start: i64,
    pub id: String,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub sensor: Option<String>,
}

/// A unified payload enum that encapsulates all stream request types.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum StreamRequestPayload {
    /// Request for semi-supervised stream with record type
    SemiSupervised {
        record_type: RequestStreamRecord,
        request: RequestSemiSupervisedStream,
    },
    /// Request for time series generator stream with record type
    TimeSeriesGenerator {
        record_type: RequestStreamRecord,
        request: RequestTimeSeriesGeneratorStream,
    },
    /// Request for pcap extraction
    PcapExtraction { filter: Vec<PcapFilter> },
}

impl StreamRequestPayload {
    /// Get the record type for this request
    /// Returns `None` for `PcapExtractRequest` as it doesn't have a specific record type
    #[must_use]
    pub fn record_type(&self) -> Option<RequestStreamRecord> {
        match self {
            StreamRequestPayload::TimeSeriesGenerator { record_type, .. }
            | StreamRequestPayload::SemiSupervised { record_type, .. } => Some(*record_type),
            StreamRequestPayload::PcapExtraction { .. } => None,
        }
    }

    /// Create a new semi-supervised stream request
    #[must_use]
    pub fn new_semi_supervised(
        record_type: RequestStreamRecord,
        request: RequestSemiSupervisedStream,
    ) -> Self {
        StreamRequestPayload::SemiSupervised {
            record_type,
            request,
        }
    }

    /// Create a new time series generator stream request
    #[must_use]
    pub fn new_time_series_generator(
        record_type: RequestStreamRecord,
        request: RequestTimeSeriesGeneratorStream,
    ) -> Self {
        StreamRequestPayload::TimeSeriesGenerator {
            record_type,
            request,
        }
    }

    /// Create a new pcap extract request
    #[must_use]
    pub fn new_pcap_extraction(filter: Vec<PcapFilter>) -> Self {
        StreamRequestPayload::PcapExtraction { filter }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_node_stream_record_type() {
    use std::str::FromStr;

    // test RequestStreamRecord
    assert_eq!(
        RequestStreamRecord::Conn,
        RequestStreamRecord::from_str("conn").unwrap()
    );
    assert_eq!(RequestStreamRecord::Conn.to_string(), "conn");

    assert_eq!(
        RequestStreamRecord::Dns,
        RequestStreamRecord::from_str("dns").unwrap()
    );
    assert_eq!(RequestStreamRecord::Dns.to_string(), "dns");

    assert_eq!(
        RequestStreamRecord::Rdp,
        RequestStreamRecord::from_str("rdp").unwrap()
    );
    assert_eq!(RequestStreamRecord::Rdp.to_string(), "rdp");

    assert_eq!(
        RequestStreamRecord::Http,
        RequestStreamRecord::from_str("http").unwrap()
    );
    assert_eq!(RequestStreamRecord::Http.to_string(), "http");

    assert_eq!(
        RequestStreamRecord::Log,
        RequestStreamRecord::from_str("log").unwrap()
    );
    assert_eq!(RequestStreamRecord::Log.to_string(), "log");

    assert_eq!(
        RequestStreamRecord::Smtp,
        RequestStreamRecord::from_str("smtp").unwrap()
    );
    assert_eq!(RequestStreamRecord::Smtp.to_string(), "smtp");

    assert_eq!(
        RequestStreamRecord::Ntlm,
        RequestStreamRecord::from_str("ntlm").unwrap()
    );
    assert_eq!(RequestStreamRecord::Ntlm.to_string(), "ntlm");

    assert_eq!(
        RequestStreamRecord::Kerberos,
        RequestStreamRecord::from_str("kerberos").unwrap()
    );
    assert_eq!(RequestStreamRecord::Kerberos.to_string(), "kerberos");

    assert_eq!(
        RequestStreamRecord::Ssh,
        RequestStreamRecord::from_str("ssh").unwrap()
    );
    assert_eq!(RequestStreamRecord::Ssh.to_string(), "ssh");

    assert_eq!(
        RequestStreamRecord::DceRpc,
        RequestStreamRecord::from_str("dce rpc").unwrap(),
    );
    assert_eq!(RequestStreamRecord::DceRpc.to_string(), "dce rpc");

    assert_eq!(
        RequestStreamRecord::Pcap,
        RequestStreamRecord::from_str("pcap").unwrap()
    );
    assert_eq!(RequestStreamRecord::Pcap.to_string(), "pcap");

    assert_eq!(
        RequestStreamRecord::Ftp,
        RequestStreamRecord::from_str("ftp").unwrap()
    );
    assert_eq!(RequestStreamRecord::Ftp.to_string(), "ftp");

    assert_eq!(
        RequestStreamRecord::Mqtt,
        RequestStreamRecord::from_str("mqtt").unwrap()
    );
    assert_eq!(RequestStreamRecord::Mqtt.to_string(), "mqtt");

    assert_eq!(
        RequestStreamRecord::Ldap,
        RequestStreamRecord::from_str("ldap").unwrap()
    );
    assert_eq!(RequestStreamRecord::Ldap.to_string(), "ldap");

    assert_eq!(
        RequestStreamRecord::Tls,
        RequestStreamRecord::from_str("tls").unwrap()
    );
    assert_eq!(RequestStreamRecord::Tls.to_string(), "tls");

    assert_eq!(
        RequestStreamRecord::Smb,
        RequestStreamRecord::from_str("smb").unwrap()
    );
    assert_eq!(RequestStreamRecord::Smb.to_string(), "smb");

    assert_eq!(
        RequestStreamRecord::Nfs,
        RequestStreamRecord::from_str("nfs").unwrap()
    );
    assert_eq!(RequestStreamRecord::Nfs.to_string(), "nfs");

    assert_eq!(
        RequestStreamRecord::Bootp,
        RequestStreamRecord::from_str("bootp").unwrap()
    );
    assert_eq!(RequestStreamRecord::Bootp.to_string(), "bootp");

    assert_eq!(
        RequestStreamRecord::Dhcp,
        RequestStreamRecord::from_str("dhcp").unwrap()
    );
    assert_eq!(RequestStreamRecord::Dhcp.to_string(), "dhcp");

    assert_eq!(
        RequestStreamRecord::FileCreate,
        RequestStreamRecord::from_str("file_create").unwrap(),
    );
    assert_eq!(RequestStreamRecord::FileCreate.to_string(), "file_create");

    assert_eq!(
        RequestStreamRecord::FileDelete,
        RequestStreamRecord::from_str("file_delete").unwrap(),
    );
    assert_eq!(RequestStreamRecord::FileDelete.to_string(), "file_delete");

    let all_request_stream_records = RequestStreamRecord::all();
    assert_eq!(all_request_stream_records.len(), 21);
    assert_eq!(
        all_request_stream_records.first(),
        Some(&RequestStreamRecord::Conn)
    );
}

#[test]
fn test_pcap_extract_request_payload() {
    use std::net::IpAddr;

    let pcap_filters = vec![
        PcapFilter {
            timestamp: 1_234_567_890,
            sensor: "sensor1".to_string(),
            src_addr: IpAddr::V4([192, 168, 1, 1].into()),
            src_port: 80,
            dst_addr: IpAddr::V4([192, 168, 1, 2].into()),
            dst_port: 443,
            proto: 6, // TCP
            end_time: 1_234_567_950,
        },
        PcapFilter {
            timestamp: 1_234_567_900,
            sensor: "sensor2".to_string(),
            src_addr: IpAddr::V6("::1".parse().unwrap()),
            src_port: 22,
            dst_addr: IpAddr::V6("::2".parse().unwrap()),
            dst_port: 2222,
            proto: 6, // TCP
            end_time: 1_234_567_960,
        },
    ];

    let payload = StreamRequestPayload::new_pcap_extraction(pcap_filters.clone());

    // Test that record_type returns None for PcapExtractRequest
    assert_eq!(payload.record_type(), None);

    // Test pattern matching
    match payload {
        StreamRequestPayload::PcapExtraction { filter } => {
            assert_eq!(filter.len(), 2);
            assert_eq!(filter[0].sensor, "sensor1");
            assert_eq!(filter[1].sensor, "sensor2");
        }
        _ => panic!("Expected PcapExtractRequest variant"),
    }
}
