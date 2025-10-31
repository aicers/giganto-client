mod bincode_utils;
pub mod connection;
pub mod frame;
pub mod ingest;
pub mod publish;
#[cfg(test)]
mod test;

use std::default::Default;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

/// A raw data type for sending/receiving raw events with Giganto server.
/// `RawEventKind` can be used in any communication modes (i.e. ingest, publish)
#[derive(
    Default,
    Clone,
    Copy,
    Debug,
    Hash,
    Deserialize,
    Eq,
    IntoPrimitive,
    PartialEq,
    Serialize,
    TryFromPrimitive,
    EnumString,
)]
#[repr(u32)]
#[non_exhaustive]
#[strum(serialize_all = "snake_case")]
pub enum RawEventKind {
    Conn = 0,
    Dns = 1,
    #[default]
    Log = 2,
    Http = 3,
    Rdp = 4,
    #[strum(serialize = "periodic_time_series", serialize = "timeseries")]
    PeriodicTimeSeries = 5,
    Smtp = 6,
    Ntlm = 7,
    Kerberos = 8,
    Ssh = 9,
    #[strum(serialize = "dce_rpc", serialize = "dce rpc")]
    DceRpc = 10,
    Statistics = 11,
    OpLog = 12,
    Packet = 13,
    Ftp = 14,
    Mqtt = 15,
    Ldap = 16,
    Tls = 17,
    Smb = 18,
    Nfs = 19,
    SecuLog = 20,
    Bootp = 21,
    Dhcp = 22,
    Radius = 23,
    MalformedDns = 24,
    Icmp = 25,
    MalformedIcmp = 26,

    // Windows Sysmon
    ProcessCreate = 31,
    FileCreateTime = 32,
    NetworkConnect = 33,
    ProcessTerminate = 35,
    ImageLoad = 37,
    FileCreate = 41,
    RegistryValueSet = 43,
    RegistryKeyRename = 44,
    FileCreateStreamHash = 45,
    PipeEvent = 47,
    #[strum(serialize = "dns_query", serialize = "dns_event")]
    DnsQuery = 52,
    FileDelete = 53,
    ProcessTamper = 55,
    FileDeleteDetected = 56,

    Netflow5 = 60,
    Netflow9 = 61,
}

#[test]
fn test_record_type() {
    use std::str::FromStr;

    assert_eq!(RawEventKind::Log, RawEventKind::from_str("log").unwrap());
    assert_eq!(
        RawEventKind::Log,
        RawEventKind::from_str("custom_log").unwrap_or(RawEventKind::Log)
    );
    assert_eq!(
        RawEventKind::Log,
        RawEventKind::from_str("custom_log").unwrap_or_default()
    );

    assert_eq!(
        RawEventKind::from_str("dce rpc").unwrap(),
        RawEventKind::DceRpc
    );

    assert_eq!(
        RawEventKind::from_str("process_create").unwrap(),
        RawEventKind::ProcessCreate
    );

    assert_eq!(
        RawEventKind::from_str("periodic_time_series").unwrap(),
        RawEventKind::PeriodicTimeSeries
    );
    assert_eq!(
        RawEventKind::from_str("timeseries").unwrap(),
        RawEventKind::PeriodicTimeSeries,
    );

    assert_eq!(
        RawEventKind::from_str("dns_query").unwrap(),
        RawEventKind::DnsQuery,
    );
    assert_eq!(
        RawEventKind::from_str("dns_event").unwrap(),
        RawEventKind::DnsQuery,
    );

    assert_eq!(
        RawEventKind::from_str("netflow5").unwrap(),
        RawEventKind::Netflow5
    );

    assert_eq!(RawEventKind::from_str("icmp").unwrap(), RawEventKind::Icmp);

    assert_eq!(
        RawEventKind::from_str("malformed_icmp").unwrap(),
        RawEventKind::MalformedIcmp
    );
}
