pub mod connection;
pub mod frame;
pub mod ingest;
pub mod publish;

pub use ingest::RFC3339_RANGE_DATA_FORMAT;
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

    // Windows Sysmon
    ProcessCreate = 31,
    FileCreateTime = 32,
    NetworkConnect = 33,
    ProcessTerminate = 35,
    DriverLoad = 36,
    ImageLoad = 37,
    CreateRemoteThread = 38,
    RawAccessRead = 39,
    ProcessAccess = 40,
    FileCreate = 41,
    RegistryObjectAddDel = 42,
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

    // Endpoint logs. The names are set explicitly so that they never take
    // `windows_event_log`, `journald` or `auditd`, which operators use as
    // log kinds.
    #[strum(serialize = "endpoint_windows_event_log")]
    WindowsEventLog = 80,
    #[strum(serialize = "endpoint_journald")]
    Journald = 81,
    #[strum(serialize = "endpoint_auditd")]
    Auditd = 82,
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
    assert!(RawEventKind::from_str("timeseries").is_err());

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
}

#[test]
fn test_endpoint_record_kinds() {
    use std::str::FromStr;

    let new_kinds = [
        (RawEventKind::DriverLoad, 36, "driver_load"),
        (RawEventKind::CreateRemoteThread, 38, "create_remote_thread"),
        (RawEventKind::RawAccessRead, 39, "raw_access_read"),
        (RawEventKind::ProcessAccess, 40, "process_access"),
        (
            RawEventKind::RegistryObjectAddDel,
            42,
            "registry_object_add_del",
        ),
        (
            RawEventKind::WindowsEventLog,
            80,
            "endpoint_windows_event_log",
        ),
        (RawEventKind::Journald, 81, "endpoint_journald"),
        (RawEventKind::Auditd, 82, "endpoint_auditd"),
    ];
    let existing_kinds = [
        (RawEventKind::Conn, 0, &["conn"][..]),
        (RawEventKind::Dns, 1, &["dns"]),
        (RawEventKind::Log, 2, &["log"]),
        (RawEventKind::Http, 3, &["http"]),
        (RawEventKind::Rdp, 4, &["rdp"]),
        (
            RawEventKind::PeriodicTimeSeries,
            5,
            &["periodic_time_series"],
        ),
        (RawEventKind::Smtp, 6, &["smtp"]),
        (RawEventKind::Ntlm, 7, &["ntlm"]),
        (RawEventKind::Kerberos, 8, &["kerberos"]),
        (RawEventKind::Ssh, 9, &["ssh"]),
        (RawEventKind::DceRpc, 10, &["dce_rpc", "dce rpc"]),
        (RawEventKind::Statistics, 11, &["statistics"]),
        (RawEventKind::OpLog, 12, &["op_log"]),
        (RawEventKind::Packet, 13, &["packet"]),
        (RawEventKind::Ftp, 14, &["ftp"]),
        (RawEventKind::Mqtt, 15, &["mqtt"]),
        (RawEventKind::Ldap, 16, &["ldap"]),
        (RawEventKind::Tls, 17, &["tls"]),
        (RawEventKind::Smb, 18, &["smb"]),
        (RawEventKind::Nfs, 19, &["nfs"]),
        (RawEventKind::SecuLog, 20, &["secu_log"]),
        (RawEventKind::Bootp, 21, &["bootp"]),
        (RawEventKind::Dhcp, 22, &["dhcp"]),
        (RawEventKind::Radius, 23, &["radius"]),
        (RawEventKind::MalformedDns, 24, &["malformed_dns"]),
        (RawEventKind::Icmp, 25, &["icmp"]),
        (RawEventKind::ProcessCreate, 31, &["process_create"]),
        (RawEventKind::FileCreateTime, 32, &["file_create_time"]),
        (RawEventKind::NetworkConnect, 33, &["network_connect"]),
        (RawEventKind::ProcessTerminate, 35, &["process_terminate"]),
        (RawEventKind::ImageLoad, 37, &["image_load"]),
        (RawEventKind::FileCreate, 41, &["file_create"]),
        (RawEventKind::RegistryValueSet, 43, &["registry_value_set"]),
        (
            RawEventKind::RegistryKeyRename,
            44,
            &["registry_key_rename"],
        ),
        (
            RawEventKind::FileCreateStreamHash,
            45,
            &["file_create_stream_hash"],
        ),
        (RawEventKind::PipeEvent, 47, &["pipe_event"]),
        (RawEventKind::DnsQuery, 52, &["dns_query", "dns_event"]),
        (RawEventKind::FileDelete, 53, &["file_delete"]),
        (RawEventKind::ProcessTamper, 55, &["process_tamper"]),
        (
            RawEventKind::FileDeleteDetected,
            56,
            &["file_delete_detected"],
        ),
        (RawEventKind::Netflow5, 60, &["netflow5"]),
        (RawEventKind::Netflow9, 61, &["netflow9"]),
    ];

    for (kind, number, name) in new_kinds {
        assert_eq!(u32::from(kind), number, "{name}");
        assert_eq!(RawEventKind::try_from(number).unwrap(), kind, "{name}");
        assert_eq!(RawEventKind::from_str(name).unwrap(), kind, "{name}");
        assert!(
            existing_kinds
                .iter()
                .all(|(_, _, names)| !names.contains(&name)),
            "{name} clashes with an existing name"
        );
    }

    for (kind, number, names) in existing_kinds {
        assert_eq!(u32::from(kind), number, "{kind:?}");
        assert_eq!(RawEventKind::try_from(number).unwrap(), kind, "{kind:?}");
        for name in names {
            assert_eq!(RawEventKind::from_str(name).unwrap(), kind, "{name}");
        }
    }

    // The explicit names replace the snake_case defaults, which operators
    // use as log kinds.
    for name in ["journald", "auditd", "windows_event_log"] {
        assert!(RawEventKind::from_str(name).is_err(), "{name}");
    }
}
