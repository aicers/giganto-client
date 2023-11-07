pub mod connection;
pub mod frame;
pub mod ingest;
pub mod publish;
#[cfg(test)]
mod test;

use std::default::Default;
use std::{fs::File, path::Path};

use anyhow::{bail, Result};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;
use tracing::metadata::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

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

/// Init operation log with tracing
///
/// This function has parameter `pkg_name` with `env!("CARGO_PKG_NAME")`
///
/// # Errors
///
/// * Path not exist
/// * Invalid path
///
pub fn init_tracing(path: &Path, pkg_name: &str) -> Result<WorkerGuard> {
    if !path.exists() {
        tracing_subscriber::fmt::init();
        bail!("Path not found {path:?}");
    }
    let file_name = format!("{pkg_name}.log");
    if File::create(path.join(file_name.clone())).is_err() {
        tracing_subscriber::fmt::init();
        bail!("Cannot create file. {}/{file_name}", path.display());
    }
    let file_appender = tracing_appender::rolling::never(path, file_name);
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let layer_file = fmt::Layer::default()
        .with_ansi(false)
        .with_target(false)
        .with_writer(file_writer)
        .with_filter(EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into()));
    let layer_stdout = fmt::Layer::default()
        .with_ansi(true)
        .with_filter(EnvFilter::from_default_env());
    tracing_subscriber::registry()
        .with(layer_file)
        .with(layer_stdout)
        .init();
    Ok(guard)
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
}
