use anyhow::Result;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

pub trait ResponseRangeData {
    /// # Errors
    ///
    /// Will return `Err` if response data's serialize faild.
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error>;

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
pub enum REconvergeKindType {
    Conn,
    Dns,
    Rdp,
    Http,
    Log,
    Smtp,
    Ntlm,
    Kerberos,
    Ssh,
    DceRpc,
    Ftp,
    Mqtt,
    Ldap,
    Timeseries,
    Tls,
    Smb,
    Nfs,
    ProcessCreate,
    FileCreateTime,
    NetworkConnect,
    ProcessTerminate,
    ImageLoad,
    FileCreate,
    RegistryValueSet,
    RegistryKeyRename,
    FileCreateStreamHash,
    PipeEvent,
    DnsEvent,
    FileDelete,
    ProcessTamper,
    FileDeleteDetected,
    Netflow5,
    Netflow9,
}

impl REconvergeKindType {
    #[must_use]
    pub fn convert_type(input: &str) -> REconvergeKindType {
        match input {
            "conn" => REconvergeKindType::Conn,
            "dns" => REconvergeKindType::Dns,
            "rdp" => REconvergeKindType::Rdp,
            "http" => REconvergeKindType::Http,
            "smtp" => REconvergeKindType::Smtp,
            "ntlm" => REconvergeKindType::Ntlm,
            "kerberos" => REconvergeKindType::Kerberos,
            "ssh" => REconvergeKindType::Ssh,
            "dce rpc" => REconvergeKindType::DceRpc,
            "ftp" => REconvergeKindType::Ftp,
            "mqtt" => REconvergeKindType::Mqtt,
            "ldap" => REconvergeKindType::Ldap,
            "timeseries" => REconvergeKindType::Timeseries,
            "tls" => REconvergeKindType::Tls,
            "smb" => REconvergeKindType::Smb,
            "nfs" => REconvergeKindType::Nfs,
            "process_create" => REconvergeKindType::ProcessCreate,
            "file_create_time" => REconvergeKindType::FileCreateTime,
            "network_connect" => REconvergeKindType::NetworkConnect,
            "process_terminate" => REconvergeKindType::ProcessTerminate,
            "image_load" => REconvergeKindType::ImageLoad,
            "file_create" => REconvergeKindType::FileCreate,
            "registry_value_set" => REconvergeKindType::RegistryValueSet,
            "registry_key_rename" => REconvergeKindType::RegistryKeyRename,
            "file_create_stream_hash" => REconvergeKindType::FileCreateStreamHash,
            "pipe_event" => REconvergeKindType::PipeEvent,
            "dns_event" => REconvergeKindType::DnsEvent,
            "file_delete" => REconvergeKindType::FileDelete,
            "process_tamper" => REconvergeKindType::ProcessTamper,
            "file_delete_detected" => REconvergeKindType::FileDeleteDetected,
            "netflow5" => REconvergeKindType::Netflow5,
            "netflow9" => REconvergeKindType::Netflow9,
            _ => REconvergeKindType::Log,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RequestRange {
    pub source: String, //network event: certification name, time_series: sampling policy id
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
