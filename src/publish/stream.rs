use anyhow::{anyhow, Result};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const STREAM_REQUEST_ALL_SOURCE: &str = "all";

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, IntoPrimitive, PartialEq, Serialize, TryFromPrimitive,
)]
#[repr(u8)]
pub enum NodeType {
    Hog = 0,
    Crusher = 1,
}

impl NodeType {
    #[must_use]
    pub fn convert_to_str(&self) -> &str {
        match self {
            NodeType::Hog => "hog",
            NodeType::Crusher => "crusher",
        }
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, IntoPrimitive, PartialEq, Serialize, TryFromPrimitive,
)]
#[repr(u32)]
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
    DceRpc = 9,
    Pcap = 10,
    Ftp = 11,
    Mqtt = 12,
    Ldap = 13,
    Tls = 14,
    Smb = 15,
    Nfs = 16,

    // sysmon
    FileCreate = 31,
    FileDelete = 32,
}

impl RequestStreamRecord {
    #[must_use]
    pub fn convert_to_str(&self) -> &str {
        match self {
            RequestStreamRecord::Conn => "conn",
            RequestStreamRecord::Dns => "dns",
            RequestStreamRecord::Rdp => "rdp",
            RequestStreamRecord::Http => "http",
            RequestStreamRecord::Log => "log",
            RequestStreamRecord::Smtp => "smtp",
            RequestStreamRecord::Ntlm => "ntlm",
            RequestStreamRecord::Kerberos => "kerberos",
            RequestStreamRecord::Ssh => "ssh",
            RequestStreamRecord::DceRpc => "dce rpc",
            RequestStreamRecord::Pcap => "pcap",
            RequestStreamRecord::Ftp => "ftp",
            RequestStreamRecord::Mqtt => "mqtt",
            RequestStreamRecord::Ldap => "ldap",
            RequestStreamRecord::Tls => "tls",
            RequestStreamRecord::Smb => "smb",
            RequestStreamRecord::Nfs => "nfs",
            RequestStreamRecord::FileCreate => "file_create",
            RequestStreamRecord::FileDelete => "file_delete",
        }
    }

    /// # Errors
    ///
    /// Will return `Err` if `input` does not match protocol string
    pub fn convert_type(input: &str) -> Result<RequestStreamRecord> {
        match input {
            "conn" => Ok(RequestStreamRecord::Conn),
            "dns" => Ok(RequestStreamRecord::Dns),
            "rdp" => Ok(RequestStreamRecord::Rdp),
            "http" => Ok(RequestStreamRecord::Http),
            "log" => Ok(RequestStreamRecord::Log),
            "smtp" => Ok(RequestStreamRecord::Smtp),
            "ntlm" => Ok(RequestStreamRecord::Ntlm),
            "kerberos" => Ok(RequestStreamRecord::Kerberos),
            "ssh" => Ok(RequestStreamRecord::Ssh),
            "dce rpc" => Ok(RequestStreamRecord::DceRpc),
            "pcap" => Ok(RequestStreamRecord::Pcap),
            "ftp" => Ok(RequestStreamRecord::Ftp),
            "mqtt" => Ok(RequestStreamRecord::Mqtt),
            "ldap" => Ok(RequestStreamRecord::Ldap),
            "tls" => Ok(RequestStreamRecord::Tls),
            "smb" => Ok(RequestStreamRecord::Smb),
            "nfs" => Ok(RequestStreamRecord::Nfs),
            "file_create" => Ok(RequestStreamRecord::FileCreate),
            "file_delete" => Ok(RequestStreamRecord::FileDelete),
            _ => Err(anyhow!("invalid protocol type")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RequestHogStream {
    pub start: i64,
    pub source: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RequestCrusherStream {
    pub start: i64,
    pub id: String,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub source: Option<String>,
}
