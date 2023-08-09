use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessCreate {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub file_version: String,
    pub description: String,
    pub product: String,
    pub company: String,
    pub original_file_name: String,
    pub command_line: String,
    pub current_directory: String,
    pub user: String,
    pub logon_guid: String,
    pub logon_id: u32,
    pub terminal_session_id: u32,
    pub integrity_level: String,
    pub hashes: Vec<String>,
    pub parent_process_guid: String,
    pub parent_process_id: u32,
    pub parent_image: String,
    pub parent_command_line: String,
    pub parent_user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileCreationTimeChanged {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_filename: String,
    pub creation_utc_time: DateTime<Utc>,
    pub previous_creation_utc_time: DateTime<Utc>,
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkConnection {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub user: String,
    pub protocol: String,
    pub initiated: bool,
    pub source_is_ipv6: bool,
    pub source_ip: IpAddr,
    pub source_hostname: String,
    pub source_port: u16,
    pub source_port_name: String,
    pub destination_is_ipv6: bool,
    pub destination_ip: IpAddr,
    pub destination_hostname: String,
    pub destination_port: u16,
    pub destination_port_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessTerminated {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImageLoaded {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub image_loaded: String,
    pub file_version: String,
    pub description: String,
    pub product: String,
    pub company: String,
    pub original_file_name: String,
    pub hashes: Vec<String>,
    pub signed: bool,
    pub signature: String,
    pub signature_status: String,
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileCreate {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_filename: String,
    pub creation_utc_time: DateTime<Utc>,
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryValueSet {
    pub agent_name: String,
    pub agent_id: String,
    pub event_type: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_object: String,
    pub details: String,
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryKeyValueRename {
    pub agent_name: String,
    pub agent_id: String,
    pub event_type: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_object: String,
    pub new_name: String,
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileCreateStreamHash {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_filename: String,
    pub creation_utc_time: DateTime<Utc>,
    pub hash: Vec<String>,
    pub contents: String,
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PipeEvent {
    pub agent_name: String,
    pub agent_id: String,
    pub event_type: String,
    pub process_guid: String,
    pub process_id: u32,
    pub pipe_name: String,
    pub image: String,
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsEvent {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub query_name: String,
    pub query_status: u32,
    pub query_results: Vec<String>, // divided by ';'
    pub image: String,
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileDelete {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub user: String,
    pub image: String,
    pub target_filename: String,
    pub hashes: Vec<String>,
    pub is_executable: bool,
    pub archived: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessTampering {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub tamper_type: String, // type
    pub user: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileDeleteDetected {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub user: String,
    pub image: String,
    pub target_filename: String,
    pub hashes: Vec<String>,
    pub is_executable: bool,
}
