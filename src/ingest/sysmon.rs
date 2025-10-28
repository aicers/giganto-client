use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::{
    bincode_utils,
    ingest::{convert_time_format, vec_to_string_or_default, TIME_FORMAT},
    publish::range::ResponseRangeData,
};

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

impl Display for ProcessCreate {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.image,
            self.file_version,
            self.description,
            self.product,
            self.company,
            self.original_file_name,
            self.command_line,
            self.current_directory,
            self.user,
            self.logon_guid,
            self.logon_id,
            self.terminal_session_id,
            self.integrity_level,
            vec_to_string_or_default(&self.hashes),
            self.parent_process_guid,
            self.parent_process_id,
            self.parent_image,
            self.parent_command_line,
            self.parent_user
        )
    }
}

impl ResponseRangeData for ProcessCreate {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let process_create_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((timestamp, sensor, &process_create_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileCreationTimeChanged {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_filename: String,
    pub creation_utc_time: Timestamp,
    pub previous_creation_utc_time: Timestamp,
    pub user: String,
}

impl Display for FileCreationTimeChanged {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.image,
            self.target_filename,
            self.creation_utc_time.strftime(TIME_FORMAT),
            self.previous_creation_utc_time.strftime(TIME_FORMAT),
            self.user,
        )
    }
}

impl ResponseRangeData for FileCreationTimeChanged {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let file_create_time_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((timestamp, sensor, &file_create_time_csv.as_bytes())))
    }
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

impl Display for NetworkConnection {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.image,
            self.user,
            self.protocol,
            self.initiated,
            self.source_is_ipv6,
            self.source_ip,
            self.source_hostname,
            self.source_port,
            self.source_port_name,
            self.destination_is_ipv6,
            self.destination_ip,
            self.destination_hostname,
            self.destination_port,
            self.destination_port_name,
        )
    }
}

impl ResponseRangeData for NetworkConnection {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let network_connect_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((timestamp, sensor, &network_connect_csv.as_bytes())))
    }
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

impl Display for ProcessTerminated {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.image,
            self.user,
        )
    }
}

impl ResponseRangeData for ProcessTerminated {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let process_terminate_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((
            timestamp,
            sensor,
            &process_terminate_csv.as_bytes(),
        )))
    }
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

impl Display for ImageLoaded {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.image,
            self.image_loaded,
            self.file_version,
            self.description,
            self.product,
            self.company,
            self.original_file_name,
            vec_to_string_or_default(&self.hashes),
            self.signed,
            self.signature,
            self.signature_status,
            self.user,
        )
    }
}

impl ResponseRangeData for ImageLoaded {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let image_load_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((timestamp, sensor, &image_load_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileCreate {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_filename: String,
    pub creation_utc_time: Timestamp,
    pub user: String,
}

impl Display for FileCreate {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.image,
            self.target_filename,
            self.creation_utc_time.strftime(TIME_FORMAT),
            self.user,
        )
    }
}

impl ResponseRangeData for FileCreate {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let file_create_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((timestamp, sensor, &file_create_csv.as_bytes())))
    }
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

impl Display for RegistryValueSet {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.event_type,
            self.process_guid,
            self.process_id,
            self.image,
            self.target_object,
            self.details,
            self.user,
        )
    }
}

impl ResponseRangeData for RegistryValueSet {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let registry_value_set_csv =
            format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((
            timestamp,
            sensor,
            &registry_value_set_csv.as_bytes(),
        )))
    }
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

impl Display for RegistryKeyValueRename {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.event_type,
            self.process_guid,
            self.process_id,
            self.image,
            self.target_object,
            self.new_name,
            self.user,
        )
    }
}

impl ResponseRangeData for RegistryKeyValueRename {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let registry_key_rename_csv =
            format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((
            timestamp,
            sensor,
            &registry_key_rename_csv.as_bytes(),
        )))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileCreateStreamHash {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_filename: String,
    pub creation_utc_time: Timestamp,
    pub hash: Vec<String>,
    pub contents: String,
    pub user: String,
}

impl Display for FileCreateStreamHash {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.image,
            self.target_filename,
            self.creation_utc_time.strftime(TIME_FORMAT),
            vec_to_string_or_default(&self.hash),
            self.contents,
            self.user,
        )
    }
}

impl ResponseRangeData for FileCreateStreamHash {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let file_create_stream_hash_csv =
            format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((
            timestamp,
            sensor,
            &file_create_stream_hash_csv.as_bytes(),
        )))
    }
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

impl Display for PipeEvent {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.event_type,
            self.process_guid,
            self.process_id,
            self.pipe_name,
            self.image,
            self.user,
        )
    }
}

impl ResponseRangeData for PipeEvent {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let pipe_event_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((timestamp, sensor, &pipe_event_csv.as_bytes())))
    }
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

impl Display for DnsEvent {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.query_name,
            self.query_status,
            vec_to_string_or_default(&self.query_results),
            self.image,
            self.user,
        )
    }
}

impl ResponseRangeData for DnsEvent {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let dns_event_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((timestamp, sensor, &dns_event_csv.as_bytes())))
    }
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

impl Display for FileDelete {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.user,
            self.image,
            self.target_filename,
            vec_to_string_or_default(&self.hashes),
            self.is_executable,
            self.archived,
        )
    }
}

impl ResponseRangeData for FileDelete {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let file_delete_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((timestamp, sensor, &file_delete_csv.as_bytes())))
    }
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

impl Display for ProcessTampering {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.image,
            self.tamper_type,
            self.user,
        )
    }
}

impl ResponseRangeData for ProcessTampering {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let process_tamper_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((timestamp, sensor, &process_tamper_csv.as_bytes())))
    }
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

impl Display for FileDeleteDetected {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.agent_name,
            self.agent_id,
            self.process_guid,
            self.process_id,
            self.user,
            self.image,
            self.target_filename,
            vec_to_string_or_default(&self.hashes),
            self.is_executable,
        )
    }
}

impl ResponseRangeData for FileDeleteDetected {
    fn response_data(
        &self,
        timestamp: i64,
        sensor: &str,
    ) -> Result<Vec<u8>, bincode::error::EncodeError> {
        let file_delete_detected_csv =
            format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode_utils::encode_legacy(&Some((
            timestamp,
            sensor,
            &file_delete_detected_csv.as_bytes(),
        )))
    }
}
