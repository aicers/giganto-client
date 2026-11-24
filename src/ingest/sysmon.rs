use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};

use crate::{
    ingest::{
        convert_time_format,
        endpoint::{EndpointHeader, endpoint_columns},
        sanitize_csv_field, to_string_or_empty, vec_to_string_or_default,
    },
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
    /// The logon ID, truncated to 32 bits.
    ///
    /// For endpoint records, this holds the logon ID if it fits in `u32`,
    /// otherwise `u32::MAX`; `logon_id_full` holds the full value.
    pub logon_id: u32,
    pub terminal_session_id: u32,
    pub integrity_level: String,
    pub hashes: Vec<String>,
    pub parent_process_guid: String,
    pub parent_process_id: u32,
    pub parent_image: String,
    pub parent_command_line: String,
    pub parent_user: String,
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
    /// The full 64-bit logon ID.
    ///
    /// Endpoint records set this to the full value; other producers leave it
    /// `None`. See `logon_id` for the truncated form.
    pub logon_id_full: Option<u64>,
}

impl Display for ProcessCreate {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.file_version),
            sanitize_csv_field(&self.description),
            sanitize_csv_field(&self.product),
            sanitize_csv_field(&self.company),
            sanitize_csv_field(&self.original_file_name),
            sanitize_csv_field(&self.command_line),
            sanitize_csv_field(&self.current_directory),
            sanitize_csv_field(&self.user),
            sanitize_csv_field(&self.logon_guid),
            self.logon_id,
            self.terminal_session_id,
            sanitize_csv_field(&self.integrity_level),
            vec_to_string_or_default(&self.hashes),
            sanitize_csv_field(&self.parent_process_guid),
            self.parent_process_id,
            sanitize_csv_field(&self.parent_image),
            sanitize_csv_field(&self.parent_command_line),
            sanitize_csv_field(&self.parent_user),
            endpoint_columns(self.endpoint.as_ref()),
            to_string_or_empty(self.logon_id_full),
        )
    }
}

impl ResponseRangeData for ProcessCreate {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let process_create_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &process_create_csv.as_bytes())))
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
    pub creation_utc_time: i64,
    pub previous_creation_utc_time: i64,
    pub user: String,
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for FileCreationTimeChanged {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.target_filename),
            convert_time_format(self.creation_utc_time),
            convert_time_format(self.previous_creation_utc_time),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for FileCreationTimeChanged {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let file_create_time_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &file_create_time_csv.as_bytes())))
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
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for NetworkConnection {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.user),
            sanitize_csv_field(&self.protocol),
            self.initiated,
            self.source_is_ipv6,
            self.source_ip,
            sanitize_csv_field(&self.source_hostname),
            self.source_port,
            sanitize_csv_field(&self.source_port_name),
            self.destination_is_ipv6,
            self.destination_ip,
            sanitize_csv_field(&self.destination_hostname),
            self.destination_port,
            sanitize_csv_field(&self.destination_port_name),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for NetworkConnection {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let network_connect_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &network_connect_csv.as_bytes())))
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
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for ProcessTerminated {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for ProcessTerminated {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let process_terminate_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((
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
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for ImageLoaded {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.image_loaded),
            sanitize_csv_field(&self.file_version),
            sanitize_csv_field(&self.description),
            sanitize_csv_field(&self.product),
            sanitize_csv_field(&self.company),
            sanitize_csv_field(&self.original_file_name),
            vec_to_string_or_default(&self.hashes),
            self.signed,
            sanitize_csv_field(&self.signature),
            sanitize_csv_field(&self.signature_status),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for ImageLoaded {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let image_load_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &image_load_csv.as_bytes())))
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
    pub creation_utc_time: i64,
    pub user: String,
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for FileCreate {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.target_filename),
            convert_time_format(self.creation_utc_time),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for FileCreate {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let file_create_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &file_create_csv.as_bytes())))
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
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for RegistryValueSet {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.event_type),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.target_object),
            sanitize_csv_field(&self.details),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for RegistryValueSet {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let registry_value_set_csv =
            format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((
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
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for RegistryKeyValueRename {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.event_type),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.target_object),
            sanitize_csv_field(&self.new_name),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for RegistryKeyValueRename {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let registry_key_rename_csv =
            format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((
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
    pub creation_utc_time: i64,
    pub hash: Vec<String>,
    pub contents: String,
    pub user: String,
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for FileCreateStreamHash {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.target_filename),
            convert_time_format(self.creation_utc_time),
            vec_to_string_or_default(&self.hash),
            sanitize_csv_field(&self.contents),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for FileCreateStreamHash {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let file_create_stream_hash_csv =
            format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((
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
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for PipeEvent {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.event_type),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.pipe_name),
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for PipeEvent {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let pipe_event_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &pipe_event_csv.as_bytes())))
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
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for DnsEvent {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.query_name),
            self.query_status,
            vec_to_string_or_default(&self.query_results),
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for DnsEvent {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let dns_event_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &dns_event_csv.as_bytes())))
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
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for FileDelete {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.user),
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.target_filename),
            vec_to_string_or_default(&self.hashes),
            self.is_executable,
            self.archived,
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for FileDelete {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let file_delete_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &file_delete_csv.as_bytes())))
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
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for ProcessTampering {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.tamper_type),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for ProcessTampering {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let process_tamper_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &process_tamper_csv.as_bytes())))
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
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for FileDeleteDetected {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.user),
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.target_filename),
            vec_to_string_or_default(&self.hashes),
            self.is_executable,
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for FileDeleteDetected {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let file_delete_detected_csv =
            format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((
            timestamp,
            sensor,
            &file_delete_detected_csv.as_bytes(),
        )))
    }
}

/// A Sysmon driver-loaded event (event ID 6).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DriverLoad {
    pub agent_name: String,
    pub agent_id: String,
    pub image_loaded: String,
    pub hashes: Vec<String>,
    pub signed: bool,
    pub signature: String,
    pub signature_status: String,
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for DriverLoad {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.image_loaded),
            vec_to_string_or_default(&self.hashes),
            self.signed,
            sanitize_csv_field(&self.signature),
            sanitize_csv_field(&self.signature_status),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for DriverLoad {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let driver_load_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &driver_load_csv.as_bytes())))
    }
}

/// A Sysmon create-remote-thread event (event ID 8).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreateRemoteThread {
    pub agent_name: String,
    pub agent_id: String,
    pub source_process_guid: String,
    pub source_process_id: u32,
    pub source_image: String,
    pub target_process_guid: String,
    pub target_process_id: u32,
    pub target_image: String,
    pub new_thread_id: u32,
    pub start_address: String,
    pub start_module: String,
    pub start_function: String,
    pub source_user: String,
    pub target_user: String,
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for CreateRemoteThread {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.source_process_guid),
            self.source_process_id,
            sanitize_csv_field(&self.source_image),
            sanitize_csv_field(&self.target_process_guid),
            self.target_process_id,
            sanitize_csv_field(&self.target_image),
            self.new_thread_id,
            sanitize_csv_field(&self.start_address),
            sanitize_csv_field(&self.start_module),
            sanitize_csv_field(&self.start_function),
            sanitize_csv_field(&self.source_user),
            sanitize_csv_field(&self.target_user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for CreateRemoteThread {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let create_remote_thread_csv =
            format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((
            timestamp,
            sensor,
            &create_remote_thread_csv.as_bytes(),
        )))
    }
}

/// A Sysmon raw-access-read event (event ID 9).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawAccessRead {
    pub agent_name: String,
    pub agent_id: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub device: String,
    pub user: String,
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for RawAccessRead {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.device),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for RawAccessRead {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let raw_access_read_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &raw_access_read_csv.as_bytes())))
    }
}

/// A Sysmon process-access event (event ID 10).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessAccess {
    pub agent_name: String,
    pub agent_id: String,
    pub source_process_guid: String,
    pub source_process_id: u32,
    pub source_thread_id: u32,
    pub source_image: String,
    pub target_process_guid: String,
    pub target_process_id: u32,
    pub target_image: String,
    pub granted_access: u64,
    pub call_trace: String,
    pub source_user: String,
    pub target_user: String,
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for ProcessAccess {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.source_process_guid),
            self.source_process_id,
            self.source_thread_id,
            sanitize_csv_field(&self.source_image),
            sanitize_csv_field(&self.target_process_guid),
            self.target_process_id,
            sanitize_csv_field(&self.target_image),
            self.granted_access,
            sanitize_csv_field(&self.call_trace),
            sanitize_csv_field(&self.source_user),
            sanitize_csv_field(&self.target_user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for ProcessAccess {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let process_access_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &process_access_csv.as_bytes())))
    }
}

/// A Sysmon registry object create-and-delete event (event ID 12).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryObjectAddDel {
    pub agent_name: String,
    pub agent_id: String,
    pub event_type: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub target_object: String,
    pub user: String,
    /// The host header of an endpoint record; `None` for records from any
    /// other producer.
    pub endpoint: Option<EndpointHeader>,
}

impl Display for RegistryObjectAddDel {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            sanitize_csv_field(&self.agent_name),
            sanitize_csv_field(&self.agent_id),
            sanitize_csv_field(&self.event_type),
            sanitize_csv_field(&self.process_guid),
            self.process_id,
            sanitize_csv_field(&self.image),
            sanitize_csv_field(&self.target_object),
            sanitize_csv_field(&self.user),
            endpoint_columns(self.endpoint.as_ref()),
        )
    }
}

impl ResponseRangeData for RegistryObjectAddDel {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let registry_object_add_del_csv =
            format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((
            timestamp,
            sensor,
            &registry_object_add_del_csv.as_bytes(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::{Debug, Display};

    use serde::de::DeserializeOwned;

    use super::*;
    use crate::ingest::endpoint::{
        ENDPOINT_HEADER_COLUMNS,
        fixtures::{ENDPOINT_HEADER_CSV, NO_ENDPOINT_HEADER_CSV, endpoint_header},
    };

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

        // The leading record timestamp must be canonical RFC 3339.
        crate::test::assert_canonical_time(
            &response_csv_fields(value, timestamp, sensor)[0],
            timestamp,
        );
    }

    /// Decodes the tab-separated range-data row produced by `response_data`.
    fn response_csv_fields<T>(value: &T, timestamp: i64, sensor: &str) -> Vec<String>
    where
        T: ResponseRangeData,
    {
        let res = value.response_data(timestamp, sensor).unwrap();
        let decoded: Option<(i64, String, Vec<u8>)> = bincode::deserialize(&res).unwrap();
        let (_, _, csv) = decoded.expect("expected Some payload");
        String::from_utf8(csv)
            .unwrap()
            .split('\t')
            .map(ToString::to_string)
            .collect()
    }

    fn fmt_time(ns: i64) -> String {
        convert_time_format(ns)
    }

    fn assert_round_trip<T>(value: &T)
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug,
    {
        let bytes = bincode::serialize(value).unwrap();
        let decoded: T = bincode::deserialize(&bytes).unwrap();
        assert_eq!(&decoded, value);
    }

    /// Asserts that the bytes of `new` deserialize into its pre-change shape
    /// `O`, so a consumer that has not upgraded keeps reading.
    fn assert_old_shape_reads_new_bytes<N, O>(new: &N)
    where
        N: Serialize,
        O: DeserializeOwned + PartialEq + Debug + for<'a> From<&'a N>,
    {
        let bytes = bincode::serialize(new).unwrap();
        let old: O = bincode::deserialize(&bytes).unwrap();
        assert_eq!(old, O::from(new));
    }

    /// Asserts that bytes of the pre-change shape do not deserialize into the
    /// new struct (fresh install, no migration).
    fn assert_fails_to_read_old_shape_bytes<N, O>(new: &N)
    where
        N: DeserializeOwned + Debug,
        O: Serialize + for<'a> From<&'a N>,
    {
        let bytes = bincode::serialize(&O::from(new)).unwrap();
        assert!(bincode::deserialize::<N>(&bytes).is_err());
    }

    /// Asserts that `Display` writes today's columns (`existing`) unchanged,
    /// then the 15 header columns, then `trailing`.
    fn assert_display_appends_header<T: Display>(
        without_header: &T,
        with_header: &T,
        existing: &str,
        trailing: &str,
    ) {
        let existing_columns = existing.split('\t').count();

        let none = without_header.to_string();
        assert_eq!(
            none,
            format!("{existing}\t{NO_ENDPOINT_HEADER_CSV}{trailing}")
        );
        let some = with_header.to_string();
        assert_eq!(some, format!("{existing}\t{ENDPOINT_HEADER_CSV}{trailing}"));

        for output in [&none, &some] {
            let fields: Vec<&str> = output.split('\t').collect();
            assert_eq!(
                fields.len(),
                existing_columns + ENDPOINT_HEADER_COLUMNS + trailing.matches('\t').count()
            );
            assert_eq!(fields[..existing_columns].join("\t"), existing);
            assert_eq!(output.lines().count(), 1);
        }
        let none_fields: Vec<&str> = none.split('\t').collect();
        assert!(
            none_fields[existing_columns..existing_columns + ENDPOINT_HEADER_COLUMNS]
                .iter()
                .all(|c| *c == "-")
        );
    }

    /// Defines a copy of a Sysmon struct as it was before the endpoint header
    /// was appended, with a conversion from the current struct.
    macro_rules! old_shape {
        ($old:ident from $new:ident { $($field:ident: $ty:ty),* $(,)? }) => {
            #[derive(Debug, Deserialize, PartialEq, Serialize)]
            struct $old {
                $($field: $ty),*
            }

            impl From<&$new> for $old {
                fn from(value: &$new) -> Self {
                    Self {
                        $($field: value.$field.clone()),*
                    }
                }
            }
        };
    }

    old_shape!(ProcessCreateOldShape from ProcessCreate {
        agent_name: String,
        agent_id: String,
        process_guid: String,
        process_id: u32,
        image: String,
        file_version: String,
        description: String,
        product: String,
        company: String,
        original_file_name: String,
        command_line: String,
        current_directory: String,
        user: String,
        logon_guid: String,
        logon_id: u32,
        terminal_session_id: u32,
        integrity_level: String,
        hashes: Vec<String>,
        parent_process_guid: String,
        parent_process_id: u32,
        parent_image: String,
        parent_command_line: String,
        parent_user: String,
    });

    old_shape!(FileCreationTimeChangedOldShape from FileCreationTimeChanged {
        agent_name: String,
        agent_id: String,
        process_guid: String,
        process_id: u32,
        image: String,
        target_filename: String,
        creation_utc_time: i64,
        previous_creation_utc_time: i64,
        user: String,
    });

    old_shape!(NetworkConnectionOldShape from NetworkConnection {
        agent_name: String,
        agent_id: String,
        process_guid: String,
        process_id: u32,
        image: String,
        user: String,
        protocol: String,
        initiated: bool,
        source_is_ipv6: bool,
        source_ip: IpAddr,
        source_hostname: String,
        source_port: u16,
        source_port_name: String,
        destination_is_ipv6: bool,
        destination_ip: IpAddr,
        destination_hostname: String,
        destination_port: u16,
        destination_port_name: String,
    });

    old_shape!(ProcessTerminatedOldShape from ProcessTerminated {
        agent_name: String,
        agent_id: String,
        process_guid: String,
        process_id: u32,
        image: String,
        user: String,
    });

    old_shape!(ImageLoadedOldShape from ImageLoaded {
        agent_name: String,
        agent_id: String,
        process_guid: String,
        process_id: u32,
        image: String,
        image_loaded: String,
        file_version: String,
        description: String,
        product: String,
        company: String,
        original_file_name: String,
        hashes: Vec<String>,
        signed: bool,
        signature: String,
        signature_status: String,
        user: String,
    });

    old_shape!(FileCreateOldShape from FileCreate {
        agent_name: String,
        agent_id: String,
        process_guid: String,
        process_id: u32,
        image: String,
        target_filename: String,
        creation_utc_time: i64,
        user: String,
    });

    old_shape!(RegistryValueSetOldShape from RegistryValueSet {
        agent_name: String,
        agent_id: String,
        event_type: String,
        process_guid: String,
        process_id: u32,
        image: String,
        target_object: String,
        details: String,
        user: String,
    });

    old_shape!(RegistryKeyValueRenameOldShape from RegistryKeyValueRename {
        agent_name: String,
        agent_id: String,
        event_type: String,
        process_guid: String,
        process_id: u32,
        image: String,
        target_object: String,
        new_name: String,
        user: String,
    });

    old_shape!(FileCreateStreamHashOldShape from FileCreateStreamHash {
        agent_name: String,
        agent_id: String,
        process_guid: String,
        process_id: u32,
        image: String,
        target_filename: String,
        creation_utc_time: i64,
        hash: Vec<String>,
        contents: String,
        user: String,
    });

    old_shape!(PipeEventOldShape from PipeEvent {
        agent_name: String,
        agent_id: String,
        event_type: String,
        process_guid: String,
        process_id: u32,
        pipe_name: String,
        image: String,
        user: String,
    });

    old_shape!(DnsEventOldShape from DnsEvent {
        agent_name: String,
        agent_id: String,
        process_guid: String,
        process_id: u32,
        query_name: String,
        query_status: u32,
        query_results: Vec<String>,
        image: String,
        user: String,
    });

    old_shape!(FileDeleteOldShape from FileDelete {
        agent_name: String,
        agent_id: String,
        process_guid: String,
        process_id: u32,
        user: String,
        image: String,
        target_filename: String,
        hashes: Vec<String>,
        is_executable: bool,
        archived: bool,
    });

    old_shape!(ProcessTamperingOldShape from ProcessTampering {
        agent_name: String,
        agent_id: String,
        process_guid: String,
        process_id: u32,
        image: String,
        tamper_type: String,
        user: String,
    });

    old_shape!(FileDeleteDetectedOldShape from FileDeleteDetected {
        agent_name: String,
        agent_id: String,
        process_guid: String,
        process_id: u32,
        user: String,
        image: String,
        target_filename: String,
        hashes: Vec<String>,
        is_executable: bool,
    });

    // ==================== Fixtures ====================

    fn process_create() -> ProcessCreate {
        ProcessCreate {
            agent_name: "agent1".to_string(),
            agent_id: "id1".to_string(),
            process_guid: "guid1".to_string(),
            process_id: 123,
            image: "image1".to_string(),
            file_version: "1.0".to_string(),
            description: "desc1".to_string(),
            product: "prod1".to_string(),
            company: "comp1".to_string(),
            original_file_name: "orig1".to_string(),
            command_line: "cmd1".to_string(),
            current_directory: "dir1".to_string(),
            user: "user1".to_string(),
            logon_guid: "logon1".to_string(),
            logon_id: 456,
            terminal_session_id: 1,
            integrity_level: "high".to_string(),
            hashes: vec!["sha256=hash1".to_string()],
            parent_process_guid: "pguid1".to_string(),
            parent_process_id: 111,
            parent_image: "pimage1".to_string(),
            parent_command_line: "pcmd1".to_string(),
            parent_user: "sid1".to_string(),
            endpoint: None,
            logon_id_full: None,
        }
    }

    const PROCESS_CREATE_CSV: &str = "agent1\tid1\tguid1\t123\timage1\t1.0\tdesc1\tprod1\tcomp1\
        \torig1\tcmd1\tdir1\tuser1\tlogon1\t456\t1\thigh\tsha256=hash1\tpguid1\t111\tpimage1\
        \tpcmd1\tsid1";

    /// A `ProcessCreate` from an endpoint whose logon ID does not fit in
    /// `u32`.
    fn endpoint_process_create() -> ProcessCreate {
        ProcessCreate {
            logon_id: u32::MAX,
            endpoint: Some(endpoint_header()),
            logon_id_full: Some(0x1_0000_00e7),
            ..process_create()
        }
    }

    fn file_creation_time_changed() -> FileCreationTimeChanged {
        FileCreationTimeChanged {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 123,
            image: "image".to_string(),
            target_filename: "file".to_string(),
            creation_utc_time: 1000,
            previous_creation_utc_time: 900,
            user: "user".to_string(),
            endpoint: None,
        }
    }

    fn file_creation_time_changed_csv() -> String {
        format!(
            "agent\tid\tpguid\t123\timage\tfile\t{}\t{}\tuser",
            fmt_time(1000),
            fmt_time(900)
        )
    }

    fn network_connection() -> NetworkConnection {
        NetworkConnection {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 42,
            image: "image".to_string(),
            user: "user".to_string(),
            protocol: "TCP".to_string(),
            initiated: true,
            source_is_ipv6: false,
            source_ip: "10.0.0.1".parse().unwrap(),
            source_hostname: "host1".to_string(),
            source_port: 1234,
            source_port_name: "http".to_string(),
            destination_is_ipv6: false,
            destination_ip: "10.0.0.2".parse().unwrap(),
            destination_hostname: "host2".to_string(),
            destination_port: 80,
            destination_port_name: "http".to_string(),
            endpoint: None,
        }
    }

    const NETWORK_CONNECTION_CSV: &str = "agent\tid\tpguid\t42\timage\tuser\tTCP\ttrue\tfalse\
        \t10.0.0.1\thost1\t1234\thttp\tfalse\t10.0.0.2\thost2\t80\thttp";

    fn process_terminated() -> ProcessTerminated {
        ProcessTerminated {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 100,
            image: "image".to_string(),
            user: "user".to_string(),
            endpoint: None,
        }
    }

    const PROCESS_TERMINATED_CSV: &str = "agent\tid\tpguid\t100\timage\tuser";

    fn image_loaded() -> ImageLoaded {
        ImageLoaded {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 123,
            image: "image".to_string(),
            image_loaded: "loaded".to_string(),
            file_version: "1.0".to_string(),
            description: "desc".to_string(),
            product: "prod".to_string(),
            company: "comp".to_string(),
            original_file_name: "orig".to_string(),
            hashes: vec!["sha256=hash".to_string()],
            signed: true,
            signature: "sig".to_string(),
            signature_status: "ok".to_string(),
            user: "user".to_string(),
            endpoint: None,
        }
    }

    const IMAGE_LOADED_CSV: &str = "agent\tid\tpguid\t123\timage\tloaded\t1.0\tdesc\tprod\tcomp\
        \torig\tsha256=hash\ttrue\tsig\tok\tuser";

    fn file_create() -> FileCreate {
        FileCreate {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 123,
            image: "image".to_string(),
            target_filename: "file".to_string(),
            creation_utc_time: 1000,
            user: "user".to_string(),
            endpoint: None,
        }
    }

    fn file_create_csv() -> String {
        format!(
            "agent\tid\tpguid\t123\timage\tfile\t{}\tuser",
            fmt_time(1000)
        )
    }

    fn registry_value_set() -> RegistryValueSet {
        RegistryValueSet {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            event_type: "set".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 123,
            image: "image".to_string(),
            target_object: "HKLM\\Key".to_string(),
            details: "data".to_string(),
            user: "user".to_string(),
            endpoint: None,
        }
    }

    const REGISTRY_VALUE_SET_CSV: &str = "agent\tid\tset\tpguid\t123\timage\tHKLM\\Key\tdata\tuser";

    fn registry_key_value_rename() -> RegistryKeyValueRename {
        RegistryKeyValueRename {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            event_type: "rename".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 321,
            image: "image".to_string(),
            target_object: "HKLM\\Key".to_string(),
            new_name: "HKLM\\KeyNew".to_string(),
            user: "user".to_string(),
            endpoint: None,
        }
    }

    const REGISTRY_KEY_VALUE_RENAME_CSV: &str =
        "agent\tid\trename\tpguid\t321\timage\tHKLM\\Key\tHKLM\\KeyNew\tuser";

    fn file_create_stream_hash() -> FileCreateStreamHash {
        FileCreateStreamHash {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 111,
            image: "image".to_string(),
            target_filename: "file".to_string(),
            creation_utc_time: 1_700,
            hash: vec!["sha256=abc".to_string()],
            contents: "content".to_string(),
            user: "user".to_string(),
            endpoint: None,
        }
    }

    fn file_create_stream_hash_csv() -> String {
        format!(
            "agent\tid\tpguid\t111\timage\tfile\t{}\tsha256=abc\tcontent\tuser",
            fmt_time(1_700)
        )
    }

    fn pipe_event() -> PipeEvent {
        PipeEvent {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            event_type: "create".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 222,
            pipe_name: "\\\\.\\pipe\\mypipe".to_string(),
            image: "image".to_string(),
            user: "user".to_string(),
            endpoint: None,
        }
    }

    const PIPE_EVENT_CSV: &str = "agent\tid\tcreate\tpguid\t222\t\\\\.\\pipe\\mypipe\timage\tuser";

    fn dns_event() -> DnsEvent {
        DnsEvent {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 333,
            query_name: "example.com".to_string(),
            query_status: 0,
            query_results: vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()],
            image: "image".to_string(),
            user: "user".to_string(),
            endpoint: None,
        }
    }

    const DNS_EVENT_CSV: &str =
        "agent\tid\tpguid\t333\texample.com\t0\t1.2.3.4,5.6.7.8\timage\tuser";

    fn file_delete() -> FileDelete {
        FileDelete {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 444,
            user: "user".to_string(),
            image: "image".to_string(),
            target_filename: "file".to_string(),
            hashes: vec!["sha256=xyz".to_string()],
            is_executable: true,
            archived: false,
            endpoint: None,
        }
    }

    const FILE_DELETE_CSV: &str =
        "agent\tid\tpguid\t444\tuser\timage\tfile\tsha256=xyz\ttrue\tfalse";

    fn process_tampering() -> ProcessTampering {
        ProcessTampering {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 555,
            image: "image".to_string(),
            tamper_type: "memory".to_string(),
            user: "user".to_string(),
            endpoint: None,
        }
    }

    const PROCESS_TAMPERING_CSV: &str = "agent\tid\tpguid\t555\timage\tmemory\tuser";

    fn file_delete_detected() -> FileDeleteDetected {
        FileDeleteDetected {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 666,
            user: "user".to_string(),
            image: "image".to_string(),
            target_filename: "file".to_string(),
            hashes: vec!["sha1=hash".to_string()],
            is_executable: false,
            endpoint: None,
        }
    }

    const FILE_DELETE_DETECTED_CSV: &str =
        "agent\tid\tpguid\t666\tuser\timage\tfile\tsha1=hash\tfalse";

    fn driver_load() -> DriverLoad {
        DriverLoad {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            image_loaded: "C:\\Windows\\System32\\drivers\\x.sys".to_string(),
            hashes: vec!["SHA256=aa".to_string(), "MD5=bb".to_string()],
            signed: true,
            signature: "Microsoft Windows".to_string(),
            signature_status: "Valid".to_string(),
            endpoint: None,
        }
    }

    const DRIVER_LOAD_CSV: &str = "agent\tid\tC:\\Windows\\System32\\drivers\\x.sys\
        \tSHA256=aa,MD5=bb\ttrue\tMicrosoft Windows\tValid";

    fn create_remote_thread() -> CreateRemoteThread {
        CreateRemoteThread {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            source_process_guid: "sguid".to_string(),
            source_process_id: 10,
            source_image: "simage".to_string(),
            target_process_guid: "tguid".to_string(),
            target_process_id: 20,
            target_image: "timage".to_string(),
            new_thread_id: 30,
            start_address: "0x00007FF6A1B2C3D4".to_string(),
            start_module: "kernel32.dll".to_string(),
            start_function: String::new(),
            source_user: "suser".to_string(),
            target_user: "tuser".to_string(),
            endpoint: None,
        }
    }

    const CREATE_REMOTE_THREAD_CSV: &str = "agent\tid\tsguid\t10\tsimage\ttguid\t20\ttimage\t30\
        \t0x00007FF6A1B2C3D4\tkernel32.dll\t-\tsuser\ttuser";

    fn raw_access_read() -> RawAccessRead {
        RawAccessRead {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 40,
            image: "image".to_string(),
            device: "\\Device\\HarddiskVolume2".to_string(),
            user: "user".to_string(),
            endpoint: None,
        }
    }

    const RAW_ACCESS_READ_CSV: &str =
        "agent\tid\tpguid\t40\timage\t\\Device\\HarddiskVolume2\tuser";

    fn process_access() -> ProcessAccess {
        ProcessAccess {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            source_process_guid: "sguid".to_string(),
            source_process_id: 50,
            source_thread_id: 51,
            source_image: "simage".to_string(),
            target_process_guid: "tguid".to_string(),
            target_process_id: 60,
            target_image: "timage".to_string(),
            granted_access: 0x1F_FFFF,
            call_trace: "C:\\x.dll+1|C:\\y.dll+2".to_string(),
            source_user: "suser".to_string(),
            target_user: "tuser".to_string(),
            endpoint: None,
        }
    }

    const PROCESS_ACCESS_CSV: &str = "agent\tid\tsguid\t50\t51\tsimage\ttguid\t60\ttimage\t2097151\
        \tC:\\x.dll+1|C:\\y.dll+2\tsuser\ttuser";

    fn registry_object_add_del() -> RegistryObjectAddDel {
        RegistryObjectAddDel {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            event_type: "CreateKey".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 70,
            image: "image".to_string(),
            target_object: "HKLM\\Key".to_string(),
            user: "user".to_string(),
            endpoint: None,
        }
    }

    const REGISTRY_OBJECT_ADD_DEL_CSV: &str =
        "agent\tid\tCreateKey\tpguid\t70\timage\tHKLM\\Key\tuser";

    /// Runs the round-trip, compatibility and `Display` checks for an existing
    /// Sysmon struct, with the header both absent and present.
    macro_rules! check_existing_sysmon {
        ($fixture:expr, $old:ty, $existing:expr) => {{
            let without_header = $fixture;
            let with_header = {
                let mut value = $fixture;
                value.endpoint = Some(endpoint_header());
                value
            };
            for value in [&without_header, &with_header] {
                assert_round_trip(value);
                assert_old_shape_reads_new_bytes::<_, $old>(value);
            }
            assert_fails_to_read_old_shape_bytes::<_, $old>(&without_header);
            assert_display_appends_header(&without_header, &with_header, &$existing, "");
        }};
    }

    /// Runs the round-trip and `Display` checks for a new Sysmon struct, with
    /// the header both absent and present.
    macro_rules! check_new_sysmon {
        ($fixture:expr, $fields:expr) => {{
            let without_header = $fixture;
            let with_header = {
                let mut value = $fixture;
                value.endpoint = Some(endpoint_header());
                value
            };
            assert_round_trip(&without_header);
            assert_round_trip(&with_header);
            assert_display_appends_header(&without_header, &with_header, &$fields, "");
            assert_response_data(&without_header, 12_000, "endpoint-sensor");
            assert_response_data(&with_header, 12_000, "endpoint-sensor");
        }};
    }

    // ==================== Existing Sysmon structs ====================

    #[test]
    fn test_process_create_display_and_response_data() {
        let pc = process_create();

        let display = format!("{pc}");
        assert_eq!(
            display,
            format!("{PROCESS_CREATE_CSV}\t{NO_ENDPOINT_HEADER_CSV}\t-")
        );

        assert_response_data(&pc, 1_000, "process-create-sensor");
        assert_response_data(&endpoint_process_create(), 1_000, "process-create-sensor");
    }

    #[test]
    fn test_process_create_round_trips_and_stays_readable() {
        for pc in [
            process_create(),
            ProcessCreate {
                endpoint: Some(endpoint_header()),
                ..process_create()
            },
            ProcessCreate {
                logon_id_full: Some(456),
                ..process_create()
            },
            endpoint_process_create(),
        ] {
            assert_round_trip(&pc);
            assert_old_shape_reads_new_bytes::<_, ProcessCreateOldShape>(&pc);
        }
        assert_fails_to_read_old_shape_bytes::<_, ProcessCreateOldShape>(&process_create());
    }

    #[test]
    fn test_process_create_appends_endpoint_then_logon_id_full() {
        let pc = endpoint_process_create();
        let header = endpoint_header();
        let logon_id_full = 0x1_0000_00e7_u64;

        let mut expected = bincode::serialize(&ProcessCreateOldShape::from(&pc)).unwrap();
        expected.extend(bincode::serialize(&Some(&header)).unwrap());
        expected.extend(bincode::serialize(&Some(logon_id_full)).unwrap());
        assert_eq!(bincode::serialize(&pc).unwrap(), expected);

        let decoded: ProcessCreate = bincode::deserialize(&expected).unwrap();
        assert_eq!(decoded.endpoint, Some(header));
        assert_eq!(decoded.logon_id_full, Some(logon_id_full));
        assert_eq!(decoded.logon_id, u32::MAX);
    }

    #[test]
    fn test_process_create_display_appends_header_then_logon_id_full() {
        assert_display_appends_header(
            &process_create(),
            &ProcessCreate {
                endpoint: Some(endpoint_header()),
                ..process_create()
            },
            PROCESS_CREATE_CSV,
            "\t-",
        );

        let pc = endpoint_process_create();
        let fields: Vec<String> = pc
            .to_string()
            .split('\t')
            .map(ToString::to_string)
            .collect();
        let existing_columns = PROCESS_CREATE_CSV.split('\t').count();
        assert_eq!(fields.len(), existing_columns + ENDPOINT_HEADER_COLUMNS + 1);
        assert_eq!(fields[14], u32::MAX.to_string()); // logon_id
        assert_eq!(
            fields[existing_columns..existing_columns + ENDPOINT_HEADER_COLUMNS].join("\t"),
            ENDPOINT_HEADER_CSV
        );
        assert_eq!(fields.last().unwrap(), "4294967527"); // logon_id_full
    }

    #[test]
    fn test_file_creation_time_changed_display_and_response_data() {
        let ftc = file_creation_time_changed();
        let display = format!("{ftc}");
        assert!(display.contains("agent"));
        assert!(display.contains("image"));
        assert!(display.contains("file"));

        assert_response_data(&ftc, 1000, "file-creation-time-changed-sensor");

        // The struct's own datetime columns must also be canonical RFC 3339.
        let fields = response_csv_fields(&ftc, 1000, "file-creation-time-changed-sensor");
        crate::test::assert_canonical_time(&fields[8], 1000); // creation_utc_time
        crate::test::assert_canonical_time(&fields[9], 900); // previous_creation_utc_time
    }

    #[test]
    fn test_network_connection_response_data() {
        assert_response_data(&network_connection(), 2_000, "network-connection-sensor");
    }

    #[test]
    fn test_process_terminated_response_data() {
        assert_response_data(&process_terminated(), 3_000, "process-terminated-sensor");
    }

    #[test]
    fn test_image_loaded_response_data() {
        let il = image_loaded();
        let display = format!("{il}");
        assert!(display.contains("agent"));
        assert!(display.contains("loaded"));

        assert_response_data(&il, 1000, "image-loaded-sensor");
    }

    #[test]
    fn test_file_create_display_and_response_data() {
        let fc = file_create();
        let display = format!("{fc}");
        assert!(display.contains("agent"));
        assert!(display.contains("file"));

        assert_response_data(&fc, 1000, "file-create-sensor");

        let fields = response_csv_fields(&fc, 1000, "file-create-sensor");
        crate::test::assert_canonical_time(&fields[8], 1000); // creation_utc_time
    }

    #[test]
    fn test_registry_value_set_response_data() {
        assert_response_data(&registry_value_set(), 4_000, "registry-value-set-sensor");
    }

    #[test]
    fn test_registry_key_value_rename_response_data() {
        assert_response_data(
            &registry_key_value_rename(),
            5_000,
            "registry-rename-sensor",
        );
    }

    #[test]
    fn test_file_create_stream_hash_response_data() {
        let fcsh = file_create_stream_hash();

        assert_response_data(&fcsh, 6_000, "file-create-stream-hash-sensor");

        let fields = response_csv_fields(&fcsh, 6_000, "file-create-stream-hash-sensor");
        crate::test::assert_canonical_time(&fields[8], 1_700); // creation_utc_time
    }

    #[test]
    fn test_pipe_event_response_data() {
        assert_response_data(&pipe_event(), 7_000, "pipe-event-sensor");
    }

    #[test]
    fn test_dns_event_response_data() {
        assert_response_data(&dns_event(), 8_000, "dns-event-sensor");
    }

    #[test]
    fn test_file_delete_response_data() {
        assert_response_data(&file_delete(), 9_000, "file-delete-sensor");
    }

    #[test]
    fn test_process_tampering_response_data() {
        assert_response_data(&process_tampering(), 10_000, "process-tampering-sensor");
    }

    #[test]
    fn test_file_delete_detected_response_data() {
        assert_response_data(
            &file_delete_detected(),
            11_000,
            "file-delete-detected-sensor",
        );
    }

    #[test]
    fn test_file_creation_time_changed_endpoint() {
        check_existing_sysmon!(
            file_creation_time_changed(),
            FileCreationTimeChangedOldShape,
            file_creation_time_changed_csv()
        );
    }

    #[test]
    fn test_network_connection_endpoint() {
        check_existing_sysmon!(
            network_connection(),
            NetworkConnectionOldShape,
            NETWORK_CONNECTION_CSV
        );
    }

    #[test]
    fn test_process_terminated_endpoint() {
        check_existing_sysmon!(
            process_terminated(),
            ProcessTerminatedOldShape,
            PROCESS_TERMINATED_CSV
        );
    }

    #[test]
    fn test_image_loaded_endpoint() {
        check_existing_sysmon!(image_loaded(), ImageLoadedOldShape, IMAGE_LOADED_CSV);
    }

    #[test]
    fn test_file_create_endpoint() {
        check_existing_sysmon!(file_create(), FileCreateOldShape, file_create_csv());
    }

    #[test]
    fn test_registry_value_set_endpoint() {
        check_existing_sysmon!(
            registry_value_set(),
            RegistryValueSetOldShape,
            REGISTRY_VALUE_SET_CSV
        );
    }

    #[test]
    fn test_registry_key_value_rename_endpoint() {
        check_existing_sysmon!(
            registry_key_value_rename(),
            RegistryKeyValueRenameOldShape,
            REGISTRY_KEY_VALUE_RENAME_CSV
        );
    }

    #[test]
    fn test_file_create_stream_hash_endpoint() {
        check_existing_sysmon!(
            file_create_stream_hash(),
            FileCreateStreamHashOldShape,
            file_create_stream_hash_csv()
        );
    }

    #[test]
    fn test_pipe_event_endpoint() {
        check_existing_sysmon!(pipe_event(), PipeEventOldShape, PIPE_EVENT_CSV);
    }

    #[test]
    fn test_dns_event_endpoint() {
        check_existing_sysmon!(dns_event(), DnsEventOldShape, DNS_EVENT_CSV);
    }

    #[test]
    fn test_file_delete_endpoint() {
        check_existing_sysmon!(file_delete(), FileDeleteOldShape, FILE_DELETE_CSV);
    }

    #[test]
    fn test_process_tampering_endpoint() {
        check_existing_sysmon!(
            process_tampering(),
            ProcessTamperingOldShape,
            PROCESS_TAMPERING_CSV
        );
    }

    #[test]
    fn test_file_delete_detected_endpoint() {
        check_existing_sysmon!(
            file_delete_detected(),
            FileDeleteDetectedOldShape,
            FILE_DELETE_DETECTED_CSV
        );
    }

    // ==================== New Sysmon structs ====================

    #[test]
    fn test_driver_load() {
        check_new_sysmon!(driver_load(), DRIVER_LOAD_CSV);
    }

    #[test]
    fn test_create_remote_thread() {
        check_new_sysmon!(create_remote_thread(), CREATE_REMOTE_THREAD_CSV);
    }

    #[test]
    fn test_raw_access_read() {
        check_new_sysmon!(raw_access_read(), RAW_ACCESS_READ_CSV);
    }

    #[test]
    fn test_process_access() {
        check_new_sysmon!(process_access(), PROCESS_ACCESS_CSV);
    }

    #[test]
    fn test_registry_object_add_del() {
        check_new_sysmon!(registry_object_add_del(), REGISTRY_OBJECT_ADD_DEL_CSV);
    }

    #[test]
    fn test_new_sysmon_display_sanitizes_and_defaults() {
        let dl = DriverLoad {
            image_loaded: "a\tb\nc".to_string(),
            hashes: Vec::new(),
            signature: String::new(),
            ..driver_load()
        };
        let output = dl.to_string();
        let fields: Vec<&str> = output.split('\t').collect();
        assert_eq!(fields.len(), 7 + ENDPOINT_HEADER_COLUMNS);
        assert_eq!(fields[2], "a b c");
        assert_eq!(fields[3], "-");
        assert_eq!(fields[5], "-");
        assert_eq!(output.lines().count(), 1);
    }
}
