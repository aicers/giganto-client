use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};

use crate::{
    ingest::{convert_time_format, vec_to_string_or_default},
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
            convert_time_format(self.creation_utc_time),
            convert_time_format(self.previous_creation_utc_time),
            self.user,
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
            convert_time_format(self.creation_utc_time),
            self.user,
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
            convert_time_format(self.creation_utc_time),
            vec_to_string_or_default(&self.hash),
            self.contents,
            self.user,
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

#[cfg(test)]
mod tests {
    use std::fmt::Display;

    use super::*;

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
    }

    #[test]
    fn test_process_create_display_and_response_data() {
        let pc = ProcessCreate {
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
        };

        let display = format!("{pc}");
        assert_eq!(
            display,
            "agent1\tid1\tguid1\t123\timage1\t1.0\tdesc1\tprod1\tcomp1\torig1\tcmd1\tdir1\tuser1\tlogon1\t456\t1\thigh\tsha256=hash1\tpguid1\t111\tpimage1\tpcmd1\tsid1"
        );

        assert_response_data(&pc, 1_000, "process-create-sensor");
    }

    #[test]
    fn test_file_creation_time_changed_display_and_response_data() {
        let ftc = FileCreationTimeChanged {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 123,
            image: "image".to_string(),
            target_filename: "file".to_string(),
            creation_utc_time: 1000,
            previous_creation_utc_time: 900,
            user: "user".to_string(),
        };
        let display = format!("{ftc}");
        assert!(display.contains("agent"));
        assert!(display.contains("image"));
        assert!(display.contains("file"));

        assert_response_data(&ftc, 1000, "file-creation-time-changed-sensor");
    }

    #[test]
    fn test_network_connection_response_data() {
        let nc = NetworkConnection {
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
        };

        assert_response_data(&nc, 2_000, "network-connection-sensor");
    }

    #[test]
    fn test_process_terminated_response_data() {
        let pt = ProcessTerminated {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 100,
            image: "image".to_string(),
            user: "user".to_string(),
        };

        assert_response_data(&pt, 3_000, "process-terminated-sensor");
    }

    #[test]
    fn test_image_loaded_response_data() {
        let il = ImageLoaded {
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
        };
        let display = format!("{il}");
        assert!(display.contains("agent"));
        assert!(display.contains("loaded"));

        assert_response_data(&il, 1000, "image-loaded-sensor");
    }

    #[test]
    fn test_file_create_display_and_response_data() {
        let fc = FileCreate {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 123,
            image: "image".to_string(),
            target_filename: "file".to_string(),
            creation_utc_time: 1000,
            user: "user".to_string(),
        };
        let display = format!("{fc}");
        assert!(display.contains("agent"));
        assert!(display.contains("file"));

        assert_response_data(&fc, 1000, "file-create-sensor");
    }

    #[test]
    fn test_registry_value_set_response_data() {
        let rvs = RegistryValueSet {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            event_type: "set".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 123,
            image: "image".to_string(),
            target_object: "HKLM\\Key".to_string(),
            details: "data".to_string(),
            user: "user".to_string(),
        };

        assert_response_data(&rvs, 4_000, "registry-value-set-sensor");
    }

    #[test]
    fn test_registry_key_value_rename_response_data() {
        let rkr = RegistryKeyValueRename {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            event_type: "rename".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 321,
            image: "image".to_string(),
            target_object: "HKLM\\Key".to_string(),
            new_name: "HKLM\\KeyNew".to_string(),
            user: "user".to_string(),
        };

        assert_response_data(&rkr, 5_000, "registry-rename-sensor");
    }

    #[test]
    fn test_file_create_stream_hash_response_data() {
        let fcsh = FileCreateStreamHash {
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
        };

        assert_response_data(&fcsh, 6_000, "file-create-stream-hash-sensor");
    }

    #[test]
    fn test_pipe_event_response_data() {
        let pipe = PipeEvent {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            event_type: "create".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 222,
            pipe_name: "\\\\.\\pipe\\mypipe".to_string(),
            image: "image".to_string(),
            user: "user".to_string(),
        };

        assert_response_data(&pipe, 7_000, "pipe-event-sensor");
    }

    #[test]
    fn test_dns_event_response_data() {
        let dns = DnsEvent {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 333,
            query_name: "example.com".to_string(),
            query_status: 0,
            query_results: vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()],
            image: "image".to_string(),
            user: "user".to_string(),
        };

        assert_response_data(&dns, 8_000, "dns-event-sensor");
    }

    #[test]
    fn test_file_delete_response_data() {
        let fd = FileDelete {
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
        };

        assert_response_data(&fd, 9_000, "file-delete-sensor");
    }

    #[test]
    fn test_process_tampering_response_data() {
        let pt = ProcessTampering {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 555,
            image: "image".to_string(),
            tamper_type: "memory".to_string(),
            user: "user".to_string(),
        };

        assert_response_data(&pt, 10_000, "process-tampering-sensor");
    }

    #[test]
    fn test_file_delete_detected_response_data() {
        let fdd = FileDeleteDetected {
            agent_name: "agent".to_string(),
            agent_id: "id".to_string(),
            process_guid: "pguid".to_string(),
            process_id: 666,
            user: "user".to_string(),
            image: "image".to_string(),
            target_filename: "file".to_string(),
            hashes: vec!["sha1=hash".to_string()],
            is_executable: false,
        };

        assert_response_data(&fdd, 11_000, "file-delete-detected-sensor");
    }
}
