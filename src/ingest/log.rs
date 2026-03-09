use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{ingest::to_string_or_empty, publish::range::ResponseRangeData};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Log {
    pub kind: String,
    pub log: Vec<u8>,
}

impl Display for Log {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}\t{}", self.kind, String::from_utf8_lossy(&self.log))
    }
}

impl ResponseRangeData for Log {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(&Some((timestamp, sensor, &self.log)))
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpLog {
    pub sensor: String,
    pub service_name: String,
    pub log_level: OpLogLevel,
    pub contents: String,
    // Category, id
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OpLogLevel {
    Info,
    Warn,
    Error,
}

impl Display for OpLog {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{:?}\t{}",
            self.sensor, self.service_name, self.log_level, self.contents
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecuLog {
    pub kind: String,
    pub log_type: String,
    pub version: String,
    pub orig_addr: Option<IpAddr>,
    pub orig_port: Option<u16>,
    pub resp_addr: Option<IpAddr>,
    pub resp_port: Option<u16>,
    pub proto: Option<u8>,
    pub contents: String,
}

impl Display for SecuLog {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.kind,
            self.log_type,
            self.version,
            to_string_or_empty(self.orig_addr),
            to_string_or_empty(self.orig_port),
            to_string_or_empty(self.resp_addr),
            to_string_or_empty(self.resp_port),
            to_string_or_empty(self.proto),
            self.contents
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_display() {
        let log = Log {
            kind: "test".to_string(),
            log: b"test log".to_vec(),
        };
        assert_eq!(format!("{log}"), "test\ttest log");
    }

    #[test]
    fn test_log_response_data() {
        let log = Log {
            kind: "test".to_string(),
            log: b"test log".to_vec(),
        };
        let res = log.response_data(100, "sensor").unwrap();
        let decoded: Option<(i64, String, Vec<u8>)> = bincode::deserialize(&res).unwrap();
        let (timestamp, sensor, log_data) = decoded.unwrap();
        assert_eq!(timestamp, 100);
        assert_eq!(sensor, "sensor");
        assert_eq!(log_data, b"test log".to_vec());
    }

    #[test]
    fn test_op_log_display() {
        let op_log = OpLog {
            sensor: "sensor".to_string(),
            service_name: "giganto".to_string(),
            log_level: OpLogLevel::Info,
            contents: "content".to_string(),
        };
        assert_eq!(format!("{op_log}"), "sensor\tgiganto\tInfo\tcontent");
    }

    #[test]
    fn test_secu_log_display() {
        let secu_log = SecuLog {
            kind: "kind".to_string(),
            log_type: "type".to_string(),
            version: "v1".to_string(),
            orig_addr: Some(IpAddr::from([127, 0, 0, 1])),
            orig_port: Some(8080),
            resp_addr: None,
            resp_port: None,
            proto: Some(6),
            contents: "content".to_string(),
        };
        assert_eq!(
            format!("{secu_log}"),
            "kind\ttype\tv1\t127.0.0.1\t8080\t-\t-\t6\tcontent"
        );
    }
}
