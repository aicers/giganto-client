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
    pub agent_name: String,
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
            self.sensor, self.agent_name, self.log_level, self.contents
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
