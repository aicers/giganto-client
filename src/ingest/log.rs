use crate::publish::range::ResponseRangeData;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

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
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(&Some((timestamp, source, &self.log)))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Oplog {
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

impl Display for Oplog {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{:?}\t{}",
            self.agent_name, self.log_level, self.contents
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Seclog {
    pub kind: String,
    pub log_type: String,
    pub version: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub contents: String,
}

impl Display for Seclog {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.kind,
            self.log_type,
            self.version,
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            self.contents
        )
    }
}
