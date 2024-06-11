use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};

use crate::{ingest::convert_time_format, publish::range::ResponseRangeData};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct Netflow5 {
    pub source: String,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub next_hop: IpAddr,
    pub input: u16,
    pub output: u16,
    pub d_pkts: u32,
    pub d_octets: u32,
    pub first: u32, // milliseconds
    pub last: u32,  // milliseconds
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub prot: u8,
    pub tos: u8, // Hex
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_mode: u8,
    pub sampling_rate: u16,
}

impl Display for Netflow5 {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:x}\t{}",
            self.source,
            self.src_addr,
            self.dst_addr,
            self.next_hop,
            self.input,
            self.output,
            self.d_pkts,
            self.d_octets,
            millis_to_secs(self.first),
            millis_to_secs(self.last),
            self.src_port,
            self.dst_port,
            tcp_flags(self.tcp_flags),
            self.prot,
            self.tos,
            self.src_as,
            self.dst_as,
            self.src_mask,
            self.dst_mask,
            self.sequence,
            self.engine_type,
            self.engine_id,
            self.sampling_mode,
            self.sampling_rate
        )
    }
}

impl ResponseRangeData for Netflow5 {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let csv = format!("{}\t{self}", convert_time_format(timestamp));
        bincode::serialize(&Some((timestamp, source, &csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct Netflow9 {
    pub source: String,
    pub sequence: u32,
    pub source_id: u32,
    pub template_id: u16,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub contents: String,
}

impl Display for Netflow9 {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.source,
            self.sequence,
            self.source_id,
            self.template_id,
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            self.contents
        )
    }
}

impl ResponseRangeData for Netflow9 {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let csv = format!("{}\t{self}", convert_time_format(timestamp));
        bincode::serialize(&Some((timestamp, source, &csv.as_bytes())))
    }
}

static TCP_FLAGS: [(u8, &str); 8] = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x08, "CWR"),
];

fn tcp_flags(b: u8) -> String {
    let mut res = String::new();
    for e in &TCP_FLAGS {
        if b & e.0 == e.0 {
            res.push_str(e.1);
            res.push('-');
        }
    }
    if res.is_empty() {
        res.push_str("None");
    }

    if res.ends_with('-') {
        res.pop();
    }
    res
}

fn millis_to_secs(millis: u32) -> String {
    format!("{}.{}", millis / 1000, millis - (millis / 1000) * 1000)
}
