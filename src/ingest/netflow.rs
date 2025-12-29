use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};

use crate::{ingest::convert_time_format, publish::range::ResponseRangeData};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct Netflow5 {
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:x}\t{}",
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
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let csv = format!("{}\t{self}", convert_time_format(timestamp));
        bincode::serialize(&Some((timestamp, sensor, &csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct Netflow9 {
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
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
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let csv = format!("{}\t{self}", convert_time_format(timestamp));
        bincode::serialize(&Some((timestamp, sensor, &csv.as_bytes())))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netflow5_display() {
        let nf5 = Netflow5 {
            src_addr: IpAddr::from([127, 0, 0, 1]),
            dst_addr: IpAddr::from([192, 168, 0, 1]),
            next_hop: IpAddr::from([10, 0, 0, 1]),
            input: 1,
            output: 2,
            d_pkts: 10,
            d_octets: 100,
            first: 1000,
            last: 2000,
            src_port: 80,
            dst_port: 8080,
            tcp_flags: 0x02, // SYN
            prot: 6,
            tos: 0,
            src_as: 65001,
            dst_as: 65002,
            src_mask: 24,
            dst_mask: 24,
            sequence: 123,
            engine_type: 1,
            engine_id: 1,
            sampling_mode: 0,
            sampling_rate: 0,
        };
        let display = format!("{nf5}");
        assert!(display.contains("127.0.0.1"));
        assert!(display.contains("SYN"));
        assert!(display.contains("1.0")); // first
        assert!(display.contains("2.0")); // last
    }

    #[test]
    fn test_netflow9_display() {
        let nf9 = Netflow9 {
            sequence: 1,
            source_id: 2,
            template_id: 3,
            orig_addr: IpAddr::from([127, 0, 0, 1]),
            orig_port: 80,
            resp_addr: IpAddr::from([192, 168, 0, 1]),
            resp_port: 8080,
            proto: 6,
            contents: "content".to_string(),
        };
        let display = format!("{nf9}");
        assert_eq!(
            display,
            "1\t2\t3\t127.0.0.1\t80\t192.168.0.1\t8080\t6\tcontent"
        );
    }

    #[test]
    fn test_netflow5_response_data() {
        let nf5 = Netflow5 {
            src_addr: IpAddr::from([10, 0, 0, 1]),
            dst_addr: IpAddr::from([10, 0, 0, 2]),
            next_hop: IpAddr::from([10, 0, 0, 3]),
            input: 1,
            output: 2,
            d_pkts: 10,
            d_octets: 100,
            first: 1500,
            last: 3500,
            src_port: 1234,
            dst_port: 4321,
            tcp_flags: 0x12, // SYN-ACK
            prot: 6,
            tos: 0,
            src_as: 65001,
            dst_as: 65002,
            src_mask: 24,
            dst_mask: 24,
            sequence: 123,
            engine_type: 1,
            engine_id: 2,
            sampling_mode: 0,
            sampling_rate: 0,
        };

        let timestamp = 1_500_000_000;
        let sensor = "sensor1";
        let res = nf5.response_data(timestamp, sensor).unwrap();
        let decoded: Option<(i64, String, Vec<u8>)> = bincode::deserialize(&res).unwrap();
        let (decoded_ts, decoded_sensor, decoded_csv) = decoded.expect("expected Some payload");

        assert_eq!(decoded_ts, timestamp);
        assert_eq!(decoded_sensor, sensor);

        let expected_csv = format!("{}\t{nf5}", convert_time_format(timestamp));
        assert_eq!(decoded_csv, expected_csv.as_bytes());
    }

    #[test]
    fn test_netflow9_response_data() {
        let nf9 = Netflow9 {
            sequence: 10,
            source_id: 20,
            template_id: 30,
            orig_addr: IpAddr::from([172, 16, 0, 1]),
            orig_port: 5050,
            resp_addr: IpAddr::from([172, 16, 0, 2]),
            resp_port: 6060,
            proto: 17,
            contents: "payload".to_string(),
        };

        let timestamp = 2_000_000_123;
        let sensor = "sensor9";
        let res = nf9.response_data(timestamp, sensor).unwrap();
        let decoded: Option<(i64, String, Vec<u8>)> = bincode::deserialize(&res).unwrap();
        let (decoded_ts, decoded_sensor, decoded_csv) = decoded.expect("expected Some payload");

        assert_eq!(decoded_ts, timestamp);
        assert_eq!(decoded_sensor, sensor);

        let expected_csv = format!("{}\t{nf9}", convert_time_format(timestamp));
        assert_eq!(decoded_csv, expected_csv.as_bytes());
    }

    #[test]
    fn test_tcp_flags() {
        assert_eq!(tcp_flags(0x02), "SYN");
        assert_eq!(tcp_flags(0x12), "SYN-ACK");
        assert_eq!(tcp_flags(0x00), "None");
    }

    #[test]
    fn test_millis_to_secs() {
        assert_eq!(millis_to_secs(1234), "1.234");
        assert_eq!(millis_to_secs(1000), "1.0");
    }
}
