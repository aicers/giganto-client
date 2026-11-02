use std::{
    fmt::{Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::Result;
use num_enum::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::{
    ingest::{
        as_str_or_default, convert_time_format, to_string_or_empty, vec_to_string_or_default,
    },
    publish::range::ResponseRangeData,
};

/// One ARP packet, including both Ethernet and ARP address fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArpMessage {
    pub timestamp: i64,
    pub eth_src_mac: [u8; 6],
    pub eth_dst_mac: [u8; 6],
    pub sender_mac: [u8; 6],
    pub sender_ip: IpAddr,
    pub target_mac: [u8; 6],
    pub target_ip: IpAddr,
}

impl Display for ArpMessage {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let mac = |bytes: &[u8; 6]| {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
            )
        };
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            convert_time_format(self.timestamp),
            mac(&self.eth_src_mac),
            mac(&self.eth_dst_mac),
            mac(&self.sender_mac),
            self.sender_ip,
            mac(&self.target_mac),
            self.target_ip,
        )
    }
}

/// An ARP transaction, including whichever request and response were observed.
///
/// Text output follows declaration order, flattening each message into seven
/// columns. MAC addresses use lowercase, colon-separated, two-digit hex octets.
/// Missing VLAN IDs and each column of a missing message are represented by `-`.
/// Start and message timestamps use the canonical range-data RFC 3339 format.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Arp {
    pub vlan_id: Option<u16>,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub request: Option<ArpMessage>,
    pub response: Option<ArpMessage>,
}

impl Display for Arp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            crate::ingest::to_string_or_empty(self.vlan_id),
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
        )?;
        for message in [&self.request, &self.response] {
            match message {
                Some(message) => write!(f, "\t{message}")?,
                None => write!(f, "\t-\t-\t-\t-\t-\t-\t-")?,
            }
        }
        Ok(())
    }
}

impl ResponseRangeData for Arp {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let arp_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &arp_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Conn {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub start_time: i64,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub orig_flags: u8,
    pub resp_flags: u8,
    pub missed_bytes: u64,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub syn_ttl: Option<u8>,
    pub syn_window_size: Option<u16>,
    pub syn_window_scale: Option<u8>,
    pub syn_mss: Option<u16>,
    pub syn_options_order: Vec<u8>,
    pub syn_df: Option<bool>,
}

impl Display for Conn {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            as_str_or_default(&self.conn_state),
            convert_time_format(self.start_time),
            self.duration,
            self.service,
            self.orig_bytes,
            self.resp_bytes,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            self.orig_flags,
            self.resp_flags,
            self.missed_bytes,
            to_string_or_empty(self.icmp_type),
            to_string_or_empty(self.icmp_code),
            to_string_or_empty(self.syn_ttl),
            to_string_or_empty(self.syn_window_size),
            to_string_or_empty(self.syn_window_scale),
            to_string_or_empty(self.syn_mss),
            vec_to_string_or_default(&self.syn_options_order),
            to_string_or_empty(self.syn_df)
        )
    }
}

impl ResponseRangeData for Conn {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let conn_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &conn_csv.as_bytes())))
    }
}

/// Data carried by a DNS resource record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ResourceData {
    /// IPv4 address.
    A(Ipv4Addr),
    /// IPv6 address.
    AAAA(Ipv6Addr),
    /// Canonical name.
    CNAME(String),
    /// Mail exchanger preference and host.
    MX { preference: u16, exchange: String },
    /// Authoritative name server.
    NS(String),
    /// Pointer domain name.
    PTR(String),
    /// Text strings in their original order.
    TXT(Vec<String>),
    /// Start of authority record.
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },
    /// Service location record.
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// EDNS parameters.
    OPT {
        payload_size: u16,
        ext_rcode: u8,
        version: u8,
        flags: u16,
    },
    /// Uninterpreted resource data bytes.
    Unknown(Vec<u8>),
}

/// A DNS resource record in an answer, authority, or additional section.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceRecord {
    /// Owner name.
    pub name: String,
    /// Numeric record type.
    pub rtype: u16,
    /// Numeric record class.
    pub rclass: u16,
    /// Time to live.
    pub ttl: i32,
    /// Type-specific record data.
    pub data: ResourceData,
}

/// A question in the DNS query section.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsQuestion {
    /// Queried name.
    pub name: String,
    /// Numeric query type.
    pub qtype: u16,
    /// Numeric query class.
    pub qclass: u16,
}

/// A DNS or mDNS transaction, including the available request and reply data.
///
/// Sections with no available content are empty. Header fields describe the
/// available transaction; empty sections do not independently prove that a
/// request or reply was absent. This schema is incompatible with the legacy
/// `Dns` API and its serialized representation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Dns {
    /// Origin IP address.
    pub orig_addr: IpAddr,
    /// Origin port, or zero when the protocol has no port.
    pub orig_port: u16,
    /// Responder IP address.
    pub resp_addr: IpAddr,
    /// Responder port.
    pub resp_port: u16,
    /// IP protocol number.
    pub proto: u8,
    /// Session start time in microseconds.
    pub start_time: i64,
    /// Session duration in microseconds.
    pub duration: i64,
    /// Origin-to-responder packet count.
    pub orig_pkts: u64,
    /// Responder-to-origin packet count.
    pub resp_pkts: u64,
    /// Origin-to-responder L2 byte count, including Ethernet frames.
    pub orig_l2_bytes: u64,
    /// Responder-to-origin L2 byte count.
    pub resp_l2_bytes: u64,
    /// DNS transaction ID; mDNS can use zero.
    pub trans_id: u16,
    /// DNS response code.
    pub rcode: u16,
    /// DNS operation code.
    pub opcode: u8,
    /// Authoritative answer flag.
    pub aa_flag: bool,
    /// Truncation flag.
    pub tc_flag: bool,
    /// Recursion desired flag.
    pub rd_flag: bool,
    /// Recursion available flag.
    pub ra_flag: bool,
    /// Authenticated data flag.
    pub ad_flag: bool,
    /// Checking disabled flag.
    pub cd_flag: bool,
    /// Questions available for the transaction.
    pub queries: Vec<DnsQuestion>,
    /// Answer records available for the transaction.
    pub answers: Vec<ResourceRecord>,
    /// Authority records available for the transaction.
    pub authorities: Vec<ResourceRecord>,
    /// Additional records available for the transaction.
    pub additionals: Vec<ResourceRecord>,
}

#[derive(Debug, FromPrimitive)]
#[repr(u16)]
pub enum Qclass {
    #[num_enum(default)]
    Unknown,
    CInternet = 1,
}

impl Display for Qclass {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CInternet => write!(f, "C_INTERNET"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

#[derive(Debug, FromPrimitive)]
#[repr(u16)]
pub enum Qtype {
    #[num_enum(default)]
    Unknown,
    A = 1,
    Ns,
    Md,
    Mf,
    Cname,
    Soa,
    Mb,
    Mg,
    Mr,
    Null,
    Wks,
    Ptr,
    Hinfo,
    Minfo,
    Mx,
    Txt,
    Rp,
    Afsdb,
    X25,
    Isdn,
    Rt,
    Nsap,
    NsapPtr,
    Sig,
    Key,
    Px,
    Gpos,
    Aaaa,
    Loc,
    Nxt,
    Eid,
    Nimloc,
    Srv,
    Atma,
    Naptr,
    Kx,
    Cert,
    A6,
    Dname,
    Sink,
    Opt,
    Apl,
    Ds,
    Sshfp,
    Ipseckey,
    Rrsig,
    Nsec,
    Dnskey,
    Dhcid,
    Nsec3,
    Nsec3param,
    Tlsa,
    Smimea,
    Hip = 55,
    Ninfo,
    Rkey,
    Talink,
    Cds,
    Cdnskey,
    Openpgpkey,
    Csync,
    Zonemd,
    Svcb,
    Https,
    Spf = 99,
}

impl Display for Qtype {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let upper = match self {
            Self::NsapPtr => "NSAP-PTR".to_string(),
            _ => format!("{self:?}").to_uppercase(),
        };
        write!(f, "{upper}")
    }
}

impl Display for Dns {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // Debug formatting escapes control characters in names and preserves
        // record types and values within each tab-separated section column.
        fn section<T: std::fmt::Debug>(values: &[T]) -> String {
            if values.is_empty() {
                "-".to_string()
            } else {
                format!("{values:?}")
            }
        }
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            jiff::Timestamp::from_microsecond(self.start_time).map_or_else(
                |_| format!("INVALID_TIMESTAMP({})", self.start_time),
                |ts| ts
                    .strftime(crate::ingest::RFC3339_RANGE_DATA_FORMAT)
                    .to_string(),
            ),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            self.trans_id,
            self.rcode,
            self.opcode,
            self.aa_flag,
            self.tc_flag,
            self.rd_flag,
            self.ra_flag,
            self.ad_flag,
            self.cd_flag,
            section(&self.queries),
            section(&self.answers),
            section(&self.authorities),
            section(&self.additionals),
        )
    }
}

impl ResponseRangeData for Dns {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let dns_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &dns_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MalformedDns {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub trans_id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub query_count: u32,
    pub resp_count: u32,
    pub query_bytes: u64,
    pub resp_bytes: u64,
    pub query_body: Vec<Vec<u8>>,
    pub resp_body: Vec<Vec<u8>>,
}

impl Display for MalformedDns {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            self.trans_id,
            self.flags,
            self.question_count,
            self.answer_count,
            self.authority_count,
            self.additional_count,
            self.query_count,
            self.resp_count,
            self.query_bytes,
            self.resp_bytes,
            format_args!("{:x?}", self.query_body),
            format_args!("{:x?}", self.resp_body),
        )
    }
}

impl ResponseRangeData for MalformedDns {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let dns_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &dns_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Http {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
}

impl Display for Http {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            as_str_or_default(&self.method),
            as_str_or_default(&self.host),
            as_str_or_default(&self.uri),
            as_str_or_default(&self.referer),
            as_str_or_default(&self.version),
            crate::ingest::sanitize_csv_field(&self.user_agent),
            self.request_len,
            self.response_len,
            self.status_code,
            as_str_or_default(&self.status_msg),
            as_str_or_default(&self.username),
            as_str_or_default(&self.password),
            as_str_or_default(&self.cookie),
            as_str_or_default(&self.content_encoding),
            as_str_or_default(&self.content_type),
            as_str_or_default(&self.cache_control),
            vec_to_string_or_default(&self.filenames),
            vec_to_string_or_default(&self.mime_types),
            crate::ingest::sanitize_csv_field_bytes(&self.body),
            as_str_or_default(&self.state),
        )
    }
}

impl ResponseRangeData for Http {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let http_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &http_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rdp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub cookie: String,
}

impl Display for Rdp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            self.cookie
        )
    }
}

impl ResponseRangeData for Rdp {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let rdp_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &rdp_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Smtp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
}

impl Display for Smtp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            as_str_or_default(&self.mailfrom),
            as_str_or_default(&self.date),
            as_str_or_default(&self.from),
            as_str_or_default(&self.to),
            as_str_or_default(&self.subject),
            as_str_or_default(&self.agent),
            as_str_or_default(&self.state),
        )
    }
}

impl ResponseRangeData for Smtp {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let smtp_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &smtp_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ntlm {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
}

impl Display for Ntlm {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            as_str_or_default(&self.protocol),
            as_str_or_default(&self.username),
            as_str_or_default(&self.hostname),
            as_str_or_default(&self.domainname),
            as_str_or_default(&self.success),
        )
    }
}

impl ResponseRangeData for Ntlm {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let ntlm_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &ntlm_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Kerberos {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub cname: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub sname: Vec<String>,
}

impl Display for Kerberos {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            convert_time_format(self.client_time),
            convert_time_format(self.server_time),
            self.error_code,
            as_str_or_default(&self.client_realm),
            self.cname_type,
            vec_to_string_or_default(&self.cname),
            as_str_or_default(&self.realm),
            self.sname_type,
            vec_to_string_or_default(&self.sname),
        )
    }
}

impl ResponseRangeData for Kerberos {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let kerberos_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &kerberos_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ssh {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub hassh_algorithms: String,
    pub hassh: String,
    pub hassh_server_algorithms: String,
    pub hassh_server: String,
    pub client_shka: String,
    pub server_shka: String,
}

impl Display for Ssh {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            as_str_or_default(&self.client),
            as_str_or_default(&self.server),
            as_str_or_default(&self.cipher_alg),
            as_str_or_default(&self.mac_alg),
            as_str_or_default(&self.compression_alg),
            as_str_or_default(&self.kex_alg),
            as_str_or_default(&self.host_key_alg),
            as_str_or_default(&self.hassh_algorithms),
            as_str_or_default(&self.hassh),
            as_str_or_default(&self.hassh_server_algorithms),
            as_str_or_default(&self.hassh_server),
            as_str_or_default(&self.client_shka),
            as_str_or_default(&self.server_shka),
        )
    }
}

impl ResponseRangeData for Ssh {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let ssh_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &ssh_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DceRpc {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub context: Vec<DceRpcContext>,
    pub request: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DceRpcContext {
    pub id: u16,
    pub abstract_syntax: u128,
    pub abstract_major: u16,
    pub abstract_minor: u16,
    pub transfer_syntax: u128,
    pub transfer_major: u16,
    pub transfer_minor: u16,
    pub acceptance: u16,
    pub reason: u16,
}

impl Display for DceRpc {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            vec_to_string_or_default(&self.context),
            vec_to_string_or_default(&self.request),
        )
    }
}

impl Display for DceRpcContext {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "({},{:032X},{},{},{:032X},{},{},{},{})",
            self.id,
            self.abstract_syntax,
            self.abstract_major,
            self.abstract_minor,
            self.transfer_syntax,
            self.transfer_major,
            self.transfer_minor,
            self.acceptance,
            self.reason,
        )
    }
}

impl ResponseRangeData for DceRpc {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let dce_rpc_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &dce_rpc_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ftp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub user: String,
    pub password: String,
    pub commands: Vec<FtpCommand>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FtpCommand {
    pub command: String,
    pub reply_code: String,
    pub reply_msg: String,
    pub data_passive: bool,
    pub data_orig_addr: IpAddr,
    pub data_resp_addr: IpAddr,
    pub data_resp_port: u16,
    pub file: String,
    pub file_size: u64,
    pub file_id: String,
}

impl Display for Ftp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            as_str_or_default(&self.user),
            as_str_or_default(&self.password),
            vec_to_string_or_default(&self.commands),
        )
    }
}

impl Display for FtpCommand {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "({},{},{},{},{},{},{},{},{},{})",
            as_str_or_default(&self.command),
            as_str_or_default(&self.reply_code),
            as_str_or_default(&self.reply_msg),
            self.data_passive,
            self.data_orig_addr,
            self.data_resp_addr,
            self.data_resp_port,
            as_str_or_default(&self.file),
            self.file_size,
            as_str_or_default(&self.file_id),
        )
    }
}

impl ResponseRangeData for Ftp {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let ftp_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &ftp_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Mqtt {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub protocol: String,
    pub version: u8,
    pub client_id: String,
    pub connack_reason: u8,
    pub subscribe: Vec<String>,
    pub suback_reason: Vec<u8>,
}

impl Display for Mqtt {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            as_str_or_default(&self.protocol),
            self.version,
            as_str_or_default(&self.client_id),
            self.connack_reason,
            vec_to_string_or_default(&self.subscribe),
            vec_to_string_or_default(&self.suback_reason),
        )
    }
}

impl ResponseRangeData for Mqtt {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let mqtt_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &mqtt_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ldap {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
}

impl Display for Ldap {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            self.message_id,
            self.version,
            vec_to_string_or_default(&self.opcode),
            vec_to_string_or_default(&self.result),
            vec_to_string_or_default(&self.diagnostic_message),
            vec_to_string_or_default(&self.object),
            vec_to_string_or_default(&self.argument),
        )
    }
}

impl ResponseRangeData for Ldap {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let ldap_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &ldap_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Tls {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
}

impl Display for Tls {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            as_str_or_default(&self.server_name),
            as_str_or_default(&self.alpn_protocol),
            as_str_or_default(&self.ja3),
            as_str_or_default(&self.version),
            vec_to_string_or_default(&self.client_cipher_suites),
            vec_to_string_or_default(&self.client_extensions),
            self.cipher,
            vec_to_string_or_default(&self.extensions),
            as_str_or_default(&self.ja3s),
            as_str_or_default(&self.serial),
            as_str_or_default(&self.subject_country),
            as_str_or_default(&self.subject_org_name),
            as_str_or_default(&self.subject_common_name),
            convert_time_format(self.validity_not_before),
            convert_time_format(self.validity_not_after),
            as_str_or_default(&self.subject_alt_name),
            as_str_or_default(&self.issuer_country),
            as_str_or_default(&self.issuer_org_name),
            as_str_or_default(&self.issuer_org_unit_name),
            as_str_or_default(&self.issuer_common_name),
            self.last_alert,
        )
    }
}

impl ResponseRangeData for Tls {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let tls_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &tls_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Smb {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub command: u8,
    pub path: String,
    pub service: String,
    pub file_name: String,
    pub file_size: u64,
    pub resource_type: u16,
    pub fid: u16,
    pub create_time: i64,
    pub access_time: i64,
    pub write_time: i64,
    pub change_time: i64,
}

impl Display for Smb {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            self.command,
            as_str_or_default(&self.path),
            as_str_or_default(&self.service),
            as_str_or_default(&self.file_name),
            self.file_size,
            self.resource_type,
            self.fid,
            // windows file time: since 1601-01-01 00:00 (UTC) in 100ns unit
            self.create_time,
            self.access_time,
            self.write_time,
            self.change_time,
        )
    }
}

impl ResponseRangeData for Smb {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let smb_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &smb_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Nfs {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
}

impl Display for Nfs {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            vec_to_string_or_default(&self.read_files),
            vec_to_string_or_default(&self.write_files),
        )
    }
}

impl ResponseRangeData for Nfs {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let nfs_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &nfs_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Bootp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub op: u8,
    pub htype: u8,
    pub hops: u8,
    pub xid: u32,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub chaddr: Vec<u8>,
    pub sname: String,
    pub file: String,
}

impl Display for Bootp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            self.op,
            self.htype,
            self.hops,
            self.xid,
            self.ciaddr,
            self.yiaddr,
            self.siaddr,
            self.giaddr,
            vec_to_string_or_default(&self.chaddr),
            as_str_or_default(&self.sname),
            as_str_or_default(&self.file),
        )
    }
}

impl ResponseRangeData for Bootp {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let bootp_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &bootp_csv.as_bytes())))
    }
}

fn display_dhcp_options(options: &[(u8, Vec<u8>)]) -> String {
    use std::fmt::Write;

    if options.is_empty() {
        "-".to_string()
    } else {
        options
            .iter()
            .map(|(tag, value)| {
                let hex =
                    value
                        .iter()
                        .fold(String::with_capacity(value.len() * 2), |mut acc, b| {
                            let _ = write!(acc, "{b:02x}");
                            acc
                        });
                format!("{tag}:{hex}")
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Dhcp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub msg_type: u8,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub subnet_mask: IpAddr,
    pub router: Vec<IpAddr>,
    pub domain_name_server: Vec<IpAddr>,
    pub req_ip_addr: IpAddr,
    pub lease_time: u32,
    pub server_id: IpAddr,
    pub param_req_list: Vec<u8>,
    pub message: String,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub class_id: Vec<u8>,
    pub client_id_type: u8,
    pub client_id: Vec<u8>,
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Display for Dhcp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            self.msg_type,
            self.ciaddr,
            self.yiaddr,
            self.siaddr,
            self.giaddr,
            self.subnet_mask,
            vec_to_string_or_default(&self.router),
            vec_to_string_or_default(&self.domain_name_server),
            self.req_ip_addr,
            self.lease_time,
            self.server_id,
            vec_to_string_or_default(&self.param_req_list),
            as_str_or_default(&self.message),
            self.renewal_time,
            self.rebinding_time,
            vec_to_string_or_default(&self.class_id),
            self.client_id_type,
            vec_to_string_or_default(&self.client_id),
            display_dhcp_options(&self.options),
        )
    }
}

impl ResponseRangeData for Dhcp {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let dhcp_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &dhcp_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Radius {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub id: u8,
    pub code: u8,
    pub resp_code: u8,
    pub auth: String,
    pub resp_auth: String,
    pub user_name: Vec<u8>,
    pub user_passwd: Vec<u8>,
    pub chap_passwd: Vec<u8>,
    pub nas_ip: IpAddr,
    pub nas_port: u32,
    pub state: Vec<u8>,
    pub nas_id: Vec<u8>,
    pub nas_port_type: u32,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Icmp {
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub id: u16,
    pub seq_num: u16,
    pub data_len: u16,
    pub payload: Vec<u8>,
}

impl Display for Radius {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            self.id,
            self.code,
            self.resp_code,
            self.auth,
            self.resp_auth,
            vec_to_string_or_default(&self.user_name),
            vec_to_string_or_default(&self.user_passwd),
            vec_to_string_or_default(&self.chap_passwd),
            self.nas_ip,
            self.nas_port,
            vec_to_string_or_default(&self.state),
            vec_to_string_or_default(&self.nas_id),
            self.nas_port_type,
            self.message,
        )
    }
}

impl ResponseRangeData for Radius {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let radius_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &radius_csv.as_bytes())))
    }
}

impl Display for Icmp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.resp_addr,
            self.proto,
            convert_time_format(self.start_time),
            self.duration,
            self.orig_pkts,
            self.resp_pkts,
            self.orig_l2_bytes,
            self.resp_l2_bytes,
            self.icmp_type,
            self.icmp_code,
            self.id,
            self.seq_num,
            self.data_len,
            format_args!("{:x?}", self.payload),
        )
    }
}

impl ResponseRangeData for Icmp {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let icmp_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &icmp_csv.as_bytes())))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn arp_transaction_round_trip_display_and_response() {
        use super::{Arp, ArpMessage};

        let request = ArpMessage {
            timestamp: -1,
            eth_src_mac: [1, 2, 3, 4, 5, 6],
            eth_dst_mac: [255; 6],
            sender_mac: [6, 5, 4, 3, 2, 1],
            sender_ip: [192, 0, 2, 1].into(),
            target_mac: [0; 6],
            target_ip: [192, 0, 2, 2].into(),
        };
        let response = ArpMessage {
            timestamp: 1_000_000_000,
            eth_src_mac: [7; 6],
            eth_dst_mac: request.eth_src_mac,
            sender_mac: [8; 6],
            sender_ip: request.target_ip,
            target_mac: request.sender_mac,
            target_ip: request.sender_ip,
        };
        let request_fields = [
            "1969-12-31T23:59:59.999999999+00:00",
            "01:02:03:04:05:06",
            "ff:ff:ff:ff:ff:ff",
            "06:05:04:03:02:01",
            "192.0.2.1",
            "00:00:00:00:00:00",
            "192.0.2.2",
        ];
        let response_fields_expected = [
            "1970-01-01T00:00:01+00:00",
            "07:07:07:07:07:07",
            "01:02:03:04:05:06",
            "08:08:08:08:08:08",
            "192.0.2.2",
            "06:05:04:03:02:01",
            "192.0.2.1",
        ];
        for (request, response) in [
            (Some(request.clone()), Some(response.clone())),
            (Some(request), None),
            (None, Some(response)),
            (None, None),
        ] {
            for vlan_id in [Some(42), None] {
                let event = Arp {
                    vlan_id,
                    start_time: 100,
                    duration: 1,
                    orig_pkts: 2,
                    resp_pkts: 3,
                    orig_l2_bytes: 60,
                    resp_l2_bytes: 120,
                    request: request.clone(),
                    response: response.clone(),
                };
                let encoded = bincode::serialize(&event).unwrap();
                let decoded: Arp = bincode::deserialize(&encoded).unwrap();
                assert_eq!(decoded, event);

                let mut expected = vec![
                    if vlan_id.is_some() { "42" } else { "-" },
                    "1970-01-01T00:00:00.0000001+00:00",
                    "1",
                    "2",
                    "3",
                    "60",
                    "120",
                ];
                expected.extend(if request.is_some() {
                    request_fields
                } else {
                    ["-"; 7]
                });
                expected.extend(if response.is_some() {
                    response_fields_expected
                } else {
                    ["-"; 7]
                });
                let fields = display_fields(&event);
                assert_eq!(fields.len(), 21);
                assert_eq!(fields, expected);

                let fields = response_fields(&event, 2_000_000_001, "arp-sensor");
                assert_eq!(fields.len(), 23);
                let mut expected_response =
                    vec!["1970-01-01T00:00:02.000000001+00:00", "arp-sensor"];
                expected_response.extend(expected);
                assert_eq!(fields, expected_response);
            }
        }
    }

    use std::fmt::Display;

    use super::*;

    fn decode_response_data<T>(value: &T, timestamp: i64, sensor: &str) -> (i64, String, String)
    where
        T: ResponseRangeData,
    {
        let res = value.response_data(timestamp, sensor).unwrap();
        let decoded: Option<(i64, String, Vec<u8>)> = bincode::deserialize(&res).unwrap();
        let (decoded_ts, decoded_sensor, decoded_csv) = decoded.expect("expected Some payload");

        (
            decoded_ts,
            decoded_sensor,
            String::from_utf8(decoded_csv).expect("expected UTF-8 CSV payload"),
        )
    }

    fn assert_response_envelope<T>(value: &T, timestamp: i64, sensor: &str) -> String
    where
        T: ResponseRangeData,
    {
        let (decoded_ts, decoded_sensor, decoded_csv) =
            decode_response_data(value, timestamp, sensor);

        assert_eq!(decoded_ts, timestamp);
        assert_eq!(decoded_sensor, sensor);

        decoded_csv
    }

    fn last_tab_field(output: &str) -> &str {
        output.split('\t').next_back().unwrap()
    }

    fn display_fields<T>(value: &T) -> Vec<String>
    where
        T: Display,
    {
        format!("{value}").split('\t').map(str::to_owned).collect()
    }

    fn response_fields<T>(value: &T, timestamp: i64, sensor: &str) -> Vec<String>
    where
        T: ResponseRangeData,
    {
        assert_response_envelope(value, timestamp, sensor)
            .split('\t')
            .map(str::to_owned)
            .collect()
    }

    fn assert_field_values(fields: &[String], expected: &[(usize, &str)]) {
        for &(index, expected_value) in expected {
            assert_eq!(
                fields[index], expected_value,
                "unexpected field value at index {index}"
            );
        }
    }

    /// Formats `ts` with the production serializer and asserts the result is in
    /// the canonical RFC 3339 contract format. Callers compare a record field
    /// against the return value, so each assertion verifies both field
    /// placement and the canonical wire format (not just that the field echoes
    /// `convert_time_format`).
    fn fmt_time(ts: i64) -> String {
        let formatted = convert_time_format(ts);
        crate::test::assert_canonical_time(&formatted, ts);
        formatted
    }

    fn assert_placeholder_fields(fields: &[String], indices: &[usize]) {
        for &index in indices {
            assert_eq!(
                fields[index], "-",
                "unexpected placeholder field at index {index}"
            );
        }
    }

    mod fixtures {
        use std::net::IpAddr;

        use super::*;

        pub(super) fn conn() -> Conn {
            Conn {
                orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
                orig_port: 46_378,
                resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
                resp_port: 80,
                proto: 6,
                conn_state: "SF".to_string(),
                start_time: 1_000,
                duration: 500,
                service: "http".to_string(),
                orig_bytes: 77,
                resp_bytes: 295,
                orig_pkts: 397,
                resp_pkts: 511,
                orig_l2_bytes: 21_515,
                resp_l2_bytes: 27_889,
                orig_flags: 18,
                resp_flags: 16,
                missed_bytes: 42,
                icmp_type: Some(8),
                icmp_code: Some(0),
                syn_ttl: Some(64),
                syn_window_size: Some(64240),
                syn_window_scale: Some(7),
                syn_mss: Some(1460),
                syn_options_order: vec![2, 4, 8, 1, 3],
                syn_df: Some(true),
            }
        }

        pub(super) fn dns() -> Dns {
            Dns {
                orig_addr: "127.0.0.1".parse().unwrap(),
                orig_port: 1234,
                resp_addr: "127.0.0.1".parse().unwrap(),
                resp_port: 53,
                proto: 17,
                start_time: 1_000,
                duration: 100,
                orig_pkts: 1,
                resp_pkts: 1,
                orig_l2_bytes: 100,
                resp_l2_bytes: 100,
                trans_id: 1,
                rcode: 0,
                opcode: 0,
                aa_flag: true,
                tc_flag: false,
                rd_flag: true,
                ra_flag: true,
                ad_flag: false,
                cd_flag: false,
                queries: vec![DnsQuestion {
                    name: "example.com".into(),
                    qtype: 1,
                    qclass: 1,
                }],
                answers: vec![ResourceRecord {
                    name: "example.com".into(),
                    rtype: 1,
                    rclass: 1,
                    ttl: 3600,
                    data: ResourceData::A("1.2.3.4".parse().unwrap()),
                }],
                authorities: vec![],
                additionals: vec![],
            }
        }

        pub(super) fn dhcp(options: Vec<(u8, Vec<u8>)>) -> Dhcp {
            Dhcp {
                orig_addr: "192.0.2.60".parse().unwrap(),
                orig_port: 68,
                resp_addr: "192.0.2.61".parse().unwrap(),
                resp_port: 67,
                proto: 17,
                start_time: 13_000,
                duration: 95,
                orig_pkts: 21,
                resp_pkts: 22,
                orig_l2_bytes: 2_100,
                resp_l2_bytes: 2_200,
                msg_type: 5,
                ciaddr: "0.0.0.0".parse().unwrap(),
                yiaddr: "192.0.2.70".parse().unwrap(),
                siaddr: "192.0.2.1".parse().unwrap(),
                giaddr: "0.0.0.0".parse().unwrap(),
                subnet_mask: "255.255.255.0".parse().unwrap(),
                router: vec!["192.0.2.1".parse().unwrap()],
                domain_name_server: vec!["192.0.2.2".parse().unwrap()],
                req_ip_addr: "192.0.2.80".parse().unwrap(),
                lease_time: 86_400,
                server_id: "192.0.2.1".parse().unwrap(),
                param_req_list: vec![1, 3, 6],
                message: "dhcp offer".to_string(),
                renewal_time: 43_200,
                rebinding_time: 64_800,
                class_id: vec![1, 2, 3],
                client_id_type: 1,
                client_id: vec![0, 1, 2, 3, 4, 5],
                options,
            }
        }

        pub(super) fn http() -> Http {
            Http {
                orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
                orig_port: 80,
                resp_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
                resp_port: 443,
                proto: 6,
                start_time: 1_000_000_000,
                duration: 0,
                orig_pkts: 1,
                resp_pkts: 1,
                orig_l2_bytes: 100,
                resp_l2_bytes: 200,
                method: "GET".to_string(),
                host: "example.com".to_string(),
                uri: "/path".to_string(),
                referer: String::new(),
                version: "1.1".to_string(),
                user_agent: "Mozilla".to_string(),
                request_len: 100,
                response_len: 200,
                status_code: 200,
                status_msg: "OK".to_string(),
                username: String::new(),
                password: String::new(),
                cookie: String::new(),
                content_encoding: String::new(),
                content_type: "text/html".to_string(),
                cache_control: String::new(),
                filenames: vec![],
                mime_types: vec![],
                body: vec![],
                state: String::new(),
            }
        }

        pub(super) fn rdp() -> Rdp {
            Rdp {
                orig_addr: "127.0.0.1".parse().unwrap(),
                orig_port: 1234,
                resp_addr: "127.0.0.1".parse().unwrap(),
                resp_port: 3389,
                proto: 6,
                start_time: 1_000,
                duration: 100,
                orig_pkts: 1,
                resp_pkts: 1,
                orig_l2_bytes: 100,
                resp_l2_bytes: 100,
                cookie: "cookie".to_string(),
            }
        }

        pub(super) fn icmp() -> Icmp {
            Icmp {
                orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
                resp_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
                proto: 1,
                start_time: 1_000_000_000,
                duration: 0,
                orig_pkts: 1,
                resp_pkts: 1,
                orig_l2_bytes: 100,
                resp_l2_bytes: 100,
                icmp_type: 8,
                icmp_code: 0,
                id: 1234,
                seq_num: 1,
                data_len: 56,
                payload: vec![0x08, 0x00, 0xff, 0xff],
            }
        }

        pub(super) fn smtp() -> Smtp {
            Smtp {
                orig_addr: "192.0.2.1".parse().unwrap(),
                orig_port: 25,
                resp_addr: "192.0.2.2".parse().unwrap(),
                resp_port: 2525,
                proto: 6,
                start_time: 3_000,
                duration: 120,
                orig_pkts: 4,
                resp_pkts: 4,
                orig_l2_bytes: 400,
                resp_l2_bytes: 450,
                mailfrom: "sender@example.com".to_string(),
                date: "Fri, 05 Jan 2024 12:00:00 GMT".to_string(),
                from: "Sender".to_string(),
                to: "recipient@example.com".to_string(),
                subject: "Hello".to_string(),
                agent: "Postfix".to_string(),
                state: "delivered".to_string(),
            }
        }

        pub(super) fn ntlm() -> Ntlm {
            Ntlm {
                orig_addr: "203.0.113.1".parse().unwrap(),
                orig_port: 139,
                resp_addr: "203.0.113.2".parse().unwrap(),
                resp_port: 445,
                proto: 6,
                start_time: 4_000,
                duration: 60,
                orig_pkts: 5,
                resp_pkts: 5,
                orig_l2_bytes: 500,
                resp_l2_bytes: 600,
                protocol: "NTLMSSP".to_string(),
                username: "user".to_string(),
                hostname: "host".to_string(),
                domainname: "domain".to_string(),
                success: "true".to_string(),
            }
        }

        pub(super) fn kerberos() -> Kerberos {
            Kerberos {
                orig_addr: "198.51.100.1".parse().unwrap(),
                orig_port: 88,
                resp_addr: "198.51.100.2".parse().unwrap(),
                resp_port: 88,
                proto: 6,
                start_time: 5_000,
                duration: 70,
                orig_pkts: 6,
                resp_pkts: 7,
                orig_l2_bytes: 600,
                resp_l2_bytes: 700,
                client_time: 1_000,
                server_time: 2_000,
                error_code: 0,
                client_realm: "EXAMPLE.COM".to_string(),
                cname_type: 1,
                cname: vec!["client".to_string()],
                realm: "EXAMPLE.COM".to_string(),
                sname_type: 2,
                sname: vec!["krbtgt".to_string(), "EXAMPLE.COM".to_string()],
            }
        }

        pub(super) fn ssh() -> Ssh {
            Ssh {
                orig_addr: "127.0.0.1".parse().unwrap(),
                orig_port: 1234,
                resp_addr: "127.0.0.1".parse().unwrap(),
                resp_port: 22,
                proto: 6,
                start_time: 1_000,
                duration: 100,
                orig_pkts: 1,
                resp_pkts: 1,
                orig_l2_bytes: 100,
                resp_l2_bytes: 100,
                client: "client".to_string(),
                server: "server".to_string(),
                cipher_alg: "alg".to_string(),
                mac_alg: "mac".to_string(),
                compression_alg: "comp".to_string(),
                kex_alg: "kex".to_string(),
                host_key_alg: "host".to_string(),
                hassh_algorithms: "hassh".to_string(),
                hassh: "hassh_val".to_string(),
                hassh_server_algorithms: "hassh_srv".to_string(),
                hassh_server: "hassh_srv_val".to_string(),
                client_shka: "cshka".to_string(),
                server_shka: "sshka".to_string(),
            }
        }

        pub(super) fn dcerpc() -> DceRpc {
            DceRpc {
                orig_addr: "127.0.0.1".parse().unwrap(),
                orig_port: 1234,
                resp_addr: "127.0.0.1".parse().unwrap(),
                resp_port: 135,
                proto: 6,
                start_time: 1_000,
                duration: 100,
                orig_pkts: 1,
                resp_pkts: 1,
                orig_l2_bytes: 100,
                resp_l2_bytes: 100,
                context: vec![DceRpcContext {
                    id: 0,
                    abstract_syntax: 0x0883_AFE1_1F5D_C911_91A4_0800_2B14_A0FA,
                    abstract_major: 3,
                    abstract_minor: 0,
                    transfer_syntax: 0x045D_888A_EB1C_C911_9FE8_0800_2B10_4860,
                    transfer_major: 2,
                    transfer_minor: 0,
                    acceptance: 0,
                    reason: 0,
                }],
                request: vec!["0:0".to_string()],
            }
        }

        pub(super) fn tls() -> Tls {
            Tls {
                orig_addr: "203.0.113.20".parse().unwrap(),
                orig_port: 443,
                resp_addr: "203.0.113.21".parse().unwrap(),
                resp_port: 443,
                proto: 6,
                start_time: 9_000,
                duration: 55,
                orig_pkts: 13,
                resp_pkts: 14,
                orig_l2_bytes: 1_300,
                resp_l2_bytes: 1_400,
                server_name: "example.com".to_string(),
                alpn_protocol: "h2".to_string(),
                ja3: "ja3".to_string(),
                version: "TLS1.3".to_string(),
                client_cipher_suites: vec![4865, 4866],
                client_extensions: vec![0, 11],
                cipher: 4865,
                extensions: vec![0, 23],
                ja3s: "ja3s".to_string(),
                serial: "serial".to_string(),
                subject_country: "US".to_string(),
                subject_org_name: "Org".to_string(),
                subject_common_name: "example.com".to_string(),
                validity_not_before: 1_700_000_000,
                validity_not_after: 1_800_000_000,
                subject_alt_name: "example.com".to_string(),
                issuer_country: "US".to_string(),
                issuer_org_name: "CA".to_string(),
                issuer_org_unit_name: "Unit".to_string(),
                issuer_common_name: "CA".to_string(),
                last_alert: 0,
            }
        }

        pub(super) fn radius() -> Radius {
            Radius {
                orig_addr: "198.51.100.30".parse().unwrap(),
                orig_port: 1812,
                resp_addr: "198.51.100.31".parse().unwrap(),
                resp_port: 1812,
                proto: 17,
                start_time: 14_000,
                duration: 105,
                orig_pkts: 23,
                resp_pkts: 24,
                orig_l2_bytes: 2_300,
                resp_l2_bytes: 2_400,
                id: 1,
                code: 1,
                resp_code: 2,
                auth: "auth".to_string(),
                resp_auth: "resp_auth".to_string(),
                user_name: b"user".to_vec(),
                user_passwd: b"pass".to_vec(),
                chap_passwd: b"chap".to_vec(),
                nas_ip: "198.51.100.100".parse().unwrap(),
                nas_port: 0,
                state: b"state".to_vec(),
                nas_id: b"nas-id".to_vec(),
                nas_port_type: 5,
                message: "ok".to_string(),
            }
        }

        pub(super) fn ftp() -> Ftp {
            Ftp {
                orig_addr: "203.0.113.10".parse().unwrap(),
                orig_port: 21,
                resp_addr: "203.0.113.11".parse().unwrap(),
                resp_port: 21,
                proto: 6,
                start_time: 6_000,
                duration: 30,
                orig_pkts: 7,
                resp_pkts: 8,
                orig_l2_bytes: 700,
                resp_l2_bytes: 800,
                user: "ftp_user".to_string(),
                password: "ftp_pass".to_string(),
                commands: vec![FtpCommand {
                    command: "LIST".to_string(),
                    reply_code: "150".to_string(),
                    reply_msg: "Here comes the directory listing".to_string(),
                    data_passive: true,
                    data_orig_addr: "203.0.113.10".parse().unwrap(),
                    data_resp_addr: "203.0.113.11".parse().unwrap(),
                    data_resp_port: 2121,
                    file: "file.txt".to_string(),
                    file_size: 1024,
                    file_id: "id123".to_string(),
                }],
            }
        }

        pub(super) fn mqtt() -> Mqtt {
            Mqtt {
                orig_addr: "192.0.2.10".parse().unwrap(),
                orig_port: 1883,
                resp_addr: "192.0.2.11".parse().unwrap(),
                resp_port: 1883,
                proto: 6,
                start_time: 7_000,
                duration: 40,
                orig_pkts: 9,
                resp_pkts: 10,
                orig_l2_bytes: 900,
                resp_l2_bytes: 1_000,
                protocol: "MQTT".to_string(),
                version: 5,
                client_id: "client-id".to_string(),
                connack_reason: 0,
                subscribe: vec!["/topic".to_string()],
                suback_reason: vec![0],
            }
        }

        pub(super) fn ldap() -> Ldap {
            Ldap {
                orig_addr: "198.51.100.10".parse().unwrap(),
                orig_port: 389,
                resp_addr: "198.51.100.11".parse().unwrap(),
                resp_port: 389,
                proto: 6,
                start_time: 8_000,
                duration: 45,
                orig_pkts: 11,
                resp_pkts: 12,
                orig_l2_bytes: 1_100,
                resp_l2_bytes: 1_200,
                message_id: 1,
                version: 3,
                opcode: vec!["bindRequest".to_string()],
                result: vec!["success".to_string()],
                diagnostic_message: vec!["diagnostic".to_string()],
                object: vec!["cn=users,dc=example,dc=com".to_string()],
                argument: vec!["arg".to_string()],
            }
        }

        pub(super) fn nfs() -> Nfs {
            Nfs {
                orig_addr: "198.51.100.20".parse().unwrap(),
                orig_port: 2049,
                resp_addr: "198.51.100.21".parse().unwrap(),
                resp_port: 2049,
                proto: 6,
                start_time: 11_000,
                duration: 75,
                orig_pkts: 17,
                resp_pkts: 18,
                orig_l2_bytes: 1_700,
                resp_l2_bytes: 1_800,
                read_files: vec!["/mnt/share/read.txt".to_string()],
                write_files: vec!["/mnt/share/write.txt".to_string()],
            }
        }

        pub(super) fn smb() -> Smb {
            Smb {
                orig_addr: "192.0.2.30".parse().unwrap(),
                orig_port: 445,
                resp_addr: "192.0.2.31".parse().unwrap(),
                resp_port: 445,
                proto: 6,
                start_time: 10_000,
                duration: 65,
                orig_pkts: 15,
                resp_pkts: 16,
                orig_l2_bytes: 1_500,
                resp_l2_bytes: 1_600,
                command: 3,
                path: r"\\server\share".to_string(),
                service: "SMB".to_string(),
                file_name: "file.txt".to_string(),
                file_size: 2_048,
                resource_type: 1,
                fid: 2,
                create_time: 1_700_000_000,
                access_time: 1_700_000_100,
                write_time: 1_700_000_200,
                change_time: 1_700_000_300,
            }
        }

        pub(super) fn bootp() -> Bootp {
            Bootp {
                orig_addr: "192.0.2.40".parse().unwrap(),
                orig_port: 68,
                resp_addr: "192.0.2.41".parse().unwrap(),
                resp_port: 67,
                proto: 17,
                start_time: 12_000,
                duration: 85,
                orig_pkts: 19,
                resp_pkts: 20,
                orig_l2_bytes: 1_900,
                resp_l2_bytes: 2_000,
                op: 1,
                htype: 1,
                hops: 0,
                xid: 0x1234_5678,
                ciaddr: "0.0.0.0".parse().unwrap(),
                yiaddr: "192.0.2.50".parse().unwrap(),
                siaddr: "192.0.2.1".parse().unwrap(),
                giaddr: "0.0.0.0".parse().unwrap(),
                chaddr: vec![0, 1, 2, 3, 4, 5],
                sname: "server".to_string(),
                file: "bootfile".to_string(),
            }
        }
    }

    #[test]
    fn test_conn_display_formats_core_fields_in_order() {
        let conn = fixtures::conn();

        let fields = display_fields(&conn);
        assert_eq!(fields.len(), 26);
        assert_field_values(
            &fields,
            &[
                (0, "192.168.4.76"),
                (1, "46378"),
                (5, "SF"),
                (8, "http"),
                (14, "27889"),
                (15, "18"),
                (16, "16"),
                (17, "42"),
                (18, "8"),
                (19, "0"),
                (20, "64"),
                (21, "64240"),
                (22, "7"),
                (23, "1460"),
                (24, "2,4,8,1,3"),
                (25, "true"),
            ],
        );
        assert_eq!(fields[6], fmt_time(conn.start_time));
    }

    #[test]
    fn test_conn_display_missing_optional_fields() {
        let mut conn = fixtures::conn();
        conn.icmp_type = None;
        conn.icmp_code = None;
        conn.syn_ttl = None;
        conn.syn_window_size = None;
        conn.syn_window_scale = None;
        conn.syn_mss = None;
        conn.syn_options_order.clear();
        conn.syn_df = None;
        let fields = display_fields(&conn);
        assert_placeholder_fields(&fields, &[18, 19, 20, 21, 22, 23, 24, 25]);
        conn.syn_df = Some(false);
        assert_eq!(display_fields(&conn)[25], "false");
    }

    #[test]
    fn test_conn_response_data_envelope() {
        let conn = fixtures::conn();

        let fields = response_fields(&conn, 1_234_567_890, "conn-sensor");
        assert_eq!(fields.len(), 28);
        assert_field_values(
            &fields,
            &[
                (1, "conn-sensor"),
                (2, "192.168.4.76"),
                (7, "SF"),
                (10, "http"),
                (16, "27889"),
                (26, "2,4,8,1,3"),
                (27, "true"),
            ],
        );
        assert_eq!(fields[0], fmt_time(1_234_567_890));
    }

    #[test]
    fn test_dns_display_and_response_data() {
        let dns = fixtures::dns();
        let fields = display_fields(&dns);
        assert_eq!(fields.len(), 24);
        assert_eq!(fields[5], "1970-01-01T00:00:00.001+00:00");
        assert!(fields[20].contains("example.com"));
        assert!(fields[21].contains("1.2.3.4"));
        assert_field_values(&fields, &[(22, "-"), (23, "-")]);
        let response = response_fields(&dns, 1000, "dns-sensor");
        assert_eq!(response.len(), 26);
        assert_eq!(response[1], "dns-sensor");
        assert_eq!(&response[2..], fields);
    }

    #[test]
    fn test_dns_round_trip_sections_and_metadata() {
        let mut dns = fixtures::dns();
        dns.trans_id = u16::MAX;
        dns.rcode = 4095;
        dns.opcode = 15;
        dns.aa_flag = true;
        dns.tc_flag = true;
        dns.rd_flag = false;
        dns.ra_flag = true;
        dns.ad_flag = true;
        dns.cd_flag = true;
        let data = vec![
            ResourceData::A("192.0.2.1".parse().unwrap()),
            ResourceData::AAAA("2001:db8::1".parse().unwrap()),
            ResourceData::CNAME("alias.example".into()),
            ResourceData::MX {
                preference: 65535,
                exchange: "mail.example".into(),
            },
            ResourceData::NS("ns.example".into()),
            ResourceData::PTR("ptr.example".into()),
            ResourceData::TXT(vec!["first".into(), "second".into()]),
            ResourceData::SOA {
                mname: "ns.example".into(),
                rname: "host.example".into(),
                serial: u32::MAX,
                refresh: -1,
                retry: -2,
                expire: -3,
                minimum: u32::MAX,
            },
            ResourceData::SRV {
                priority: 1,
                weight: 2,
                port: 65535,
                target: "service.example".into(),
            },
            ResourceData::OPT {
                payload_size: 4096,
                ext_rcode: 255,
                version: 1,
                flags: 32768,
            },
            ResourceData::Unknown(vec![0, 1, 127, 255]),
        ];
        let records: Vec<_> = data
            .into_iter()
            .enumerate()
            .map(|(i, data)| ResourceRecord {
                name: format!("record{i}.example"),
                rtype: u16::try_from(i).unwrap(),
                rclass: 255,
                ttl: -1,
                data,
            })
            .collect();
        dns.answers = records[..4].to_vec();
        dns.authorities = records[4..8].to_vec();
        dns.additionals = records[8..].to_vec();
        let bytes = bincode::serialize(&dns).unwrap();
        assert_eq!(bincode::deserialize::<Dns>(&bytes).unwrap(), dns);
    }

    #[test]
    fn test_dns_missing_sides_round_trip() {
        let mut request = fixtures::dns();
        request.answers.clear();
        let request: Dns = bincode::deserialize(&bincode::serialize(&request).unwrap()).unwrap();
        assert_eq!(request.queries, fixtures::dns().queries);
        assert!(
            request.answers.is_empty()
                && request.authorities.is_empty()
                && request.additionals.is_empty()
        );
        let mut reply = fixtures::dns();
        reply.queries.clear();
        let reply: Dns = bincode::deserialize(&bincode::serialize(&reply).unwrap()).unwrap();
        assert_eq!(reply.queries, []);
        assert_eq!(reply.answers, fixtures::dns().answers);
        assert_eq!(display_fields(&reply)[20], "-");
    }

    #[test]
    fn test_malformed_dns_response_data_envelope() {
        let malformed = MalformedDns {
            orig_addr: "10.0.0.1".parse().unwrap(),
            orig_port: 1111,
            resp_addr: "10.0.0.2".parse().unwrap(),
            resp_port: 2222,
            proto: 17,
            start_time: 2_000,
            duration: 50,
            orig_pkts: 2,
            resp_pkts: 3,
            orig_l2_bytes: 200,
            resp_l2_bytes: 300,
            trans_id: 42,
            flags: 0x1234,
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
            query_count: 2,
            resp_count: 1,
            query_bytes: 128,
            resp_bytes: 256,
            query_body: vec![b"query".to_vec()],
            resp_body: vec![b"resp".to_vec()],
        };

        let fields = response_fields(&malformed, 9_999, "malformed-dns");
        assert_eq!(fields.len(), 25);
        assert_eq!(fields[0], fmt_time(9_999));
        assert_eq!(fields[1], "malformed-dns");
        assert_eq!(fields[14], "4660");
        assert_eq!(fields[19], "2");
        assert_eq!(fields[20], "1");
        assert_eq!(fields[23], "[[71, 75, 65, 72, 79]]");
        assert_eq!(fields[24], "[[72, 65, 73, 70]]");
    }

    #[test]
    fn test_http_display_sanitizes_special_characters() {
        let http = Http {
            user_agent: "Mozilla/5.0\t(Windows NT\n10.0;\rWin64)".to_string(),
            body: b"username=test\tpassword=secret\nsubmit=true\r".to_vec(),
            ..fixtures::http()
        };

        let csv_output = format!("{http}");
        let fields: Vec<&str> = csv_output.split('\t').collect();

        assert_eq!(fields.len(), 31);
        assert_eq!(fields[16], "Mozilla/5.0 (Windows NT 10.0; Win64)");
        assert!(!fields[16].contains('\n'));
        assert!(!fields[16].contains('\r'));
        assert!(!fields[16].contains('\t'));

        assert_eq!(fields[29], "username=test password=secret submit=true ");
        assert!(!fields[29].contains('\t'));
        assert!(!fields[29].contains('\n'));
        assert!(!fields[29].contains('\r'));
    }

    #[test]
    fn test_http_display_uses_dash_for_empty_user_agent_and_body() {
        let http = Http {
            user_agent: String::new(),
            body: vec![],
            ..fixtures::http()
        };

        let csv_output = format!("{http}");
        let fields: Vec<&str> = csv_output.split('\t').collect();

        assert_eq!(fields.len(), 31);
        assert_eq!(fields[16], "-");
        assert_eq!(fields[29], "-");
    }

    #[test]
    fn test_http_response_data_envelope() {
        let http = Http {
            orig_addr: "127.0.0.1".parse().unwrap(),
            orig_port: 1234,
            resp_addr: "127.0.0.1".parse().unwrap(),
            resp_port: 80,
            start_time: 1000,
            duration: 100,
            resp_l2_bytes: 100,
            uri: "/".to_string(),
            response_len: 100,
            ..fixtures::http()
        };

        let fields = response_fields(&http, 1000, "http-sensor");
        assert_eq!(fields.len(), 33);
        assert_eq!(fields[0], fmt_time(1_000));
        assert_eq!(fields[1], "http-sensor");
        assert_eq!(fields[2], "127.0.0.1");
        assert_eq!(fields[5], "80");
        assert_eq!(fields[15], "/");
        assert_eq!(fields[20], "100");
        assert_eq!(fields[31], "-");
    }

    #[test]
    fn test_rdp_display_and_response_envelope() {
        let rdp = fixtures::rdp();

        let display = display_fields(&rdp);
        assert_eq!(display.len(), 12);
        assert_field_values(&display, &[(11, "cookie")]);
        assert_eq!(display[5], fmt_time(rdp.start_time));

        let fields = response_fields(&rdp, 2_000, "rdp-sensor");
        assert_eq!(fields.len(), 14);
        assert_field_values(&fields, &[(1, "rdp-sensor"), (13, "cookie")]);
        assert_eq!(fields[0], fmt_time(2_000));
    }

    #[test]
    fn test_smtp_response_data_envelope() {
        let smtp = fixtures::smtp();

        let fields = response_fields(&smtp, 3_000, "smtp-sensor");
        assert_eq!(fields.len(), 20);
        assert_field_values(
            &fields,
            &[
                (1, "smtp-sensor"),
                (2, "192.0.2.1"),
                (3, "25"),
                (4, "192.0.2.2"),
                (5, "2525"),
                (13, "sender@example.com"),
                (14, "Fri, 05 Jan 2024 12:00:00 GMT"),
                (15, "Sender"),
                (16, "recipient@example.com"),
                (17, "Hello"),
                (18, "Postfix"),
                (19, "delivered"),
            ],
        );
        assert_eq!(fields[7], fmt_time(3_000));
    }

    #[test]
    fn test_ntlm_response_data_envelope() {
        let ntlm = fixtures::ntlm();

        let fields = response_fields(&ntlm, 4_000, "ntlm-sensor");
        assert_eq!(fields.len(), 18);
        assert_field_values(
            &fields,
            &[
                (1, "ntlm-sensor"),
                (2, "203.0.113.1"),
                (3, "139"),
                (4, "203.0.113.2"),
                (5, "445"),
                (13, "NTLMSSP"),
                (14, "user"),
                (15, "host"),
                (16, "domain"),
                (17, "true"),
            ],
        );
        assert_eq!(fields[7], fmt_time(4_000));
    }

    #[test]
    fn test_kerberos_response_data_envelope() {
        let kerberos = fixtures::kerberos();

        let fields = response_fields(&kerberos, 5_000, "kerberos-sensor");
        assert_eq!(fields.len(), 22);
        assert_field_values(
            &fields,
            &[
                (1, "kerberos-sensor"),
                (16, "EXAMPLE.COM"),
                (18, "client"),
                (21, "krbtgt,EXAMPLE.COM"),
            ],
        );
        assert_eq!(fields[13], fmt_time(1_000));
        assert_eq!(fields[14], fmt_time(2_000));
    }

    #[test]
    fn test_kerberos_display_uses_dash_for_empty_string_and_vector_fields() {
        let kerberos = Kerberos {
            client_realm: String::new(),
            cname: vec![],
            realm: String::new(),
            sname: vec![],
            ..fixtures::kerberos()
        };

        let fields = display_fields(&kerberos);
        assert_eq!(fields.len(), 20);
        assert_field_values(&fields, &[(14, "-"), (16, "-"), (17, "-"), (19, "-")]);
    }

    #[test]
    fn test_ssh_display_and_response_envelope() {
        let ssh = fixtures::ssh();

        let display = display_fields(&ssh);
        assert_eq!(display.len(), 24);
        assert_field_values(
            &display,
            &[
                (11, "client"),
                (12, "server"),
                (18, "hassh"),
                (20, "hassh_srv"),
                (23, "sshka"),
            ],
        );

        let fields = response_fields(&ssh, 1000, "ssh-sensor");
        assert_eq!(fields.len(), 26);
        assert_field_values(
            &fields,
            &[
                (1, "ssh-sensor"),
                (13, "client"),
                (14, "server"),
                (20, "hassh"),
                (22, "hassh_srv"),
                (25, "sshka"),
            ],
        );
    }

    #[test]
    fn test_ssh_display_uses_dash_for_empty_string_fields() {
        let ssh = Ssh {
            client: String::new(),
            server: String::new(),
            cipher_alg: String::new(),
            mac_alg: String::new(),
            compression_alg: String::new(),
            kex_alg: String::new(),
            host_key_alg: String::new(),
            hassh_algorithms: String::new(),
            hassh: String::new(),
            hassh_server_algorithms: String::new(),
            hassh_server: String::new(),
            client_shka: String::new(),
            server_shka: String::new(),
            ..fixtures::ssh()
        };

        let fields = display_fields(&ssh);
        assert_eq!(fields.len(), 24);
        for (index, _) in fields.iter().enumerate().take(23 + 1).skip(11) {
            assert_eq!(
                fields[index], "-",
                "unexpected SSH placeholder field at index {index}"
            );
        }
    }

    #[test]
    fn test_dcerpc_display_and_response_envelope() {
        let dcerpc = fixtures::dcerpc();

        let display = display_fields(&dcerpc);
        assert_eq!(display.len(), 13);
        assert_field_values(
            &display,
            &[
                (
                    11,
                    "(0,0883AFE11F5DC91191A408002B14A0FA,3,0,045D888AEB1CC9119FE808002B104860,2,0,0,0)",
                ),
                (12, "0:0"),
            ],
        );

        let fields = response_fields(&dcerpc, 1000, "dcerpc-sensor");
        assert_eq!(fields.len(), 15);
        assert_field_values(
            &fields,
            &[
                (1, "dcerpc-sensor"),
                (
                    13,
                    "(0,0883AFE11F5DC91191A408002B14A0FA,3,0,045D888AEB1CC9119FE808002B104860,2,0,0,0)",
                ),
                (14, "0:0"),
            ],
        );
        assert_eq!(fields[7], fmt_time(1_000));
    }

    #[test]
    fn test_dcerpc_display_uses_dash_for_empty_vectors() {
        let dcerpc = DceRpc {
            context: vec![],
            request: vec![],
            ..fixtures::dcerpc()
        };

        let fields = display_fields(&dcerpc);
        assert_eq!(fields.len(), 13);
        assert_field_values(&fields, &[(11, "-"), (12, "-")]);
    }

    #[test]
    fn test_ftp_response_data_envelope() {
        let ftp = fixtures::ftp();

        let fields = response_fields(&ftp, 6_000, "ftp-sensor");
        assert_eq!(fields.len(), 16);
        assert_eq!(fields[1], "ftp-sensor");
        assert_eq!(fields[13], "ftp_user");
        assert_eq!(fields[14], "ftp_pass");
        assert_eq!(
            fields[15],
            "(LIST,150,Here comes the directory listing,true,203.0.113.10,203.0.113.11,2121,file.txt,1024,id123)"
        );
    }

    #[test]
    fn test_mqtt_response_data_envelope() {
        let mqtt = fixtures::mqtt();

        let fields = response_fields(&mqtt, 7_000, "mqtt-sensor");
        assert_eq!(fields.len(), 19);
        assert_field_values(
            &fields,
            &[
                (1, "mqtt-sensor"),
                (2, "192.0.2.10"),
                (3, "1883"),
                (4, "192.0.2.11"),
                (5, "1883"),
                (13, "MQTT"),
                (14, "5"),
                (15, "client-id"),
                (16, "0"),
                (17, "/topic"),
                (18, "0"),
            ],
        );
        assert_eq!(fields[7], fmt_time(7_000));
    }

    #[test]
    fn test_ldap_response_data_envelope() {
        let ldap = fixtures::ldap();

        let fields = response_fields(&ldap, 8_000, "ldap-sensor");
        assert_eq!(fields.len(), 20);
        assert_eq!(fields[1], "ldap-sensor");
        assert_eq!(fields[13], "1");
        assert_eq!(fields[14], "3");
        assert_eq!(fields[15], "bindRequest");
        assert_eq!(fields[16], "success");
        assert_eq!(fields[17], "diagnostic");
        assert_eq!(fields[18], "cn=users,dc=example,dc=com");
        assert_eq!(fields[19], "arg");
    }

    #[test]
    fn test_tls_response_data_envelope() {
        let tls = Tls {
            orig_addr: "203.0.113.20".parse().unwrap(),
            orig_port: 443,
            resp_addr: "203.0.113.21".parse().unwrap(),
            resp_port: 443,
            proto: 6,
            start_time: 9_000,
            duration: 55,
            orig_pkts: 13,
            resp_pkts: 14,
            orig_l2_bytes: 1_300,
            resp_l2_bytes: 1_400,
            server_name: "example.com".to_string(),
            alpn_protocol: "h2".to_string(),
            ja3: "ja3".to_string(),
            version: "TLS1.3".to_string(),
            client_cipher_suites: vec![4865, 4866],
            client_extensions: vec![0, 11],
            cipher: 4865,
            extensions: vec![0, 23],
            ja3s: "ja3s".to_string(),
            serial: "serial".to_string(),
            subject_country: "US".to_string(),
            subject_org_name: "Org".to_string(),
            subject_common_name: "example.com".to_string(),
            validity_not_before: 1_700_000_000,
            validity_not_after: 1_800_000_000,
            subject_alt_name: "example.com".to_string(),
            issuer_country: "US".to_string(),
            issuer_org_name: "CA".to_string(),
            issuer_org_unit_name: "Unit".to_string(),
            issuer_common_name: "CA".to_string(),
            last_alert: 0,
        };

        let fields = response_fields(&tls, 9_000, "tls-sensor");
        assert_eq!(fields.len(), 34);
        assert_eq!(fields[1], "tls-sensor");
        assert_eq!(fields[13], "example.com");
        assert_eq!(fields[14], "h2");
        assert_eq!(fields[17], "4865,4866");
        assert_eq!(fields[18], "0,11");
        assert_eq!(fields[19], "4865");
        assert_eq!(fields[20], "0,23");
        assert_eq!(fields[26], fmt_time(1_700_000_000));
        assert_eq!(fields[27], fmt_time(1_800_000_000));
        assert_eq!(fields[33], "0");
    }

    #[test]
    fn test_smb_response_data_envelope() {
        let smb = fixtures::smb();

        let fields = response_fields(&smb, 10_000, "smb-sensor");
        assert_eq!(fields.len(), 24);
        assert_field_values(
            &fields,
            &[
                (1, "smb-sensor"),
                (13, "3"),
                (14, r"\\server\share"),
                (15, "SMB"),
                (16, "file.txt"),
                (21, "1700000100"),
                (23, "1700000300"),
            ],
        );
    }

    #[test]
    fn test_smb_display_uses_dash_for_empty_string_fields() {
        let smb = Smb {
            path: String::new(),
            service: String::new(),
            file_name: String::new(),
            ..fixtures::smb()
        };

        let fields = display_fields(&smb);
        assert_eq!(fields.len(), 22);
        assert_field_values(&fields, &[(12, "-"), (13, "-"), (14, "-")]);
    }

    #[test]
    fn test_nfs_response_data_envelope() {
        let nfs = fixtures::nfs();

        let fields = response_fields(&nfs, 11_000, "nfs-sensor");
        assert_eq!(fields.len(), 15);
        assert_eq!(fields[1], "nfs-sensor");
        assert_eq!(fields[13], "/mnt/share/read.txt");
        assert_eq!(fields[14], "/mnt/share/write.txt");
    }

    #[test]
    fn test_bootp_response_data_envelope() {
        let bootp = fixtures::bootp();

        let fields = response_fields(&bootp, 12_000, "bootp-sensor");
        assert_eq!(fields.len(), 24);
        assert_field_values(
            &fields,
            &[
                (1, "bootp-sensor"),
                (2, "192.0.2.40"),
                (3, "68"),
                (4, "192.0.2.41"),
                (5, "67"),
                (13, "1"),
                (14, "1"),
                (15, "0"),
                (16, "305419896"),
                (17, "0.0.0.0"),
                (18, "192.0.2.50"),
                (19, "192.0.2.1"),
                (20, "0.0.0.0"),
                (21, "0,1,2,3,4,5"),
                (22, "server"),
                (23, "bootfile"),
            ],
        );
        assert_eq!(fields[7], fmt_time(12_000));
    }

    #[test]
    fn test_dhcp_response_data_includes_formatted_options() {
        let dhcp = fixtures::dhcp(vec![(12, b"myhost".to_vec()), (51, vec![0, 1, 81, 128])]);

        let csv = assert_response_envelope(&dhcp, 13_000, "dhcp-sensor");
        assert_eq!(last_tab_field(&csv), "12:6d79686f7374,51:00015180");
    }

    #[test]
    fn test_dhcp_display_empty_options() {
        let dhcp = fixtures::dhcp(vec![]);

        let output = format!("{dhcp}");
        assert_eq!(last_tab_field(&output), "-");
    }

    #[test]
    fn test_dhcp_display_formats_options_as_tag_and_lowercase_hex() {
        let dhcp = fixtures::dhcp(vec![
            (12, b"myhost".to_vec()),
            (53, vec![5]),
            (61, vec![0xde, 0xad, 0xbe, 0xef]),
        ]);

        let output = format!("{dhcp}");
        assert_eq!(last_tab_field(&output), "12:6d79686f7374,53:05,61:deadbeef");
    }

    #[test]
    fn test_dhcp_display_supports_empty_option_values() {
        let dhcp = fixtures::dhcp(vec![(0, vec![]), (255, vec![])]);

        let output = format!("{dhcp}");
        assert_eq!(last_tab_field(&output), "0:,255:");
    }

    #[test]
    fn test_dhcp_response_data_with_empty_options_uses_dash_placeholder() {
        let dhcp = fixtures::dhcp(vec![]);

        let csv = assert_response_envelope(&dhcp, 13_000, "dhcp-sensor");
        assert_eq!(last_tab_field(&csv), "-");
    }

    #[test]
    fn test_radius_response_data_envelope() {
        let radius = fixtures::radius();

        let fields = response_fields(&radius, 14_000, "radius-sensor");
        assert_eq!(fields.len(), 27);
        assert_field_values(
            &fields,
            &[
                (1, "radius-sensor"),
                (2, "198.51.100.30"),
                (3, "1812"),
                (4, "198.51.100.31"),
                (5, "1812"),
                (13, "1"),
                (14, "1"),
                (15, "2"),
                (16, "auth"),
                (17, "resp_auth"),
                (18, "117,115,101,114"),
                (19, "112,97,115,115"),
                (20, "99,104,97,112"),
                (21, "198.51.100.100"),
                (22, "0"),
                (23, "115,116,97,116,101"),
                (24, "110,97,115,45,105,100"),
                (25, "5"),
                (26, "ok"),
            ],
        );
        assert_eq!(fields[7], fmt_time(14_000));
    }

    #[test]
    fn test_icmp_display_formats_payload_and_fields() {
        let icmp = fixtures::icmp();

        let csv_output = format!("{icmp}");
        let fields: Vec<&str> = csv_output.split('\t').collect();

        assert_eq!(fields.len(), 15);
        assert_eq!(fields[0], "192.168.1.1");
        assert_eq!(fields[1], "192.168.1.2");
        assert_eq!(fields[2], "1");
        assert_eq!(fields[5], "1");
        assert_eq!(fields[6], "1");
        assert_eq!(fields[7], "100");
        assert_eq!(fields[8], "100");
        assert_eq!(fields[9], "8");
        assert_eq!(fields[10], "0");
        assert_eq!(fields[11], "1234");
        assert_eq!(fields[12], "1");
        assert_eq!(fields[13], "56");
        assert_eq!(fields[14], "[8, 0, ff, ff]");
    }

    #[test]
    fn test_icmp_response_data_envelope() {
        let icmp = fixtures::icmp();

        let fields = response_fields(&icmp, 1_000_000_000, "icmp-sensor");
        assert_eq!(fields.len(), 17);
        assert_eq!(fields[0], fmt_time(1_000_000_000));
        assert_eq!(fields[1], "icmp-sensor");
        assert_eq!(fields[11], "8");
        assert_eq!(fields[12], "0");
        assert_eq!(fields[16], "[8, 0, ff, ff]");
    }

    #[test]
    fn test_smtp_display_uses_dash_for_empty_string_fields() {
        let smtp = Smtp {
            mailfrom: String::new(),
            date: String::new(),
            from: String::new(),
            to: String::new(),
            subject: String::new(),
            agent: String::new(),
            state: String::new(),
            ..fixtures::smtp()
        };

        let fields = display_fields(&smtp);
        assert_eq!(fields.len(), 18);
        assert_placeholder_fields(&fields, &[11, 12, 13, 14, 15, 16, 17]);
    }

    #[test]
    fn test_ntlm_display_uses_dash_for_empty_string_fields() {
        let ntlm = Ntlm {
            protocol: String::new(),
            username: String::new(),
            hostname: String::new(),
            domainname: String::new(),
            success: String::new(),
            ..fixtures::ntlm()
        };

        let fields = display_fields(&ntlm);
        assert_eq!(fields.len(), 16);
        assert_placeholder_fields(&fields, &[11, 12, 13, 14, 15]);
    }

    #[test]
    fn test_tls_display_uses_dash_for_empty_strings_and_vectors() {
        let tls = Tls {
            server_name: String::new(),
            alpn_protocol: String::new(),
            ja3: String::new(),
            version: String::new(),
            client_cipher_suites: vec![],
            client_extensions: vec![],
            extensions: vec![],
            ja3s: String::new(),
            serial: String::new(),
            subject_country: String::new(),
            subject_org_name: String::new(),
            subject_common_name: String::new(),
            subject_alt_name: String::new(),
            issuer_country: String::new(),
            issuer_org_name: String::new(),
            issuer_org_unit_name: String::new(),
            issuer_common_name: String::new(),
            ..fixtures::tls()
        };

        let fields = display_fields(&tls);
        assert_eq!(fields.len(), 32);
        assert_placeholder_fields(
            &fields,
            &[
                11, 12, 13, 14, 15, 16, 18, 19, 20, 21, 22, 23, 26, 27, 28, 29, 30,
            ],
        );
    }

    #[test]
    fn test_radius_display_uses_dash_for_empty_byte_vectors() {
        let radius = Radius {
            user_name: vec![],
            user_passwd: vec![],
            chap_passwd: vec![],
            state: vec![],
            nas_id: vec![],
            ..fixtures::radius()
        };

        let fields = display_fields(&radius);
        assert_eq!(fields.len(), 25);
        assert_placeholder_fields(&fields, &[16, 17, 18, 21, 22]);
    }

    #[test]
    fn test_ftp_display_uses_dash_for_empty_strings_and_commands() {
        let ftp = Ftp {
            user: String::new(),
            password: String::new(),
            commands: vec![],
            ..fixtures::ftp()
        };

        let fields = display_fields(&ftp);
        assert_eq!(fields.len(), 14);
        assert_placeholder_fields(&fields, &[11, 12, 13]);
    }

    #[test]
    fn test_mqtt_display_uses_dash_for_empty_strings_and_vectors() {
        let mqtt = Mqtt {
            protocol: String::new(),
            client_id: String::new(),
            subscribe: vec![],
            suback_reason: vec![],
            ..fixtures::mqtt()
        };

        let fields = display_fields(&mqtt);
        assert_eq!(fields.len(), 17);
        assert_placeholder_fields(&fields, &[11, 13, 15, 16]);
    }

    #[test]
    fn test_ldap_display_uses_dash_for_empty_vectors() {
        let ldap = Ldap {
            opcode: vec![],
            result: vec![],
            diagnostic_message: vec![],
            object: vec![],
            argument: vec![],
            ..fixtures::ldap()
        };

        let fields = display_fields(&ldap);
        assert_eq!(fields.len(), 18);
        assert_placeholder_fields(&fields, &[13, 14, 15, 16, 17]);
    }

    #[test]
    fn test_nfs_display_uses_dash_for_empty_vectors() {
        let nfs = Nfs {
            read_files: vec![],
            write_files: vec![],
            ..fixtures::nfs()
        };

        let fields = display_fields(&nfs);
        assert_eq!(fields.len(), 13);
        assert_placeholder_fields(&fields, &[11, 12]);
    }

    #[test]
    fn test_bootp_display_uses_dash_for_empty_chaddr_and_optional_text_fields() {
        let bootp = Bootp {
            chaddr: vec![],
            sname: String::new(),
            file: String::new(),
            ..fixtures::bootp()
        };

        let fields = display_fields(&bootp);
        assert_eq!(fields.len(), 22);
        assert_placeholder_fields(&fields, &[19, 20, 21]);
    }
}
