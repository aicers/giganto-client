use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

use anyhow::Result;
use num_enum::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::{
    ingest::{as_str_or_default, convert_time_format, vec_to_string_or_default},
    publish::range::ResponseRangeData,
};
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
}

impl Display for Conn {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
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
            self.resp_l2_bytes
        )
    }
}

impl ResponseRangeData for Conn {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        let conn_csv = format!("{}\t{sensor}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, sensor, &conn_csv.as_bytes())))
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Dns {
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
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
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
            self.query,
            vec_to_string_or_default(&self.answer),
            self.trans_id,
            self.rtt,
            Qclass::from(self.qclass),
            Qtype::from(self.qtype),
            self.rcode,
            self.aa_flag,
            self.tc_flag,
            self.rd_flag,
            self.ra_flag,
            vec_to_string_or_default(&self.ttl),
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
    pub client_name: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub service_name: Vec<String>,
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
            vec_to_string_or_default(&self.client_name),
            as_str_or_default(&self.realm),
            self.sname_type,
            vec_to_string_or_default(&self.service_name),
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
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
}

impl Display for DceRpc {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
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
            self.rtt,
            as_str_or_default(&self.named_pipe),
            as_str_or_default(&self.endpoint),
            as_str_or_default(&self.operation),
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
}

impl Display for Dhcp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
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
    use std::fmt::Display;
    use std::net::IpAddr;

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

        let expected_csv = format!("{}	{sensor}	{value}", convert_time_format(timestamp));
        assert_eq!(decoded_csv, expected_csv.as_bytes());
    }

    #[test]
    fn conn_display() {
        let conn = Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: "SF".to_string(),
            start_time: 1000,
            duration: 500,
            service: "http".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 21515,
            resp_l2_bytes: 27889,
        };
        let display = format!("{conn}");
        assert!(display.contains("192.168.4.76"));
        assert!(display.contains("46378"));
        assert!(display.contains("SF"));
        assert!(display.contains("http"));
    }

    #[test]
    fn test_conn_response_data_contents() {
        let conn = Conn {
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            conn_state: "SF".to_string(),
            start_time: 1000,
            duration: 500,
            service: "http".to_string(),
            orig_bytes: 77,
            resp_bytes: 295,
            orig_pkts: 397,
            resp_pkts: 511,
            orig_l2_bytes: 21515,
            resp_l2_bytes: 27889,
        };

        assert_response_data(&conn, 1_234_567_890, "conn-sensor");
    }

    #[test]
    fn dns_display() {
        let dns = Dns {
            orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            orig_port: 1234,
            resp_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            resp_port: 53,
            proto: 17,
            start_time: 1000,
            duration: 500,
            orig_pkts: 10,
            resp_pkts: 20,
            orig_l2_bytes: 150,
            resp_l2_bytes: 250,
            query: "example.com".to_string(),
            answer: vec!["1.2.3.4".to_string()],
            trans_id: 1,
            rtt: 100,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: true,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: vec![3600],
        };
        let display = format!("{dns}");
        assert!(display.contains("example.com"));
        assert!(display.contains("1.2.3.4"));
    }

    #[test]
    fn test_dns_response_data() {
        let dns = Dns {
            orig_addr: "127.0.0.1".parse().unwrap(),
            orig_port: 1234,
            resp_addr: "127.0.0.1".parse().unwrap(),
            resp_port: 53,
            proto: 17,
            start_time: 1000,
            duration: 100,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 100,
            resp_l2_bytes: 100,
            query: "example.com".to_string(),
            answer: vec!["1.2.3.4".to_string()],
            trans_id: 1,
            rtt: 10,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: true,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: vec![3600],
        };

        assert_response_data(&dns, 1000, "dns-sensor");
    }

    #[test]
    fn test_malformed_dns_response_data() {
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

        assert_response_data(&malformed, 9_999, "malformed-dns");
    }

    #[test]
    fn http_csv_export_with_special_characters() {
        let http = Http {
            orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            orig_port: 80,
            resp_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            resp_port: 443,
            proto: 6,
            start_time: 1_000_000_000_000_000_000, // 1 second in nanoseconds
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
            user_agent: "Mozilla/5.0\t(Windows NT\n10.0;\rWin64)".to_string(),
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
            body: b"username=test\tpassword=secret\nsubmit=true\r".to_vec(),
            state: String::new(),
        };

        let csv_output = format!("{http}");

        // Split by tabs to get individual fields and verify the specific fields
        let fields: Vec<&str> = csv_output.split('\t').collect();

        // Verify that user_agent field has special characters replaced with spaces (at index 16)
        assert_eq!(fields[16], "Mozilla/5.0 (Windows NT 10.0; Win64)");

        // Verify that post_body field has special characters replaced with spaces (at index 29)
        assert_eq!(fields[29], "username=test password=secret submit=true ");

        // Verify the sanitized fields don't contain special characters
        assert!(!fields[16].contains('\n'));
        assert!(!fields[16].contains('\r'));
        assert!(!fields[29].contains('\t'));
        assert!(!fields[29].contains('\n'));
        assert!(!fields[29].contains('\r'));
    }

    #[test]
    fn http_csv_export_empty_fields() {
        let http = Http {
            orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            orig_port: 80,
            resp_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            resp_port: 443,
            proto: 6,
            start_time: 1_000_000_000_000_000_000,
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            method: String::new(),
            host: String::new(),
            uri: String::new(),
            referer: String::new(),
            version: String::new(),
            user_agent: String::new(),
            request_len: 0,
            response_len: 0,
            status_code: 0,
            status_msg: String::new(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: String::new(),
            cache_control: String::new(),
            filenames: vec![],
            mime_types: vec![],
            body: vec![],
            state: String::new(),
        };

        let csv_output = format!("{http}");

        // Verify that empty user_agent and post_body fields are converted to "-"
        let fields: Vec<&str> = csv_output.split('\t').collect();
        // user_agent is at index 16, post_body is at index 29
        assert_eq!(fields[16], "-");
        assert_eq!(fields[29], "-");
    }

    #[test]
    fn test_http_response_data() {
        let http = Http {
            orig_addr: "127.0.0.1".parse().unwrap(),
            orig_port: 1234,
            resp_addr: "127.0.0.1".parse().unwrap(),
            resp_port: 80,
            proto: 6,
            start_time: 1000,
            duration: 100,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 100,
            resp_l2_bytes: 100,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/".to_string(),
            referer: String::new(),
            version: "1.1".to_string(),
            user_agent: "Mozilla".to_string(),
            request_len: 100,
            response_len: 100,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: String::new(),
            cache_control: String::new(),
            filenames: vec![],
            mime_types: vec![],
            body: vec![],
            state: String::new(),
        };

        assert_response_data(&http, 1000, "http-sensor");
    }

    #[test]
    fn test_rdp_response_data_contents() {
        let rdp = Rdp {
            orig_addr: "127.0.0.1".parse().unwrap(),
            orig_port: 1234,
            resp_addr: "127.0.0.1".parse().unwrap(),
            resp_port: 3389,
            proto: 6,
            start_time: 1000,
            duration: 100,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 100,
            resp_l2_bytes: 100,
            cookie: "cookie".to_string(),
        };

        let display = format!("{rdp}");
        assert!(display.contains("cookie"));

        assert_response_data(&rdp, 2_000, "rdp-sensor");
    }

    #[test]
    fn test_smtp_response_data() {
        let smtp = Smtp {
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
        };

        assert_response_data(&smtp, 3_000, "smtp-sensor");
    }

    #[test]
    fn test_ntlm_response_data() {
        let ntlm = Ntlm {
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
        };

        assert_response_data(&ntlm, 4_000, "ntlm-sensor");
    }

    #[test]
    fn test_kerberos_response_data() {
        let kerberos = Kerberos {
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
            client_name: vec!["client".to_string()],
            realm: "EXAMPLE.COM".to_string(),
            sname_type: 2,
            service_name: vec!["krbtgt".to_string(), "EXAMPLE.COM".to_string()],
        };

        assert_response_data(&kerberos, 5_000, "kerberos-sensor");
    }

    #[test]
    fn ssh_display_and_response_data() {
        let ssh = Ssh {
            orig_addr: "127.0.0.1".parse().unwrap(),
            orig_port: 1234,
            resp_addr: "127.0.0.1".parse().unwrap(),
            resp_port: 22,
            proto: 6,
            start_time: 1000,
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
        };
        let display = format!("{ssh}");
        assert!(display.contains("client"));
        assert!(display.contains("server"));

        assert_response_data(&ssh, 1000, "ssh-sensor");
    }

    #[test]
    fn dcerpc_display() {
        let dcerpc = DceRpc {
            orig_addr: "127.0.0.1".parse().unwrap(),
            orig_port: 1234,
            resp_addr: "127.0.0.1".parse().unwrap(),
            resp_port: 135,
            proto: 6,
            start_time: 1000,
            duration: 100,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 100,
            resp_l2_bytes: 100,
            rtt: 10,
            named_pipe: "pipe".to_string(),
            endpoint: "endpoint".to_string(),
            operation: "op".to_string(),
        };
        let display = format!("{dcerpc}");
        assert!(display.contains("pipe"));
        assert!(display.contains("endpoint"));
        assert!(display.contains("op"));

        assert_response_data(&dcerpc, 1000, "dcerpc-sensor");
    }

    #[test]
    fn test_ftp_response_data() {
        let ftp = Ftp {
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
        };

        assert_response_data(&ftp, 6_000, "ftp-sensor");
    }

    #[test]
    fn test_mqtt_response_data() {
        let mqtt = Mqtt {
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
        };

        assert_response_data(&mqtt, 7_000, "mqtt-sensor");
    }

    #[test]
    fn test_ldap_response_data() {
        let ldap = Ldap {
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
            diagnostic_message: vec![String::new()],
            object: vec!["cn=users,dc=example,dc=com".to_string()],
            argument: vec!["arg".to_string()],
        };

        assert_response_data(&ldap, 8_000, "ldap-sensor");
    }

    #[test]
    fn test_tls_response_data() {
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

        assert_response_data(&tls, 9_000, "tls-sensor");
    }

    #[test]
    fn test_smb_response_data() {
        let smb = Smb {
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
        };

        assert_response_data(&smb, 10_000, "smb-sensor");
    }

    #[test]
    fn test_nfs_response_data() {
        let nfs = Nfs {
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
        };

        assert_response_data(&nfs, 11_000, "nfs-sensor");
    }

    #[test]
    fn test_bootp_response_data() {
        let bootp = Bootp {
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
        };

        assert_response_data(&bootp, 12_000, "bootp-sensor");
    }

    #[test]
    fn test_dhcp_response_data() {
        let dhcp = Dhcp {
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
        };

        assert_response_data(&dhcp, 13_000, "dhcp-sensor");
    }

    #[test]
    fn test_radius_response_data() {
        let radius = Radius {
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
        };

        assert_response_data(&radius, 14_000, "radius-sensor");
    }

    #[test]
    fn icmp_display() {
        let icmp = Icmp {
            orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            proto: 1,
            start_time: 1_000_000_000_000_000_000,
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
        };

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
    fn icmp_response_data() {
        let icmp = Icmp {
            orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            resp_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            proto: 1,
            start_time: 1_000_000_000_000_000_000,
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
        };

        assert_response_data(&icmp, 1_000_000_000_000_000_000, "icmp-sensor");
    }
}
