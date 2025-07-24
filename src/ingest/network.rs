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
    pub end_time: i64,
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
            convert_time_format(self.end_time),
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
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
pub struct Http {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
    pub cookie: String,
}

impl Display for Rdp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
}

impl Display for DceRpc {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
    pub user: String,
    pub password: String,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
            as_str_or_default(&self.user),
            as_str_or_default(&self.password),
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
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
}

impl Display for Nfs {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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
    pub end_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.start_time),
            convert_time_format(self.end_time),
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn http_csv_export_with_special_characters() {
        let http = Http {
            orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            orig_port: 80,
            resp_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            resp_port: 443,
            proto: 6,
            start_time: 1_000_000_000_000_000_000, // 1 second in nanoseconds
            end_time: 1_000_000_000_000_000_000,   // 1 second in nanoseconds
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

        // Verify that user_agent field has special characters replaced with spaces
        assert_eq!(fields[12], "Mozilla/5.0 (Windows NT 10.0; Win64)");

        // Verify that post_body field has special characters replaced with spaces (at index 25)
        assert_eq!(fields[25], "username=test password=secret submit=true ");

        // Verify the sanitized fields don't contain special characters
        assert!(!fields[12].contains('\n'));
        assert!(!fields[12].contains('\r'));
        assert!(!fields[25].contains('\t'));
        assert!(!fields[25].contains('\n'));
        assert!(!fields[25].contains('\r'));
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
            end_time: 1_000_000_000_000_000_000,
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
        // user_agent is at index 12, post_body is at index 25
        assert_eq!(fields[12], "-");
        assert_eq!(fields[25], "-");
    }
}
