use crate::{
    ingest::{as_str_or_default, convert_time_format, vec_to_string_or_default},
    publish::range::ResponseRangeData,
};
use anyhow::Result;
use num_enum::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Conn {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
}

impl Display for Conn {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            as_str_or_default(&self.conn_state),
            convert_time_format(self.duration),
            self.service,
            self.orig_bytes,
            self.resp_bytes,
            self.orig_pkts,
            self.resp_pkts
        )
    }
}

impl ResponseRangeData for Conn {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let conn_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &conn_csv.as_bytes())))
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
    pub last_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
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
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let dns_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &dns_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Http {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referrer: String,
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
    pub orig_filenames: Vec<String>,
    pub orig_mime_types: Vec<String>,
    pub resp_filenames: Vec<String>,
    pub resp_mime_types: Vec<String>,
    pub post_body: Vec<u8>,
    pub state: String,
}

impl Display for Http {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
            as_str_or_default(&self.method),
            as_str_or_default(&self.host),
            as_str_or_default(&self.uri),
            as_str_or_default(&self.referrer),
            as_str_or_default(&self.version),
            as_str_or_default(&self.user_agent),
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
            vec_to_string_or_default(&self.orig_filenames),
            vec_to_string_or_default(&self.orig_mime_types),
            vec_to_string_or_default(&self.resp_filenames),
            vec_to_string_or_default(&self.resp_mime_types),
            if self.post_body.is_empty() {
                String::from("-")
            } else {
                std::str::from_utf8(self.post_body.as_slice()).unwrap_or_default().replace('\t', " ")
            },
            as_str_or_default(&self.state),
        )
    }
}

impl ResponseRangeData for Http {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let http_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &http_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rdp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub cookie: String,
}

impl Display for Rdp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
            self.cookie
        )
    }
}

impl ResponseRangeData for Rdp {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let rdp_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &rdp_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Smtp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
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
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let smtp_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &smtp_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ntlm {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
            as_str_or_default(&self.protocol),
            as_str_or_default(&self.username),
            as_str_or_default(&self.hostname),
            as_str_or_default(&self.domainname),
            as_str_or_default(&self.success),
        )
    }
}

impl ResponseRangeData for Ntlm {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let ntlm_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &ntlm_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Kerberos {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
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
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let kerberos_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &kerberos_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ssh {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub version: i64,
    pub auth_success: String,
    pub auth_attempts: i64,
    pub direction: String,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub host_key: String,
    pub hassh_algorithms: String,
    pub hassh_server_algorithms: String,
    pub client_shka: String,
    pub server_shka: String,
    pub client_encrypt_len: u64,
    pub server_encrypt_len: u64,
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
            convert_time_format(self.last_time),
            self.version,
            as_str_or_default(&self.auth_success),
            self.auth_attempts,
            as_str_or_default(&self.direction),
            as_str_or_default(&self.client),
            as_str_or_default(&self.server),
            as_str_or_default(&self.cipher_alg),
            as_str_or_default(&self.mac_alg),
            as_str_or_default(&self.compression_alg),
            as_str_or_default(&self.kex_alg),
            as_str_or_default(&self.host_key_alg),
            as_str_or_default(&self.host_key),
            as_str_or_default(&self.hassh_algorithms),
            as_str_or_default(&self.hassh_server_algorithms),
            as_str_or_default(&self.client_shka),
            as_str_or_default(&self.server_shka),
            self.client_encrypt_len,
            self.server_encrypt_len,
        )
    }
}

impl ResponseRangeData for Ssh {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let ssh_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &ssh_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DceRpc {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
}

impl Display for DceRpc {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
            self.rtt,
            as_str_or_default(&self.named_pipe),
            as_str_or_default(&self.endpoint),
            as_str_or_default(&self.operation),
        )
    }
}

impl ResponseRangeData for DceRpc {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let dce_rpc_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &dce_rpc_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ftp {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
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
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let ftp_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &ftp_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Mqtt {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
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
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let mqtt_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &mqtt_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ldap {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
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
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let ldap_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &ldap_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Tls {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub cipher: u16,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
            as_str_or_default(&self.server_name),
            as_str_or_default(&self.alpn_protocol),
            as_str_or_default(&self.ja3),
            as_str_or_default(&self.version),
            self.cipher,
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
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let tls_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &tls_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Smb {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
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
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
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
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let smb_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &smb_csv.as_bytes())))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Nfs {
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub last_time: i64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
}

impl Display for Nfs {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.orig_addr,
            self.orig_port,
            self.resp_addr,
            self.resp_port,
            self.proto,
            convert_time_format(self.last_time),
            vec_to_string_or_default(&self.read_files),
            vec_to_string_or_default(&self.write_files),
        )
    }
}

impl ResponseRangeData for Nfs {
    fn response_data(&self, timestamp: i64, source: &str) -> Result<Vec<u8>, bincode::Error> {
        let nfs_csv = format!("{}\t{source}\t{self}", convert_time_format(timestamp));

        bincode::serialize(&Some((timestamp, source, &nfs_csv.as_bytes())))
    }
}
