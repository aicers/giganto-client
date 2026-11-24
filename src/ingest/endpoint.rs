//! The host header that endpoint records carry.
//!
//! An endpoint (Clumit Endpoint) sends host telemetry to Giganto. Each record
//! it sends is stored with an [`EndpointHeader`] describing the host, the
//! stream and the collection that produced it.

use std::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ingest::{
    bytes_to_hex_or_default, convert_time_format, sanitize_csv_field, to_string_or_empty,
    vec_to_string_or_default,
};

/// The number of tab-separated columns an [`EndpointHeader`] occupies in a
/// CSV row.
pub(crate) const ENDPOINT_HEADER_COLUMNS: usize = 15;

/// A host header identifying the endpoint, stream and collection a record
/// came from.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndpointHeader {
    pub endpoint_id: Uuid,
    pub stream: Uuid,
    pub seq: u64,
    /// The time the event occurred, in nanoseconds since the Unix epoch.
    pub event_time: i64,
    /// The time the endpoint collected the event, in nanoseconds since the
    /// Unix epoch.
    pub collected_at: i64,
    pub clock_offset: Option<ClockOffset>,
    pub hostname: String,
    pub ips: Vec<IpAddr>,
    pub default_route_ip: Option<IpAddr>,
    pub net_state_source: NetStateSource,
    pub os_family: OsFamily,
    pub os_version: String,
    pub collection_mode: CollectionMode,
    /// The value of the endpoint's process key; its OS is `os_family`.
    pub process_key: Option<Vec<u8>>,
    /// The schema version of the endpoint record.
    pub schema: u16,
}

/// A measured offset of the endpoint's clock.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClockOffset {
    pub offset_ms: i64,
    pub uncertainty_ms: u32,
    /// The time the offset was measured, in nanoseconds since the Unix epoch.
    pub measured_at: i64,
}

/// A source of the endpoint's network state.
///
/// `Other` carries a value this crate does not know.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NetStateSource {
    Observed,
    Inferred,
    Unknown,
    Other(String),
}

/// An operating system family of the endpoint.
///
/// `Other` carries a value this crate does not know.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OsFamily {
    Windows,
    Linux,
    Macos,
    Other(String),
}

/// A collection mode the endpoint ran in.
///
/// `Other` carries a value this crate does not know.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CollectionMode {
    Extended,
    Essential,
    Other(String),
}

impl Display for NetStateSource {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::Observed => f.write_str("observed"),
            Self::Inferred => f.write_str("inferred"),
            Self::Unknown => f.write_str("unknown"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

impl Display for OsFamily {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::Windows => f.write_str("windows"),
            Self::Linux => f.write_str("linux"),
            Self::Macos => f.write_str("macos"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

impl Display for CollectionMode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::Extended => f.write_str("extended"),
            Self::Essential => f.write_str("essential"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

impl Display for ClockOffset {
    /// Writes `offset_ms,uncertainty_ms,measured_at`.
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{},{},{}",
            self.offset_ms,
            self.uncertainty_ms,
            convert_time_format(self.measured_at)
        )
    }
}

impl Display for EndpointHeader {
    /// Writes the header's 15 tab-separated CSV columns in field order.
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.endpoint_id,
            self.stream,
            self.seq,
            convert_time_format(self.event_time),
            convert_time_format(self.collected_at),
            to_string_or_empty(self.clock_offset.as_ref()),
            sanitize_csv_field(&self.hostname),
            vec_to_string_or_default(&self.ips),
            to_string_or_empty(self.default_route_ip),
            sanitize_csv_field(&self.net_state_source.to_string()),
            sanitize_csv_field(&self.os_family.to_string()),
            sanitize_csv_field(&self.os_version),
            sanitize_csv_field(&self.collection_mode.to_string()),
            bytes_to_hex_or_default(self.process_key.as_deref().unwrap_or_default()),
            self.schema,
        )
    }
}

/// Formats the header columns of an optional header: the header's columns
/// when present, otherwise [`ENDPOINT_HEADER_COLUMNS`] columns of `-`.
pub(crate) fn endpoint_columns(endpoint: Option<&EndpointHeader>) -> String {
    match endpoint {
        Some(header) => header.to_string(),
        None => vec!["-"; ENDPOINT_HEADER_COLUMNS].join("\t"),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::{ClockOffset, CollectionMode, EndpointHeader, NetStateSource, OsFamily};

    /// A header with every field filled.
    pub(crate) fn endpoint_header() -> EndpointHeader {
        EndpointHeader {
            endpoint_id: "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0".parse().unwrap(),
            stream: "F0E9D8C7-B6A5-4493-8271-605F4E3D2C1B".parse().unwrap(),
            seq: 42,
            event_time: 1_000_000_001,
            collected_at: 2_000_000_000,
            clock_offset: Some(ClockOffset {
                offset_ms: -15,
                uncertainty_ms: 3,
                measured_at: 1_500_000_000,
            }),
            hostname: "host-01".to_string(),
            ips: vec![
                "192.0.2.10".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
            default_route_ip: Some("192.0.2.10".parse().unwrap()),
            net_state_source: NetStateSource::Observed,
            os_family: OsFamily::Windows,
            os_version: "10.0.19045".to_string(),
            collection_mode: CollectionMode::Extended,
            process_key: Some(vec![0x00, 0xab, 0x0f, 0xff]),
            schema: 3,
        }
    }

    /// The CSV columns `endpoint_header()` is written as.
    pub(crate) const ENDPOINT_HEADER_CSV: &str = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0\t\
        f0e9d8c7-b6a5-4493-8271-605f4e3d2c1b\t\
        42\t\
        1970-01-01T00:00:01.000000001+00:00\t\
        1970-01-01T00:00:02+00:00\t\
        -15,3,1970-01-01T00:00:01.5+00:00\t\
        host-01\t\
        192.0.2.10,2001:db8::1\t\
        192.0.2.10\t\
        observed\t\
        windows\t\
        10.0.19045\t\
        extended\t\
        00ab0fff\t\
        3";

    /// The CSV columns an absent header is written as.
    pub(crate) const NO_ENDPOINT_HEADER_CSV: &str = "-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-";
}

#[cfg(test)]
mod tests {
    use super::fixtures::{ENDPOINT_HEADER_CSV, NO_ENDPOINT_HEADER_CSV, endpoint_header};
    use super::*;

    fn round_trip<T>(value: &T) -> T
    where
        T: Serialize + serde::de::DeserializeOwned,
    {
        let bytes = bincode::serialize(value).unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    fn header_with_others() -> EndpointHeader {
        EndpointHeader {
            net_state_source: NetStateSource::Other("probed".to_string()),
            os_family: OsFamily::Other("freebsd".to_string()),
            collection_mode: CollectionMode::Other("minimal".to_string()),
            ..endpoint_header()
        }
    }

    fn header_with_absent_values() -> EndpointHeader {
        EndpointHeader {
            clock_offset: None,
            hostname: String::new(),
            ips: Vec::new(),
            default_route_ip: None,
            os_version: String::new(),
            process_key: None,
            ..endpoint_header()
        }
    }

    #[test]
    fn endpoint_header_round_trips_with_every_field_filled() {
        let header = endpoint_header();
        assert_eq!(round_trip(&header), header);
    }

    #[test]
    fn endpoint_header_round_trips_with_absent_values() {
        let header = header_with_absent_values();
        assert_eq!(round_trip(&header), header);
    }

    #[test]
    fn endpoint_header_round_trips_other_values() {
        let header = header_with_others();
        assert_eq!(round_trip(&header), header);
    }

    #[test]
    fn header_enums_round_trip_every_variant() {
        for value in [
            NetStateSource::Observed,
            NetStateSource::Inferred,
            NetStateSource::Unknown,
            NetStateSource::Other("probed".to_string()),
            NetStateSource::Other(String::new()),
        ] {
            assert_eq!(round_trip(&value), value);
        }
        for value in [
            OsFamily::Windows,
            OsFamily::Linux,
            OsFamily::Macos,
            OsFamily::Other("freebsd".to_string()),
        ] {
            assert_eq!(round_trip(&value), value);
        }
        for value in [
            CollectionMode::Extended,
            CollectionMode::Essential,
            CollectionMode::Other("minimal".to_string()),
        ] {
            assert_eq!(round_trip(&value), value);
        }
    }

    #[test]
    fn endpoint_header_display_notation() {
        let header = endpoint_header();
        let output = header.to_string();
        assert_eq!(output, ENDPOINT_HEADER_CSV);
        assert_eq!(output.split('\t').count(), ENDPOINT_HEADER_COLUMNS);

        let fields: Vec<&str> = output.split('\t').collect();
        // UUIDs are lowercase hyphenated even when parsed from uppercase.
        assert_eq!(fields[1], "f0e9d8c7-b6a5-4493-8271-605f4e3d2c1b");
        crate::test::assert_canonical_time(fields[3], 1_000_000_001);
        crate::test::assert_canonical_time(fields[4], 2_000_000_000);
        let (offset, measured_at) = fields[5].rsplit_once(',').unwrap();
        assert_eq!(offset, "-15,3");
        crate::test::assert_canonical_time(measured_at, 1_500_000_000);
    }

    #[test]
    fn endpoint_header_display_absent_values_are_dashes() {
        let output = header_with_absent_values().to_string();
        let fields: Vec<&str> = output.split('\t').collect();
        assert_eq!(fields.len(), ENDPOINT_HEADER_COLUMNS);
        assert_eq!(fields[5], "-"); // clock_offset
        assert_eq!(fields[6], "-"); // hostname
        assert_eq!(fields[7], "-"); // ips
        assert_eq!(fields[8], "-"); // default_route_ip
        assert_eq!(fields[11], "-"); // os_version
        assert_eq!(fields[13], "-"); // process_key

        let empty_key = EndpointHeader {
            process_key: Some(Vec::new()),
            ..endpoint_header()
        };
        assert_eq!(empty_key.to_string().split('\t').nth(13), Some("-"));
    }

    #[test]
    fn endpoint_header_display_enums() {
        let fields_of = |header: &EndpointHeader| {
            let output = header.to_string();
            let fields: Vec<String> = output.split('\t').map(ToString::to_string).collect();
            (fields[9].clone(), fields[10].clone(), fields[12].clone())
        };

        let known = [
            (
                NetStateSource::Observed,
                OsFamily::Windows,
                CollectionMode::Extended,
                ("observed", "windows", "extended"),
            ),
            (
                NetStateSource::Inferred,
                OsFamily::Linux,
                CollectionMode::Essential,
                ("inferred", "linux", "essential"),
            ),
            (
                NetStateSource::Unknown,
                OsFamily::Macos,
                CollectionMode::Essential,
                ("unknown", "macos", "essential"),
            ),
        ];
        for (net_state_source, os_family, collection_mode, expected) in known {
            let header = EndpointHeader {
                net_state_source,
                os_family,
                collection_mode,
                ..endpoint_header()
            };
            let (n, o, c) = fields_of(&header);
            assert_eq!((n.as_str(), o.as_str(), c.as_str()), expected);
        }

        let (n, o, c) = fields_of(&header_with_others());
        assert_eq!(
            (n.as_str(), o.as_str(), c.as_str()),
            ("probed", "freebsd", "minimal")
        );
    }

    #[test]
    fn endpoint_header_display_keeps_columns_on_one_line() {
        let header = EndpointHeader {
            hostname: "host\tname\n".to_string(),
            os_version: "10\r\n".to_string(),
            net_state_source: NetStateSource::Other("a\tb".to_string()),
            os_family: OsFamily::Other(String::new()),
            ..endpoint_header()
        };
        let output = header.to_string();
        assert_eq!(output.split('\t').count(), ENDPOINT_HEADER_COLUMNS);
        assert_eq!(output.lines().count(), 1);
        assert!(!output.contains('\r'));
        let fields: Vec<&str> = output.split('\t').collect();
        assert_eq!(fields[6], "host name ");
        assert_eq!(fields[9], "a b");
        assert_eq!(fields[10], "-");
    }

    #[test]
    fn endpoint_columns_of_absent_header_are_dashes() {
        assert_eq!(endpoint_columns(None), NO_ENDPOINT_HEADER_CSV);
        assert_eq!(
            endpoint_columns(None).split('\t').count(),
            ENDPOINT_HEADER_COLUMNS
        );
        assert!(endpoint_columns(None).split('\t').all(|c| c == "-"));
        assert_eq!(
            endpoint_columns(Some(&endpoint_header())),
            ENDPOINT_HEADER_CSV
        );
    }
}
