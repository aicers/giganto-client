# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added session information fields to all network event structures:
  - `duration` field (`i64`) to track session duration
  - `orig_pkts` and `resp_pkts` fields (`u64`) for packet counts
  - `orig_l2_bytes` and `resp_l2_bytes` fields (`u64`) for L2 byte counts
  - This affects all network event structures: `Conn`, `Dns`, `Http`, `Rdp`,
    `Smtp`, `Ntlm`, `Kerberos`, `Ssh`, `DceRpc`, `Ftp`, `Mqtt`, `Ldap`, `Tls`,
    `Smb`, `Nfs`, `Bootp`, `Dhcp`, `Radius`, and `MalformedDns`
  - The `start_time` field represents the session start time and complements
    the existing `end_time` field.
- Added `Radius`, `MalformedDns` event structure.

### Fixed

- Fixed special character handling in HTTP event CSV export. The `user_agent` and
  `post_body` fields now properly sanitize horizontal tabs (0x09), line feeds
  (0x0a), and carriage returns (0x0d) by replacing them with spaces to ensure
  proper CSV parsing.

### Changed

- **BREAKING**: Migrated from Chrono to Jiff crate for time handling. Time fields
  now use `jiff::Timestamp` instead of `chrono::DateTime<Utc>` for improved type
  safety and performance:
  - Network events: `start_time` and `end_time` fields now use `jiff::Timestamp`
  - Sysmon events: time fields like `creation_utc_time` now use `jiff::Timestamp`
  - Users must update their code to work with `jiff::Timestamp` types
- Modified `Ftp` event to store vector of commands.
- Updated CSV export format to include new session information fields
- Added `StreamRequestPayload` enum to encapsulate different stream request
  types (semi-supervised, time series generator, and pcap extraction).
  - Updated `send_stream_request`, `receive_stream_request` functions to use
    `StreamRequestPayload` for sending and receiving requests, removing the need
    for `NodeType` enum.
- Renamed `timestamp` field to `start_time` in `PcapFilter` struct for consistency
  with protocol event structures.

## [0.23.0] - 2025-06-18

### Changed

- Renamed `last_time` to `end_time` in all network event structures for improved
  clarity and consistency with future `start_time` field.
  - This change affects all network event structures: `Dns`, `Http`, `Rdp`, `Smtp`,
    `Ntlm`, `Kerberos`, `Ssh`, `DceRpc`, `Ftp`, `Mqtt`, `Ldap`, `Tls`, `Smb`, `Nfs`,
    `Bootp`, `Dhcp`, and `PcapFilter`.
- Renamed `duration` to `end_time` in the `Conn` raw event structure for consistency
  with other network event structures.
- Renamed `referrer` to `referer` throughout the codebase for consistency with
  the HTTP header field name.
  - This change aligns with the official HTTP standard and ensures accurate representation
    of the `Referer` header in variable names, struct fields, and documentation.
- Changed HTTP event field structure.
  - Merged `orig_filenames` and `resp_filenames` into `filenames`.
  - Merged `orig_mime_types` and `resp_mime_types` into `mime_types`.
  - Renamed `post_body` to `body`.

### Removed

- Removed `init_tracing` function to align giganto-client's responsibilities as
  a communication library.

## [0.22.0] - 2025-01-24

### Changed

- Renamed `Crusher` to `TimeSeriesGenerator` for consistency with the
  review-database. Updated identifers include:
  - `NodeType::Crusher` to `NodeType::TimeSeriesGenerator`
  - `RequestCrusherStream` to `RequestTimeSeriesGeneratorStream`
  - `receive_crusher_stream_start_message` to `receive_time_series_generator_stream_start_message`
  - `receive_crusher_data` to `receive_time_series_generator_data`
- Similarly, identifiers referencing semi-supervised learning engines have been
  renamed. Below are the result of the changes:
  - `NodeType::SemiSupervised`
  - `RequestSemiSupervisedStream`
  - `send_semi_supervised_stream_start_message`
  - `receive_semi_supervised_stream_start_message`
  - `receive_semi_supervised_data`

## [0.21.0] - 2024-11-21

### Added

- Added `sensor` field to `OpLog`.

### Changed

- Changed `source` to `sensor`, which is a more appropriate term for the name of
  the device that sensed/captured the raw event.

### Removed

- Removed the unused `source` within the `Netflow5`, `Netflow9`, `SecuLog`.

## [0.20.0] - 2024-09-10

### Changed

- Rename the `chwaddr` field in `Bootp` to `chaddr`.
- Add `all()` function to `RequestStreamRecord` for automatic vector generation
  of all variants.

## [0.19.0] - 2024-06-28

### Added

- Added `Bootp`,`Dhcp` to the `RequestStreamRecord` to handle requests for new
  protocols in the giganto publish module.

### Changed

- Fixed `RequestStreamRecord`, `NodeType` to use strum crate for type change
  between string and enum.

## [0.18.0] - 2024-06-27

### Added

- Added `Bootp` and `Dhcp` event structures.

### Changed

- Modified connection log structure to include total L2 frame length of a session.
- Apply rustfmt's option `group_imports=StdExternalCrate`.
  - Modify the code with the command `cargo fmt -- --config group_imports=StdExternalCrate`.
    This command must be applied automatically or manually before all future
    pull requests are submitted.
  - Add `--config group_imports=StdExternalCrate` to the CI process like:
    - `cargo fmt -- --check --config group_imports=StdExternalCrate`

## [0.17.0] - 2024-05-16

### Added

- Added `CloseStreamError` to `PublishError` to handle error types added by
  `quinn` version update.

### Changed

- Modified tls event structure to store: `client_cipher_suites`,
  `client_extensions`, `extensions`
- Bump dependencies.
  - Update quinn to version 0.11.
  - Update rustls to version 0.23.
  - Update rcgen to version 0.13.

## [0.16.0] - 2024-02-16

### Changed

- Modified event structure to store NTLM error information.
- Modified connection event structure to report connection state.
- Modified http and smtp event structure to store state information.
- Modified ssh event structure.

## [0.15.2] - 2023-11-16

### Added

- Added source field to `Netflow5`, `Netflow9`.

## [0.15.1] - 2023-11-08

### Added

- Added source field to `SecuLog`.

## [0.15.0] - 2023-11-07

### Changed

- Renamed ingest::log::Oplog|Seculog -> ingest::log::OpLog|SecuLog

## [0.14.0] - 2023-11-07

### Changed

- Removed REconvergeKindType
- Moved and renamed crate::ingest::RecordType to crate::RawEventKind
- Renamed RecordType::Oplog to RawEventKind::OpLog and RecordType::Seculog to RawEventKind::SecuLog

## [0.13.2] - 2023-11-01

### Added

- Add security logs event.

## [0.13.1] - 2023-10-20

### Added

- Add `Netflow5`, `Netflow9` event.

## [0.13.0] - 2023-09-26

### Changed

- Modify Kerberos event structure to report Kerberos error

## [0.12.2] - 2023-08-23

### Added

- Added sysmon events (`FileCreate`, `FileDelete`) to publish stream data.

## [0.12.1] - 2023-08-17

### Added

- Added sysmon events to publish range data.

## [0.12.0] - 2023-08-14

### Security

- The default features of chrono that might cause SEGFAULT were turned off. See
  [RUSTSEC-2020-0071](https://rustsec.org/advisories/RUSTSEC-2020-0071) for details.

### Changed

- Changed Sysmon events.
  - Added `agent_name`, `agent_id` field to sysmon events for use as a key.
  - Modified `DateTime<Utc>` to `i64` timestamp.

## [0.11.1] - 2023-07-26

### Added

- Added sysmon event structs.

### Changed

- Add `core` field to statistics structure. `core` value can be used to identify
  statistics value from different core of same machine.

## [0.11.0] - 2023-07-04

### Added

- Supports the SMB protocol.
- Supports the NFS protocol.

## [0.10.0] - 2023-06-22

### Added

- Supports the TLS protocol.

### Changed

- Changed the type of Tls::proto field from u16 to u8. (The `proto` field type
  for all protocols in `giganto-client` must be `u8`).

## [0.9.0] - 2023-06-20

### Changed

- Change `Log`, `PeriodicTimeSeries` to `ReqRange` in enum `MessageCode`. So
  when requesting data for analysis, `REconverge` use `MessageCode::ReqRange`.
- Change the data types that `send_raw_events` and `receive_raw_events` send and
  receive to `Vec<(i64, String, Vec<u8>)>`.

### Removed

- remove `RequestTimeSeriesRange` structure. So when requesting data for analysis,
  `REconverge` use `RequestRange` structure.

## [0.8.0] - 2023-06-12

### Added

- Supports the LDAP protocol.

### Changed

- Expanded `struct Http` in the ingest protocol to improve file handling capabilities:
  - `orig_filenames: Vec<String>`
  - `orig_mime_types: Vec<String>`
  - `resp_filenames: Vec<String>`
  - `resp_mime_types: Vec<String>`
- Modify `Ftp`, `Mqtt`'s `proto` type to u8 from u16.

### Removed

- Moved `send_ack_timestamp` to Giganto.
- remove `RequestTimeSeriesRange` structure. So when requesting data for analysis,
  `REconverge` use `RequestRange` structure.

## [0.7.0] - 2023-05-12

### Changed

- Updated quinn from 0.9 to 0.10, and rustls from 0.20 to 0.21. As
  giganto-client exposes quinn's structs in its public API, it is important to
  make sure you update your direct dependencies on both quinn and rustls to the
  same versions as required by giganto-client.

### Removed

- Moved `send_crusher_stream_start_message` and `send_crusher_data` to Giganto.
- Removed `is_reproduce` from `server_handshake`.

## [0.6.0] - 2023-05-08

### Added

- Supports the MQTT protocol.

### Removed

- `convert_time_format` function is no longer available as a public function in
  the API. It has been made private to avoid exposing the internal protocol
  format used for network transmission.

## [0.5.0] - 2023-04-26

### Changed

- Added the source field to the CSV record of an FTP connection. This additional
  field makes the FTP record compatible with other CSV records.
- `RecordType` became `#[non_exhaustive]`. This change ensures that adding new
  record types in the future will not result in breaking changes for downstream
  users who have exhaustively matched on the `RecordType` variants. This makes
  it easier for both the library maintainers and users to evolve the codebase
  and adapt to new requirements without introducing breaking changes.

## [0.4.0] - 2023-04-21

### Added

- Add response data message's source to network event's TSV-formatted value.
- Supports the FTP protocol.

## [0.3.1] - 2023-04-17

### Added

- Add `MessageCode::RawData = 3`
- Add struct `RequestRawData`
- Add `send_raw_events`, `receive_raw_events` to publish api

## [0.3.0] - 2023-03-31

### Changed

- Add source values to log and time series response data message.
- Move the network event's TSV-formatted source value to the response data message.

## [0.2.0] - 2023-03-29

### Changed

- Change the field type of `RequestHogStream` to `Option<Vec<String>>` to
  support multiple sources.
- Change field name `duration` to `last_time`. (Except Conn struct)
- Renamed variable `des_ip` to `dst_ip` for consistency with the naming
  convention of `src_ip`.

## [0.1.0] - 2023-03-27

### Added

- Move from giganto

[Unreleased]: https://github.com/aicers/giganto-client/compare/0.23.0...main
[0.23.0]: https://github.com/aicers/giganto-client/compare/0.22.0...0.23.0
[0.22.0]: https://github.com/aicers/giganto-client/compare/0.21.0...0.22.0
[0.21.0]: https://github.com/aicers/giganto-client/compare/0.20.0...0.21.0
[0.20.0]: https://github.com/aicers/giganto-client/compare/0.19.0...0.20.0
[0.19.0]: https://github.com/aicers/giganto-client/compare/0.18.0...0.19.0
[0.18.0]: https://github.com/aicers/giganto-client/compare/0.17.0...0.18.0
[0.17.0]: https://github.com/aicers/giganto-client/compare/0.16.0...0.17.0
[0.16.0]: https://github.com/aicers/giganto-client/compare/0.15.2...0.16.0
[0.15.2]: https://github.com/aicers/giganto-client/compare/0.15.1...0.15.2
[0.15.1]: https://github.com/aicers/giganto-client/compare/0.15.0...0.15.1
[0.15.0]: https://github.com/aicers/giganto-client/compare/0.14.0...0.15.0
[0.14.0]: https://github.com/aicers/giganto-client/compare/0.13.2...0.14.0
[0.13.2]: https://github.com/aicers/giganto-client/compare/0.13.1...0.13.2
[0.13.1]: https://github.com/aicers/giganto-client/compare/0.13.0...0.13.1
[0.13.0]: https://github.com/aicers/giganto-client/compare/0.12.2...0.13.0
[0.12.2]: https://github.com/aicers/giganto-client/compare/0.12.1...0.12.2
[0.12.1]: https://github.com/aicers/giganto-client/compare/0.12.0...0.12.1
[0.12.0]: https://github.com/aicers/giganto-client/compare/0.11.1...0.12.0
[0.11.1]: https://github.com/aicers/giganto-client/compare/0.11.0...0.11.1
[0.11.0]: https://github.com/aicers/giganto-client/compare/0.10.0...0.11.0
[0.10.0]: https://github.com/aicers/giganto-client/compare/0.9.0...0.10.0
[0.9.0]: https://github.com/aicers/giganto-client/compare/0.8.0...0.9.0
[0.8.0]: https://github.com/aicers/giganto-client/compare/0.7.0...0.8.0
[0.7.0]: https://github.com/aicers/giganto-client/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/aicers/giganto-client/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/aicers/giganto-client/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/aicers/giganto-client/compare/0.3.1...0.4.0
[0.3.1]: https://github.com/aicers/giganto-client/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/aicers/giganto-client/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/aicers/giganto-client/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/aicers/giganto-client/tree/0.1.0
