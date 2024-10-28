# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `sensor` field to `OpLog`.

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
    This command must be applied automatically or manually before all future pull
    requests are submitted.
  - Add `--config group_imports=StdExternalCrate` to the CI process like:
    - `cargo fmt -- --check --config group_imports=StdExternalCrate`

## [0.17.0] - 2024-05-16

### Added

- Added `CloseStreamError` to `PublishError` to handle error types added by `quinn`
  version update.

### Changed

- Modified tls event structure to store: `client_cipher_suites`, `client_extensions`,
`extensions`
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
  [RUSTSEC-2020-0071](https://rustsec.org/advisories/RUSTSEC-2020-0071) for
  details.

### Changed

- Changed Sysmon events.
  - Added `agent_name`, `agent_id` field to sysmon events for use as a key.
  - Modified `DateTime<Utc>` to `i64` timestamp.

## [0.11.1] - 2023-07-26

### Added

- Added sysmon event structs.

### Changed

- Add `core` field to statistics structure. `core` value can be used to
  identify statistics value from different core of same machine.

## [0.11.0] - 2023-07-04

### Added

- Supports the SMB protocol.
- Supports the NFS protocol.

## [0.10.0] - 2023-06-22

### Added

- Supports the TLS protocol.

### Changed

- Changed the type of Tls::proto field from u16 to u8. (The `proto` field type for
  all protocols in `giganto-client` must be `u8`).

## [0.9.0] - 2023-06-20

### Changed

- Change `Log`, `PeriodicTimeSeries` to `ReqRange` in enum `MessageCode`.
  So when requesting data for analysis, `REconverge` use `MessageCode::ReqRange`.
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

- Added the source field to the CSV record of an FTP connection. This
  additional field makes the FTP record compatible with other CSV records.
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
- Move the network event's TSV-formatted source value to the response
  data message.

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

[Unreleased]: https://github.com/aicers/giganto-client/compare/0.20.0...main
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
