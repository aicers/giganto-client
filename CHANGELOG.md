# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/aicers/giganto-client/compare/0.11.0...main
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
