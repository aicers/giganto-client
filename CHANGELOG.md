# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/aicers/giganto-client/compare/0.5.0...main
[0.5.0]: https://github.com/aicers/giganto-client/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/aicers/giganto-client/compare/0.3.1...0.4.0
[0.3.1]: https://github.com/aicers/giganto-client/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/aicers/giganto-client/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/aicers/giganto-client/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/aicers/giganto-client/tree/0.1.0
