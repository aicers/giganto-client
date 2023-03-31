# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/aicers/giganto-client/compare/0.2.0...main
[0.2.0]: https://github.com/aicers/giganto-client/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/aicers/giganto-client/tree/0.1.0
