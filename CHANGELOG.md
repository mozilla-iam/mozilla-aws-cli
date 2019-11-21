# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2019-11-21
### Fixed
* Case when using Python 2 with a config module

## [0.1.0] - 2019-11-20
### Added
* Add support for `$(maws)` syntax by removing carriage returns from output #122

### Changed
* Changed the precedence of the mozilla_aws_cli_config module such that if the
  module is present it overrides settings in the ~/.maws/config file only for
  settings that it asserts, leaving any additional settings set in the config
  file intact

## [0.0.2] - 2019-11-19
### Added
* Initial release of the mozilla-aws-cli tool

[Unreleased]: https://github.com/olivierlacan/keep-a-changelog/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/olivierlacan/keep-a-changelog/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/olivierlacan/keep-a-changelog/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/olivierlacan/keep-a-changelog/releases/tag/v0.0.2
