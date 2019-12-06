# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2019-12-06
### Added
* Documentation warning about YADR and ZSH #140
* Detection of ID Tokens that are older than AWS allows #150
* 15 minute session duration fallback for IAM Roles which have under 1 hour max
  session durations #150
* Detection of expired ID tokens initiating a new auth flow #150
* Faster login when using `-w` as now the cached ID Token is used if it's valid #150
* Documentation on config file format #154
* `print_role_arn` config setting #154
* Printing the role_arn to the console #154
* Option to set the AWS profile name in shared and awscli output #132 #157
* Add new Group Role Map rebuild triggering mechanism #158

### Changed
* Config file path changed from mozilla_aws_cli to maws #139
* Config file parsing to use an intentional `maws` section #154
* Changes the expected `idtoken_for_roles_url` URL format to expect the root URL
  instead of the URL ending in `/roles`
  * This change requires that config files use the base URL now and that any
    installed mozilla-aws-cli python packages providing `mozilla_aws_config`
    set the base URL for `idtoken_for_roles_url`

### Fixed
* If the web interface gets closed, making sure to shutdown the CLI #143 #128
* Utils not using the global logger #147
* Config file and config module settings not being merged #151
* When specifying role with -r that's not available, erroring out #127 #156

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

[Unreleased]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/mozilla-iam/mozilla-aws-cli/releases/tag/v0.0.2
