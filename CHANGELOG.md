# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.4] - 2021-08-12

### Added
* Show the AWS Account ID for each account on the federated login page.
  Allows for easier discoverability when tracing Account ID to Account
  name.

## [1.2.3] - 2021-04-27

### Fixed
* `--output awscli` on Windows clients running Python 2.7 which weren't able to 
  find the `aws` executable [#235](https://github.com/mozilla-iam/mozilla-aws-cli/issues/235)

## [1.2.2] - 2020-07-14

### Fixed
* Bug when an AWS Account has no alias. Previously, if a user used 
  mozilla-aws-cli with an AWS account that had no account alias defined, 
  it would respond with errors described in #220. Now it gracefully handles AWS
  accounts without aliases. This fixes the bug in mozilla-aws-cli and changes
  the ID Token for Roles API to prevent the bug in deployed versions of
  mozilla-aws-cli prior to v1.2.2 [#221](https://github.com/mozilla-iam/mozilla-aws-cli/issues/221)

### Added
* A check to the Group Role Map Builder that the federated principal in an 
  IAM policy has the same AWS account ID as the account containing the policy.
  This will prevent malformed IAM Role policies from being included in the group
  role map. [#218](https://github.com/mozilla-iam/mozilla-aws-cli/issues/218)
* Support for sending informational messages from the backend to the frontend.
  Previously only error messages could be passed. [#219](https://github.com/mozilla-iam/mozilla-aws-cli/issues/219)

## [1.2.1] - 2020-05-20

### Fixed
* Change prompt to always use role and account name instead of profile name [#216](https://github.com/mozilla-iam/mozilla-aws-cli/issues/216)
* Fix bug with using -o awscli or -o shared without a profile name [#216](https://github.com/mozilla-iam/mozilla-aws-cli/issues/216)

## [1.2.0] - 2020-02-27

### Fixed
*  Fix case where zsh prompt has duplicated maws profile names added [#207](https://github.com/mozilla-iam/mozilla-aws-cli/issues/207)

### Added
* Output format `boto` which outputs JSON that can be consumed in Python boto3 
  code and `js` which works in Javascript with the AWS Javascript SDK [#208](https://github.com/mozilla-iam/mozilla-aws-cli/issues/208)
* Documentation on the new `boto` and `js` output formats [#209](https://github.com/mozilla-iam/mozilla-aws-cli/issues/209) [#210](https://github.com/mozilla-iam/mozilla-aws-cli/issues/210)
* `--print-url` argument which prints out the federation URL [#212](https://github.com/mozilla-iam/mozilla-aws-cli/issues/212)

## [1.1.1] - 2020-02-20

### Fixed
* Case where a user has no `~/.cache/` directory and `maws` fails to create it [#199](https://github.com/mozilla-iam/mozilla-aws-cli/issues/199)

## [1.1.0] - 2020-02-13
### Changed
* Revert the change in [#160](https://github.com/mozilla-iam/mozilla-aws-cli/issues/160)
  in which the URL format for idtoken_for_roles_url was changed from 
  https://example.com/roles to https://example.com/. Now with this reversion, 
  the idtoken_for_roles_url should again be the full URL ending in `/roles`.
  This change is not backwards compatible and will require that a config file
  or config module be changed to use the new full URL.

## [1.0.0] - 2020-02-05
### Added
* Feature to pass the "cache" argument that the user asserts on the command line
  on to the id_token_for_role API so the cacheing behavior that the user wants
  is reflected there too [#162](https://github.com/mozilla-iam/mozilla-aws-cli/issues/162)
* Feature to fix directory permissions on config and cache directories [#163](https://github.com/mozilla-iam/mozilla-aws-cli/issues/163)
* Error checking for network failures [#164](https://github.com/mozilla-iam/mozilla-aws-cli/issues/164) fixes [#100](https://github.com/mozilla-iam/mozilla-aws-cli/issues/100)
* Improved handling of AWS Access Denied responses including [#166](https://github.com/mozilla-iam/mozilla-aws-cli/issues/166)
* New heartbeat API endpoint to keep track of how long it's been since the
  frontend last checked in with the backend to detect if the user closes the
  browser before completing the login [#180](https://github.com/mozilla-iam/mozilla-aws-cli/issues/180)
* Shell prompt customization to show which AWS account is currently active [#185](https://github.com/mozilla-iam/mozilla-aws-cli/issues/185)

### Changed
* **Synchronous blocking frontend backend interactions to non-blocking** [#180](https://github.com/mozilla-iam/mozilla-aws-cli/issues/180)
  * This large change removed all synchronous blocking frontend backend 
    interactions and instead now relies entirely on the pollState frontend 
    polling loop.
    * Previously there was a mix of frontend backend interactions which were async
      and one which blocked and waited for other async calls to finish
    * This removes this behavior so that all frontend to backend interactions 
      are async and the frontends movement through the workflow
      is entirely governed by the changes to the login.state value
* Config file and cache directory locations to standard XDG locations [#178](https://github.com/mozilla-iam/mozilla-aws-cli/issues/178)
* Issuer URL which is used when an AWS web console session expires to enable the
  user to refresh their session by visiting the federated-aws-rp. Previously the
  URL shown to the user contained the AWS account ID. Now it contains the more
  human readable account alias. [#190](https://github.com/mozilla-iam/mozilla-aws-cli/issues/190)

### Removed
* **Support for `/etc/maws/config` and `~/.maws/config` config files** [#178](https://github.com/mozilla-iam/mozilla-aws-cli/issues/178)
  * This is a breaking change and an exiting config file will need to be moved
    by the user into the new location(s) described in the README

### Fixed
* Errors when maws was used on a Windows client [#170](https://github.com/mozilla-iam/mozilla-aws-cli/issues/170) [#172](https://github.com/mozilla-iam/mozilla-aws-cli/issues/172)
 
## [0.2.0] - 2019-12-06
### Added
* Documentation warning about YADR and ZSH [#140](https://github.com/mozilla-iam/mozilla-aws-cli/issues/140)
* Detection of ID Tokens that are older than AWS allows [#150](https://github.com/mozilla-iam/mozilla-aws-cli/issues/150)
* 15 minute session duration fallback for IAM Roles which have under 1 hour max
  session durations [#150](https://github.com/mozilla-iam/mozilla-aws-cli/issues/150)
* Detection of expired ID tokens initiating a new auth flow [#150](https://github.com/mozilla-iam/mozilla-aws-cli/issues/150)
* Faster login when using `-w` as now the cached ID Token is used if it's valid [#150](https://github.com/mozilla-iam/mozilla-aws-cli/issues/150)
* Documentation on config file format [#154](https://github.com/mozilla-iam/mozilla-aws-cli/issues/154)
* `print_role_arn` config setting [#154](https://github.com/mozilla-iam/mozilla-aws-cli/issues/154)
* Printing the role_arn to the console [#154](https://github.com/mozilla-iam/mozilla-aws-cli/issues/154)
* Option to set the AWS profile name in shared and awscli output [#132](https://github.com/mozilla-iam/mozilla-aws-cli/issues/132) [#157](https://github.com/mozilla-iam/mozilla-aws-cli/issues/157)
* Add new Group Role Map rebuild triggering mechanism [#158](https://github.com/mozilla-iam/mozilla-aws-cli/issues/158)

### Changed
* Config file path changed from mozilla_aws_cli to maws [#139](https://github.com/mozilla-iam/mozilla-aws-cli/issues/139)
* Config file parsing to use an intentional `maws` section [#154](https://github.com/mozilla-iam/mozilla-aws-cli/issues/154)
* Changes the expected `idtoken_for_roles_url` URL format to expect the root URL
  instead of the URL ending in `/roles`
  * This change requires that config files use the base URL now and that any
    installed mozilla-aws-cli python packages providing `mozilla_aws_config`
    set the base URL for `idtoken_for_roles_url`

### Fixed
* If the web interface gets closed, making sure to shutdown the CLI [#143](https://github.com/mozilla-iam/mozilla-aws-cli/issues/143) [#128](https://github.com/mozilla-iam/mozilla-aws-cli/issues/128)
* Utils not using the global logger [#147](https://github.com/mozilla-iam/mozilla-aws-cli/issues/147)
* Config file and config module settings not being merged [#151](https://github.com/mozilla-iam/mozilla-aws-cli/issues/151)
* When specifying role with -r that's not available, erroring out [#127](https://github.com/mozilla-iam/mozilla-aws-cli/issues/127) [#156](https://github.com/mozilla-iam/mozilla-aws-cli/issues/156)

## [0.1.1] - 2019-11-21
### Fixed
* Case when using Python 2 with a config module

## [0.1.0] - 2019-11-20
### Added
* Add support for `$(maws)` syntax by removing carriage returns from output [#122](https://github.com/mozilla-iam/mozilla-aws-cli/issues/122)

### Changed
* Changed the precedence of the mozilla_aws_cli_config module such that if the
  module is present it overrides settings in the ~/.maws/config file only for
  settings that it asserts, leaving any additional settings set in the config
  file intact

## [0.0.2] - 2019-11-19
### Added
* Initial release of the mozilla-aws-cli tool

[Unreleased]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v1.2.4...HEAD
[1.2.4]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mozilla-iam/mozilla-aws-cli/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/mozilla-iam/mozilla-aws-cli/releases/tag/v0.0.2
