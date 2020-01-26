# Change log for xSystemSecurity

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- xSystemSecurity
  - Added automatic release with a new CI pipeline.

## [1.4.0.0] - 2018-06-13

- Changes to xFileSystemAccessRule
  - Fixed issue when cluster shared disk is not present on the server
    ([issue #16](https://github.com/dsccommunity/xSystemSecurity/issues/16)).
    [Dan Reist (@randomnote1)](https://github.com/randomnote1)

### [1.3.0.0] - 2017-12-20

- Updated FileSystemACL Set

### [1.2.0.0] - 2016-09-21

- Converted appveyor.yml to install Pester from PSGallery instead of from
  Chocolatey.
- Added xFileSystemAccessRule resource

### [1.1.0.0] - 2015-09-11

- Fixed encoding

### [1.0.0.0] - 2015-04-23

- Initial release with the following resources
  - xUAC
  - xIEEsc
