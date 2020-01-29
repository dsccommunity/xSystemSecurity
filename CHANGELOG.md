# Change log for xSystemSecurity

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- xSystemSecurity
  - Added continuous delivery with a new CI pipeline.

### Fixed

- xSystemSecurity
  - Fixed the correct URL on status badges.
- xFileSystemAccessRule
  - Corrected flag handling so that the `Test-TargetResource` passes
    correctly.
  - Using `Ensure = 'Absent'` with no rights specified will now correctly
    remove existing ACLs for the specified identity, rather than silently
    leaving them there.
  - Correctly returns property `Ensure` from the function `Get-TargetResource`.

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
