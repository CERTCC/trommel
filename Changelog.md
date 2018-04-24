# Changelog
All notable changes to this project will be documented in this file.

## 2018-04-24
### Changed
- Updated trommel.py to include one-off user specified keyword search
- Updated indicators.py & indicator_config.py to include print off files in /opt directory

## 2018-04-20
### Changed 
- Updated trommel.py to include a check for vFeed database. If doesn't exist, program exits.

## 2018-03-23
### Changed
- Updated Documentation.md and README.md
- Updated trommel.py, indicators.py, and indicator_config.py to print and write instruction set architecture based on the busybox binary

## 2018-03-22
### Added
- Added a argument to search binary files for indicators. By default it only searches plain text files.

## 2018-03-21
### Changed
- Updated mime regex search string in indicator_config.py. Thanks to my colleague @woytek

## 2018-03-02
### Changed
- Updated the description.

## 2018-02-25
### Changed
- Added a instruction set architecture check based on the byte offsets in ELF executable. Currently, just checks Busybox binary. 

## 2018-01-26
### Changed
- Updated indicators.py to include regex searches for version numbers of BusyBox, Dropbear (late 2011 or newer), and lighttpd.

## 2017-12-21
### Added
- Created this Changelog.md file. 

## 2017-12-20
### Changed
- Updated indicators.py to include byte offsets for (most) indicator hits in non-plain text files. 

## 2017-12-08
### Changed
- Updated indicators.py to make output grep-able.

## 2017-12-08
### Changed
- Updated indicators.py to make output grep-able.

## 2017-11-12
### Added
- indicators.py was created and contains the searching functions.
- indicator_config.py was created and contains all the indicators for searching.

### Changed
- trommmel.py was made into a loader.

## 2017-10-30
### Added
- Created Documentation.md

## 2017-10-19
### Added
- TROMMEL was uploaded to GitHub.

