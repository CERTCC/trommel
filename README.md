# TROMMEL

TROMMEL sifts through embedded device files to identify potential vulnerable indicators. <br />

TROMMEL identifies the following indicators related to:
* Secure Shell (SSH) key files
* Secure Socket Layer (SSL) key files
* Internet Protocol (IP) addresses
* Uniform Resource Locator (URL)
* email addresses
* shell scripts
* web server binaries
* configuration files
* database files
* specific binaries files (i.e. Dropbear, BusyBox, etc.)
* shared object library files
* web application scripting variables, and
* Android application package (APK) file permissions.

TROMMEL has also integrated [vFeed](https://vfeed.io/) which allows for further in-depth vulnerability analysis of identified indicators to enrich the output. <br />

## Dependencies
* [Python-Magic](https://pypi.python.org/pypi/python-magic) - See documentation for instructions for Python3-magic installation
* [vFeed Database](https://vfeed.io/pricing/) - For non-commercial use, register and download the Community Edition database

# Usage
```
$ trommel.py --help
```
Output TROMMEL results to a file based on a given directory. By default, only searches plain text files.
```
$ trommel.py -p /directory -o output_file
```
Output TROMMEL results to a file based on a given directory. Search both binary and plain text files.
```
$ trommel.py -p /directory -o output_file -b
```

## Notes
* The intended to assist researchers during firmware analysis to find potential vulnerabilities
* Network defenders can benefit as well to assess devices on their network or for devices they plan to add to their network
* Devices can include IoT (web cams, smart devices (light bulbs, plugs, switches, TVs, fridge, coffee maker, etc.)), SCADA/ICS, routers, really anything with an embedded flash chip that boots an OS on startup.
* TROMMEL has been tested using Python3 on Kali Linux x86_64.

## References

* [vFeed](https://vfeed.io/)
* [Firmwalker](https://github.com/craigz28/firmwalker)
* [Lua Code: Security Overview and Practical Approaches to Static Analysis by Andrei Costin](http://firmware.re/lua/)

## Author
* Kyle O'Meara - komeara AT cert DOT org and @cool_breeze26
