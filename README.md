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

## Dependencies
* [Python-Magic](https://pypi.python.org/pypi/python-magic)
* [Pyfiglet](https://pypi.org/project/pyfiglet/0.7/)

# Usage
TROMMEL help menu.
```
$ trommel.py --help
```
Output TROMMEL results to a specific file and a specific directory based on a given root file system directory.
```
$ trommel.py -p <root file system directory> -o results_output_file -d <directory to save results output file>
```

## Notes
* Red Team point of view: researchers during firmware analysis to find potential vulnerabilities
* Blue Team point of view: Network defenders can benefit as well to assess devices on their network or for devices they plan to add to their network
* Devices can include IoT (web cams, smart devices (light bulbs, plugs, switches, TVs, fridge, coffee maker, etc.)), SCADA/ICS, routers, really anything with an embedded flash chip that boots an OS (or like an OS) on startup.
* TROMMEL has been tested using Python3 on Kali Linux x86_64.

## References
* [Firmwalker](https://github.com/craigz28/firmwalker)
* [Lua Code: Security Overview and Practical Approaches to Static Analysis by Andrei Costin](http://firmware.re/lua/)
