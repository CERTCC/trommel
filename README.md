# TROMMEL

TROMMEL sifts through directories of files to identify indicators that may contain vulnerabilities. <br />

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

TROMMEL has also integrated [vFeed](https://vfeed.io/) which allows for further in-depth vulnerability analysis of identified indicators. <br />

TROMMEL was written with the intent to help with identifying indicators that may contain vulnerabilities found in firmware of embedded devices.


## Dependencies
* [Python-Magic](https://pypi.python.org/pypi/python-magic)
* [vFeed Database](https://vfeed.io/pricing/) - For non-commercial use, register and download the Community Edition database


## Usage
```
$ trommel.py --help
```

Output TROMMEL results to a file based on a given directory
```
$ trommel.py -p /directory -o output_file
```

## Notes
TROMMEL has been tested using Python 2.7 on macOS Sierra and Kali Linux x86_64.

## References

* [vFeed](https://vfeed.io/)
* [Firmwalker](https://github.com/craigz28/firmwalker)
* [Lua Code: Security Overview and Practical Approaches to Static Analysis by Andrei Costin](http://firmware.re/lua/)
