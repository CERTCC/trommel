# TROMMEL Documentation
* TROMMEL sifts through embedded device files to identify potential vulnerable indicators. Specifically, TROMMEL identifies the following indicators:
	* Secure Shell (SSH) key files
	* Secure Socket Layer (SSL) key files
	* Internet Protocol (IP) addresses
	* Uniform Resource Locators (URLs)
	* email addresses
	* shell scripts
	* web server binaries
	* configuration files
	* database files
	* specific binaries files (for example, Dropbear, BusyBox, and others)
	* shared object library files
	* web application scripting variables
	* Android application package (APK) file permissions

* TROMMEL integrates vFeed, which is a database wrapper that pulls in content from Common Vulnerabilities and Exposures (CVE) database and the intersection with Exploit-DB, Metasploit, Snort, and Nmap. vFeed offers a free, downloadable Community Database for non-commercial users. This integration allows for further in-depth vulnerability analysis of identified indicators to enrich the output.

* TROMMEL significantly lessens the manual analysis time of the researcher by automating much of the vulnerability discovery and analysis process.

#TROMMEL Output
* Upon execution, TROMMEL provides the following feedback to the researcher in the terminal and writes 3 (CSV parsable) results files:
	* Results will be saved to User-Supplied-File-Name_Trommel_YYYYMMDD_HHMMSS.
	* vFeed results will be saved to User-Supplied-File-Name_TROMMEL_vFeed_Results_YYYYMMDD_HHMMSS.
	* Hashes of files will be saved to User-Supplied-File-Name_TROMMEL_Hash_Results_YYYYMMDD_HHMMSS.
* Checks the architecture of the BusyBox binary.
* The text file is named according to the above naming convention and will contain the following information preceding the identified indicators:
	* Trommel Results File Name: [Researcher Supplied File Name]
	* Directory: [Researcher Supplied Directory]
	* There are [Count of Files] total files within the directory.
* The results should be reviewed to identify and remove false positives and to identify indicators that need further analysis for potential vulnerabilities.


# Handling Dependencies
* Download TROMMEL
* Download vFeed Community Database from vFeed tool from https://vfeed.io/pricing/.
	* This database needs to be placed in the root of the working directory of TROMMEL.
* Python3-magic
	* For Linux:
		* apt-get install python3-magic

# Usage
```
$ trommel.py --help
```
Output TROMMEL results to a file based on a given directory. By default, only searches plain text files.
```
$ trommel.py -p /extracted_firmware_directory -o output_file -d output_file_dir
```
Output TROMMEL results to a file based on a given directory. Search both binary and plain text files.
```
$ trommel.py -p /extracted_firmware_directory -o output_file -d output_file_dir -b
```
One-off text search of directory
```
$ trommel.py -p /extracted_firmware_directory -s user_search_term
```
One-off specialized search option of vFeed
```
$ trommel.py -p /extracted_firmware_directory -v user_search_term
```


# Suggested usage:
* Steps:
	* Once TROMMEL is installed, down a firmware binary, extract the contents of the firmware binary to expose the files/file system using [binwalk](https://github.com/devttys0/binwalk) or something similar.
	* Run TROMMEL on the extracted firmware file system directory
