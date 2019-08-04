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

* TROMMEL significantly lessens the manual analysis time of the researcher by automating much of the vulnerability discovery and analysis process.

# TROMMEL Output
* Upon execution, TROMMEL provides the following feedback to the researcher in the terminal and writes 2 (CSV parsable) results files:
	* Results will be saved to User-Supplied-File-Name_Trommel_YYYYMMDD_HHMMSS.
	* Hashes of files will be saved to User-Supplied-File-Name_TROMMEL_Hash_Results_YYYYMMDD_HHMMSS.
* Checks the system architecture by using the BusyBox binary.
* The text file is named according to the above naming convention and will contain the following information preceding the identified indicators:
	* TROMMEL Results File Name: [Researcher Supplied File Name]
	* Directory: [Researcher Supplied Directory]
	* There are [Count of Files] total files within the directory.
* The results should be reviewed to identify and remove false positives and to identify indicators that need further analysis for potential vulnerabilities.


# Handling Dependencies
* Download TROMMEL
* Python3-magic
	* For Linux: apt-get install python3-magic
* Pyfiglet
	* For linux: pip3 install pyfiglet

# Usage
TROMMEL Help Menu
```
$ trommel.py --help
```
Output TROMMEL results to a specific file and a specific directory based on a given root file system directory.
```
$ trommel.py -p <root file system directory> -o results_output_file -d <directory to save results output file>
```

# Suggested usage:
* Steps:
	* Once TROMMEL is installed, down a firmware binary, extract the contents of the firmware binary to expose the files/file system using [binwalk](https://github.com/devttys0/binwalk) or something similar.
	* Run TROMMEL on the extracted firmware root file system directory
