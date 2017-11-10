import argparse
import os
import re
from datetime import datetime
import magic

#Imports from vFeed
from lib.core.methods import *
from lib.core.search import Search


parser = argparse.ArgumentParser(description= "TROMMEL: Sift Through Directories of Files to Identify Indicators That May Contain Vulnerabilities")
parser.add_argument("-p","--path", required=True, help="Directory to Search")
parser.add_argument("-o","--output", required=True, help="Output Trommel Results File Name (no spaces)")

args = vars(parser.parse_args())

path = args['path']
output = args['output']


#Function to search for keywords in file. Writes keyword, file name, number hits in file
def read_search_kw(file, keyword):
	try:

		with open (file, 'r') as keyword_search:
			text = keyword_search.read()
			hits = re.findall(keyword, text, re.I)
			if hits:
				magic_mime = magic.from_file(file, mime=True)
				magic_hit = re.search(r'x-executable|x-sharedlib|x-binary|LSB executable|LSB shared object|archive data|GNU message catalog|tar archive|gzip compressed data', magic_mime, re.I)
				if magic_hit:
					trommel_output.write("Found a non-plain text file that contains keyword '%s': %s : Number of occurences in file: %d\n" % (keyword, file, len(hits)))
				else:
					trommel_output.write("Found a plain text file that contains keyword '%s': %s : Number of occurences in file: %d\n" % (keyword, file, len(hits)))

	except IOError:
		pass

#Function to search for keywords in file (case sensitive). Writes keyword, file name, number hits in file
def read_search_case_kw(file, keyword):
	try:
		with open (file, 'r') as keyword_search:
			text = keyword_search.read()
			hits = re.findall(keyword, text)
			if hits:
				magic_mime = magic.from_file(file, mime=True)
				magic_hit = re.search(r'x-executable|x-sharedlib|x-binary|LSB executable|LSB shared object|archive data|GNU message catalog|tar archive|gzip compressed data', magic_mime, re.I)
				if magic_hit:
					trommel_output.write("Found a non-plain text that contains keyword '%s': %s : Number of occurences in file: %d\n" % (keyword, file, len(hits)))
				else:
					trommel_output.write("Found a plain text file that contains keyword '%s': %s : Number of occurences in file: %d\n" % (keyword, file, len(hits)))
	except IOError:
		pass

#Function to search for keywords in file (case sensitive). Writes keyword, file name, number hits in file
def read_search_lua_kw(file, keyword):
	try:
		with open (file, 'r') as keyword_search:
			text = keyword_search.read()
			hits = re.findall(keyword, text)
			if hits:
				trommel_output.write("Found a Lua script file that contains a potential vulnerable command '%s': %s : Number of occurences in file: %d\n" % (keyword, file, len(hits)))
	except IOError:
		pass

#Function to search for keywords in file (case sensitive). Writes keyword, file name, number hits in file
def read_search_apk(file, keyword):
	try:
		with open (file, 'r') as keyword_search:
			text = keyword_search.read()
			hits = re.findall(keyword, text, re.I)
			if hits:
				trommel_output.write("Found a file that contains a Android APK keyword '%s': %s : Number of occurences in file: %d\n" % (keyword, file, len(hits)))
	except IOError:
		pass

#Function to search CVEs in CVE Community Edition Database in CVE Community Edition Database
def cve_search_func(cve_term):
	found_cve = Search(cve_term).cve()
	return found_cve		

#Function to return Exploit DB association with CVE in CVE Community Edition Database
def exploitdb_result(cve_term):
	edb = CveExploit(cve_term).get_edb()
	return edb
	
#Function to return Metasploit Module association with CVE in CVE Community Edition Database
def metasploit_result(cve_term):
	msf = CveExploit(cve_term).get_msf()
	return msf

#Function to text search in CVE Community Edition Database
def text_search(search_term):
	search_text = Search(search_term).text()
	cve_field = re.findall(r'CVE-\d+-\d+', search_text, re.S)
	if search_text is not "null":
		cve_hit = '"(CVE-\d+-\d+ : .*\.)"'
		name_hit = re.findall(cve_hit, search_text)
		for match_hit in name_hit:
			trommel_output.write("Check file version on embedded device - Found %s and it has been associated with %s\n" % (search_term, match_hit))
	#Searches above CVE in Exploit-DB and Metasploit
	for cve_hit in cve_field:
		edb = exploitdb_result(cve_hit)
		msf = metasploit_result(cve_hit)
		#Exploit-DB result
		if edb is not "null":
			url_match = "http://www.exploit-db.com/exploits/\d{1,8}"
			urls = re.findall(url_match, edb, re.S)
			for url_hit in urls:
				trommel_output.write("%s has a known exploit: %s\n" % (cve_hit, url_hit))
		#Metasploit results
		if msf is not "null":
			msf_fname = "metasploit-framework/modules/.*\.rb"
			msf_title = '"title": "(.*)"'
			msf_fn_match = re.findall(msf_fname, msf) 
			msf_title_match = re.findall(msf_title, msf)
			for match in msf_fn_match:
				for match2 in msf_title_match:
					trommel_output.write("%s is associated with the following Metasploit Module: %s - %s\n" % (cve_hit, match2, match))


#Date informtion
yrmoday = datetime.now().strftime("%Y%m%d_%H%M%S")

#Save file name and date information to file in working directory script
trommel_output =  file(output+'_Trommel_'+yrmoday,'wt')


#Main function		
def main():
	
	#Print information to terminal
	print "\nTrommel is working to sift through the directory of files.\nResults will be saved to '%s_Trommel_%s'\n" % (output, yrmoday)
	
	#Title written to file
	trommel_output.write('''

 :::==== :::====  :::====  :::=======  :::=======  :::===== :::     
 :::==== :::  === :::  === ::: === === ::: === === :::      :::     
   ===   =======  ===  === === === === === === === ======   ===     
   ===   === ===  ===  === ===     === ===     === ===      ===     
   ===   ===  ===  ======  ===     === ===     === ======== ========
                                                                                                                                                              

''')
	
	#User given name and path to user given directory to search
	trommel_output.write("Trommel Results File Name: %s\nDirectory: %s\n" % (output,path))
	
	#Count number of files within given path directory
	total = 0
	for root, dirs, files in os.walk(path, followlinks=False):
		total += len(files)
	trommel_output.write("There are %d total files within the directory.\n\n" % total)
	
	#Disclaimer written to output file
	trommel_output.write("Results could be vulnerabilities. These results should be verified as false positives may exist.\n\n")
		
    #Enumerate dir passed by user
	for root, dirs, files in os.walk(path):
		
		for names in files:
			ff = os.path.join(root,names)
			
			#Ignore any symlinks
			if not os.path.islink(ff):
				
				#Ignore the /dev directory. Script has problems with files in this directory
				dev_kw = "/dev/"
				if not dev_kw in ff:
				
					if path and output: 
						#Search key or password related files & keywords
						passwd = 'passwd'; shadow = 'shadow'; psk_hits = ".psk"; key_pass = "kdb"; k_wallet = "kwallet"; open_vpn = "ovpn"; pgp_log = "pgplog"; pgp_policy = "pgppolicy.xml"; pgp_prefs = "pgpprefs.xml"; \
						priv_kw = "private"; secret_kw = "secret"; javaks = ".jks"; sftpconfig = "sftp-config"; bitcoinfile = "wallet.dat"; pwd_safe = ".psafe3"
						if passwd in ff:
							trommel_output.write("Found a passwd file: %s\n" % ff)
						if shadow in ff:
							trommel_output.write("Found a shadow file: %s\n" % ff)
						if psk_hits in ff:
							trommel_output.write("Found a .psk file: %s\n" % ff)
						if key_pass in ff:
							trommel_output.write("Found a keypass file: %s\n" % ff)
						if k_wallet in ff:
							trommel_output.write("Found a kwallet file: %s\n" % ff)	
						if open_vpn in ff:
							trommel_output.write("Found an ovpn file: %s\n" % ff)
						if pgp_log in ff:
							trommel_output.write("Found a pgplog file: %s\n" % ff)
						if pgp_policy in ff:
							trommel_output.write("Found a pgppolicy.xml file: %s\n" % ff)
						if pgp_prefs in ff:
							trommel_output.write("Found a pgpprefs.xml file: %s\n" % ff)
						if priv_kw in ff:
							trommel_output.write("Found a file with private in the file name: %s\n" % ff)
						if secret_kw in ff:
							trommel_output.write("Found a file with secret in the file name: %s\n" % ff)
						if javaks in ff:
							trommel_output.write("Found a JavaKeyStore file: %s\n" % ff)
						if sftpconfig in ff:
							trommel_output.write("Found a sftp-config file: %s\n" % ff)
						if bitcoinfile in ff:
							trommel_output.write("Found a Bitcoin Wallet: %s\n" % ff)
						if pwd_safe in ff:
							trommel_output.write("Found a Password Safe file: %s\n" % ff)


						#Search for SSH related files
						auth_key_file = 'authorized_keys'; host_key_file = "host_key"; id_rsa_file = 'id_rsa'; id_dsa_file = 'id_dsa'; dotPub = ".pub"; id_ecdsa_file = "id_ecdsa"; id_ed25519_file="id_ed25519"
						if auth_key_file in ff:
							trommel_output.write("Found an authorized_keys file: %s\n" % ff)
						if host_key_file in ff:
							trommel_output.write("Found a host_key file: %s\n" % ff)
						if id_rsa_file in ff:
							trommel_output.write("Found an id_rsa file: %s\n" % ff)
						if id_dsa_file in ff:
							trommel_output.write("Found an id_dsa file: %s\n" % ff)
						if dotPub in ff:
							trommel_output.write("Found a .pub file: %s\n" % ff)
						if id_ecdsa_file in ff:
							trommel_output.write("Found an id_ecdsa file: %s\n" % ff)
						if id_ed25519_file in ff:
							trommel_output.write("Found an id_ed25519 file: %s\n" % ff)
						read_search_kw(ff, id_dsa_file)
						read_search_kw(ff, host_key_file)
						read_search_kw(ff, auth_key_file)
						read_search_kw(ff, id_rsa_file)	
						read_search_kw(ff, id_ecdsa_file)
						read_search_kw(ff, id_ed25519_file)
	
						#Search for SSL related files - filenames: *.pem, *.crt, *.cer, *.p7b, *.p12, *.key
						pem = '.pem'; crt = '.crt'; cer = ".cer"; p7b = '.p7b'; p12 = '.p12'; dotKey = ".key"; p15 =".p15"
						if pem in ff:
							trommel_output.write("Found a SSL related .pem file: %s\n" % ff)
						if crt in ff:
							trommel_output.write("Found a SSL related .crt file: %s\n" % ff)
						if cer in ff:
							trommel_output.write("Found a SSL related .cer file: %s\n" % ff)
						if p7b in ff:
							trommel_output.write("Found a SSL related .p7b file: %s\n" % ff)
						if p12 in ff:
							trommel_output.write("Found a SSL related .p12 file: %s\n" % ff)
						if dotKey in ff:
							trommel_output.write("Found a SSL related .key file: %s\n" % ff)
						if p15 in ff:
							trommel_output.write("Found a SSL related .p15 file: %s\n" % ff)


						#Search for keyword of interest within files
						upgrade_kw = "upgrade"
						admin_kw = "admin"
						root_kw = "root"
						password_kw = "password"
						passwd_kw = "passwd"
						pwd_kw = "pwd"
						dropbear_kw = "dropbear"
						ssl_kw = "ssl"
						telnet_kw = "telnet"
						crypt_kw = "crypt"
						auth_kw = "authentication"
						sql_kw = "sql"
						passphrase_kw = "passphrase"
						rsa_key_pair = "rsakeypair"
						secretkey_kw = "secretkey"
						ssh_hot_keys = "sshhostkeys"
						read_search_kw(ff, upgrade_kw)
						read_search_kw(ff, admin_kw)
						read_search_kw(ff, root_kw)
						read_search_kw(ff, password_kw)
						read_search_kw(ff, passwd_kw)
						read_search_kw(ff, pwd_kw)
						read_search_kw(ff, dropbear_kw)
						read_search_kw(ff, ssl_kw)
						read_search_kw(ff, telnet_kw)
						read_search_kw(ff, crypt_kw)
						read_search_kw(ff, auth_kw)
						read_search_kw(ff, sql_kw)
						read_search_kw(ff, passphrase_kw)
						read_search_kw(ff, rsa_key_pair)
						read_search_kw(ff, secretkey_kw)
						read_search_kw(ff, ssh_hot_keys)


						#Search for keywords "private key", IP addresses, URLs, and email addresses
						private_key_kw = "private.*key"
						ipaddr = '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
						urls = "(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,8}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,8}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]\.[^\s]{2,8}|www\.[a-zA-Z0-9]\.[^\s]{2,8})"
						email = "[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"				
						secret_key_kw = "secret.*key"
						try:
							with open (ff, 'r') as privkey_keyword:
								text = privkey_keyword.read()
								hits = re.findall(private_key_kw, text, re.I)
								if hits:
									trommel_output.write("Found a file that contains variation of keyword 'private key': %s : Number of occurences in file: %d\n" % (ff, len(hits)))
						except IOError:
							pass
				
						try:
							with open (ff, 'r') as ipaddr_keyword:
								text = ipaddr_keyword.read()
								hits = re.findall(ipaddr, text, re.S)
								for h in hits:
									trommel_output.write("Found a file that contains an IP address: %s : %s\n" % (ff, h))
						except IOError:
							pass
				
						try:
							with open (ff, 'r') as url_keyword:
								text = url_keyword.read()
								hits = re.findall(urls, text, re.S)
								for h in hits:
									trommel_output.write("Found a file that contains a URLs: %s : %s\n" % (ff, h))
						except IOError:
							pass
					
						try:
							with open (ff, 'r') as email_addr:
								text = email_addr.read()
								hits = re.findall(email, text, re.S)
								for h in hits:
									trommel_output.write("Found a file that contains a email address(es): %s : %s\n" % (ff, h))
						except IOError:
							pass
					
						try:
							with open (ff, 'r') as seckey_keyword:
								text = seckey_keyword.read()
								hits = re.findall(secret_key_kw, text, re.I)
								if hits:
									trommel_output.write("Found a file that contains variation of keyword 'secret key': %s : Number of occurences in file: %d\n" % (ff, len(hits)))
						except IOError:
							pass


						#Search for files in /opt directory. This directory sometimes has specific files put there by the vendor. 
						opt_dir_kw = "/opt"
						if opt_dir_kw in ff:
							trommel_output.write("The following file is in the /opt directory: %s\n" % ff)
					
						#Search for shell script files with .sh extension
						shell_script = ".sh"
						if shell_script in ff:
							trommel_output.write("The following shell script was found: %s\n" % ff)


						#Search for web server binaries - apache, lighttpd, alphapd, httpd
						apache_bin = "apache"
						lighttpd_bin = "lighttpd"
						alphapd_bin = "alphapd"
						httpd_bin = "httpd"
						if apache_bin in ff:
							trommel_output.write("Found an apache binary file: %s\n" % ff)
						if lighttpd_bin in ff:
							text_search(lighttpd_bin)
						if alphapd_bin in ff:
							text_search(alphapd_bin)
						if httpd_bin in ff:
							trommel_output.write("Found a httpd binary file: %s\n" % ff)

						#Search for config files with these extensions *.conf, *.cfg, *.ini
						config_1 = ".conf"
						config_2 = ".cfg"
						config_3 = ".ini"
						if config_1 in ff:
							trommel_output.write("Found a .conf configuration file: %s\n" % ff)
						if config_2 in ff:
							trommel_output.write("Found a .cfg configuration file: %s\n" % ff)
						if config_3 in ff:
							trommel_output.write("Found a .ini configuration file: %s\n" % ff)

						#Search for database files with these extensions *.db and *.sqlite
						db_file = ".db"
						sqlite_file = ".sqlite"
						sql_file = ".sql"
						if db_file in ff:
							trommel_output.write("Found a .db file: %s\n" % ff)
						if sqlite_file in ff:
							trommel_output.write("Found a .sqlite file: %s\n" % ff)
						if sql_file in ff:
							trommel_output.write("Found a .sql file: %s\n" % ff)

						#Search for binary files of interest
						ssh_bin = "ssh"
						sshd_bin = "sshd"
						scp_bin = "scp"
						sftp_bin = "sftp"
						tftp_bin = "tftp"
						dropbear_bin = "dropbear"
						busybox_bin = "busybox"
						telnet_bin = "telnet"
						telnetd_bin = "telnetd"
						openssl_bin = "openssl"
						other_bins = ".bin$"
	
						if ssh_bin in ff:
							trommel_output.write("Found a ssh binary file: %s\n" % ff)
						if sshd_bin in ff:
							trommel_output.write("Found a sshd binary file: %s\n" % ff)
						if scp_bin in ff:
							trommel_output.write("Found a scp binary file: %s\n" % ff)
						if sftp_bin in ff:
							trommel_output.write("Found a sftp binary file: %s\n" % ff)
						if tftp_bin in ff:
							trommel_output.write("Found a tftp binary file: %s\n" % ff)
						if dropbear_bin in ff:
							text_search(dropbear_bin)
						if telnet_bin in ff:
							trommel_output.write("Found a telnet binary file: %s\n" % ff)
						if telnetd_bin in ff:
							trommel_output.write("Found a telnetd binary file: %s\n" % ff)
						if openssl_bin in ff:
							trommel_output.write("Found a openssel binary file: %s\n" % ff)		
						if busybox_bin in ff:
							text_search(busybox_bin)	
						if other_bins in ff:
							trommel_output.write("Found a .bin file: %s\n" % ff)			


						#WebApp specific - PHP, Javascript, VBScript, Lua
						#PHP untrusted user input functions
						php_fn = ".php"
						if php_fn in ff:
							php_server_func = "\$_SERVER"
							php_get_func = "\$_GET"
							php_post_func = "\$_POST"
							php_request_func = "\$_REQUEST"
							php_files_func = "\$_FILES"
							php_cookie_func = "\$_COOKIE"
							php_split_kw = "split"
							read_search_case_kw(ff, php_server_func)
							read_search_case_kw(ff, php_get_func)
							read_search_case_kw(ff, php_post_func)
							read_search_case_kw(ff, php_request_func)
							read_search_case_kw(ff, php_files_func)
							read_search_case_kw(ff, php_cookie_func)	
							read_search_case_kw(ff, php_split_kw)
						
							#PHP SQL related results
							php_sql_com1 = "SELECT"
							php_sql_com2 = "FROM"
							php_sql_com3 = "WHERE"
							read_search_case_kw(ff, php_sql_com1)
							read_search_case_kw(ff, php_sql_com2)
							read_search_case_kw(ff, php_sql_com3)
					
							#PHP shell injection function.
							php_shellexec_func = "shell_exec"
							php_exec_func = "exec"
							php_passthru_func = "passthru"
							php_system_func = "system"
							read_search_kw(ff, php_shellexec_func)
							read_search_kw(ff, php_exec_func)
							read_search_kw(ff, php_passthru_func)
							read_search_kw(ff, php_system_func)

						#Javascript	functions of interest
						alert_kw = "script.*alert.*script"
						src_kw = "src="
						script_kw = "script%3e"
						script1_kw = "script\x3e"
						doc_url_kw = "document.URL"
						doc_loc_kw = "document.location"
						doc_referrer_kw = "document.referrer"
						win_loc_kw = "window.location"
						doc_cookies_kw = "document.cookies"
						eval_kw = "eval"
						settimeout_kw = "setTimeout"
						setinterval_kw = "setInterval"
						loc_assign_kw = "location.assign"
						nav_referrer_kw = "navigation.referrer"
						win_name_kw = "window.name"

						script_word = "script"
						try:
							with open (ff, 'r') as js_file:
								text = js_file.read()
								hits = re.findall(script_word, text, re.S)
								if hits:
									read_search_kw(ff, alert_kw)
									read_search_kw(ff, src_kw)
									read_search_kw(ff, script_kw)
									read_search_kw(ff, script1_kw)
									read_search_case_kw(ff, doc_url_kw)
									read_search_case_kw(ff, doc_loc_kw)
									read_search_case_kw(ff, doc_referrer_kw)
									read_search_case_kw(ff, win_loc_kw)
									read_search_case_kw(ff, doc_cookies_kw)
									read_search_case_kw(ff, eval_kw)
									read_search_case_kw(ff, settimeout_kw)
									read_search_case_kw(ff, setinterval_kw)
									read_search_case_kw(ff, loc_assign_kw)
									read_search_case_kw(ff, nav_referrer_kw)
									read_search_case_kw(ff, win_name_kw)
						except IOError:
							pass

						#VBScript presence
						vbscript_kw = "vbscript"
						read_search_kw(ff, vbscript_kw)
					
						#Lua script functions of interest
						lua_fn = ".lua"
						if lua_fn in ff:
							lua_get = "_GET\["
							lua_cgi_query = "cgilua.QUERY."
							lua_cgi_post = "cgilua.POST."
							lua_print = "print"
							lua_iowrite = "io.write"
							lua_ioopen = "io.open"
							lua_cgi_put = "cgilua.put"
							lua_cgi_handhelp = "cgilua.handlelp"
							lua_execute = "execute"
							lua_strcat = "strcat"
							lua_htmlentities = "htmlentities"
							lua_htmlspecialchars = "htmlspecialchars"
							lua_htmlescape = "htmlescape"
							lua_htmlentitydecode = "html_entity_decode"
							lua_htmlunescape = "htmlunescape"
							lua_iopopen = "io.popen"
							lua_escapeshellarg = "escapeshellarg"
							lua_unescapeshellarg = "unescapeshellarg"
							lua_escapeshellcmd = "escapeshellcmd"
							lua_unescapeshellcmd = "unescapeshellcmd"
							lua_fhupo = "fake_htmlunescape_print_popen\("
							lua_fhpo = "fake_htmlescape_print_popen\("
							lua_fsppo = "fake_strcat_print_popen\("
							lua_ntopreaddir = "ntop.readdir\("
						
							read_search_lua_kw(ff, lua_get)
							read_search_lua_kw(ff, lua_cgi_query)
							read_search_lua_kw(ff, lua_cgi_post)
							read_search_lua_kw(ff, lua_print)
							read_search_lua_kw(ff, lua_iowrite)
							read_search_lua_kw(ff, lua_ioopen)
							read_search_lua_kw(ff, lua_cgi_put)
							read_search_lua_kw(ff, lua_cgi_handhelp)
							read_search_lua_kw(ff, lua_execute)
							read_search_lua_kw(ff, lua_strcat)
							read_search_lua_kw(ff, lua_htmlentities)
							read_search_lua_kw(ff, lua_htmlspecialchars)
							read_search_lua_kw(ff, lua_htmlescape)
							read_search_lua_kw(ff, lua_htmlentitydecode)
							read_search_lua_kw(ff, lua_htmlunescape)
							read_search_lua_kw(ff, lua_iopopen)
							read_search_lua_kw(ff, lua_escapeshellarg)
							read_search_lua_kw(ff, lua_unescapeshellarg)
							read_search_lua_kw(ff, lua_escapeshellcmd)
							read_search_lua_kw(ff, lua_unescapeshellcmd)
							read_search_lua_kw(ff, lua_fhupo)
							read_search_lua_kw(ff, lua_fhpo)
							read_search_lua_kw(ff, lua_fsppo)
							read_search_lua_kw(ff, lua_ntopreaddir)
				
				
						#Search library base name against CVE Community Edition Database
						lib_file = ".so"
						if lib_file in ff:
							base_name = re.search(r'lib[a-zA-Z]{1,20}', names, re.S)
							if base_name is not None:
								m = base_name.group()
								mm = m + ".so"
								text_search(mm)
	
	
						#Search specific content related decompress and decompiled Android APKs
						#APK App permisssion					
						perm = 'android\.permission\.[A-Z_]{1,50}'
						try:
							with open (ff, 'r') as file:
								text = file.read()
								hits = re.findall(perm, text, re.S)
								for h in hits:
									trommel_output.write("Found a file that contains a Android permission: %s : %s\n" % (ff, h))
						except IOError:
							pass
					
						#APK App package name
						pkg_name = 'package="(.*?)"'
						try:
							with open (ff, 'r') as file:
								text = file.read()
								hits = re.findall(pkg_name, text, re.S)
								for h in hits:
									trommel_output.write("Found a file that contains a Android package/app name: %s : %s\n" % (ff, h))
						except IOError:
							pass
							
if __name__ == '__main__':
    main()