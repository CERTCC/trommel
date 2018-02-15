
import magic
import re
import os
from itertools import count

from indicator_config import *

#Imports from vFeed
from lib.core.methods import *
from lib.core.search import Search

#Function to search for keywords in file. Writes keyword, file name, number hits in file
def read_search_kw(ff, keyword, trommel_output):
	try:
		with open (ff, 'r') as keyword_search:
			text = keyword_search.read()
			hits = re.findall(keyword, text, re.I)
			if hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(keyword, text, re.I):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword: '%s', File: %s, Offset(s) in File: " % (keyword, ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					trommel_output.write("Plain Text File, Keyword: '%s', File: %s, Keyword Hits in File: %d\n" % (keyword, ff, len(hits)))
	except IOError:
		pass

#Function to search for keywords in file (case sensitive). Writes keyword, file name, number hits in file
def read_search_case_kw(ff, keyword, trommel_output):
	try:	
		with open (ff, 'r') as keyword_search:
			text = keyword_search.read()
			hits = re.findall(keyword, text)
			if hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(keyword, text):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword: '%s', File: %s, Offset(s) in File: " % (keyword, ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					trommel_output.write("Plain Text File, Keyword: '%s', File: %s, Keyword Hits in File: %d\n" % (keyword, ff, len(hits)))
	except IOError:
		pass

#Function to search for keywords in file (case sensitive). Writes keyword, file name, number hits in file
def read_search_lua_kw(ff, keyword, trommel_output):
	try:
		with open (ff, 'r') as keyword_search:
			text = keyword_search.read()
			hits = re.findall(keyword, text)
			if hits:
				trommel_output.write("Lua Script file, Keyword: '%s', File: %s, Keyword Hits in File: %d\n" % (keyword, ff, len(hits)))
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
def text_search(search_term, trommel_output):
	search_text = Search(search_term).text()
	cve_field = re.findall(r'CVE-\d+-\d+', search_text, re.S)
	if search_text is not "null":
		cve_hit = '"(CVE-\d+-\d+ : .*\.)"'
		name_hit = re.findall(cve_hit, search_text)
		for match_hit in name_hit:
			trommel_output.write("Check file version on embedded device [may need to emulate environment] - Found %s and it has been associated with %s\n" % (search_term, match_hit))
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

def check_arch(ff, trommel_output):
	ISADict = {b'\x00':'No Specific Instruction Set', b'\x02':'SPARC' , b'\x03':'x86', b'\x08':'MIPS', b'\x14':'PowerPC',b'\x16':'S390',b'\x28':'ARM', b'\x2a':'SuperH', b'\x32':'IA-64', b'\x3e':'x86-64', b'\xb7':'Arch64', b'\xf3':'RISC-V'}
	magic_mime = magic.from_file(ff, mime=True)
	magic_hit = re.search(mime_kw, magic_mime, re.I)
	if magic_hit:
		with open(ff, "rb") as f:
			byte = f.read(20)
			for key, value in ISADict.items():
				if byte[5] == b'\x01' and byte[18] == key:
					trommel_output.write("The instruction set architecture is %s.\n" % value)
				else:
					if byte[5] == b'\x02' and byte[19] == key: 
						trommel_output.write("The instruction set architecture is %s\n" % value)


#Main function 	
def kw(ff, trommel_output, names):
	
	bb_bin = '/bin/%s' % busybox_bin
	if bb_bin in ff:
		check_arch(ff, trommel_output)

			
	#Search for binary files of interest
	if ssh_bin in ff:
		trommel_output.write("Non-Plain Text File, ssh binary file: %s\n" % ff)
	if sshd_bin in ff:
		trommel_output.write("Non-Plain Text File, sshd binary file: %s\n" % ff)
	if scp_bin in ff:
		trommel_output.write("Non-Plain Text File, scp binary file: %s\n" % ff)
	if sftp_bin in ff:
		trommel_output.write("Non-Plain Text File, sftp binary file: %s\n" % ff)
	if tftp_bin in ff:
		trommel_output.write("Non-Plain Text File, tftp binary file: %s\n" % ff)
	if dropbear_bin in ff:
		with open (ff, 'r') as keyword_search:
			text = keyword_search.read()
			drop_term = 'Dropbear server v[0-9]{4}\.[0-9]{2,3}'
			drop_hit = re.search(drop_term, text)
			if drop_hit:
				trommel_output.write("The Dropbear (late 2011 or newer) binary found is %s\n" % drop_hit.group())
		text_search(dropbear_bin, trommel_output)
	if telnet_bin in ff:
		trommel_output.write("Non-Plain Text File, telnet binary file: %s\n" % ff)
	if telnetd_bin in ff:
		trommel_output.write("Non-Plain Text File, telnetd binary file: %s\n" % ff)
	if openssl_bin in ff:
		trommel_output.write("Non-Plain Text File, openssl binary file: %s\n" % ff)		
	if busybox_bin in ff:
		with open (ff, 'r') as keyword_search:
			text = keyword_search.read()
			bb_term = 'BusyBox v[0-9]{1}\.[0-9]{1,2}\.[0-9]{1}'
			bb_hit = re.search(bb_term, text)
			if bb_hit:
				trommel_output.write("The BusyBox binary found is %s\n" % bb_hit.group())
		text_search(busybox_bin, trommel_output)
	if other_bins in ff:
		trommel_output.write("Non-Plain Text File, .bin file: %s\n" % ff)
	
	
	#Search key or password related files & keywords
	if passwd in ff:
		trommel_output.write("A passwd file: %s\n" % ff)
	if shadow in ff:
		trommel_output.write("A shadow file: %s\n" % ff)
	if psk_hits in ff:
		trommel_output.write("A .psk file: %s\n" % ff)
	if key_pass in ff:
		trommel_output.write("A keypass file: %s\n" % ff)
	if k_wallet in ff:
		trommel_output.write("A kwallet file: %s\n" % ff)	
	if open_vpn in ff:
		trommel_output.write("An ovpn file: %s\n" % ff)
	if pgp_log in ff:
		trommel_output.write("A pgplog file: %s\n" % ff)
	if pgp_policy in ff:
		trommel_output.write("A pgppolicy.xml file: %s\n" % ff)
	if pgp_prefs in ff:
		trommel_output.write("A pgpprefs.xml file: %s\n" % ff)
	if priv_kw in ff:
		trommel_output.write("A file with private in the file name: %s\n" % ff)
	if secret_kw in ff:
		trommel_output.write("A file with secret in the file name: %s\n" % ff)
	if javaks in ff:
		trommel_output.write("A JavaKeyStore file: %s\n" % ff)
	if sftpconfig in ff:
		trommel_output.write("A sftp-config file: %s\n" % ff)
	if bitcoinfile in ff:
		trommel_output.write("A Bitcoin Wallet: %s\n" % ff)
	if pwd_safe in ff:
		trommel_output.write("A Password Safe file: %s\n" % ff)


	#Search for SSH related files
	if auth_key_file in ff:
		trommel_output.write("An authorized_keys file: %s\n" % ff)
	if host_key_file in ff:
		trommel_output.write("A host_key file: %s\n" % ff)
	if id_rsa_file in ff:
		trommel_output.write("An id_rsa file: %s\n" % ff)
	if id_dsa_file in ff:
		trommel_output.write("An id_dsa file: %s\n" % ff)
	if dotPub in ff:
		trommel_output.write("A .pub file: %s\n" % ff)
	if id_ecdsa_file in ff:
		trommel_output.write("An id_ecdsa file: %s\n" % ff)
	if id_ed25519_file in ff:
		trommel_output.write("An id_ed25519 file: %s\n" % ff)
	read_search_kw(ff, id_dsa_file, trommel_output)
	read_search_kw(ff, host_key_file, trommel_output)
	read_search_kw(ff, auth_key_file, trommel_output)
	read_search_kw(ff, id_rsa_file, trommel_output)	
	read_search_kw(ff, id_ecdsa_file, trommel_output)
	read_search_kw(ff, id_ed25519_file, trommel_output)

	#Search for SSL related files - filenames: *.pem, *.crt, *.cer, *.p7b, *.p12, *.key
	if pem in ff:
		trommel_output.write("A SSL related .pem file: %s\n" % ff)
	if crt in ff:
		trommel_output.write("A SSL related .crt file: %s\n" % ff)
	if cer in ff:
		trommel_output.write("A SSL related .cer file: %s\n" % ff)
	if p7b in ff:
		trommel_output.write("A SSL related .p7b file: %s\n" % ff)
	if p12 in ff:
		trommel_output.write("A SSL related .p12 file: %s\n" % ff)
	if dotKey in ff:
		trommel_output.write("A SSL related .key file: %s\n" % ff)
	if p15 in ff:
		trommel_output.write("A SSL related .p15 file: %s\n" % ff)


	#Search for keyword of interest within files
	read_search_kw(ff, upgrade_kw, trommel_output)
	read_search_kw(ff, admin_kw, trommel_output)
	read_search_kw(ff, root_kw, trommel_output)
	read_search_kw(ff, password_kw, trommel_output)
	read_search_kw(ff, passwd_kw, trommel_output)
	read_search_kw(ff, pwd_kw, trommel_output)
	read_search_kw(ff, dropbear_kw, trommel_output)
	read_search_kw(ff, ssl_kw, trommel_output)
	read_search_kw(ff, telnet_kw, trommel_output)
	read_search_kw(ff, crypt_kw, trommel_output)
	read_search_kw(ff, auth_kw, trommel_output)
	read_search_kw(ff, sql_kw, trommel_output)
	read_search_kw(ff, passphrase_kw, trommel_output)
	read_search_kw(ff, rsa_key_pair, trommel_output)
	read_search_kw(ff, secretkey_kw, trommel_output)
	read_search_kw(ff, ssh_hot_keys, trommel_output)


	#Search for keywords "private key", IP addresses, URLs, and email addresses

	try:
		with open (ff, 'r') as privkey_keyword:
			text = privkey_keyword.read()
			hits = re.findall(private_key_kw, text, re.I)
			if hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(private_key_kw, text, re.I):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword Variation: 'private key', File: %s, Offset(s) in File: " % (ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					trommel_output.write("Plain Text File, Keyword Variation: 'private key', File: %s, Keyword Hits in File: %d\n" % (ff, len(hits)))
	except IOError:
		pass

	try:
		with open (ff, 'r') as ipaddr_keyword:
			text = ipaddr_keyword.read()
			hits = re.findall(ipaddr, text, re.S)
			if hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(ipaddr, text, re.S):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword IP Address: '%s', File: %s, Offset(s) in File: " % (m.group(0), ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					for h in hits:
						trommel_output.write("Plain Text File, Keyword IP Address: %s, File: %s\n" % (h, ff))
	except IOError:
		pass

	try:
		with open (ff, 'r') as url_keyword:
			text = url_keyword.read()
			hits = re.findall(urls, text, re.S)
			for h in hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(urls, text, re.S):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword URL: '%s', File: %s, Offset(s) in File: " % (h, ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					trommel_output.write("Plain Text File, Keyword URL: %s, File: %s\n" % (h, ff))
	except IOError:
		pass

	try:
		with open (ff, 'r') as email_addr:
			text = email_addr.read()
			hits = re.findall(email, text, re.S)
			for h in hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					trommel_output.write("Non-Plain Text File, Keyword Email Address: '%s', File: %s" % (h, ff))
				else:
					trommel_output.write("Plain Text File, Keyword Email Address: %s, File: %s\n" % (h, ff))
	except IOError:
		pass

	try:
		with open (ff, 'r') as seckey_keyword:
			text = seckey_keyword.read()
			hits = re.findall(secret_key_kw, text, re.I)
			if hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(secret_key_kw, text, re.I):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword Variation: 'secret key', File: %s, Offset(s) in File: " % (ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					trommel_output.write("Plain Text File, Keyword Variation: 'secret key', File: %s, Keyword Hits in File: %d\n" % (ff, len(hits)))
	except IOError:
		pass


	#Search for files in /opt directory. This directory sometimes has specific files put there by the vendor. 
	opt_dir_kw = "/opt"
	if opt_dir_kw in ff:
		trommel_output.write("A file is in the /opt directory: %s" % ff)

	#Search for shell script files with .sh extension
	if shell_script in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Non-Plain Text File, A shell script, File: %s\n" % (ff))
		else:
			trommel_output.write("Plain Text File, A shell script, File: %s\n" % (ff))


	#Search for web server binaries - apache, lighttpd, alphapd, httpd
	if apache_bin in ff:
		trommel_output.write("Non-Plain Text File, Apache binary file: %s\n" % ff)
		
	if lighttpd_bin in ff:
		with open (ff, 'r') as keyword_search:
			text = keyword_search.read()
			lt_term = 'lighttpd/[0-9]{1}\.[0-9]{1,2}\.[0-9]{1,2}'
			lt_hit = re.search(lt_term, text)
			if lt_hit:
				trommel_output.write("The lighttpd binary found is %s\n" % lt_hit.group())
		text_search(lighttpd_bin, trommel_output)
		
	if alphapd_bin in ff:
		text_search(alphapd_bin, trommel_output)
		
	if httpd_bin in ff:
		trommel_output.write("Non-Plain Text File, httpd binary file: %s\n" % ff)

	#Search for config files with these extensions *.conf, *.cfg, *.ini
	if config_1 in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Non-Plain Text File, A configuration file (.conf), File: %s\n" % (ff))
		else:
			trommel_output.write("Plain Text File, A configuration file (.conf), File: %s\n" % (ff))
		
	if config_2 in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Non-Plain Text File, A configuration file (.cfg), File: %s\n" % (ff))
		else:
			trommel_output.write("Plain Text File, A configuration file (.cfg), File: %s\n" % (ff))
				
		
	if config_3 in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Non-Plain Text File, A configuration file (.ini), File: %s\n" % (ff))
		else:
			trommel_output.write("Plain Text File, A configuration file (.ini), File: %s\n" % (ff))
			
		trommel_output.write("A .ini configuration file: %s\n" % ff)

	#Search for database files with these extensions *.db and *.sqlite
	if db_file in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Non-Plain Text File, A database file (.db), File: %s\n" % (ff))
		else:
			trommel_output.write("Plain Text File,  A database file (.db), File: %s\n" % (ff))
	
	if sqlite_file in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Non-Plain Text File, A database file (.sqlite), File: %s\n" % (ff))
		else:
			trommel_output.write("Plain Text File,  A database file (.sqlite), File: %s\n" % (ff))
		
	if sql_file in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Non-Plain Text File, A database file (.sql), File: %s\n" % (ff))
		else:
			trommel_output.write("Plain Text File,  A database file (.sql), File: %s\n" % (ff))
		

		


	#WebApp specific - PHP, Javascript, VBScript, Lua
	#PHP untrusted user input functions
	if php_fn in ff:
		read_search_case_kw(ff, php_server_func, trommel_output)
		read_search_case_kw(ff, php_get_func, trommel_output)
		read_search_case_kw(ff, php_post_func, trommel_output)
		read_search_case_kw(ff, php_request_func, trommel_output)
		read_search_case_kw(ff, php_files_func, trommel_output)
		read_search_case_kw(ff, php_cookie_func, trommel_output)	
		read_search_case_kw(ff, php_split_kw, trommel_output)

		#PHP SQL related results
		read_search_case_kw(ff, php_sql_com1, trommel_output)
		read_search_case_kw(ff, php_sql_com2, trommel_output)
		read_search_case_kw(ff, php_sql_com3, trommel_output)

		#PHP shell injection function.
		read_search_kw(ff, php_shellexec_func, trommel_output)
		read_search_kw(ff, php_exec_func, trommel_output)
		read_search_kw(ff, php_passthru_func, trommel_output)
		read_search_kw(ff, php_system_func, trommel_output)

	#Javascript	functions of interest
	try:
		with open (ff, 'r') as js_file:
			text = js_file.read()
			hits = re.findall(script_word, text, re.S)
			if hits:
				read_search_kw(ff, alert_kw, trommel_output)
				read_search_kw(ff, src_kw, trommel_output)
				read_search_kw(ff, script_kw, trommel_output)
				read_search_kw(ff, script1_kw, trommel_output)
				read_search_case_kw(ff, doc_url_kw, trommel_output)
				read_search_case_kw(ff, doc_loc_kw, trommel_output)
				read_search_case_kw(ff, doc_referrer_kw, trommel_output)
				read_search_case_kw(ff, win_loc_kw, trommel_output)
				read_search_case_kw(ff, doc_cookies_kw, trommel_output)
				read_search_case_kw(ff, eval_kw, trommel_output)
				read_search_case_kw(ff, settimeout_kw, trommel_output)
				read_search_case_kw(ff, setinterval_kw, trommel_output)
				read_search_case_kw(ff, loc_assign_kw, trommel_output)
				read_search_case_kw(ff, nav_referrer_kw, trommel_output)
				read_search_case_kw(ff, win_name_kw, trommel_output)
	except IOError:
		pass

	#VBScript presence
	read_search_kw(ff, vbscript_kw, trommel_output)

	#Lua script functions of interest
	if lua_fn in ff:
		read_search_lua_kw(ff, lua_get, trommel_output)
		read_search_lua_kw(ff, lua_cgi_query, trommel_output)
		read_search_lua_kw(ff, lua_cgi_post, trommel_output)
		read_search_lua_kw(ff, lua_print, trommel_output)
		read_search_lua_kw(ff, lua_iowrite, trommel_output)
		read_search_lua_kw(ff, lua_ioopen, trommel_output)
		read_search_lua_kw(ff, lua_cgi_put, trommel_output)
		read_search_lua_kw(ff, lua_cgi_handhelp, trommel_output)
		read_search_lua_kw(ff, lua_execute, trommel_output)
		read_search_lua_kw(ff, lua_strcat, trommel_output)
		read_search_lua_kw(ff, lua_htmlentities, trommel_output)
		read_search_lua_kw(ff, lua_htmlspecialchars, trommel_output)
		read_search_lua_kw(ff, lua_htmlescape, trommel_output)
		read_search_lua_kw(ff, lua_htmlentitydecode, trommel_output)
		read_search_lua_kw(ff, lua_htmlunescape, trommel_output)
		read_search_lua_kw(ff, lua_iopopen, trommel_output)
		read_search_lua_kw(ff, lua_escapeshellarg, trommel_output)
		read_search_lua_kw(ff, lua_unescapeshellarg, trommel_output)
		read_search_lua_kw(ff, lua_escapeshellcmd, trommel_output)
		read_search_lua_kw(ff, lua_unescapeshellcmd, trommel_output)
		read_search_lua_kw(ff, lua_fhupo, trommel_output)
		read_search_lua_kw(ff, lua_fhpo, trommel_output)
		read_search_lua_kw(ff, lua_fsppo, trommel_output)
		read_search_lua_kw(ff, lua_ntopreaddir, trommel_output)


	#Search library base name against CVE Community Edition Database
	if lib_file in ff:
		base_name = re.search(r'lib[a-zA-Z]{1,20}', names, re.S)
		if base_name is not None:
			m = base_name.group()
			mm = m + ".so"
			text_search(mm, trommel_output)


	#Search specific content related decompress and decompiled Android APKs
	#APK App permisssion					
	try:
		with open (ff, 'r') as file:
			text = file.read()
			hits = re.findall(perm, text, re.S)
			for h in hits:
				trommel_output.write("Found a file that contains a Android permission: %s : %s\n" % (ff, h))
	except IOError:
		pass

	#APK App package name
	try:
		with open (ff, 'r') as file:
			text = file.read()
			hits = re.findall(pkg_name, text, re.S)
			for h in hits:
				trommel_output.write("Found a file that contains a Android package/app name: %s : %s\n" % (ff, h))
	except IOError:
		pass


	