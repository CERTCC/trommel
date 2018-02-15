passwd = 'passwd'
shadow = 'shadow'
psk_hits = ".psk"
key_pass = "kdb"
k_wallet = "kwallet"
open_vpn = "ovpn"
pgp_log = "pgplog"
pgp_policy = "pgppolicy.xml" 
pgp_prefs = "pgpprefs.xml" 
priv_kw = "private" 
secret_kw = "secret"
javaks = ".jks"
sftpconfig = "sftp-config"
bitcoinfile = "wallet.dat"
pwd_safe = ".psafe3"

auth_key_file = 'authorized_keys'
host_key_file = "host_key"
id_rsa_file = 'id_rsa' 
id_dsa_file = 'id_dsa'
dotPub = ".pub" 
id_ecdsa_file = "id_ecdsa"
id_ed25519_file="id_ed25519"

pem = '.pem'
crt = '.crt'
cer = ".cer"
p7b = '.p7b'
p12 = '.p12'
dotKey = ".key"
p15 =".p15"

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

mime_kw = 'x-executable|x-sharedlib|x-binary|LSB executable|LSB shared object|MSB executable|MSB shared object|archive data|GNU message catalog|tar archive|gzip compressed data|byte-compiled'

private_key_kw = "private.*key"
ipaddr = '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
urls = "(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,8}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,8}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]\.[^\s]{2,8}|www\.[a-zA-Z0-9]\.[^\s]{2,8})"
email = "[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"				
secret_key_kw = "secret.*key"

shell_script = ".sh"

apache_bin = "apache"
lighttpd_bin = "lighttpd"
alphapd_bin = "alphapd"
httpd_bin = "httpd"

config_1 = ".conf"
config_2 = ".cfg"
config_3 = ".ini"

db_file = ".db"
sqlite_file = ".sqlite"
sql_file = ".sql"

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

php_fn = ".php"
php_server_func = "\$_SERVER"
php_get_func = "\$_GET"
php_post_func = "\$_POST"
php_request_func = "\$_REQUEST"
php_files_func = "\$_FILES"
php_cookie_func = "\$_COOKIE"
php_split_kw = "split"
php_sql_com1 = "SELECT"
php_sql_com2 = "FROM"
php_sql_com3 = "WHERE"
php_shellexec_func = "shell_exec"
php_exec_func = "exec"
php_passthru_func = "passthru"
php_system_func = "system"

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

vbscript_kw = "vbscript"

lua_fn = ".lua"
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

lib_file = ".so"

perm = 'android\.permission\.[A-Z_]{1,50}'
pkg_name = 'package="(.*?)"'