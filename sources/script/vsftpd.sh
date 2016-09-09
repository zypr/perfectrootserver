# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow and https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

vsftpd() {

source ~/addonconfig.cfg

# VSFTPD
if [ ${USE_VSFTPD} == '1' ]; then
	echo "${info} VSFTPD..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	#Host IP check
	ip=$(hostname -I)
	#creating a strong password!
	userpass=$(openssl rand -base64 30  |  sed 's|/|_|')
	cd >/dev/null 2>&1
	apt-get -y install vsftpd >/dev/null 2>&1
	openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem -subj "/C=/ST=/L=/O=/OU=/CN=*.$MYDOMAIN" >/dev/null 2>&1
	rm -rf /etc/vsftpd.conf >/dev/null 2>&1
				
	cat > /etc/vsftpd.conf <<END
# Run standalone vs. from an inetd – start daemon from an initscript
listen=YES
#
# Disallow anonymous FTP. 
anonymous_enable=NO
#
# Allow local users to log in.
local_enable=YES
#
# Allow per-user configuration for local users.
user_config_dir=/etc/vsftpd_user_conf
#
# Enable FTP write commands – controlled with cmds_allowed list.
write_enable=YES
#
# Don’t allow recursive listing – prevents excessive I/O usage.
ls_recurse_enable=NO
#
# Activate directory messages - messages given to remote users when they
# go into a certain directory.
dirmessage_enable=YES
#
# Display directory listings with the time in  your  local  time  zone.
# Default is to display GMT.
use_localtime=YES
#
# Activate logging of uploads/downloads, but not in xferlog format
xferlog_enable=YES
xferlog_std_format=NO
log_ftp_protocol=YES
#
# Make sure PORT transfer connections originate from port 20 (ftp-data).
connect_from_port_20=YES
#
# Uploaded files are owned by the uploader.
chown_uploads=NO
#
# Default log – enable and change for custom location/name
xferlog_file=/var/log/vsftpd.log
#
# You may change the default value for timing out an idle session.
idle_session_timeout=600
#
# You may change the default value for timing out a data connection.
data_connection_timeout=120
#
# Don’t allow ASCII mangling on files when in ASCII mode.
# ASCII mangling is a horrible feature of the protocol.
ascii_upload_enable=NO
ascii_download_enable=NO
#
# Customize the login banner string:
ftpd_banner=Welcome to our FTP service.
#
# Customization
#
# Some of vsftpd's default settings don't fit the filesystem layout.
#
# Empty directory which isn’t writable by the ftp user. This directory is used
# as a secure chroot() jail when vsftpd does not require filesystem access.
secure_chroot_dir=/var/run/vsftpd/empty
#
# This string is the name of the PAM service vsftpd will use.
pam_service_name=vsftpd
#
# Location of the RSA certificate to use for SSL encrypted connections.
rsa_cert_file=/etc/ssl/private/vsftpd.pem
#
# Allow PASV (passive ftp)
pasv_enable=YES
pasv_min_port=12000
pasv_max_port=12500
port_enable=YES
# enter your IP address on the line below – example: 184.37.445.210
pasv_address=$IP
pasv_addr_resolve=NO
#####################################################
listen_ipv6=NO
nopriv_user=www-data
chroot_local_user=YES
allow_writeable_chroot=YES
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
ssl_enable=YES
utf8_filesystem=YES
# Disable SSL session reuse (required by WinSCP)
require_ssl_reuse=NO
# Select which SSL ciphers vsftpd will allow for encrypted SSL connections (required by FileZilla)
ssl_ciphers=HIGH
######################################################
#
# set chmod correctly for apache, see
# http://en.gentoowiki.com/wiki/Vsftpd
file_open_mode=0666
# Default umask for local users is 077 – replace with 022
local_umask=0022
#
END
	groupadd wwwftp >/dev/null 2>&1
	adduser $FTP_USERNAME --gecos "" --no-create-home --disabled-password --home /etc/nginx/html --ingroup wwwftp >/dev/null 2>&1
	echo $FTP_USERNAME:$userpass | chpasswd >/dev/null 2>&1
	#edit file for user
	#-----------------------------------
	#delete the last line 
	sed '$d' /etc/passwd >/dev/null 2>&1
	#and paste the new content
	echo "${FTP_USERNAME}:x:1001:1001:My Website,,,:/etc/nginx/html:/bin/false/" >> /etc/passwd >/dev/null 2>&1
	# set chown for both groups
	chown -R www-data:wwwftp /etc/nginx/html >/dev/null 2>&1
	chmod -R 775 /etc/nginx/html >/dev/null 2>&1
	#disable pam_shell
	rm -rf /etc/pam.d/vsftpd >/dev/null 2>&1
	cat > /etc/pam.d/vsftpd <<END
# Standard behaviour for ftpd(8).
auth	required	pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed
# Note: vsftpd handles anonymous logins on its own. Do not enable pam_ftp.so.
# Standard pam includes
@include common-account
@include common-session
@include common-auth
#auth	required	pam_shells.so
END
	#restart some services
	systemctl -q restart vsftpd >/dev/null 2>&1
	systemctl -q restart sshd >/dev/null 2>&1
	# Save the Login to a nice file
cat > /root/VSFTP_LOGINDATA.txt <<END
-------------------------------------------------------
Your Serverip: $ip
Your Port: $FTP_PORT
Your username: $FTP_USERNAME
Your password: $userpass
-------------------------------------------------------
END
sed -i "/\<$FTP_PORT\>/ "\!"s/^OPEN_TCP=\"/&$FTP_PORT,/" /etc/arno-iptables-firewall/firewall.conf
sleep 1
	echo "--------------------------------------------" >> ~/addoninformation.txt
	echo "VSFTP" >> ~/addoninformation.txt
	echo "--------------------------------------------" >> ~/addoninformation.txt
	cat /root/VSFTP_LOGINDATA.txt >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt
fi
}
