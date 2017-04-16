#!/bin/bash
# The perfect rootserver - Your Webserverinstallation Script!
# by shoujii | BoBBer446 > 2017
#####
# https://github.com/shoujii/perfectrootserver
# Compatible with Debian 8.x (jessie)
# Special thanks to Zypr!
#
	# This program is free software; you can redistribute it and/or modify
    # it under the terms of the GNU General Public License as published by
    # the Free Software Foundation; either version 2 of the License, or
    # (at your option) any later version.

    # This program is distributed in the hope that it will be useful,
    # but WITHOUT ANY WARRANTY; without even the implied warranty of
    # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    # GNU General Public License for more details.

    # You should have received a copy of the GNU General Public License along
    # with this program; if not, write to the Free Software Foundation, Inc.,
    # 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#-------------------------------------------------------------------------------------------------------------
################################################################
################## ATTENTION ! NOT UP TO DATE ##################
################## ATTENTION ! NOT UP TO DATE ##################
############################ 04.2017 ###########################
################################################################
# >>> -.. ---     -. --- -     ..- ... .     .. -     -·-·--<<< #
#----------------------------------------------------------------------#
#-------------------DO NOT EDIT SOMETHING BELOW THIS-------------------#
#----------------------------------------------------------------------#

if [ ${USE_VSFTPD} == '1' ]; then
SSL_PATH_VSFTPD="/etc/ssl/private"
RSA_KEY_VSFTPD="2048"
MYDOMAIN="meinedomain.tld"
FTP_USERNAME="meinftpuser"
FTP_USER_GROUP="wwwftp"


##########################################################################
###################### DO NOT EDIT ANYTHING BELOW! #######################
##########################################################################
#If you change it, the script will broken
PATH_TO_WEBFOLDER="/etc/nginx/html"
# Some nice colors
red() { echo "$(tput setaf 1)$*$(tput setaf 9)"; }
green() { echo "$(tput setaf 2)$*$(tput setaf 9)"; }
yellow() { echo "$(tput setaf 3)$*$(tput setaf 9)"; }
magenta() { echo "$(tput setaf 5)$*$(tput setaf 9)"; }
cyan() { echo "$(tput setaf 6)$*$(tput setaf 9)"; }
textb() { echo $(tput bold)${1}$(tput sgr0); }
greenb() { echo $(tput bold)$(tput setaf 2)${1}$(tput sgr0); }
redb() { echo $(tput bold)$(tput setaf 1)${1}$(tput sgr0); }
yellowb() { echo $(tput bold)$(tput setaf 3)${1}$(tput sgr0); }
pinkb() { echo $(tput bold)$(tput setaf 5)${1}$(tput sgr0); }

# Some nice variables
info="$(textb [INFO] -)"
warn="$(yellowb [WARN] -)"
error="$(redb [ERROR] -)"
fyi="$(pinkb [INFO] -)"
ok="$(greenb [OKAY] -)"

echo
echo
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo "$(date +"[%T]") |  $(textb Very) $(textb Secure) $(textb FTP) $(textb deamon) $(textb vsFTPd)"
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo
echo "$(date +"[%T]") | ${info} Welcome to the Perfect Rootserver installation!"
echo "$(date +"[%T]") | ${info} This script install and FTP Service"
echo "$(date +"[%T]") | ${info} Please wait while the installer is preparing for the first use..."

# --------------------------------------------------------------------------------------------------------------------------------------------------

echo "${info} VSFTPD..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'


#creating a strong password!
userpass=$(openssl rand -base64 30  |  sed 's|/|_|')

#Host IP check
	ip=$(hostname -I)
	# FTP Port
	FTP_PORT="21"
	# pasv_min_port / pasv_max_port
	PASV_PORT="12000:12500"

	FTP_PORT_PASS="26246"


apt-get install -y vsftpd >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

mkdir -p $SSL_PATH_VSFTPD >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
openssl req -x509 -nodes -days 365 -newkey rsa:$RSA_KEY_VSFTPD -keyout $SSL_PATH_VSFTPD/vsftpd.pem -out $SSL_PATH_VSFTPD/vsftpd.pem -subj "/C=/ST=/L=/O=/OU=/CN=*.$MYDOMAIN" >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log


chmod 600 $SSL_PATH_VSFTPD/vsftpd.pem >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
chmod 700 $SSL_PATH_VSFTPD >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log


rm -rf /etc/vsftpd.conf >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
cat > /etc/vsftpd.conf <<END
# Example config file /etc/vsftpd.conf
#
# The default compiled in settings are fairly paranoid. This sample file
# loosens things up a bit, to make the ftp daemon more usable.
# Please see vsftpd.conf.5 for all compiled in defaults.
#
# READ THIS: This example file is NOT an exhaustive list of vsftpd options.
# Please read the vsftpd.conf.5 manual page to get a full idea of vsftpd's
# capabilities.
#
#
# Run standalone?  vsftpd can run either from an inetd or as a standalone
# daemon started from an initscript.
listen=YES
#
# This directive enables listening on IPv6 sockets. By default, listening
# on the IPv6 "any" address (::) will accept connections from both IPv6
# and IPv4 clients. It is not necessary to listen on *both* IPv4 and IPv6
# sockets. If you want that (perhaps because you want to listen on specific
# addresses) then you must run two copies of vsftpd with two configuration
# files.
listen_ipv6=NO
#
# Allow anonymous FTP? (Disabled by default).
anonymous_enable=NO
#
# Uncomment this to allow local users to log in.
local_enable=YES
#
# Uncomment this to enable any form of FTP write command.
write_enable=YES
#
# Default umask for local users is 077. You may wish to change this to 022,
# if your users expect that (022 is used by most other ftpd's)
local_umask=022
#
# Uncomment this to allow the anonymous FTP user to upload files. This only
# has an effect if the above global write enable is activated. Also, you will
# obviously need to create a directory writable by the FTP user.
#anon_upload_enable=YES
#
# Uncomment this if you want the anonymous FTP user to be able to create
# new directories.
#anon_mkdir_write_enable=YES
#
# Activate directory messages - messages given to remote users when they
# go into a certain directory.
dirmessage_enable=YES
#
# If enabled, vsftpd will display directory listings with the time
# in  your  local  time  zone.  The default is to display GMT. The
# times returned by the MDTM FTP command are also affected by this
# option.
use_localtime=YES
#
# Activate logging of uploads/downloads.
xferlog_enable=YES
#
# Make sure PORT transfer connections originate from port 20 (ftp-data).
connect_from_port_20=YES
pasv_min_port=12000
pasv_max_port=12500
#
# If you want, you can arrange for uploaded anonymous files to be owned by
# a different user. Note! Using "root" for uploaded files is not
# recommended!
#chown_uploads=YES
#chown_username=whoever
#
# You may override where the log file goes if you like. The default is shown
# below.
#xferlog_file=/var/log/vsftpd.log
#
# If you want, you can have your log file in standard ftpd xferlog format.
# Note that the default log file location is /var/log/xferlog in this case.
#xferlog_std_format=YES
#
# You may change the default value for timing out an idle session.
#idle_session_timeout=600
#
# You may change the default value for timing out a data connection.
#data_connection_timeout=120
#
# It is recommended that you define on your system a unique user which the
# ftp server can use as a totally isolated and unprivileged user.
#nopriv_user=ftpsecure
#
# Enable this and the server will recognise asynchronous ABOR requests. Not
# recommended for security (the code is non-trivial). Not enabling it,
# however, may confuse older FTP clients.
#async_abor_enable=YES
#
# By default the server will pretend to allow ASCII mode but in fact ignore
# the request. Turn on the below options to have the server actually do ASCII
# mangling on files when in ASCII mode.
# Beware that on some FTP servers, ASCII support allows a denial of service
# attack (DoS) via the command "SIZE /big/file" in ASCII mode. vsftpd
# predicted this attack and has always been safe, reporting the size of the
# raw file.
# ASCII mangling is a horrible feature of the protocol.
#ascii_upload_enable=YES
#ascii_download_enable=YES
#
# You may fully customise the login banner string:
ftpd_banner=Welcome to Yourdeals24 FTP service.
#
# You may specify a file of disallowed anonymous e-mail addresses. Apparently
# useful for combatting certain DoS attacks.
#deny_email_enable=YES
# (default follows)
#banned_email_file=/etc/vsftpd.banned_emails
#
# You may restrict local users to their home directories.  See the FAQ for
# the possible risks in this before using chroot_local_user or
# chroot_list_enable below.
chroot_local_user=YES
allow_writeable_chroot=YES
#
# You may specify an explicit list of local users to chroot() to their home
# directory. If chroot_local_user is YES, then this list becomes a list of
# users to NOT chroot().
# (Warning! chroot'ing can be very dangerous. If using chroot, make sure that
# the user does not have write access to the top level directory within the
# chroot)
#chroot_local_user=YES
#chroot_list_enable=YES
# (default follows)
#chroot_list_file=/etc/vsftpd.chroot_list
#
# You may activate the "-R" option to the builtin ls. This is disabled by
# default to avoid remote users being able to cause excessive I/O on large
# sites. However, some broken FTP clients such as "ncftp" and "mirror" assume
# the presence of the "-R" option, so there is a strong case for enabling it.
#ls_recurse_enable=YES
#
# Customization
#
# Some of vsftpd's settings don't fit the filesystem layout by
# default.
#
# This option should be the name of a directory which is empty.  Also, the
# directory should not be writable by the ftp user. This directory is used
# as a secure chroot() jail at times vsftpd does not require filesystem
# access.
secure_chroot_dir=/var/run/vsftpd/empty
#
# This string is the name of the PAM service vsftpd will use.
pam_service_name=vsftpd
#
# This option specifies the location of the RSA certificate to use for SSL
# encrypted connections.
rsa_cert_file=$SSL_PATH_VSFTPD/vsftpd.pem
rsa_private_key_file=$SSL_PATH_VSFTPD/vsftpd.pem
ssl_enable=YES

# Allow anonymous users to use secured SSL connections
allow_anon_ssl=NO
# All non-anonymous logins are forced to use a secure SSL connection in order to
# send and receive data on data connections.
force_local_data_ssl=YES

# All non-anonymous logins are forced to use a secure SSL connection in order to send the password.
force_local_logins_ssl=YES

# Wenn Sie force_local_logins_ssl=YES und force_local_data_ssl=YES verwenden werden nur TLS Verbindungen erlaubt
# (dies sperrt alle Benutzer alter FTP Clients aus, die keine TLS Unterstützung haben);
# bei Benutzung von force_local_logins_ssl=NO und force_local_data_ssl=NO werden sowohl TLS als auch nicht-TLS Verbindungen erlaubt,
# je nach dem was der FTP Client unterstützt.

# Permit TLS v1 protocol connections. TLS v1 connections are preferred
ssl_tlsv1=YES

# Permit SSL v2 protocol connections. TLS v1 connections are preferred
ssl_sslv2=NO

# permit SSL v3 protocol connections. TLS v1 connections are preferred
ssl_sslv3=NO

# Disable SSL session reuse (required by WinSCP)
require_ssl_reuse=NO

# Select which SSL ciphers vsftpd will allow for encrypted SSL connections (required by FileZilla)
ssl_ciphers=HIGH
END


####################################
##   Generate Group and Username   #
####################################
groupadd $FTP_USER_GROUP >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
adduser $FTP_USERNAME --gecos "" --no-create-home --disabled-password --home $PATH_TO_WEBFOLDER --ingroup $FTP_USER_GROUP >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
echo $FTP_USERNAME:$userpass | chpasswd >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log



#Change the directory owner and group:
chown www-data:www-data $PATH_TO_WEBFOLDER >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
#allow the group to write to the directory with appropriate permissions:
chmod -R 777 $PATH_TO_WEBFOLDER >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
#Add myself to the www-data group:
usermod -a -G www-data $FTP_USERNAME >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log


#usermod -d $PATH_TO_WEBFOLDER/ $FTP_USERNAME >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log


#chown -R www-data:$FTP_USER_GROUP $PATH_TO_WEBFOLDER >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
#chmod -R 775 $PATH_TO_WEBFOLDER >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log




#/etc/passwd
#PATH_TO_WEBFOLDER_ESCAPE="\/etc\/nginx\/html"
#ToDo:
#Fix Escape webfolder
sed -i 's/$FTP_USERNAME:x:1001:5001:,,,:\/etc\/nginx\/html:\/bin\/bash/$FTP_USERNAME:x:1001:5001:,,,:\/etc\/nginx\/html:\/bin\/false/' /etc/passwd >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

#disable pam_shell
	rm -rf /etc/pam.d/vsftpd  >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
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
	service vsftpd start >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
	systemctl -q restart vsftpd >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
	systemctl -q restart sshd >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
	# Save the Login to a nice file
cat > /root/VSFTP_LOGINDATA.txt <<END
-------------------------------------------------------
Your Serverip: $ip
Your Port: $FTP_PORT
Your username: $FTP_USERNAME
Your password: $userpass
-------------------------------------------------------
END
	sed -i "/\<$FTP_PORT\>/ "\!"s/^OPEN_TCP=\"/&$FTP_PORT, /" /etc/arno-iptables-firewall/firewall.conf
	sleep 1
	sed -i "/\<$FTP_PORT_PASS\>/ "\!"s/^OPEN_TCP=\"/&$FTP_PORT_PASS, /" /etc/arno-iptables-firewall/firewall.conf
	sleep 1
	sed -i "/\<$PASV_PORT\>/ "\!"s/^OPEN_TCP=\"/&$PASV_PORT, /" /etc/arno-iptables-firewall/firewall.conf
	sleep 1
	systemctl force-reload arno-iptables-firewall.service

fi
