#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

mailcow() {
# Service				Protocol	Port
# Postfix Submission	TCP			587
# Postfix SMTPS			TCP			465
# Postfix SMTP			TCP			25
# Dovecot IMAP			TCP			143
# Dovecot IMAPS			TCP			993
# Dovecot POP3			TCP			110
# Dovecot POP3S			TCP			995
# Dovecot ManageSieve	TCP			4190
# HTTP(S)				TCP			80/443

#Add Ports to Firewall
MAILCOW_PORTS="587,465,25,143,993,110,995,4190"

#remove any web and mail services
apt-get purge exim4* >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

	
	
	
# DNS Records:
# Name						Type		Value					Priority
# sys_hostname.sys_domain	A/AAAA		IPv4/6					any
# sys_domain				MX			sys_hostname.sys_domain	25

# Optional, Autoconfic (like Thunderbird)
# Name					Type	Value	Priority
# autoconfig.sys_domain	A/AAAA	IPv4/6	any
# autodiscover.sys_domain	A/AAAA	IPv4/6	any
	
	
# Please setup a SPF TXT record according to docs you will find on the internet. 
# SPF is broken by design and a huge headache when it comes to forwarding. 
# Try to not push yourself with a -all record but prefer ?all. Also known as "I use SPF but I do not actually care". :-)


mkdir ~/build ; cd ~/build
wget -O - https://github.com/andryyy/mailcow/archive/v0.14.tar.gz | tar xfz -
cd mailcow-*


# Edit nano mailcow.config

# sys_hostname - Hostname without domain
# sys_domain - Domain name. "$sys_hostname.$sys_domain" equals to FQDN.
# ?? Please make sure your FQDN resolves correctly!

# sys_timezone - The timezone must be defined in a valid format (Europe/Berlin, America/New_York etc.)
# use_lets_encrypt - Tries to obtain a certificate from Let's Encrypt CA. If it fails, it can be retried by calling ./install.sh -s. Installs a cronjob to renew the certificate but keeps the same key.
# httpd_platform - Select wether to use Nginx ("nginx") or Apache2 ("apache2"). Nginx is default.
# mailing_platform - Can be "sogo" or "roundcube"
# my_dbhost - ADVANCED: Leave as-is ("localhost") for a local database installation. Anything but "localhost" or "127.0.0.1" is recognized as a remote installation.
# my_usemariadb - Use MariaDB instead of MySQL. Only valid for local databases. Installer stops when MariaDB is detected, but MySQL selected - and vice versa.
# my_mailcowdb, my_mailcowuser, my_mailcowpass - SQL database name, username and password for use with Postfix. You can use the default values.
# my_rcdb, my_rcuser, my_rcpass - SQL database name, username and password for Roundcube. You can use the default values.
# my_rootpw - SQL root password is generated automatically by default. You can define a complex password here if you want to. Set to your current root password to use an existing SQL instance.
# mailcow_admin_user and mailcow_admin_pass - mailcow administrator. Password policy: minimum length 8 chars, must contain uppercase and lowercase letters and at least 2 digits. You can use the default values.
# inst_debug - Sets Bash mode -x
# inst_confirm_proceed - Skip "Press any key to continue" dialogs by setting this to "no"
# Empty configuration values are invalid!

./install.sh
	
	sed -i "s/^OPEN_TCP=\"/&$MAILCOW_PORTS, /" /etc/arno-iptables-firewall/firewall.conf
	sleep 1
	systemctl force-reload arno-iptables-firewall.service
	

}