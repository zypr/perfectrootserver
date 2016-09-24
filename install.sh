#!/bin/bash
# The perfect rootserver
# by Zypr
# https://github.com/zypr/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow
# Compatible with Debian 8.x (jessie)

source sources/script/checksystem.sh
source sources/script/checkconfig.sh
source sources/script/logininformation.sh
source sources/script/instructions.sh


source sources/script/system.sh
source sources/script/sslssh.sh
source sources/script/nginx.sh
source sources/script/mailserver.sh
source sources/script/firewall.sh


source sources/addons/ajenti.sh
source sources/addons/teamspeak3.sh
source sources/addons/minecraft.sh
source sources/addons/vsftpd.sh
source sources/addons/openvpn.sh

#source sources/addons/disablerootlogin.sh
#source sources/addons/addnewsite.sh
#source sources/addons/addnewmysqluser.sh

checksystem
checkconfig
system
openssl
nginx
mailserver
firewall
addoninformation

ajenti
teamspeak3
minecraft
vsftpd
openvpn
#disablerootlogin
#addnewsite

logininformation
instructions
