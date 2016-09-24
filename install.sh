#!/bin/bash
# The perfect rootserver
# by Zypr
# https://github.com/zypr/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow
# Compatible with Debian 8.x (jessie)

source sources/script/system.sh
source sources/script/openssl.sh
source sources/script/nginx.sh
source sources/script/mailserver.sh
source sources/script/firewall.sh



source sources/script/checksystem.sh
source sources/script/checkconfig.sh
source sources/script/logininformation.sh
source sources/script/instructions.sh

source sources/script/ajenti.sh
source sources/script/teamspeak3.sh
source sources/script/minecraft.sh
source sources/script/vsftpd.sh
source sources/script/openvpn.sh

#source sources/script/disablerootlogin.sh
#source sources/script/addnewsite.sh

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
