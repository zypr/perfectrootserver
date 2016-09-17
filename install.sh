#!/bin/bash
# The perfect rootserver
# by Zypr
# https://github.com/zypr/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow
# Compatible with Debian 8.x (jessie)

source sources/script/checksystem.sh
source sources/script/checkconfig.sh
source sources/script/functions.sh

source sources/script/ajenti.sh
source sources/script/teamspeak3.sh
source sources/script/minecraft.sh
source sources/script/vsftpd.sh

#source sources/script/disablerootlogin.sh
#source sources/script/openvpn.sh
#source sources/script/addnewsite.sh

checksystem
checkconfig
installation
addoninformation

ajenti
teamspeak3
minecraft
vsftpd
#disablerootlogin
#addnewsite
#openvpn

logininformation
instructions
