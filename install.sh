#!/bin/bash
# The perfect server
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectserver
# Big thanks to https://github.com/zypr/perfectserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

source script/security.sh
source script/functions.sh
source script/checksystem.sh
source script/checkconfig.sh
source script/addoncheckconfig.sh
source script/logininformation.sh
source script/instructions.sh

source script/bash.sh
source script/system.sh
source script/mariadb.sh
if [ ${USE_PHP7} == '1' ] && [ ${USE_PHP5} == '0' ]; then
		source script/php7.sh
fi

if [ ${USE_PHP7} == '0' ] && [ ${USE_PHP5} == '1' ]; then
		source script/php.sh
fi


source script/ssl.sh
source script/ssh.sh
source script/publickey.sh
source script/nginx.sh
source script/fail2ban.sh
source script/phpmyadmin.sh

source script/dovecot.sh
source script/postfix.sh
source script/roundcube.sh
source script/vimbadmin.sh
source script/mailfilter.sh

source script/firewall.sh

source addons/ajenti.sh
source addons/teamspeak3.sh
source addons/minecraft.sh
source addons/vsftpd.sh

#source addons/openvpn.sh
#source addons/disablelogin.sh
#source addons/addnewsite.sh
#source addons/addnewmysqluser.sh


createpw
checksystem
checkconfig
addoncheckconfig
system
mariadb
bashinstall
ssl
ssh
nginx
if [ ${USE_PHP7} == '1' ] && [ ${USE_PHP5} == '0' ]; then
		php7
fi

if [ ${USE_PHP7} == '0' ] && [ ${USE_PHP5} == '1' ]; then
		php
fi

dovecot
postfix
mailfilter
roundcube
vimbadmin


firewall
fail2ban

phpmyadmin
publickey

#Was ist das?
#Kann doch weg..
#addoninformation

ajenti
teamspeak3
minecraft
vsftpd
#openvpn
#disablelogin
#addnewsite

logininformation
instructions
