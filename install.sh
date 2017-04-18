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

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

#Enable debug:
#if [ ${DEBUG_IS_SET} == '1' ]; then
#	set -x
#fi

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
		source script/php5.sh
fi

source script/ssl.sh
source script/ssh.sh
source script/publickey.sh
source script/nginx.sh
source script/fail2ban.sh
source script/phpmyadmin.sh

source script/dovecot.sh
source script/postfix.sh
source script/mailfilter.sh
source script/roundcube.sh
source script/vimbadmin.sh

source script/firewall.sh

#source script/finischer.sh

# Addons
 source addons/ajenti.sh
 source addons/teamspeak3.sh
 source addons/minecraft.sh
 source addons/vsftpdinstall.sh
 source addons/prestashopinstall.sh
 source addons/piwik.sh


# source addons/openvpn.sh
# source addons/disablelogin.sh
# source addons/addnewsite.sh
# source addons/addnewmysqluser.sh


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
		php5
fi

dovecot
postfix
mailfilter
roundcube
vimbadmin

# Special harding
#policydweight

firewall
fail2ban
phpmyadmin
publickey


# Addon functions
ajenti
teamspeak3
minecraft
vsftpd

# untestet
prestashopinstall
piwikinstall

#openvpn
#disablelogin
#addnewsite
#finischer


# Only at End!
logininformation
instructions
