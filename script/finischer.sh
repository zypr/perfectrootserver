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

finischer() {
PATH_TO_VMA_SALTS="/root/vma.txt"
wget "http://${MYDOMAIN}/vma/auth/setup" -O vma.txt 

VMA_SECURITY_SALT=$(grep -Pom 1 "(?<=^securitysalt                       = ).*$" $PATH_TO_VMA_SALTS)
VMA_REMEMBERME_SALT=$(grep -Pom 1 "(?<=^resources.auth.oss.rememberme.salt = ).*$" $PATH_TO_VMA_SALTS)
MAILBOX_PASSWORD_SALT=$(grep -Pom 1 "(?<=^defaults.mailbox.password_salt     = ).*$" $PATH_TO_VMA_SALTS)

echo "VMA_SECURITY_SALT"
echo $VMA_SECURITY_SALT
echo "-----------------------"

echo "VMA_REMEMBERME_SALT"
echo $VMA_REMEMBERME_SALT
echo "-----------------------"

echo "MAILBOX_PASSWORD_SALT"
echo $MAILBOX_PASSWORD_SALT
echo "-----------------------"
}
source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg
