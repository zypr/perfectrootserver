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


#DisableRootLogin
disablerootlogin() {
	
if [ ${DISABLE_ROOT_LOGIN} == '1' ]; then

echo
echo
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo "$(date +"[%T]") |  $(textb Disable Root Login in Perfect RootServer Script) "
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo
echo "$(date +"[%T]") | ${info} Welcome to the Perfect Rootserver Addon installation!"
echo "$(date +"[%T]") | ${info} Please wait while the installer is preparing for the first use..."

#creating a strong password!
USERPASS=$(openssl rand -base64 30  |  sed 's|/|_|')
	
sed 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config >>/root/stderror.log 2>&1  >> /root/stdout.log
sed -i "/LoginGraceTime 30/ s//\n AllowGroups $SSHUSER \n/" /etc/ssh/sshd_config >>/root/stderror.log 2>&1  >> /root/stdout.log

groupadd --system sshusers >>/root/stderror.log 2>&1  >> /root/stdout.log

#  --disabled-password yes or no for ssh login
adduser $SSHUSER --gecos "" --no-create-home --home /root/ --ingroup sshusers >>/root/stderror.log 2>&1  >> /root/stdout.log
echo $SSHUSER:$USERPASS | chpasswd >>/root/stderror.log 2>&1  >> /root/stdout.log
	
#restart
service ssh restart

echo "--------------------------------------------" >> ~/addoninformation.txt
	echo "DisableRootLogin" >> ~/addoninformation.txt
	echo "--------------------------------------------" >> ~/addoninformation.txt
	echo Your SSH USER: $SSHUSER >> ~/addoninformation.txt
	echo Your SSH USER Password: $USERPASS >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt >> ~/addoninformation.txt
fi
}

source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg