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
#DisableRootLogin
disablerootlogin() {
# Check if Perfectrootserver Script is installed
if [ ! -f /root/credentials.txt ]; then
    echo "${error} Can not find file /root/credentials.txt!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 0
fi
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

sed 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config >>"$main_log" 2>>"$err_log"
sed -i "/LoginGraceTime 30/ s//\n AllowGroups $SSHUSER \n/" /etc/ssh/sshd_config >>"$main_log" 2>>"$err_log"

groupadd --system sshusers >>"$main_log" 2>>"$err_log"

#  --disabled-password yes or no for ssh login
adduser $SSHUSER --gecos "" --no-create-home --home /root/ --ingroup sshusers >>"$main_log" 2>>"$err_log"
echo $SSHUSER:$USERPASS | chpasswd >>"$main_log" 2>>"$err_log"

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
