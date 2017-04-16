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

publickey() {

# Public Key Authentication
echo "${info} Generating key for public key authentication..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
ssh-keygen -f ~/ssh.key -b 3072 -t rsa -N ${SSH_PASS} >>"$main_log" 2>>"$err_log"
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat ~/ssh.key.pub > ~/.ssh/authorized_keys2 && rm ~/ssh.key.pub
chmod 600 ~/.ssh/authorized_keys2
mv ~/ssh.key ~/ssh_privatekey.txt

sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/^UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config
echo -e "" >> /etc/ssh/sshd_config
echo -e "# Disable password based logins" >> /etc/ssh/sshd_config
echo -e "AuthenticationMethods publickey" >> /etc/ssh/sshd_config
systemctl -q restart ssh.service

truncate -s 0 /var/log/daemon.log
truncate -s 0 /var/log/syslog
}
source ~/configs/userconfig.cfg