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

fail2ban() {
mkdir -p ~/sources/${FAIL2BAN_VERSION}/ >>"$main_log" 2>>"$err_log"
cd ~/sources/${FAIL2BAN_VERSION}/ >>"$main_log" 2>>"$err_log"
wget https://github.com/fail2ban/fail2ban/archive/${FAIL2BAN_VERSION}.tar.gz >>"$main_log" 2>>"$err_log"

tar -xzf ${FAIL2BAN_VERSION}.tar.gz >>"$main_log" 2>>"$err_log"
cd fail2ban-${FAIL2BAN_VERSION}
python setup.py -q install >>"$main_log" 2>>"$err_log"

mkdir -p /var/run/fail2ban >>"$main_log" 2>>"$err_log"
cp ~/files/fail2ban/conf/fail2ban.service /etc/systemd/system/fail2ban.service >>"$main_log" 2>>"$err_log"
[[ -f /lib/systemd/system/fail2ban.service ]] && rm /lib/systemd/system/fail2ban.service
if [[ ! -f /var/log/mail.warn ]]; then
	touch /var/log/mail.warn
fi
if [[ ! -f /etc/fail2ban/jail.local ]]; then
	cp ~/files/fail2ban/conf/jail.local /etc/fail2ban/jail.local
fi
cp ~/files/fail2ban/conf/jail.d/*.conf /etc/fail2ban/jail.d/
#rm -rf ~/sources/files/fail2ban/inst/${FAIL2BAN_VERSION}
[[ -z $(grep fail2ban /etc/rc.local) ]] && sed -i '/^exit 0/i\test -d /var/run/fail2ban || install -m 755 -d /var/run/fail2ban/' /etc/rc.local
mkdir -p /var/run/fail2ban/
service fail2ban start >>"$main_log" 2>>"$err_log"
systemctl -q daemon-reload >>"$main_log" 2>>"$err_log"
systemctl -q enable fail2ban >>"$main_log" 2>>"$err_log"
}
source ~/configs/versions.cfg

