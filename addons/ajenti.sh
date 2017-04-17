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



ajenti() {
# Check if Perfectrootserver Script is installed
if [ ! -f /root/credentials.txt ]; then
    echo "${error} Can not find file /root/credentials.txt!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 0
fi

# Ajenti
if [ ${USE_AJENTI} == '1' ] && [ ${USE_VALID_SSL} == '1' ]; then
	echo "${info} Installing Ajenti..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	wget -q http://repo.ajenti.org/debian/key -O- | apt-key add - >>"$main_log" 2>>"$err_log"
	echo "deb http://repo.ajenti.org/debian main main debian" >> /etc/apt/sources.list
	apt-get -qq update && apt-get -q -y --force-yes install ajenti >>"$main_log" 2>>"$err_log"

#gevent workaround -> https://github.com/ajenti/ajenti/issues/702 https://github.com/ajenti/ajenti/issues/870
	sudo easy_install -U gevent==1.1b4 >>"$main_log" 2>>"$err_log"

#Use Lets Encrypt Cert for Ajenti
	cat /etc/letsencrypt/live/${MYDOMAIN}/fullchain.pem /etc/letsencrypt/live/${MYDOMAIN}/privkey.pem > /etc/letsencrypt/live/${MYDOMAIN}/${MYDOMAIN}-combined.pem
	ln -s /etc/letsencrypt/live/${MYDOMAIN}/${MYDOMAIN}-combined.pem /etc/nginx/ssl/${MYDOMAIN}-combined.pem
	sed -i 's~\("certificate_path": "/etc/\)ajenti/ajenti.pem"~\1nginx/ssl/'${MYDOMAIN}'-combined.pem"~' /etc/ajenti/config.json
	ajentihash=$(python -c "from passlib.hash import sha512_crypt; print sha512_crypt.encrypt('${AJENTI_PASS}')")
	sed -i.bak 's/^[[:space:]]*"password.*$/"password" : "sha512|'"${ajentihash//\//\\/}"'",/' /etc/ajenti/config.json
	service ajenti restart

AJENTI_PORTS="8000"
	sed -i "/\<$AJENTI_PORTS\>/ "\!"s/^OPEN_TCP=\"/&$AJENTI_PORTS, /" /etc/arno-iptables-firewall/firewall.conf
sleep 1
	#If the Addon runs in Standalone we need that
	systemctl force-reload arno-iptables-firewall.service >>"$main_log" 2>>"$err_log"

	echo "--------------------------------------------" >> ~/addoninformation.txt
	echo "Ajenti" >> ~/addoninformation.txt
	echo "--------------------------------------------" >> ~/addoninformation.txt
	echo "https://${MYDOMAIN}:8000" >> ~/addoninformation.txt
	echo "login: root" >> ~/credentials.txt
	echo "password = ${AJENTI_PASS}" >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt

else
	if [ ${USE_AJENTI} == '1' ] && [ ${USE_VALID_SSL} == '0' ]; then
		echo "${warn} USE_VALID_SSL is disabled, skipping Ajenti installation!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	fi
fi
}

source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg
