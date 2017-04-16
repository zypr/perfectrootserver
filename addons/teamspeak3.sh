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
teamspeak3() {
# Check if Perfectrootserver Script is installed
if [ ! -f /root/credentials.txt ]; then
    echo "${error} Can not find file /root/credentials.txt!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 0
fi

# Teamspeak 3
if [ ${USE_TEAMSPEAK} == '1' ]; then
	echo "${info} Installing Teamspeak 3..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	adduser ts3user --gecos "" --no-create-home --disabled-password >>/root/stderror.log 2>&1  >> /root/stdout.log
	mkdir /usr/local/ts3user
	chown ts3user /usr/local/ts3user
	cd /usr/local/ts3user
	wget -q http://dl.4players.de/ts/releases/${TEAMSPEAK_VERSION}/teamspeak3-server_linux_amd64-${TEAMSPEAK_VERSION}.tar.bz2
	tar -xjf teamspeak3-server_linux*.tar.bz2 >>/root/stderror.log 2>&1  >> /root/stdout.log
	mkdir -p /usr/local/ts3user/ts3server/ && cp -r -u /usr/local/ts3user/teamspeak3-server_linux_amd64/* /usr/local/ts3user/ts3server/
	rm -r /usr/local/ts3user/teamspeak3-server_linux_amd64/
	chown -R ts3user /usr/local/ts3user/ts3server
	timeout 10 sudo -u  ts3user /usr/local/ts3user/ts3server/ts3server_minimal_runscript.sh > ts3serverdata.txt
echo "#! /bin/sh
### BEGIN INIT INFO
# Provides:         ts3server
# Required-Start: 	"'$local_fs $network'"
# Required-Stop:	"'$local_fs $network'"
# Default-Start: 	2 3 4 5
# Default-Stop: 	0 1 6
# Description:      TS 3 Server
### END INIT INFO
case "'"$1"'" in
start)
echo "'"Starte Teamspeak 3 Server ... "'"
su ts3user -c "'"/usr/local/ts3user/ts3server/ts3server_startscript.sh start"'"
;;
stop)
echo "'"Beende Teamspeak 3 Server ..."'"
su ts3user -c "'"/usr/local/ts3user/ts3server/ts3server_startscript.sh stop"'"
;;
*)
echo "'"Sie können folgende Befehle nutzen: TS3 starten: /etc/init.d/ts3server start TS3 stoppen: /etc/init.d/ts3server stop"'" > /usr/local/ts3user/ts3server/ts3befehle.txt
exit 1
;;
esac
exit 0" >> /etc/init.d/ts3server
	chmod 755 /etc/init.d/ts3server
	update-rc.d ts3server defaults
	/etc/init.d/ts3server start >>/root/stderror.log 2>&1  >> /root/stdout.log

TS3_PORTS_TCP="2008, 10011, 30033, 41144"
TS3_PORTS_UDP="2010, 9987"

	sed -i "/\<$TS3_PORTS_TCP\>/ "\!"s/^OPEN_TCP=\"/&$TS3_PORTS_TCP, /" /etc/arno-iptables-firewall/firewall.conf
	sed -i "/\<$TS3_PORTS_UDP\>/ "\!"s/^OPEN_UDP=\"/&$TS3_PORTS_UDP, /" /etc/arno-iptables-firewall/firewall.conf
	sed -i '1171s/, "/"/' /etc/arno-iptables-firewall/firewall.conf
sleep 1
	#If the Addon runs in Standalone we need that
	systemctl force-reload arno-iptables-firewall.service >>/root/stderror.log 2>&1  >> /root/stdout.log

	echo "--------------------------------------------" >> ~/addoninformation.txt
	echo "Teamspeak 3" >> ~/addoninformation.txt
	echo "--------------------------------------------" >> ~/addoninformation.txt
	cat /usr/local/ts3user/ts3serverdata.txt >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt
fi
}

source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg
