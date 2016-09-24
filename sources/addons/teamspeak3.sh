# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow and https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

teamspeak3() {

source ~/addonconfig.cfg

# Teamspeak 3
if [ ${USE_TEAMSPEAK} == '1' ]; then
	echo "${info} Installing Teamspeak 3..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	adduser ts3user --gecos "" --no-create-home --disabled-password >/dev/null 2>&1
	mkdir /usr/local/ts3user
	chown ts3user /usr/local/ts3user
	cd /usr/local/ts3user
	wget -q http://dl.4players.de/ts/releases/${TEAMSPEAK_VERSION}/teamspeak3-server_linux_amd64-${TEAMSPEAK_VERSION}.tar.bz2
	tar -xjf teamspeak3-server_linux*.tar.bz2 >/dev/null 2>&1
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
	/etc/init.d/ts3server start >/dev/null 2>&1
	
TS3_PORTS_TCP="2008, 10011, 30033, 41144"
TS3_PORTS_UDP="2010, 9987"

	sed -i "/\<$TS3_PORTS_TCP\>/ "\!"s/^OPEN_TCP=\"/&$TS3_PORTS_TCP, /" /etc/arno-iptables-firewall/firewall.conf
	sed -i "/\<$TS3_PORTS_UDP\>/ "\!"s/^OPEN_UDP=\"/&$TS3_PORTS_UDP, /" /etc/arno-iptables-firewall/firewall.conf
	sed -i '1171s/, "/"/' /etc/arno-iptables-firewall/firewall.conf
sleep 1
	#If the Addon runs in Standalone we need that
	systemctl force-reload arno-iptables-firewall.service >/dev/null 2>&1
	
	echo "--------------------------------------------" >> ~/addoninformation.txt
	echo "Teamspeak 3" >> ~/addoninformation.txt
	echo "--------------------------------------------" >> ~/addoninformation.txt
	cat /usr/local/ts3user/ts3serverdata.txt >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt
fi
}
