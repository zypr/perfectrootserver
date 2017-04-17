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
minecraft() {
# Check if Perfectrootserver Script is installed
if [ ! -f /root/credentials.txt ]; then
    echo "${error} Can not find file /root/credentials.txt!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 0
fi

# Minecraft
if [ ${USE_MINECRAFT} == '1' ]; then
echo "${info} Installing Minecraft..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

apt-get update -y >>"$main_log" 2>>"$err_log" && apt-get -y upgrade >>"$main_log" 2>>"$err_log"
apt-get -y install screen >>"$main_log" 2>>"$err_log"
apt-get -y install openjdk-7-jre-headless >>"$main_log" 2>>"$err_log"

adduser minecraft --gecos "" --no-create-home --disabled-password >>"$main_log" 2>>"$err_log"

MINECRAFT_PORTS="25565"
       sed -i "/\<$MINECRAFT_PORTS\>/ "\!"s/^OPEN_TCP=\"/&$MINECRAFT_PORTS, /" /etc/arno-iptables-firewall/firewall.conf

sleep 1

#If the Addon runs in Standalone we need that
systemctl force-reload arno-iptables-firewall.service >>"$main_log" 2>>"$err_log"

mkdir /usr/local/minecraft/
chown minecraft /usr/local/minecraft/
cd /usr/local/minecraft/
sudo -u  minecraft wget -q https://s3.amazonaws.com/Minecraft.Download/versions/${MINECRAFT_VERSION}/minecraft_server.${MINECRAFT_VERSION}.jar

echo "#!/bin/bash
cd /usr/local/minecraft/
java -Xmx1024M -Xms1024M -jar minecraft_server.*.*.*.jar nogui
" >> /usr/local/minecraft/run-minecraft-server.sh

chmod +x run-minecraft-server.sh
sudo -u  minecraft /usr/local/minecraft/run-minecraft-server.sh >>"$main_log" 2>>"$err_log"

sed -i 's|eula=false|eula=true|' /usr/local/minecraft/eula.txt


echo "--------------------------------------------" >> ~/addoninformation.txt
	echo "Minecraft" >> ~/addoninformation.txt
	echo "--------------------------------------------" >> ~/addoninformation.txt
	echo "Zum starten von Minecraft bitte folgenden Befehl verwenden: screen sudo -u  minecraft /usr/local/minecraft/run-minecraft-server.sh" >> ~/addoninformation.txt
	echo "Um die Screen Session zu verlassen: Ctrl + A dann Ctrl + D drücken" >> ~/addoninformation.txt
	echo "Zum zurück kehren in die Screen Session: screen -r in der Terminal eingeben" >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt
fi
}

source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg
