# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow and https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

minecraft() {

source ~/addonconfig.cfg

# Minecraft
if [ ${USE_MINECRAFT} == '1' ]; then
echo "${info} Installing Minecraft..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

apt-get update -y >/dev/null 2>&1 && apt-get -y upgrade >/dev/null 2>&1
apt-get -y install screen >/dev/null 2>&1
apt-get -y install openjdk-7-jre-headless >/dev/null 2>&1

echo "${info} Creating User..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
adduser minecraft --gecos "" --no-create-home --disabled-password >/dev/null 2>&1

echo "${info} Add Firewall Ports..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
MINECRAFT_PORTS="25565"
       sed -i "/\<$MINECRAFT_PORTS\>/ "\!"s/^OPEN_TCP=\"/&$MINECRAFT_PORTS, /" /etc/arno-iptables-firewall/firewall.conf

sleep 1

#If the Addon runs in Standalone we need that
systemctl force-reload arno-iptables-firewall.service >/dev/null 2>&1

echo "${info} Download..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
mkdir /usr/local/minecraft/
chown minecraft /usr/local/minecraft/
cd /usr/local/minecraft/
sudo -u  minecraft wget -q https://s3.amazonaws.com/Minecraft.Download/versions/${MINECRAFT_VERSION}/minecraft_server.${MINECRAFT_VERSION}.jar

echo "${info} Create Config..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
echo "#!/bin/bash
cd /usr/local/minecraft/
java -Xmx1024M -Xms1024M -jar minecraft_server.*.*.*.jar nogui
" >> /usr/local/minecraft/run-minecraft-server.sh

chmod +x run-minecraft-server.sh
sudo -u  minecraft /usr/local/minecraft/run-minecraft-server.sh >/dev/null 2>&1

sed -i 's|eula=false|eula=true|' /usr/local/minecraft/eula.txt


echo "--------------------------------------------" >> ~/addoninformation.txt
	echo "Minecraft" >> ~/addoninformation.txt
	echo "--------------------------------------------" >> ~/addoninformation.txt
	echo "Zum starten von Minecraft bitte folgenden Befehl verwenden "screen sudo -u  minecraft /usr/local/minecraft/run-minecraft-server.sh" to start >> ~/addoninformation.txt
	echo "Um die Screen Session zu verlassen Ctrl + A dann Ctrl + D drücken" >> ~/addoninformation.txt
	echo "Zum zurück kehren in die Screen Session "screen -r" in der Terminal eingeben" >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt
fi
}
