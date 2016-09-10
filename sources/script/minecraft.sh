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
sudo -u  minecraft wget -q https://s3.amazonaws.com/Minecraft.Download/versions/1.10.2/minecraft_server.1.10.2.jar

echo "${info} Create Config..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
echo "#!/bin/bash
cd /usr/local/minecraft/
java -Xmx1024M -Xms1024M -jar minecraft_server.*.*.*.jar nogui
" >> /usr/local/minecraft/run-minecraft-server.sh

chmod +x run-minecraft-server.sh
sudo -u  minecraft /usr/local/minecraft/run-minecraft-server.sh

sed -i 's|eula=false"|eula=true"|' /usr/local/minecraft/eula.txt
