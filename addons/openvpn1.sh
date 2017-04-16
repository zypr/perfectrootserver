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
openvpn() {
# Check if Perfectrootserver Script is installed
if [ ! -f /root/credentials.txt ]; then
    echo "${error} Can not find file /root/credentials.txt!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 0
fi
#OpenVPN
if [ ${USE_OPENVPN} == '1' ]; then
echo "${info} Installing OPENVPN..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
apt-get -qq update && apt-get -q -y --force-yes install openvpn easy-rsa >>/root/stderror.log 2>&1  >> /root/stdout.log
gunzip -c /usr/share/doc/openvpn/examples/sample-config-files/server.conf.gz > /etc/openvpn/server.conf

sed -i 's|dh dh1024.pem|dh dh2048.pem|' /etc/openvpn/server.conf
sed -i 's|;push "redirect-gateway def1 bypass-dhcp"|push "redirect-gateway def1 bypass-dhcp"|' /etc/openvpn/server.conf
sed -i 's|;push "dhcp-option DNS 208.67.222.222"|push "dhcp-option DNS 208.67.222.222"|' /etc/openvpn/server.conf
sed -i 's|;push "dhcp-option DNS 208.67.220.220"|push "dhcp-option DNS 208.67.220.220"|' /etc/openvpn/server.conf
sed -i 's|;user nobody|user nobody|' /etc/openvpn/server.conf
sed -i 's|;group nogroup|group nogroup|' /etc/openvpn/server.conf

echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf

#firewall port needs to be opened + forward


cp -r /usr/share/easy-rsa/ /etc/openvpn
mkdir /etc/openvpn/easy-rsa/keys

sed -i 's|export KEY_COUNTRY="US"|export KEY_COUNTRY="'${KEY_COUNTRY}'"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_PROVINCE="CA"|export KEY_PROVINCE="'${KEY_PROVINCE}'"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_CITY="SanFrancisco"|export KEY_CITY="'${KEY_CITY}'"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_ORG="Fort-Funston"|export KEY_ORG="Private"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_EMAIL="me@myhost.mydomain"|export KEY_EMAIL="'${KEY_EMAIL}'"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_OU="MyOrganizationalUnit"|export KEY_OU="Private"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_NAME="EasyRSA"|export KEY_NAME="server"|' /etc/openvpn/easy-rsa/vars

openssl dhparam -out /etc/openvpn/dh2048.pem 2048 >>/root/stderror.log 2>&1  >> /root/stdout.log
cd /etc/openvpn/easy-rsa
. ./vars
./clean-all >>/root/stderror.log 2>&1  >> /root/stdout.log
./build-ca
./build-key-server server
cp /etc/openvpn/easy-rsa/keys/{server.crt,server.key,ca.crt} /etc/openvpn
service openvpn start

#Cert + key for Client
./build-key client1
cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf /etc/openvpn/easy-rsa/keys/client.ovpn
sed -i 's|remote my-server-1 1194|remote '${SERVER_IP}' 1194|' /etc/openvpn/easy-rsa/keys/client.ovpn
fi
}

source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg
