#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

logininformation() {

touch ~/addoninformation.txt
echo "///////////////////////////////////////////////////////////////////////////" >> ~/addoninformation.txt
echo "// Passwords, Usernames, Databases" >> ~/addoninformation.txt
echo "///////////////////////////////////////////////////////////////////////////" >> ~/addoninformation.txt
echo "" >> ~/addoninformation.txt
echo "_______________________________________________________________________________________" >> ~/addoninformation.txt

touch ~/credentials.txt
echo "///////////////////////////////////////////////////////////////////////////" >> ~/credentials.txt
echo "// Passwords, Usernames, Databases" >> ~/credentials.txt
echo "///////////////////////////////////////////////////////////////////////////" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "_______________________________________________________________________________________" >> ~/credentials.txt
echo "### MYSQL & WEB" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt
echo "MySQL root" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt
echo "hostname = ${MYSQL_HOSTNAME}" >> ~/credentials.txt
echo "username = root" >> ~/credentials.txt
echo "password = ${MYSQL_ROOT_PASS}" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "" >> ~/credentials.txt
if [ ${USE_PMA} == '1' ]; then
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "phpMyAdmin database" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "database = ${MYSQL_PMADB_NAME}" >> ~/credentials.txt
	echo "username = ${MYSQL_PMADB_USER}" >> ~/credentials.txt
	echo "password = ${MYSQL_PMADB_PASS}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "phpMyAdmin web" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "username = ${PMA_HTTPAUTH_USER}" >> ~/credentials.txt
	echo "password = ${PMA_HTTPAUTH_PASS}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "blowfish = ${PMA_BFSECURE_PASS}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
fi
echo "_______________________________________________________________________________________" >> ~/credentials.txt
echo "## SSH" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "port       = ${SSH_PORT}" >> ~/credentials.txt
echo "password   = ${SSH_PASS}" >> ~/credentials.txt
echo "privatekey = check /root/ssh_privatekey.txt" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "_______________________________________________________________________________________" >> ~/credentials.txt
echo "## URLs" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt
echo "your domain" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt
echo "https://${MYDOMAIN}" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "" >> ~/credentials.txt
if [ ${USE_PMA} == '1' ]; then
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "phpMyAdmin" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "https://${MYDOMAIN}/pma" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
fi
echo "_______________________________________________________________________________________" >> ~/credentials.txt
echo "## SYSTEM INFORMATION" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt
echo "open ports" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt

echo "TCP = 80 (HTTP), 443 (HTTPS), ${SSH_PORT} (SSH)" >> ~/credentials.txt
echo "UDP = All ports are closed" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "" >> ~/credentials.txt


echo "You can add additional ports, just edit \"/etc/arno-iptables-firewall/firewall.conf\" (lines 1164 & 1165)" >> ~/credentials.txt
echo "and restart your firewall -> \"systemctl force-reload arno-iptables-firewall\"" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "_______________________________________________________________________________________" >> ~/credentials.txt
echo "${ok} Done! The credentials are located in the file $(textb /root/credentials.txt)!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
echo "${ok} Done! The add on credentials are located in the file $(textb /root/configs/addoninformation.txt)!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
}
source ~/configs/userconfig.cfg