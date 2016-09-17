logininformation() {

source ~/userconfig.cfg
source ~/addonconfig.cfg

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
if [ ${USE_MAILSERVER} == '1' ]; then
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "mailcow admin" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "username = ${MAILCOW_ADMIN_USER}" >> ~/credentials.txt
	echo "password = ${MAILCOW_ADMIN_PASS}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "mailcow database" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "database = ${MYSQL_MCDB_NAME}" >> ~/credentials.txt
	echo "username = ${MYSQL_MCDB_USER}" >> ~/credentials.txt
	echo "password = ${MYSQL_MCDB_PASS}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
		if [ ${USE_WEBMAIL} == '1' ]; then
			echo "--------------------------------------------" >> ~/credentials.txt
			echo "roundcube database" >> ~/credentials.txt
			echo "--------------------------------------------" >> ~/credentials.txt
			echo "database = ${MYSQL_RCDB_NAME}" >> ~/credentials.txt
			echo "username = ${MYSQL_RCDB_USER}" >> ~/credentials.txt
			echo "password = ${MYSQL_RCDB_PASS}" >> ~/credentials.txt
			echo "" >> ~/credentials.txt
			echo "" >> ~/credentials.txt
		fi
fi
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
echo "port       = ${SSH}" >> ~/credentials.txt
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
if [ ${USE_MAILSERVER} == '1' ]; then
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "mailcow (mailserver admin)" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "https://${MYDOMAIN}/admin" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	if [ ${USE_WEBMAIL} == '1' ]; then
		echo "--------------------------------------------" >> ~/credentials.txt
		echo "roundcube (webmail)" >> ~/credentials.txt
		echo "--------------------------------------------" >> ~/credentials.txt
		echo "https://${MYDOMAIN}/mail" >> ~/credentials.txt
		echo "" >> ~/credentials.txt
		echo "" >> ~/credentials.txt
	fi
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "caldav" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "https://dav.${MYDOMAIN}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "autoconfigure" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "https://autodiscover.${MYDOMAIN}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
fi
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
if [ ${USE_MAILSERVER} == '1' ]; then
		echo "TCP = 25 (SMTP), 80 (HTTP), 110 (POP3), 143(IMAP), 443 (HTTPS), 465 (SMPTS)" >> ~/credentials.txt 
		echo "TCP = 587 (Submission), 993 (IMAPS), 995 (POP3S), ${SSH} (SSH)" >> ~/credentials.txt
		echo "UDP = All ports are closed" >> ~/credentials.txt
		echo "" >> ~/credentials.txt
		echo "" >> ~/credentials.txt
else
		echo "TCP = 80 (HTTP), 443 (HTTPS), ${SSH} (SSH)" >> ~/credentials.txt
		echo "UDP = All ports are closed" >> ~/credentials.txt
		echo "" >> ~/credentials.txt
		echo "" >> ~/credentials.txt
fi

echo "You can add additional ports, just edit \"/etc/arno-iptables-firewall/firewall.conf\" (lines 1164 & 1165)" >> ~/credentials.txt
echo "and restart your firewall -> \"systemctl force-reload arno-iptables-firewall\"" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "_______________________________________________________________________________________" >> ~/credentials.txt
echo "${ok} Done! The credentials are located in the file $(textb /root/credentials.txt)!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
echo "${ok} Done! The add on credentials are located in the file $(textb /root/addoninformation.txt)!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
}
