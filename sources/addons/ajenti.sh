# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow and https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

ajenti() {

source ~/addonconfig.cfg

# Ajenti
if [ ${USE_AJENTI} == '1' ] && [ ${USE_VALID_SSL} == '1' ]; then
	echo "${info} Installing Ajenti..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	wget -q http://repo.ajenti.org/debian/key -O- | apt-key add - >>/root/stderror.log 2>&1  >> /root/stdout.log
	echo "deb http://repo.ajenti.org/debian main main debian" >> /etc/apt/sources.list
	apt-get -qq update && apt-get -q -y --force-yes install ajenti >>/root/stderror.log 2>&1  >> /root/stdout.log
	
#gevent workaround -> https://github.com/ajenti/ajenti/issues/702 https://github.com/ajenti/ajenti/issues/870
	sudo easy_install -U gevent==1.1b4 >>/root/stderror.log 2>&1  >> /root/stdout.log
	
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
	systemctl force-reload arno-iptables-firewall.service >>/root/stderror.log 2>&1  >> /root/stdout.log
	
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
