ajenti() {

source ~/userconfig.cfg

# Ajenti
if [ ${USE_AJENTI} == '1' ] && [ ${USE_VALID_SSL} == '1' ]; then
	echo "${info} Installing Ajenti..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	wget -q http://repo.ajenti.org/debian/key -O- | apt-key add - >/dev/null 2>&1
	echo "deb http://repo.ajenti.org/debian main main debian" >> /etc/apt/sources.list
	apt-get -qq update && apt-get -q -y --force-yes install ajenti >/dev/null 2>&1
	
#gevent workaround -> https://github.com/ajenti/ajenti/issues/702 https://github.com/ajenti/ajenti/issues/870
	apt-get -q -y --force-yes install python-setuptools python-dev build-essential >/dev/null 2>&1
	sudo easy_install -U gevent==1.1b4 >/dev/null 2>&1
	
#Use Lets Encrypt Cert for Ajenti
	cat /etc/letsencrypt/live/${MYDOMAIN}/fullchain.pem /etc/letsencrypt/live/${MYDOMAIN}/privkey.pem > /etc/letsencrypt/live/${MYDOMAIN}/${MYDOMAIN}-combined.pem
	ln -s /etc/letsencrypt/live/${MYDOMAIN}/${MYDOMAIN}-combined.pem /etc/nginx/ssl/${MYDOMAIN}-combined.pem
	sed -i 's~\("certificate_path": "/etc/\)ajenti/ajenti.pem"~\1nginx/ssl/'${MYDOMAIN}'-combined.pem"~' /etc/ajenti/config.json
	ajentihash=$(python -c "from passlib.hash import sha512_crypt; print sha512_crypt.encrypt('${AJENTI_PASS}')")
	sed -i.bak 's/^[[:space:]]*"password.*$/"password" : "sha512|'"${ajentihash//\//\\/}"'",/' /etc/ajenti/config.json
	service ajenti restart
	
	AJENTI_PORTS="8000"
	sed -i "/^OPEN_TCP=\"/ s//&$AJENTI_PORTS,/" /etc/arno-iptables-firewall/firewall.conf >/dev/null 2>&1
	
	#AJENTI UDP credentials.txt All Ports are open output is wrong
	
	
else 
	if [ ${USE_AJENTI} == '1' ] && [ ${USE_VALID_SSL} == '0' ]; then
		echo "${warn} USE_VALID_SSL is disabled, skipping Ajenti installation!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'	
	fi	
	
echo "--------------------------------------------" >> ~/credentials.txt
	echo "Ajenti" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "https://${MYDOMAIN}:8000" >> ~/credentials.txt
	echo "login: root" >> ~/credentials.txt
	echo "password = ${AJENTI_PASS}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt	
fi
}
