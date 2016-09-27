# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow and https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

mailserver() {

if [ ${USE_MAILSERVER} == '1' ]; then
	echo "${info} Installing mailserver..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

genpasswd() {
	count=0
	while [ ${count} -lt 3 ]; do
		pw_valid=$(tr -cd A-Za-z0-9 < /dev/urandom | fold -w24 | head -n1)
		count=$(grep -o "[0-9]" <<< ${pw_valid} | wc -l)
	done
	echo ${pw_valid}
}

checkconfig() {

	pass_count=$(grep -o "[0-9]" <<< ${mailcow_admin_pass} | wc -l)
	pass_chars=$(echo ${mailcow_admin_pass} | egrep "^.{8,255}" | \
	egrep "[ABCDEFGHIJKLMNOPQRSTUVXYZ]" | \
	egrep "[abcdefghijklmnopqrstuvxyz"] | \
	egrep "[0-9]")
	if [[ ${pass_count} -lt 2 || -z ${pass_chars} ]]; then
		echo "$(redb [ERR]) - mailcow administrator password does not meet password policy requirements (8 char., 2 num., UPPER- + lowercase)"
		echo
		exit 1
	fi
	if [[ ${inst_debug} == "yes" ]]; then
		set -x
	fi
}

installtask() {
	case ${1} in
	#environment
			[[ -z $(grep fs.inotify.max_user_instances /etc/sysctl.conf) ]] && echo "fs.inotify.max_user_instances=1024" >> /etc/sysctl.conf
			sysctl -p > /dev/null 2>&1
			if [[ -f /usr/share/zoneinfo/${sys_timezone} ]] ; then
				echo ${sys_timezone} > /etc/timezone
				dpkg-reconfigure -f noninteractive tzdata > /dev/null 2>&1
				if [ "$?" -ne "0" ]; then
					echo "$(redb [ERR]) - Timezone configuration failed: dpkg returned exit code != 0"
					exit 1
				fi
			else
				echo "$(redb [ERR]) - Cannot set your timezone: timezone is unknown"
				exit 1
			fi
			echo "${sys_hostname}.${sys_domain}" > /etc/mailname
			echo "$(textb [INFO]) - Installing prerequisites..."
			apt-get -y update > /dev/null ; apt-get -y install lsb-release whiptail apt-utils ssl-cert > /dev/null 2>&1
			[[ $roundcube == "roundcube" ]] && hashing_method="SHA512-CRYPT" || hashing_method="SSHA256"
			[[ $roundcube == "roundcube" ]] && site_config="_rc" || site_config="_sogo"
			;;
			
			
	#installpackages		
	/usr/sbin/make-ssl-cert generate-default-snakeoil --force-overwrite
	echo "$(textb [INFO]) - Installing packages unattended, please stand by, errors will be reported."
	apt-get -y update >/dev/null
	if [[ ${my_dbhost} == "localhost" || ${my_dbhost} == "127.0.0.1" ]] && [[ ${is_upgradetask} != "yes" ]]; then
		if [[ ${my_usemariadb} == "yes" ]]; then
			DATABASE_BACKEND="mariadb-client mariadb-server"
		else
			DATABASE_BACKEND="mysql-client mysql-server"
		fi
	else
		DATABASE_BACKEND=""
	fi

DEBIAN_FRONTEND=noninteractive apt-get --force-yes -y install dnsutils sudo zip bzip2 unzip unrar-free curl rrdtool mailgraph fcgiwrap spawn-fcgi python-setuptools libmail-spf-perl libmail-dkim-perl file bsd-mailx \
openssl php-auth-sasl php-http-request php-mail php-mail-mime php-mail-mimedecode php-net-dime php-net-smtp \
php-net-socket php-net-url php-pear php-soap php5 php5-cli php5-common php5-curl php5-gd php5-imap \
php5-intl php5-xsl php5-mcrypt php5-mysql libawl-php php5-xmlrpc ${DATABASE_BACKEND} nginx-extras php5-fpm mailutils pyzor razor \
postfix postfix-mysql postfix-pcre postgrey pflogsumm spamassassin spamc sa-compile libdbd-mysql-perl opendkim opendkim-tools clamav-daemon \
python-magic liblockfile-simple-perl libdbi-perl libmime-base64-urlsafe-perl libtest-tempdir-perl liblogger-syslog-perl \
openjdk-7-jre-headless libcurl4-openssl-dev libexpat1-dev solr-jetty > /dev/null
	
	update-alternatives --set mailx /usr/bin/bsd-mailx --quiet > /dev/null 2>&1
	mkdir -p /etc/dovecot/private/
	cp /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/dovecot/dovecot.pem
	cp /etc/ssl/private/ssl-cert-snakeoil.key /etc/dovecot/dovecot.key
	cp /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/dovecot/private/dovecot.pem
	cp /etc/ssl/private/ssl-cert-snakeoil.key /etc/dovecot/private/dovecot.key
DEBIAN_FRONTEND=noninteractive apt-get --force-yes -y install dovecot-common dovecot-core dovecot-imapd dovecot-lmtpd dovecot-managesieved dovecot-sieve dovecot-mysql dovecot-pop3d dovecot-solr >/dev/null
	for oldfiles in /etc/cron.daily/mc_clean_spam_aliases /usr/local/sbin/mc_pflog_renew /usr/local/sbin/mc_msg_size /usr/local/sbin/mc_dkim_ctrl /usr/local/sbin/mc_resetadmin
	do
	if [ -f "${oldfiles}" ] ; then
		rm "${oldfiles}"
		fi
	done
	install -m 755 misc/mailcow-clean-spam-aliases /etc/cron.daily/mailcow-clean-spam-aliases
	install -m 755 misc/mailcow-renew-pflogsumm /usr/local/sbin/mailcow-renew-pflogsumm
	install -m 755 misc/mailcow-set-message-limit /usr/local/sbin/mailcow-set-message-limit
	install -m 755 misc/mailcow-dkim-tool /usr/local/sbin/mailcow-dkim-tool
	install -m 755 misc/mailcow-reset-admin /usr/local/sbin/mailcow-reset-admin
			
			
	#ssl
	mkdir /etc/ssl/mail 2> /dev/null
	echo "$(textb [INFO]) - Generating 2048 bit DH parameters, this may take a while, please wait..."
	openssl dhparam -out /etc/ssl/mail/dhparams.pem 2048 2> /dev/null
	openssl req -new -newkey rsa:4096 -sha256 -days 1095 -nodes -x509 -subj "/C=ZZ/ST=mailcow/L=mailcow/O=mailcow/CN=${sys_hostname}.${sys_domain}/subjectAltName=DNS.1=${sys_hostname}.${sys_domain}" -keyout /etc/ssl/mail/mail.key -out /etc/ssl/mail/mail.crt
	chmod 600 /etc/ssl/mail/mail.key
	cp /etc/ssl/mail/mail.crt /usr/local/share/ca-certificates/
	update-ca-certificates
			
	#ssl_le
	curled_ip="$(curl -4s ifconfig.co)"
	for ip in  $(dig ${sys_hostname}.${sys_domain} a +short)
	do
		if [[ "${ip}" == "${curled_ip}" ]]; then
			ip_useable=1
		fi
	done
	if [[ ${ip_useable} -ne 1 ]]; then
		echo "$(redb [ERR]) - Cannot validate IP address against DNS"
		echo "You can retry to obtain Let's Encrypt certificates after fixing this error by running ./install.sh -s"
	else
		mkdir -p /opt/letsencrypt-sh/
		mkdir -p "/var/www/mail/.well-known/acme-challenge"
		tar xf letsencrypt-sh/inst/${letsencrypt_sh_version}.tar -C letsencrypt-sh/inst/ 2> /dev/null
		cp -R letsencrypt-sh/inst/${letsencrypt_sh_version}/* /opt/letsencrypt-sh/
				install -m 644 letsencrypt-sh/conf/config.sh /opt/letsencrypt-sh/config.sh
		install -m 644 letsencrypt-sh/conf/domains.txt /etc/ssl/mail/domains.txt
		sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/${sys_hostname}.${sys_domain}/g" /etc/ssl/mail/domains.txt
		# Set postmaster as certificate owner
		sed -i "s/MAILCOW_DOMAIN/${sys_domain}/g" /opt/letsencrypt-sh/config.sh
		# letsencrypt-sh will use config instead of config.sh for versions >= 0.2.0
		cp /opt/letsencrypt-sh/config.sh /opt/letsencrypt-sh/config
		install -m 755 letsencrypt-sh/conf/le-renew /etc/cron.weekly/le-renew
		rm -rf letsencrypt-sh/inst/${letsencrypt_sh_version}
		/etc/cron.weekly/le-renew
		if [[ $? -eq 0 ]]; then
			mv /etc/ssl/mail/mail.key /etc/ssl/mail/mail.key_self-signed
			mv /etc/ssl/mail/mail.crt /etc/ssl/mail/mail.crt_self-signed
			ln -s /etc/ssl/mail/certs/${sys_hostname}.${sys_domain}/fullchain.pem /etc/ssl/mail/mail.crt
			ln -s /etc/ssl/mail/certs/${sys_hostname}.${sys_domain}/privkey.pem /etc/ssl/mail/mail.key
		fi
		service nginx restart
	fi
			
			
	#mysql
	if [[ ${mysql_useable} -ne 1 ]]; then
		if [[ ! -z $(mysql --version | grep '5.7') ]]; then
			# MySQL >= 5.7 uses auth_socket when installing without password (like we do)
			for host in $(mysql --defaults-file=/etc/mysql/debian.cnf mysql -e "select Host from user where User='root';" -BN); do
				mysql --defaults-file=/etc/mysql/debian.cnf -e "ALTER USER 'root'@'${host}' IDENTIFIED WITH mysql_native_password BY '${my_rootpw}';"
			done
			mysql --defaults-file=/etc/mysql/debian.cnf -e "FLUSH PRIVILEGES;"
		else
			for host in $(mysql --defaults-file=/etc/mysql/debian.cnf mysql -e "select Host from user where User='root';" -BN); do
				mysql --defaults-file=/etc/mysql/debian.cnf -e "SET PASSWORD FOR 'root'@'${host}' = PASSWORD('${my_rootpw}');"
			done
			mysql --defaults-file=/etc/mysql/debian.cnf -e "FLUSH PRIVILEGES;"
		fi
	fi
	SQLCMDARRAY=(
		"DROP DATABASE IF EXISTS ${my_mailcowdb}"
		"DROP DATABASE IF EXISTS ${my_rcdb}"
		"CREATE DATABASE ${my_mailcowdb}"
		"GRANT ALL PRIVILEGES ON ${my_mailcowdb}.* TO '${my_mailcowuser}'@'%' IDENTIFIED BY '${my_mailcowpass}'"
	)
	if [[ $roundcube == "roundcube" ]]; then
		SQLCMDARRAY+=(
			"CREATE DATABASE ${my_rcdb}"
			"GRANT ALL PRIVILEGES ON ${my_rcdb}.* TO '$my_rcuser'@'%' IDENTIFIED BY '$my_rcpass'"
		)
	fi
	SQLCMDARRAY+=("FLUSH PRIVILEGES")
	for ((i = 0; i < ${#SQLCMDARRAY[@]}; i++)); do
		mysql --host ${my_dbhost} -u root -p${my_rootpw} -e "${SQLCMDARRAY[$i]}"
		if [[ $? -eq 1 ]]; then
			echo "$(redb [ERR]) - SQL failed at command '${SQLCMDARRAY[$i]}'"
			exit 1
		fi
	done
			
			
	#postfix
	mkdir -p /etc/postfix/sql
	chown root:postfix "/etc/postfix/sql"; chmod 750 "/etc/postfix/sql"
	for file in $(ls postfix/conf/sql)
	do
		install -o root -g postfix -m 640 postfix/conf/sql/${file} /etc/postfix/sql/${file}
	done
	install -m 644 postfix/conf/master.cf /etc/postfix/master.cf
	install -m 644 postfix/conf/main.cf /etc/postfix/main.cf
	install -o www-data -g www-data -m 644 postfix/conf/mailcow_anonymize_headers.pcre /etc/postfix/mailcow_anonymize_headers.pcre
	install -m 644 postfix/conf/postscreen_access.cidr /etc/postfix/postscreen_access.cidr
	install -m 644 postfix/conf/smtp_dsn_filter.pcre /etc/postfix/smtp_dsn_filter.pcre
	sed -i "s/sys_hostname.sys_domain/${sys_hostname}.${sys_domain}/g" /etc/postfix/main.cf
	sed -i "s/sys_domain/${sys_domain}/g" /etc/postfix/main.cf
	sed -i "s/my_mailcowpass/${my_mailcowpass}/g" /etc/postfix/sql/*
	sed -i "s/my_mailcowuser/${my_mailcowuser}/g" /etc/postfix/sql/*
	sed -i "s/my_mailcowdb/${my_mailcowdb}/g" /etc/postfix/sql/*
	sed -i "s/my_dbhost/${my_dbhost}/g" /etc/postfix/sql/*
	sed -i '/^POSTGREY_OPTS=/s/=.*/="--inet=127.0.0.1:10023"/' /etc/default/postgrey
	chmod 755 /var/spool/
	sed -i "/%www-data/d" /etc/sudoers 2> /dev/null
	sed -i "/%vmail/d" /etc/sudoers 2> /dev/null
	echo '%www-data ALL=(ALL) NOPASSWD: /usr/sbin/dovecot reload, /usr/sbin/postfix reload, /usr/local/sbin/mailcow-dkim-tool, /usr/local/sbin/mailcow-set-message-limit, /usr/local/sbin/mailcow-renew-pflogsumm, /usr/sbin/postconf -e smtpd_recipient_restrictions*, /usr/sbin/postconf -e smtpd_sender_restrictions*' > /etc/sudoers.d/mailcow
	chmod 440 /etc/sudoers.d/mailcow
			
			
	#fuglu
	if [[ -z $(grep fuglu /etc/passwd) ]]; then
		userdel fuglu 2> /dev/null
		groupadd fuglu 2> /dev/null
		useradd -g fuglu -s /bin/false fuglu
		usermod -a -G debian-spamd fuglu
		usermod -a -G clamav fuglu
	fi
	rm /tmp/fuglu_control.sock 2> /dev/null
	mkdir /var/log/fuglu 2> /dev/null
	chown fuglu:fuglu /var/log/fuglu
	tar xf fuglu/inst/${fuglu_version}.tar -C fuglu/inst/ 2> /dev/null
	(cd fuglu/inst/${fuglu_version} ; python setup.py -q install)
	cp -R fuglu/conf/* /etc/fuglu/
		cp fuglu/inst/${fuglu_version}/scripts/startscripts/debian/8/fuglu.service /etc/systemd/system/fuglu.service
		systemctl disable fuglu
		[[ -f /lib/systemd/system/fuglu.service ]] && rm /lib/systemd/system/fuglu.service
		systemctl daemon-reload
		systemctl enable fuglu
	rm -rf fuglu/inst/${fuglu_version}	
			
			
	#dovecot
	if [[ -f /lib/systemd/systemd ]]; then
		systemctl disable dovecot.socket > /dev/null 2>&1
	fi
	if [[ -z $(grep '/var/vmail:' /etc/passwd | grep '5000:5000') ]]; then
		userdel vmail 2> /dev/null
		groupdel vmail 2> /dev/null
		groupadd -g 5000 vmail
		useradd -g vmail -u 5000 vmail -d /var/vmail
	fi
	chmod 755 "/etc/dovecot/"
	install -o root -g dovecot -m 640 dovecot/conf/dovecot-dict-sql.conf /etc/dovecot/dovecot-dict-sql.conf
	install -o root -g vmail -m 640 dovecot/conf/dovecot-mysql.conf /etc/dovecot/dovecot-mysql.conf
	install -m 644 dovecot/conf/dovecot.conf /etc/dovecot/dovecot.conf
	touch /etc/dovecot/mailcow_public_folder.conf
	chmod 664 "/etc/dovecot/mailcow_public_folder.conf"; chown root:www-data "/etc/dovecot/mailcow_public_folder.conf"
	DOVEFILES=$(find /etc/dovecot -maxdepth 1 -type f -printf '/etc/dovecot/%f ')
	sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/${sys_hostname}.${sys_domain}/g" ${DOVEFILES}
	sed -i "s/MAILCOW_DOMAIN/${sys_domain}/g" ${DOVEFILES}
	sed -i "s/my_mailcowpass/${my_mailcowpass}/g" ${DOVEFILES}
	sed -i "s/my_mailcowuser/${my_mailcowuser}/g" ${DOVEFILES}
	sed -i "s/my_mailcowdb/${my_mailcowdb}/g" ${DOVEFILES}
	sed -i "s/my_dbhost/${my_dbhost}/g" ${DOVEFILES}
	sed -i "s/MAILCOW_HASHING/${hashing_method}/g" ${DOVEFILES}
	[[ ${IPV6} != "yes" ]] && sed -i '/listen =/c\listen = *' /etc/dovecot/dovecot.conf
	mkdir /etc/dovecot/conf.d 2> /dev/null
	mkdir -p /var/vmail/sieve 2> /dev/null
	mkdir -p /var/vmail/public 2> /dev/null
	if [ ! -f /var/vmail/public/dovecot-acl ]; then
		echo "anyone lrwstipekxa" > /var/vmail/public/dovecot-acl
	fi
	install -m 644 dovecot/conf/global.sieve /var/vmail/sieve/global.sieve
	touch /var/vmail/sieve/default.sieve
	sievec /var/vmail/sieve/global.sieve
	chown -R vmail:vmail /var/vmail
	[[ -f /etc/cron.daily/doverecalcq ]] && rm /etc/cron.daily/doverecalcq
	install -m 755 dovecot/conf/dovemaint /etc/cron.daily/
	install -m 644 dovecot/conf/solrmaint /etc/cron.d/
	# Solr
	#if [[ -z $(curl -s --connect-timeout 3 "http://127.0.0.1:8983/solr/admin/info/system" 2> /dev/null | grep -o '[0-9.]*' | grep "^${solr_version}\$") ]]; then
	#	(
	#	TMPSOLR=$(mktemp -d)
	#	cd $TMPSOLR
	#	MIRRORS_SOLR=(http://mirror.23media.de/apache/lucene/solr/${solr_version}/solr-${solr_version}.tgz
	#	http://mirror2.shellbot.com/apache/lucene/solr/${solr_version}/solr-${solr_version}.tgz
	#	http://mirrors.koehn.com/apache/lucene/solr/${solr_version}/solr-${solr_version}.tgz
	#	http://mirrors.sonic.net/apache/lucene/solr/${solr_version}/solr-${solr_version}.tgz
	#	http://apache.mirrors.ovh.net/ftp.apache.org/dist/lucene/solr/${solr_version}/solr-${solr_version}.tgz
	#	http://mirror.nohup.it/apache/lucene/solr/${solr_version}/solr-${solr_version}.tgz
	#	http://ftp-stud.hs-esslingen.de/pub/Mirrors/ftp.apache.org/dist/lucene/solr/${solr_version}/solr-${solr_version}.tgz
	#	http://mirror.netcologne.de/apache.org/lucene/solr/${solr_version}/solr-${solr_version}.tgz)
	#	for i in "${MIRRORS_SOLR[@]}"; do
	#		if curl --connect-timeout 3 --output /dev/null --silent --head --fail "$i"; then
	#			SOLR_URL="$i"
	#			break
	#		fi
	#	done
	#	if [[ -z ${SOLR_URL} ]]; then
	#		echo "$(redb [ERR]) - No Solr mirror was usable"
	#		exit 1
	#	fi
	#	echo $(textb "Downloading Solr ${solr_version}...")
	#	curl ${SOLR_URL} -# | tar xfz -
	#	if [[ ! -d /opt/solr ]]; then
	#		mkdir /opt/solr/
	#	fi
	#	cp -R solr-${solr_version}/* /opt/solr
	#	rm -r ${TMPSOLR}
	#	)
	#	if [[ ! -d /var/solr ]]; then
	#		mkdir /var/solr/
	#	fi
	#	if [[ ! -f /var/solr/solr.in.sh ]]; then
	#	install -m 644 /opt/solr/bin/solr.in.sh /var/solr/solr.in.sh
	#	sed -i '/SOLR_HOST/c\SOLR_HOST=127.0.0.1' /var/solr/solr.in.sh
	#	sed -i '/SOLR_PORT/c\SOLR_PORT=8983' /var/solr/solr.in.sh
	#	sed -i "/SOLR_TIMEZONE/c\SOLR_TIMEZONE=\"${sys_timezone}\"" /var/solr/solr.in.sh
	#	[[ -z $(grep "jetty.host=localhost" /var/solr/solr.in.sh) ]] && echo 'SOLR_OPTS="$SOLR_OPTS -Djetty.host=localhost"' >> /var/solr/solr.in.sh
	#fi
	#if [[ ! -f /etc/init.d/solr ]]; then
	#	install -m 755 /opt/solr/bin/init.d/solr /etc/init.d/solr
	#	update-rc.d solr defaults
	#	if [[ -f /lib/systemd/systemd ]]; then
	#		systemctl daemon-reload
	#	fi
	#fi
	#if [[ -z $(grep solr /etc/passwd) ]]; then
	#	useradd -r -d /opt/solr solr
	#fi
	#chown -R solr: /opt/solr
	#service solr restart
	#sleep 2
	#if [[ ! -d /opt/solr/server/solr/dovecot2/ ]]; then
	#	sudo -u solr /opt/solr/bin/solr create -c dovecot2
	#fi
	#fi
	update-rc.d -f solr remove > /dev/null 2>&1
	service solr stop > /dev/null 2>&1
	[[ -f /usr/share/doc/dovecot-core/dovecot/solr-schema.xml ]] && cp /usr/share/doc/dovecot-core/dovecot/solr-schema.xml /etc/solr/conf/schema.xml
	[[ -f /usr/share/dovecot/solr-schema.xml ]] && cp /usr/share/dovecot/solr-schema.xml /etc/solr/conf/schema.xml
	sed -i '/NO_START/c\NO_START=0' /etc/default/jetty8
    sed -i '/JETTY_HOST/c\JETTY_HOST=127.0.0.1' /etc/default/jetty8
	sed -i '/JETTY_PORT/c\JETTY_PORT=8983' /etc/default/jetty8
			
		
	#clamav
	usermod -a -G vmail clamav 2> /dev/null
	if [[ -f /etc/apparmor.d/usr.sbin.clamd || -f /etc/apparmor.d/local/usr.sbin.clamd ]]; then
		rm /etc/apparmor.d/usr.sbin.clamd > /dev/null 2>&1
		rm /etc/apparmor.d/local/usr.sbin.clamd > /dev/null 2>&1
		service apparmor restart > /dev/null 2>&1
	fi
	sed -i '/MaxFileSize/c\MaxFileSize 10M' /etc/clamav/clamd.conf
	sed -i '/StreamMaxLength/c\StreamMaxLength 10M' /etc/clamav/clamd.conf
			
			
	#opendkim
	echo 'SOCKET="inet:10040@localhost"' > /etc/default/opendkim
	mkdir -p /etc/opendkim/{keyfiles,dnstxt} 2> /dev/null
	touch /etc/opendkim/{KeyTable,SigningTable}
	install -m 644 opendkim/conf/opendkim.conf /etc/opendkim.conf
			
	#spamassassin
	cp spamassassin/conf/local.cf /etc/spamassassin/local.cf
	if [[ ! -f /etc/spamassassin/local.cf.include ]]; then
        cp spamassassin/conf/local.cf.include /etc/spamassassin/local.cf.include
    fi
	sed -i '/^OPTIONS=/s/=.*/="--create-prefs --max-children 5 --helper-home-dir --username debian-spamd --socketpath \/var\/run\/spamd.sock --socketowner debian-spamd --socketgroup debian-spamd --sql-config --nouser-config"/' /etc/default/spamassassin
	sed -i '/^CRON=/s/=.*/="1"/' /etc/default/spamassassin
	sed -i '/^ENABLED=/s/=.*/="1"/' /etc/default/spamassassin
	sed -i "s/my_mailcowpass/${my_mailcowpass}/g" /etc/spamassassin/local.cf
	sed -i "s/my_mailcowuser/${my_mailcowuser}/g" /etc/spamassassin/local.cf
	sed -i "s/my_mailcowdb/${my_mailcowdb}/g" /etc/spamassassin/local.cf
	sed -i "s/my_dbhost/${my_dbhost}/g" /etc/spamassassin/local.cf
	# Thanks to mf3hd@GitHub
	[[ -z $(grep RANDOM_DELAY /etc/crontab) ]] && sed -i '/SHELL/a RANDOM_DELAY=30' /etc/crontab
	install -m 755 spamassassin/conf/spamlearn /etc/cron.daily/spamlearn
	install -m 755 spamassassin/conf/spamassassin_heinlein /etc/cron.daily/spamassassin_heinlein
	# Thanks to mf3hd@GitHub, again!
	chmod g+s /etc/spamassassin
	chown -R debian-spamd: /etc/spamassassin
	chmod 600 /etc/spamassassin/local.cf
	razor-admin -create -home /etc/razor -conf=/etc/razor/razor-agent.conf
	razor-admin -discover -home /etc/razor
	razor-admin -register -home /etc/razor
	su debian-spamd -c "pyzor --homedir /etc/mail/spamassassin/.pyzor discover 2> /dev/null"
	su debian-spamd -c "sa-update 2> /dev/null"
	if [[ -f /lib/systemd/systemd ]]; then
		systemctl enable spamassassin
	fi
			
	
	#webserver
	mkdir -p /var/www/ 2> /dev/null
	# Some systems miss the default php fpm listener, reinstall it now
	apt-get -o Dpkg::Options::="--force-confmiss" install -y --reinstall php5-fpm > /dev/null
	rm /etc/nginx/sites-enabled/*mailcow* 2>/dev/null
	cp webserver/nginx/conf/sites-available/mailcow${site_config} /etc/nginx/sites-available/mailcow.conf
	cp webserver/php-fpm/conf/5/pool/mail.conf /etc/php5/fpm/pool.d/mail.conf
	cp webserver/php-fpm/conf/5/php-fpm.conf /etc/php5/fpm/php-fpm.conf
	sed -i "/date.timezone/c\php_admin_value[date.timezone] = ${sys_timezone}" /etc/php5/fpm/pool.d/mail.conf
	ln -s /etc/nginx/sites-available/mailcow.conf /etc/nginx/sites-enabled/mailcow.conf 2>/dev/null
	[[ ! -z $(grep "server_names_hash_bucket_size" /etc/nginx/nginx.conf) ]] && \
		sed -i "/server_names_hash_bucket_size/c\ \ \ \ \ \ \ \ server_names_hash_bucket_size 64;" /etc/nginx/nginx.conf || \
		sed -i "/http {/a\ \ \ \ \ \ \ \ server_names_hash_bucket_size 64;" /etc/nginx/nginx.conf
		sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN;/${sys_hostname}.${sys_domain};/g" /etc/nginx/sites-available/mailcow.conf
		sed -i "s/MAILCOW_DOMAIN;/${sys_domain};/g" /etc/nginx/sites-available/mailcow.conf
				
	mkdir /var/lib/php5/sessions 2> /dev/null
	cp -R webserver/htdocs/mail /var/www/
	find /var/www/mail -type d -exec chmod 755 {} \;
	find /var/www/mail -type f -exec chmod 644 {} \;
	echo none > /var/log/pflogsumm.log
	sed -i "s/my_dbhost/${my_dbhost}/g" /var/www/mail/inc/vars.inc.php
	sed -i "s/my_mailcowpass/${my_mailcowpass}/g" /var/www/mail/inc/vars.inc.php
	sed -i "s/my_mailcowuser/${my_mailcowuser}/g" /var/www/mail/inc/vars.inc.php
	sed -i "s/my_mailcowdb/${my_mailcowdb}/g" /var/www/mail/inc/vars.inc.php
	sed -i "s/MAILCOW_HASHING/${hashing_method}/g" /var/www/mail/inc/vars.inc.php
	chown -R www-data: /var/www/mail/. /var/lib/php5/sessions
	mysql --host ${my_dbhost} -u root -p${my_rootpw} ${my_mailcowdb} < webserver/htdocs/init.sql
	if [[ -z $(mysql --host ${my_dbhost} -u root -p${my_rootpw} ${my_mailcowdb} -e "SHOW COLUMNS FROM domain LIKE 'relay_all_recipients';" -N -B) ]]; then
		mysql --host ${my_dbhost} -u root -p${my_rootpw} ${my_mailcowdb} -e "ALTER TABLE domain ADD relay_all_recipients tinyint(1) NOT NULL DEFAULT '0';" -N -B
	fi
	if [[ -z $(mysql --host ${my_dbhost} -u root -p${my_rootpw} ${my_mailcowdb} -e "SHOW COLUMNS FROM mailbox LIKE 'tls_enforce_in';" -N -B) ]]; then
		mysql --host ${my_dbhost} -u root -p${my_rootpw} ${my_mailcowdb} -e "ALTER TABLE mailbox ADD tls_enforce_in tinyint(1) NOT NULL DEFAULT '0';" -N -B
		mysql --host ${my_dbhost} -u root -p${my_rootpw} ${my_mailcowdb} -e "ALTER TABLE mailbox ADD tls_enforce_out tinyint(1) NOT NULL DEFAULT '0';" -N -B
	fi
	mysql --host ${my_dbhost} -u root -p${my_rootpw} ${my_mailcowdb} -e "DELETE FROM spamalias"
	mysql --host ${my_dbhost} -u root -p${my_rootpw} ${my_mailcowdb} -e "ALTER TABLE spamalias MODIFY COLUMN validity int(11) NOT NULL"
	if [[ $(mysql --host ${my_dbhost} -u root -p${my_rootpw} ${my_mailcowdb} -s -N -e "SELECT * FROM admin;" | wc -l) -lt 1 ]]; then
		mailcow_admin_pass_hashed=$(doveadm pw -s ${hashing_method} -p ${mailcow_admin_pass})
		mysql --host ${my_dbhost} -u root -p${my_rootpw} ${my_mailcowdb} -e "INSERT INTO admin VALUES ('$mailcow_admin_user','${mailcow_admin_pass_hashed}', '1', NOW(), NOW(), '1');"
		mysql --host ${my_dbhost} -u root -p${my_rootpw} ${my_mailcowdb} -e "INSERT INTO domain_admins (username, domain, created, active) VALUES ('$mailcow_admin_user', 'ALL', NOW(), '1');"
	else
		echo "$(textb [INFO]) - An administrator exists, will not create another mailcow administrator"
	fi
			
			
	#roundcube
	mkdir -p /var/www/mail/rc
	tar xf roundcube/inst/${roundcube_version}.tar -C roundcube/inst/
	cp -R roundcube/inst/${roundcube_version}/* /var/www/mail/rc/
	if [[ ${is_upgradetask} != "yes" ]]; then
		cp -R roundcube/conf/* /var/www/mail/rc/
		sed -i "s/my_dbhost/${my_dbhost}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/my_rcuser/${my_rcuser}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/my_rcpass/${my_rcpass}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/my_rcdb/${my_rcdb}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/conf_rcdeskey/$(genpasswd)/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/${sys_hostname}.${sys_domain}/g" /var/www/mail/rc/config/config.inc.php
		mysql --host ${my_dbhost} -u ${my_rcuser} -p${my_rcpass} ${my_rcdb} < /var/www/mail/rc/SQL/mysql.initial.sql
	else
		chmod +x roundcube/inst/${roundcube_version}/bin/installto.sh
		roundcube/inst/${roundcube_version}/bin/installto.sh /var/www/mail/rc
	fi
	chown -R www-data: /var/www/mail/rc
	rm -rf roundcube/inst/${roundcube_version}
	rm -rf /var/www/mail/rc/installer/
			
			
	#restartservices
		[[ -f /lib/systemd/systemd ]] && echo "$(textb [INFO]) - Restarting services, this may take a few seconds..."
		for var in jetty8 nginx php5-fpm spamassassin fuglu dovecot postfix opendkim clamav-daemon mailgraph
		do
			service ${var} stop
			sleep 1.5
			service ${var} start
		done
}
