# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow and https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

mailserver() {

if [ ${USE_MAILSERVER} == '1' ]; then
	echo "${info} Installing mailserver..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

	# Mailcow binaries
	install -m 755 ~/sources/mailcow/misc/mc_clean_spam_aliases /etc/cron.daily/mc_clean_spam_aliases
	install -m 755 ~/sources/mailcow/misc/mc_pfset /usr/local/sbin/mc_pfset
	install -m 755 ~/sources/mailcow/misc/mc_pflog_renew /usr/local/sbin/mc_pflog_renew
	install -m 755 ~/sources/mailcow/misc/mc_msg_size /usr/local/sbin/mc_msg_size
	install -m 755 ~/sources/mailcow/misc/mc_dkim_ctrl /usr/local/sbin/mc_dkim_ctrl
	install -m 755 ~/sources/mailcow/misc/mc_setup_backup /usr/local/sbin/mc_setup_backup
	install -m 700 ~/sources/mailcow/misc/mc_resetadmin /usr/local/sbin/mc_resetadmin

	# Prerequisites
	update-alternatives --set mailx /usr/bin/bsd-mailx --quiet >/dev/null 2>&1
	DEBIAN_FRONTEND=noninteractive aptitude -y install clamav-daemon dovecot-common dovecot-core dovecot-imapd dovecot-lmtpd dovecot-managesieved dovecot-mysql dovecot-pop3d dovecot-sieve dovecot-solr fcgiwrap fetchmail imagemagick mailutils mailgraph/unstable mpack opendkim opendkim-tools pflogsumm postfix postfix-mysql postfix-pcre postgrey pyzor razor rrdtool/unstable spamassassin spamc spawn-fcgi wkhtmltopdf >/dev/null 2>&1

	# Create SSL
	mkdir -p /etc/ssl/mail >/dev/null 2>&1
	rm /etc/ssl/mail/* >/dev/null 2>&1
	cp /etc/nginx/ssl/dh.pem /etc/ssl/mail/dhparams.pem
	if [ ${USE_VALID_SSL} == '1' ]; then
		ln -s /etc/letsencrypt/live/${MYDOMAIN}/fullchain.pem /etc/ssl/mail/mail.crt
		ln -s /etc/letsencrypt/live/${MYDOMAIN}/privkey.pem /etc/ssl/mail/mail.key
	else
		openssl req -new -newkey rsa:4096 -sha256 -days 1095 -nodes -x509 -subj "/C=/ST=/L=/O=/OU=/CN=mail.${MYDOMAIN}" -keyout /etc/ssl/mail/mail.key -out /etc/ssl/mail/mail.crt >/dev/null 2>&1
		chmod 600 /etc/ssl/mail/mail.key
		cp /etc/ssl/mail/mail.crt /usr/local/share/ca-certificates/
		update-ca-certificates >/dev/null 2>&1
	fi

	# Create MySQL databases
	echo "${info} Creating MySQL databases..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} -e "CREATE DATABASE ${MYSQL_MCDB_NAME}; GRANT SELECT, INSERT, UPDATE, DELETE ON ${MYSQL_MCDB_NAME}.* TO '${MYSQL_MCDB_USER}'@'%' IDENTIFIED BY '${MYSQL_MCDB_PASS}';"
	mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} -e "CREATE DATABASE ${MYSQL_RCDB_NAME}; GRANT ALL PRIVILEGES ON ${MYSQL_RCDB_NAME}.* TO '${MYSQL_RCDB_USER}'@'%' IDENTIFIED BY '${MYSQL_RCDB_PASS}';"
	mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} -e "GRANT SELECT ON ${MYSQL_MCDB_NAME}.* TO 'vmail'@'%'; FLUSH PRIVILEGES;"

	# Postfix
	echo "${info} Installing Postfix..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	cp -R ~/sources/mailcow/postfix/conf/* /etc/postfix/
	chown root:postfix "/etc/postfix/sql"; chmod 750 "/etc/postfix/sql"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_alias_domain_catchall_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_alias_domain_catchall_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_alias_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_alias_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_alias_domain_mailbox_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_alias_domain_mailbox_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_mailbox_limit_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_mailbox_limit_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_mailbox_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_mailbox_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_mxdomain_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_mxdomain_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_alias_domain_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_alias_domain_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_spamalias_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_spamalias_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_sender_acl.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_sender_acl.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_domains_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_domains_maps.cf"
	chown root:root "/etc/postfix/master.cf"; chmod 644 "/etc/postfix/master.cf"
	chown root:root "/etc/postfix/main.cf"; chmod 644 "/etc/postfix/main.cf"
	sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYDOMAIN}/g" /etc/postfix/main.cf
	sed -i "s/MAILCOW_DOMAIN/${MYDOMAIN}/g" /etc/postfix/main.cf
	chmod +x /usr/local/sbin/mc_pfset /usr/local/sbin/mc_pflog_renew
	chmod 700 /etc/cron.daily/mc_clean_spam_aliases
	sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
	sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
	sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
	sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
	sed -i '/^POSTGREY_OPTS=/s/=.*/="--inet=127.0.0.1:10023"/' /etc/default/postgrey
	chown www-data: /etc/postfix/mailcow_*
	chmod 755 /var/spool/
	sed -i "/%www-data/d" /etc/sudoers >/dev/null 2>&1
	sed -i "/%vmail/d" /etc/sudoers >/dev/null 2>&1
	echo '%www-data ALL=(ALL) NOPASSWD: /usr/bin/doveadm * sync *, /usr/local/sbin/mc_pfset *, /usr/bin/doveadm quota recalc -A, /usr/sbin/dovecot reload, /usr/sbin/postfix reload, /usr/local/sbin/mc_dkim_ctrl, /usr/local/sbin/mc_msg_size, /usr/local/sbin/mc_pflog_renew, /usr/local/sbin/mc_setup_backup' >> /etc/sudoers
	if [ ${USE_VALID_SSL} == '1' ]; then
		sed -i 's/smtp_tls_CAfile/# smtp_tls_CAfile/g' /etc/postfix/main.cf
	fi

	# Fuglu
	if [[ -z $(grep fuglu /etc/passwd) ]]; then
		userdel fuglu >/dev/null 2>&1
		groupadd fuglu >/dev/null 2>&1
		useradd -g fuglu -s /bin/false fuglu
		usermod -a -G debian-spamd fuglu
		usermod -a -G clamav fuglu
	fi
	rm /tmp/fuglu_control.sock >/dev/null 2>&1
	mkdir /var/log/fuglu >/dev/null 2>&1
	chown fuglu:fuglu /var/log/fuglu
	tar xf ~/sources/mailcow/fuglu/inst/0.6.5.tar -C ~/sources/mailcow/fuglu/inst/ >/dev/null 2>&1
	(cd ~/sources/mailcow/fuglu/inst/0.6.5 ; python setup.py -q install)
	cp -R ~/sources/mailcow/fuglu/conf/* /etc/fuglu/
	cp ~/sources/mailcow/fuglu/inst/0.6.5/scripts/startscripts/debian/8/fuglu.service /etc/systemd/system/fuglu.service
	systemctl -q disable fuglu
	[[ -f /lib/systemd/system/fuglu.service ]] && rm /lib/systemd/system/fuglu.service
	systemctl -q daemon-reload
	systemctl -q enable fuglu
	rm -rf ~/sources/mailcow/fuglu/inst/0.6.5

	# Dovecot
	echo "${info} Installing Dovecot..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	systemctl -q disable dovecot.socket
	if [[ -z $(grep '/var/vmail:' /etc/passwd | grep '5000:5000') ]]; then
		userdel vmail >/dev/null 2>&1
		groupdel vmail >/dev/null 2>&1
		groupadd -g 5000 vmail
		useradd -g vmail -u 5000 vmail -d /var/vmail
 	fi
	chmod 755 "/etc/dovecot/"
	install -o root -g dovecot -m 640 ~/sources/mailcow/dovecot/conf/dovecot-dict-sql.conf /etc/dovecot/dovecot-dict-sql.conf
	install -o root -g vmail -m 640 ~/sources/mailcow/dovecot/conf/dovecot-mysql.conf /etc/dovecot/dovecot-mysql.conf
	install -m 644 ~/sources/mailcow/dovecot/conf/dovecot.conf /etc/dovecot/dovecot.conf
	touch /etc/dovecot/mailcow_public_folder.conf
	chmod 664 "/etc/dovecot/mailcow_public_folder.conf"; chown root:www-data "/etc/dovecot/mailcow_public_folder.conf"
	DOVEFILES=$(find /etc/dovecot -maxdepth 1 -type f -printf '/etc/dovecot/%f ')
	sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYDOMAIN}/g" ${DOVEFILES}
	sed -i "s/MAILCOW_DOMAIN/${MYDOMAIN}/g" ${DOVEFILES}
	sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" ${DOVEFILES}
	sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" ${DOVEFILES}
	sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" ${DOVEFILES}
	sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" ${DOVEFILES}
	mkdir /etc/dovecot/conf.d >/dev/null 2>&1
	mkdir -p /var/vmail/sieve >/dev/null 2>&1
	mkdir -p /var/vmail/public >/dev/null 2>&1
	if [ ! -f /var/vmail/public/dovecot-acl ]; then
		echo "anyone lrwstipekxa" > /var/vmail/public/dovecot-acl
	fi
	install -m 644 ~/sources/mailcow/dovecot/conf/global.sieve /var/vmail/sieve/global.sieve
	touch /var/vmail/sieve/default.sieve
	install -m 755 ~/sources/mailcow/misc/mc_msg_size /usr/local/sbin/mc_msg_size
	sievec /var/vmail/sieve/global.sieve
	chown -R vmail:vmail /var/vmail
	[[ -f /etc/cron.daily/doverecalcq ]] && rm /etc/cron.daily/doverecalcq
	install -m 755 ~/sources/mailcow/dovecot/conf/dovemaint /etc/cron.daily/
	install -m 644 ~/sources/mailcow/dovecot/conf/solrmaint /etc/cron.d/

	# clamav
	echo "${info} Installing ClamaV..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	usermod -a -G vmail clamav >/dev/null 2>&1
	service clamav-freshclam stop >/dev/null 2>&1
	killall freshclam >/dev/null 2>&1
	rm -f /var/lib/clamav/* >/dev/null 2>&1 >/dev/null 2>&1
	sed -i '/DatabaseMirror/d' /etc/clamav/freshclam.conf
	sed -i '/MaxFileSize/c\MaxFileSize 10240M' /etc/clamav/clamd.conf
	sed -i '/StreamMaxLength/c\StreamMaxLength 10240M' /etc/clamav/clamd.conf
	echo "DatabaseMirror clamav.netcologne.de
DatabaseMirror clamav.internet24.eu
DatabaseMirror clamav.inode.at" >> /etc/clamav/freshclam.conf
	if [[ -f /etc/apparmor.d/usr.sbin.clamd || -f /etc/apparmor.d/local/usr.sbin.clamd ]]; then
		rm /etc/apparmor.d/usr.sbin.clamd >/dev/null 2>&1
		rm /etc/apparmor.d/local/usr.sbin.clamd >/dev/null 2>&1
		service apparmor restart >/dev/null 2>&1
	fi
	cp -f ~/sources/mailcow/clamav/clamav-unofficial-sigs.sh /usr/local/bin/clamav-unofficial-sigs.sh
	chmod +x /usr/local/bin/clamav-unofficial-sigs.sh
	cp -f ~/sources/mailcow/clamav/clamav-unofficial-sigs.conf /etc/clamav-unofficial-sigs.conf
	cp -f ~/sources/mailcow/clamav/clamav-unofficial-sigs.8 /usr/share/man/man8/clamav-unofficial-sigs.8
	cp -f ~/sources/mailcow/clamav/clamav-unofficial-sigs-cron /etc/cron.d/clamav-unofficial-sigs-cron
	cp -f ~/sources/mailcow/clamav/clamav-unofficial-sigs-logrotate /etc/logrotate.d/clamav-unofficial-sigs-logrotate
	mkdir -p /var/log/clamav-unofficial-sigs >/dev/null 2>&1
	sed -i '/MaxFileSize/c\MaxFileSize 10M' /etc/clamav/clamd.conf
	sed -i '/StreamMaxLength/c\StreamMaxLength 10M' /etc/clamav/clamd.conf
	freshclam >/dev/null 2>&1

	# OpenDKIM
	echo "${info} Installing OpenDKIM..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo 'SOCKET="inet:10040@localhost"' > /etc/default/opendkim
	mkdir -p /etc/opendkim/{keyfiles,dnstxt} >/dev/null 2>&1
	touch /etc/opendkim/{KeyTable,SigningTable}
	install -m 644 ~/sources/mailcow/opendkim/conf/opendkim.conf /etc/opendkim.conf

	# SpamAssassin
	echo "${info} Installing SpamAssassin..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	cp ~/sources/mailcow/spamassassin/conf/local.cf /etc/spamassassin/local.cf
	sed -i '/^OPTIONS=/s/=.*/="--create-prefs --max-children 5 --helper-home-dir --username debian-spamd --socketpath \/var\/run\/spamd.sock --socketowner debian-spamd --socketgroup debian-spamd"/' /etc/default/spamassassin
	sed -i '/^CRON=/s/=.*/="1"/' /etc/default/spamassassin
	sed -i '/^ENABLED=/s/=.*/="1"/' /etc/default/spamassassin
	# Thanks to mf3hd@GitHub
	[[ -z $(grep RANDOM_DELAY /etc/crontab) ]] && sed -i '/SHELL/a RANDOM_DELAY=30' /etc/crontab
	install -m 755 ~/sources/mailcow/spamassassin/conf/spamlearn /etc/cron.daily/spamlearn
	install -m 755 ~/sources/mailcow/spamassassin/conf/spamassassin_heinlein /etc/cron.daily/spamassassin_heinlein
	# Thanks to mf3hd@GitHub, again!
	chmod g+s /etc/spamassassin
	chown -R debian-spamd: /etc/spamassassin
	razor-admin -create -home /etc/razor -conf=/etc/razor/razor-agent.conf >/dev/null 2>&1
	razor-admin -discover -home /etc/razor >/dev/null 2>&1
	razor-admin -register -home /etc/razor >/dev/null 2>&1
	su debian-spamd -c "pyzor --homedir /etc/mail/spamassassin/.pyzor discover >/dev/null 2>&1"
	su debian-spamd -c "sa-update >/dev/null 2>&1"
	systemctl enable spamassassin >/dev/null 2>&1

	# Mailcow
	echo "${info} Installing Mailcow..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	mkdir -p /var/mailcow/log
	mkdir -p /var/www/ >/dev/null 2>&1
	cp ~/sources/mailcow/webserver/php5-fpm/conf/pool/mail.conf /etc/php5/fpm/pool.d/mail.conf
	sed -i "/date.timezone/c\php_admin_value[date.timezone] = ${TIMEZONE}" /etc/php5/fpm/pool.d/mail.conf
	mkdir /var/lib/php5/sessions >/dev/null 2>&1
	chown -R www-data:www-data /var/lib/php5/sessions
	install -m 755 ~/sources/mailcow/misc/mc_setup_backup /usr/local/sbin/mc_setup_backup
	cp -R ~/sources/mailcow/webserver/htdocs/{mail,dav,zpush} /var/www/
	tar xf /var/www/dav/vendor.tar -C /var/www/dav/ ; rm /var/www/dav/vendor.tar
	tar xf /var/www/zpush/vendor.tar -C /var/www/zpush/ ; rm /var/www/zpush/vendor.tar
	find /var/www/{dav,mail,zpush} -type d -exec chmod 755 {} \;
	find /var/www/{dav,mail,zpush} -type f -exec chmod 644 {} \;
	sed -i "/date_default_timezone_set/c\date_default_timezone_set('${TIMEZONE}');" /var/www/dav/server.php
	touch /var/mailcow/mailbox_backup_env
	echo none > /var/mailcow/log/pflogsumm.log
	cp ~/sources/mailcow/misc/mc_resetadmin /usr/local/sbin/mc_resetadmin ; chmod 700 /usr/local/sbin/mc_resetadmin
	sed -i "s/mailcow_sub/mail/g" /var/www/mail/autoconfig.xml
	sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /var/www/mail/inc/vars.inc.php /var/www/dav/server.php /usr/local/sbin/mc_resetadmin /var/www/zpush/config.php /var/www/zpush/backend/imap/config.php
	sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" /var/www/mail/inc/vars.inc.php /var/www/dav/server.php /usr/local/sbin/mc_resetadmin /var/www/zpush/config.php /var/www/zpush/backend/imap/config.php
	sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" /var/www/mail/inc/vars.inc.php /var/www/dav/server.php /usr/local/sbin/mc_resetadmin /var/www/zpush/config.php /var/www/zpush/backend/imap/config.php
	sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" /var/www/mail/inc/vars.inc.php /var/www/dav/server.php /usr/local/sbin/mc_resetadmin /var/www/zpush/config.php /var/www/zpush/backend/imap/config.php
	sed -i "s/httpd_dav_subdomain/dav/g" /var/www/mail/inc/vars.inc.php
	chown -R www-data: /var/www/{.,mail,dav} /var/lib/php5/sessions /var/mailcow/mailbox_backup_env
	mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} < ~/sources/mailcow/webserver/htdocs/init.sql
	if [[ -z $(mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} -e "SHOW INDEX FROM propertystorage WHERE KEY_NAME = 'path_property';" -N -B) ]]; then
		mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} -e "CREATE UNIQUE INDEX path_property ON propertystorage (path(600), name(100));" -N -B
	fi
	if [[ -z $(mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} -e "SHOW INDEX FROM zpush_states WHERE KEY_NAME = 'idx_zpush_states_unique';" -N -B) ]]; then
		mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} -e "CREATE unique index idx_zpush_states_unique on zpush_states (device_id, uuid, state_type, counter);" -N -B
	fi
	if [[ -z $(mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} -e "SHOW INDEX FROM zpush_preauth_users WHERE KEY_NAME = 'index_zpush_preauth_users_on_username_and_device_id';" -N -B) ]]; then
		mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} -e "CREATE unique index index_zpush_preauth_users_on_username_and_device_id on zpush_preauth_users (username, device_id);" -N -B
	fi
	if [[ -z $(mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} -e "SHOW COLUMNS FROM domain LIKE 'relay_all_recipients';" -N -B) ]]; then
		mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} -e "ALTER TABLE domain ADD relay_all_recipients tinyint(1) NOT NULL DEFAULT '0';" -N -B
	fi
	if [[ $(mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} -s -N -e "SELECT * FROM admin;" | wc -l) -lt 1 ]]; then
		mailcow_admin_pass_hashed=$(doveadm pw -s SHA512-CRYPT -p ${MAILCOW_ADMIN_PASS})
		mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} -e "INSERT INTO admin VALUES ('${MAILCOW_ADMIN_USER}','$mailcow_admin_pass_hashed',1,now(),now(),1);"
		mysql -uroot -p${MYSQL_ROOT_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_MCDB_NAME} -e "INSERT INTO domain_admins (username, domain, created, active) VALUES ('${MAILCOW_ADMIN_USER}', 'ALL', now(), '1');"
	else
		echo "${info} At least one administrator exists, will not create another mailcow administrator" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	fi

	# zpush
	echo "${info} Installing Z-Push..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	sed -i "s#MAILCOW_TIMEZONE#${TIMEZONE}#g" /var/www/zpush/config.php
	sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYDOMAIN}/g" /var/www/zpush/backend/imap/config.php
	sed -i "s/MAILCOW_DAV_HOST.MAILCOW_DOMAIN/dav.${MYDOMAIN}/g" /var/www/zpush/backend/caldav/config.php
	sed -i "s/MAILCOW_DAV_HOST.MAILCOW_DOMAIN/dav.${MYDOMAIN}/g" /var/www/zpush/backend/carddav/config.php
	mkdir /var/{lib,log}/z-push 2>/dev/null
	chown -R www-data: /var/{lib,log}/z-push
	mkdir /var/www/zpush/mail
	cat > /var/www/zpush/mail/config-v1.1.xml <<END
<?xml version="1.0" encoding="UTF-8"?>

<clientConfig version="1.1">
  <emailProvider id="${MYDOMAIN}">
    <domain>${MYDOMAIN}</domain>
    <displayName>${MYDOMAIN} Mail</displayName>
    <displayShortName>${MYDOMAIN}</displayShortName>
    <incomingServer type="imap">
      <hostname>mail.${MYDOMAIN}</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>mail.${MYDOMAIN}</hostname>
      <port>143</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>mail.${MYDOMAIN}</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>mail.${MYDOMAIN}</hostname>
      <port>110</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>mail.${MYDOMAIN}</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
    <documentation url="https://${MYDOMAIN}/admin">
      <descr lang="de">Allgemeine Beschreibung der Einstellungen</descr>
      <descr lang="en">Generic settings page</descr>
    </documentation>
    <documentation url="https://${MYDOMAIN}/admin">
      <descr lang="de">TB 2.0 IMAP-Einstellungen</descr>
      <descr lang="en">TB 2.0 IMAP settings</descr>
    </documentation>
  </emailProvider>
</clientConfig>
END
	chown -R www-data: /var/www/zpush/mail/

	# Cleaning up old files
	sed -i '/test -d /var/run/fetchmail/d' /etc/rc.local >/dev/null 2>&1
	rm /etc/cron.d/pfadminfetchmail >/dev/null 2>&1
	rm /etc/mail/postfixadmin/fetchmail.conf >/dev/null 2>&1
	rm /usr/local/bin/fetchmail.pl >/dev/null 2>&1

	# Create Nginx Config
	cat > /etc/nginx/sites-custom/mailcow.conf <<END
location /admin {
    alias /var/www/mail;
    index index.php;

    location ~ ^/admin/(.+\.php)$ {
        alias /var/www/mail/\$1;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        include fastcgi_params;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME /var/www/mail/\$1;
        fastcgi_pass unix:/var/run/php5-fpm-mail.sock;
    }

    location ~* ^/admin/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
        alias /var/www/mail/\$1;
    }
}

location ~ ^/(admin/rc)/ {
    deny all;
    return 301 /admin;
}

location ~ \.cgi\$ {
	allow 127.0.0.1;
	deny all;
	alias /usr/lib/cgi-bin;
	include fastcgi_params;
	fastcgi_param SCRIPT_FILENAME /usr/lib/cgi-bin/\$1;
	fastcgi_pass unix:/var/run/fcgiwrap.socket;
}
END

	cat > /etc/nginx/sites-available/mailgraph.conf <<END
server {
	listen 127.0.0.1:81;
		location ~ \.cgi\$ {
		    alias /usr/lib/cgi-bin/\$1;
		    include /etc/nginx/fastcgi_params;
		    fastcgi_pass unix:/var/run/fcgiwrap.socket;
		}
}
END

	cat > /etc/nginx/sites-available/autodiscover.${MYDOMAIN}.conf <<END
server {
			listen 80;
			server_name autodiscover.${MYDOMAIN} autoconfig.${MYDOMAIN};
			return 301 https://autodiscover.${MYDOMAIN}\$request_uri;
}

server {
			listen 443 ssl http2;
			server_name autodiscover.${MYDOMAIN} autoconfig.${MYDOMAIN};

			root /var/www/zpush;
			index index.php;
			charset utf-8;

			error_page 404 /index.php;

			ssl_certificate 	ssl/${MYDOMAIN}.pem;
			ssl_certificate_key ssl/${MYDOMAIN}.key.pem;
			#ssl_trusted_certificate ssl/${MYDOMAIN}.pem;
			ssl_dhparam	     	ssl/dh.pem;
			#ssl_ecdh_curve		secp384r1;
			ssl_session_cache   shared:SSL:10m;
			ssl_session_timeout 10m;
			ssl_session_tickets off;
			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
			ssl_prefer_server_ciphers on;
			ssl_buffer_size 	1400;

			#ssl_stapling 		on;
			#ssl_stapling_verify on;
			#resolver 			8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220 valid=60s;
			#resolver_timeout 	2s;

			ssl_ciphers 		"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";

			#add_header 		Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
			##add_header 		Public-Key-Pins 'pin-sha256="PIN1"; pin-sha256="PIN2"; max-age=5184000; includeSubDomains';
			add_header 			Cache-Control "public";
			add_header 			X-Frame-Options SAMEORIGIN;
			add_header 			Alternate-Protocol  443:npn-http/2;
			add_header 			X-Content-Type-Options nosniff;
			add_header 			X-XSS-Protection "1; mode=block";
			add_header 			X-Permitted-Cross-Domain-Policies "master-only";
			add_header 			"X-UA-Compatible" "IE=Edge";
			add_header 			"Access-Control-Allow-Origin" "*";
			add_header 			Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com cdnjs.cloudflare.com assets.zendesk.com connect.facebook.net; frame-src 'self' *.youtube.com assets.zendesk.com *.facebook.com s-static.ak.facebook.com tautt.zendesk.com; object-src 'self'";

			auth_basic_user_file htpasswd/.htpasswd;

			location ~ ^(.+\.php)(.*)\$ {
				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
				try_files \$fastcgi_script_name =404;
				set \$path_info \$fastcgi_path_info;
				fastcgi_param PATH_INFO \$path_info;
				fastcgi_param APP_ENV production;
				fastcgi_pass unix:/var/run/php5-fpm.sock;
				fastcgi_index index.php;
				include fastcgi.conf;
				fastcgi_intercept_errors on;
				fastcgi_ignore_client_abort off;
				fastcgi_buffers 256 16k;
				fastcgi_buffer_size 128k;
				fastcgi_connect_timeout 3s;
				fastcgi_send_timeout 120s;
				fastcgi_read_timeout 120s;
				fastcgi_busy_buffers_size 256k;
				fastcgi_temp_file_write_size 256k;
			}

			rewrite (?i)^/autodiscover/autodiscover\.xml\$ /autodiscover/autodiscover.php;

			location / {
				try_files \$uri \$uri/ /index.php;
			}

			location /Microsoft-Server-ActiveSync {
            	rewrite ^(.*)\$  /index.php last;
        	}

			location ~ /(\.ht|Core|Specific) {
                deny all;
                return 404;
        	}

			location = /favicon.ico {
				access_log off;
				log_not_found off;
			}
				
			location = /robots.txt {
				allow all;
				access_log off;
				log_not_found off;
			}

			location ~* ^.+\.(css|js)\$ {
				rewrite ^(.+)\.(\d+)\.(css|js)\$ \$1.\$3 last;
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

			location ~* \.(asf|asx|wax|wmv|wmx|avi|bmp|class|divx|doc|docx|eot|exe|gif|gz|gzip|ico|jpg|jpeg|jpe|mdb|mid|midi|mov|qt|mp3|m4a|mp4|m4v|mpeg|mpg|mpe|mpp|odb|odc|odf|odg|odp|ods|odt|ogg|ogv|otf|pdf|png|pot|pps|ppt|pptx|ra|ram|svg|svgz|swf|tar|t?gz|tif|tiff|ttf|wav|webm|wma|woff|wri|xla|xls|xlsx|xlt|xlw|zip)\$ {
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

			if (\$http_user_agent ~* "FeedDemon|JikeSpider|Indy Library|Alexa Toolbar|AskTbFXTV|AhrefsBot|CrawlDaddy|CoolpadWebkit|Java|Feedly|UniversalFeedParser|ApacheBench|Microsoft URL Control|Swiftbot|ZmEu|oBot|jaunty|Python-urllib|lightDeckReports Bot|YYSpider|DigExt|YisouSpider|HttpClient|MJ12bot|heritrix|EasouSpider|Ezooms|Scrapy") {
            	return 403;
            }

}
END

	cat > /etc/nginx/sites-available/dav.${MYDOMAIN}.conf <<END
server {
			listen 80;
			server_name dav.${MYDOMAIN};
			return 301 https://dav.${MYDOMAIN}\$request_uri;
}

server {
			listen 443 ssl http2;
			server_name dav.${MYDOMAIN};

			root /var/www/dav;
			index server.php;
			charset utf-8;

			error_page 404 /index.php;

			ssl_certificate 	ssl/${MYDOMAIN}.pem;
			ssl_certificate_key ssl/${MYDOMAIN}.key.pem;
			#ssl_trusted_certificate ssl/${MYDOMAIN}.pem;
			ssl_dhparam	     	ssl/dh.pem;
			#ssl_ecdh_curve		secp384r1;
			ssl_session_cache   shared:SSL:10m;
			ssl_session_timeout 10m;
			ssl_session_tickets off;
			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
			ssl_prefer_server_ciphers on;
			ssl_buffer_size 	1400;

			#ssl_stapling 		on;
			#ssl_stapling_verify on;
			#resolver 			8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220 valid=60s;
			#resolver_timeout 	2s;

			ssl_ciphers 		"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";

			#add_header 		Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
			##add_header 		Public-Key-Pins 'pin-sha256="PIN1"; pin-sha256="PIN2"; max-age=5184000; includeSubDomains';
			add_header 			Cache-Control "public";
			add_header 			X-Frame-Options SAMEORIGIN;
			add_header 			Alternate-Protocol  443:npn-http/2;
			add_header 			X-Content-Type-Options nosniff;
			add_header 			X-XSS-Protection "1; mode=block";
			add_header 			X-Permitted-Cross-Domain-Policies "master-only";
			add_header 			"X-UA-Compatible" "IE=Edge";
			add_header 			"Access-Control-Allow-Origin" "*";
			add_header 			Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com cdnjs.cloudflare.com assets.zendesk.com connect.facebook.net; frame-src 'self' *.youtube.com assets.zendesk.com *.facebook.com s-static.ak.facebook.com tautt.zendesk.com; object-src 'self'";
			
			auth_basic_user_file htpasswd/.htpasswd;

			location ~ ^(.+\.php)(.*)\$ {
				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
				try_files \$fastcgi_script_name =404;
				set \$path_info \$fastcgi_path_info;
				fastcgi_param PATH_INFO \$path_info;
				fastcgi_param APP_ENV production;
				fastcgi_pass unix:/var/run/php5-fpm.sock;
				fastcgi_index index.php;
				include fastcgi.conf;
				fastcgi_intercept_errors on;
				fastcgi_ignore_client_abort off;
				fastcgi_buffers 256 16k;
				fastcgi_buffer_size 128k;
				fastcgi_connect_timeout 3s;
				fastcgi_send_timeout 120s;
				fastcgi_read_timeout 120s;
				fastcgi_busy_buffers_size 256k;
				fastcgi_temp_file_write_size 256k;
			}

			rewrite ^/.well-known/caldav /server.php redirect;
			rewrite ^/.well-known/carddav /server.php redirect;

			location / {
				try_files \$uri \$uri/ /server.php?\$args;
			}

			location ~ /(\.ht|Core|Specific) {
                deny all;
                return 404;
        	}

			location = /favicon.ico {
				access_log off;
				log_not_found off;
			}
				
			location = /robots.txt {
				allow all;
				access_log off;
				log_not_found off;
			}

			location ~* ^.+\.(css|js)\$ {
				rewrite ^(.+)\.(\d+)\.(css|js)\$ \$1.\$3 last;
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

			location ~* \.(asf|asx|wax|wmv|wmx|avi|bmp|class|divx|doc|docx|eot|exe|gif|gz|gzip|ico|jpg|jpeg|jpe|mdb|mid|midi|mov|qt|mp3|m4a|mp4|m4v|mpeg|mpg|mpe|mpp|odb|odc|odf|odg|odp|ods|odt|ogg|ogv|otf|pdf|png|pot|pps|ppt|pptx|ra|ram|svg|svgz|swf|tar|t?gz|tif|tiff|ttf|wav|webm|wma|woff|wri|xla|xls|xlsx|xlt|xlw|zip)\$ {
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

			if (\$http_user_agent ~* "FeedDemon|JikeSpider|Indy Library|Alexa Toolbar|AskTbFXTV|AhrefsBot|CrawlDaddy|CoolpadWebkit|Java|Feedly|UniversalFeedParser|ApacheBench|Microsoft URL Control|Swiftbot|ZmEu|oBot|jaunty|Python-urllib|lightDeckReports Bot|YYSpider|DigExt|YisouSpider|HttpClient|MJ12bot|heritrix|EasouSpider|Ezooms|Scrapy") {
            	return 403;
            }
}
END

	if [ ${CLOUDFLARE} == '0' ] && [ ${USE_VALID_SSL} == '1' ]; then
		sed -i 's/#ssl/ssl/g' /etc/nginx/sites-available/autodiscover.${MYDOMAIN}.conf /etc/nginx/sites-available/dav.${MYDOMAIN}.conf
		sed -i 's/#resolver/resolver/g' /etc/nginx/sites-available/autodiscover.${MYDOMAIN}.conf /etc/nginx/sites-available/dav.${MYDOMAIN}.conf
		sed -i 's/#add/add/g' /etc/nginx/sites-available/autodiscover.${MYDOMAIN}.conf /etc/nginx/sites-available/dav.${MYDOMAIN}.conf
	fi

	ln -s /etc/nginx/sites-available/mailgraph.conf /etc/nginx/sites-enabled/mailgraph.conf
	ln -s /etc/nginx/sites-available/autodiscover.${MYDOMAIN}.conf /etc/nginx/sites-enabled/autodiscover.${MYDOMAIN}.conf
	ln -s /etc/nginx/sites-available/dav.${MYDOMAIN}.conf /etc/nginx/sites-enabled/dav.${MYDOMAIN}.conf

	# RoundCube
	echo "${info} Installing RoundCube..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	if [ ${USE_WEBMAIL} == '1' ]; then
		mkdir -p /var/www/mail/rc
		tar xf ~/sources/mailcow/roundcube/inst/1.1.3.tar -C ~/sources/mailcow/roundcube/inst/
		cp -R ~/sources/mailcow/roundcube/inst/1.1.3/* /var/www/mail/rc/
		cp -R ~/sources/mailcow/roundcube/conf/* /var/www/mail/rc/
		sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" /var/www/mail/rc/plugins/password/config.inc.php
		sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" /var/www/mail/rc/plugins/password/config.inc.php
		sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" /var/www/mail/rc/plugins/password/config.inc.php
		sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /var/www/mail/rc/plugins/password/config.inc.php
		sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/my_rcuser/${MYSQL_RCDB_USER}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/my_rcpass/${MYSQL_RCDB_PASS}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/my_rcdb/${MYSQL_RCDB_NAME}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/conf_rcdeskey/$(generatepw)/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYDOMAIN}/g" /var/www/mail/rc/config/config.inc.php
		mysql -u${MYSQL_RCDB_USER} -p${MYSQL_RCDB_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_RCDB_NAME} < /var/www/mail/rc/SQL/mysql.initial.sql
		chown -R www-data: /var/www/mail/rc
		rm -rf ~/sources/mailcow/roundcube/inst/1.1.3
		rm -rf /var/www/mail/rc/installer/

		# Create Nginx Config
		cat > /etc/nginx/sites-custom/roundcube.conf <<END
location /mail {
    alias /var/www/mail/rc;
    index index.php;

    location ~ ^/mail/(.+\.php)$ {
        alias /var/www/mail/rc/\$1;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        include fastcgi_params;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME /var/www/mail/rc/\$1;
        fastcgi_pass unix:/var/run/php5-fpm-mail.sock;
    }

    location ~* ^/mail/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
        alias /var/www/mail/rc/\$1;
    }
}

location ~ ^/(mail/temp|mail/SQL|mail/config|mail/logs)/ {
    deny all;
    return 301 /mail;
}
END
	fi

	# Rsyslogd
	if [[ -d /etc/rsyslog.d ]]; then
		rm /etc/rsyslog.d/10-fufix >/dev/null 2>&1
		cp ~/sources/mailcow/rsyslog/conf/10-mailcow /etc/rsyslog.d/
		service rsyslog restart >/dev/null 2>&1
		postlog -p warn dummy >/dev/null 2>&1
		postlog -p info dummy >/dev/null 2>&1
		postlog -p err dummy >/dev/null 2>&1
	fi
fi

}

source ~/userconfig.cfg
