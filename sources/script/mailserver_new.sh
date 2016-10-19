# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow and https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

mailserver() {

if [ ${USE_MAILSERVER} == '1' ]; then
	echo "${info} Installing mailserver..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			/usr/sbin/make-ssl-cert generate-default-snakeoil --force-overwrite
			
echo "${info} Point 1" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'			
			apt-get -y update >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get --force-yes -y install unrar-free rrdtool mailgraph fcgiwrap spawn-fcgi mariadb-client mailutils pyzor razor \
postfix postfix-mysql postfix-pcre postgrey pflogsumm spamassassin spamc sa-compile opendkim opendkim-tools clamav-daemon python-magic openjdk-7-jre-headless solr-jetty

echo "${info} Point 2" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'			
			update-alternatives --set mailx /usr/bin/bsd-mailx --quiet 
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
echo "${info} Point 3" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'	
			install -m 755 ~/sources/mailcow/misc/mailcow-clean-spam-aliases /etc/cron.daily/mailcow-clean-spam-aliases
			install -m 755 ~/sources/mailcow/misc/mailcow-renew-pflogsumm /usr/local/sbin/mailcow-renew-pflogsumm
			install -m 755 ~/sources/mailcow/misc/mailcow-set-message-limit /usr/local/sbin/mailcow-set-message-limit
			install -m 755 ~/sources/mailcow/misc/mailcow-dkim-tool /usr/local/sbin/mailcow-dkim-tool
			install -m 755 ~/sources/mailcow/misc/mailcow-reset-admin /usr/local/sbin/mailcow-reset-admin

echo "${info} Point 4" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
		#ssl
			mkdir /etc/ssl/mail 
			echo "$(textb [INFO]) - Generating 2048 bit DH parameters, this may take a while, please wait..."
			openssl dhparam -out /etc/ssl/mail/dhparams.pem 2048 
			openssl req -new -newkey rsa:4096 -sha256 -days 1095 -nodes -x509 -subj "/C=ZZ/ST=mailcow/L=mailcow/O=mailcow/CN=mail.${MYDOMAIN}/subjectAltName=DNS.1=mail.${MYDOMAIN}" -keyout /etc/ssl/mail/mail.key -out /etc/ssl/mail/mail.crt
			chmod 600 /etc/ssl/mail/mail.key
			cp /etc/ssl/mail/mail.crt /usr/local/share/ca-certificates/
			update-ca-certificates

echo "${info} Point 5" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
		#mysql
			if [[ ${mysql_useable} -ne 1 ]]; then
				if [[ ! -z $(mysql --version | grep '5.7') ]]; then
					# MySQL >= 5.7 uses auth_socket when installing without password (like we do)
					for host in $(mysql --defaults-file=/etc/mysql/debian.cnf mysql -e "select Host from user where User='root';" -BN); do
						mysql --defaults-file=/etc/mysql/debian.cnf -e "ALTER USER 'root'@'${host}' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASS}';"
					done
					mysql --defaults-file=/etc/mysql/debian.cnf -e "FLUSH PRIVILEGES;"
				else
					for host in $(mysql --defaults-file=/etc/mysql/debian.cnf mysql -e "select Host from user where User='root';" -BN); do
						mysql --defaults-file=/etc/mysql/debian.cnf -e "SET PASSWORD FOR 'root'@'${host}' = PASSWORD('${MYSQL_ROOT_PASS}');"
					done
					mysql --defaults-file=/etc/mysql/debian.cnf -e "FLUSH PRIVILEGES;"
				fi
			fi
echo "${info} Point 6" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
			SQLCMDARRAY=(
				"DROP DATABASE IF EXISTS ${MYSQL_MCDB_NAME}"
				"DROP DATABASE IF EXISTS ${MYSQL_RCDB_NAME}"
				"CREATE DATABASE ${MYSQL_MCDB_NAME}"
				"GRANT ALL PRIVILEGES ON ${MYSQL_MCDB_NAME}.* TO '${MYSQL_MCDB_USER}'@'%' IDENTIFIED BY '${MYSQL_MCDB_PASS}'"
			)
				SQLCMDARRAY+=(
					"CREATE DATABASE ${MYSQL_RCDB_NAME}"
					"GRANT ALL PRIVILEGES ON ${MYSQL_RCDB_NAME}.* TO '$MYSQL_RCDB_USER'@'%' IDENTIFIED BY '$MYSQL_RCDB_PASS'"
				)
			SQLCMDARRAY+=("FLUSH PRIVILEGES")
			for ((i = 0; i < ${#SQLCMDARRAY[@]}; i++)); do
				mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} -e "${SQLCMDARRAY[$i]}"
				if [[ $? -eq 1 ]]; then
					echo "$(redb [ERR]) - SQL failed at command '${SQLCMDARRAY[$i]}'"
					exit 1
				fi
			done
			
echo "${info} Point 7" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
		#postfix
			mkdir -p /etc/postfix/sql
			chown root:postfix "/etc/postfix/sql"; chmod 750 "/etc/postfix/sql"
			for file in $(ls ~/sources/mailcow/postfix/conf/sql)
			do
				install -o root -g postfix -m 640 ~/sources/mailcow/postfix/conf/sql/${file} /etc/postfix/sql/${file}
			done
			install -m 644 ~/sources/mailcow/postfix/conf/master.cf /etc/postfix/master.cf
			install -m 644 ~/sources/mailcow/postfix/conf/main.cf /etc/postfix/main.cf
			install -o www-data -g www-data -m 644 ~/sources/mailcow/postfix/conf/mailcow_anonymize_headers.pcre /etc/postfix/mailcow_anonymize_headers.pcre
			install -m 644 ~/sources/mailcow/postfix/conf/postscreen_access.cidr /etc/postfix/postscreen_access.cidr
			install -m 644 ~/sources/mailcow/postfix/conf/smtp_dsn_filter.pcre /etc/postfix/smtp_dsn_filter.pcre
			sed -i "s/sys_hostname.sys_domain/mail.${MYDOMAIN}/g" /etc/postfix/main.cf
			sed -i "s/sys_domain/${MYDOMAIN}/g" /etc/postfix/main.cf
			sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
			sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
			sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
			sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
			sed -i '/^POSTGREY_OPTS=/s/=.*/="--inet=127.0.0.1:10023"/' /etc/default/postgrey
			chmod 755 /var/spool/
			sed -i "/%www-data/d" /etc/sudoers
			sed -i "/%vmail/d" /etc/sudoers
			echo '%www-data ALL=(ALL) NOPASSWD: /usr/sbin/dovecot reload, /usr/sbin/postfix reload, /usr/local/sbin/mailcow-dkim-tool, /usr/local/sbin/mailcow-set-message-limit, /usr/local/sbin/mailcow-renew-pflogsumm, /usr/sbin/postconf -e smtpd_recipient_restrictions*, /usr/sbin/postconf -e smtpd_sender_restrictions*' > /etc/sudoers.d/mailcow
			chmod 440 /etc/sudoers.d/mailcow

echo "${info} Point 8" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
		#fuglu
			if [[ -z $(grep fuglu /etc/passwd) ]]; then
				userdel fuglu
				groupadd fuglu 
				useradd -g fuglu -s /bin/false fuglu
				usermod -a -G debian-spamd fuglu
				usermod -a -G clamav fuglu
			fi
			rm /tmp/fuglu_control.sock
			mkdir /var/log/fuglu
			chown fuglu:fuglu /var/log/fuglu
			tar xf ~/sources/mailcow/fuglu/inst/0.6.6.tar -C ~/sources/mailcow/fuglu/inst/ 
			(cd ~/sources/mailcow/fuglu/inst/0.6.6 ; python setup.py -q install)
			cp -R ~/sources/mailcow/fuglu/conf/* /etc/fuglu/
			cp ~/sources/mailcow/fuglu/inst/0.6.6/scripts/startscripts/debian/8/fuglu.service /etc/systemd/system/fuglu.service
			systemctl disable fuglu
			[[ -f /lib/systemd/system/fuglu.service ]] && rm /lib/systemd/system/fuglu.service
			systemctl daemon-reload
			systemctl enable fuglu
			rm -rf ~/sources/mailcow/fuglu/inst/0.6.6

echo "${info} Point 9" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
		#dovecot
			systemctl disable dovecot.socket
			if [[ -z $(grep '/var/vmail:' /etc/passwd | grep '5000:5000') ]]; then
				userdel vmail 
				groupdel vmail
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
			
echo "${info} Point 10" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
			sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYDOMAIN}/g" ${DOVEFILES}
			sed -i "s/MAILCOW_DOMAIN/${MYDOMAIN}/g" ${DOVEFILES}
			sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" ${DOVEFILES}
			sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" ${DOVEFILES}
			sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" ${DOVEFILES}
			sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" ${DOVEFILES}
			sed -i "s/MAILCOW_HASHING/SHA512-CRYPT/g" ${DOVEFILES}
			
echo "${info} Point 11" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
			mkdir /etc/dovecot/conf.d 
			mkdir -p /var/vmail/sieve 
			mkdir -p /var/vmail/public 
			if [ ! -f /var/vmail/public/dovecot-acl ]; then
				echo "anyone lrwstipekxa" > /var/vmail/public/dovecot-acl
			fi
			
echo "${info} Point 12" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
			install -m 644 ~/sources/mailcow/dovecot/conf/global.sieve /var/vmail/sieve/global.sieve
			touch /var/vmail/sieve/default.sieve
			sievec /var/vmail/sieve/global.sieve
			chown -R vmail:vmail /var/vmail
			[[ -f /etc/cron.daily/doverecalcq ]] && rm /etc/cron.daily/doverecalcq
			install -m 755 ~/sources/mailcow/dovecot/conf/dovemaint /etc/cron.daily/
			install -m 644 ~/sources/mailcow/dovecot/conf/solrmaint /etc/cron.d/
			
echo "${info} Point 13" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
			update-rc.d -f solr remove 
			service solr stop
			[[ -f /usr/share/doc/dovecot-core/dovecot/solr-schema.xml ]] && cp /usr/share/doc/dovecot-core/dovecot/solr-schema.xml /etc/solr/conf/schema.xml
			[[ -f /usr/share/dovecot/solr-schema.xml ]] && cp /usr/share/dovecot/solr-schema.xml /etc/solr/conf/schema.xml
			sed -i '/NO_START/c\NO_START=0' /etc/default/jetty8
                        sed -i '/JETTY_HOST/c\JETTY_HOST=127.0.0.1' /etc/default/jetty8
			sed -i '/JETTY_PORT/c\JETTY_PORT=8983' /etc/default/jetty8
			
		#clamav
echo "${info} Point 14" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'			
			usermod -a -G vmail clamav 
			if [[ -f /etc/apparmor.d/usr.sbin.clamd || -f /etc/apparmor.d/local/usr.sbin.clamd ]]; then
				rm /etc/apparmor.d/usr.sbin.clamd 
				rm /etc/apparmor.d/local/usr.sbin.clamd
				service apparmor restart
			fi
			sed -i '/MaxFileSize/c\MaxFileSize 10M' /etc/clamav/clamd.conf
			sed -i '/StreamMaxLength/c\StreamMaxLength 10M' /etc/clamav/clamd.conf

echo "${info} Point 15" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
		#opendkim
			echo 'SOCKET="inet:10040@localhost"' > /etc/default/opendkim
			mkdir -p /etc/opendkim/{keyfiles,dnstxt}
			touch /etc/opendkim/{KeyTable,SigningTable}
			install -m 644 ~/sources/mailcow/opendkim/conf/opendkim.conf /etc/opendkim.conf

echo "${info} Point 16" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
		#spamassassin
			cp ~/sources/mailcow/spamassassin/conf/local.cf /etc/spamassassin/local.cf
			if [[ ! -f /etc/spamassassin/local.cf.include ]]; then
                        	cp ~/sources/mailcow/spamassassin/conf/local.cf.include /etc/spamassassin/local.cf.include
                        fi
			sed -i '/^OPTIONS=/s/=.*/="--create-prefs --max-children 5 --helper-home-dir --username debian-spamd --socketpath \/var\/run\/spamd.sock --socketowner debian-spamd --socketgroup debian-spamd --sql-config --nouser-config"/' /etc/default/spamassassin
			sed -i '/^CRON=/s/=.*/="1"/' /etc/default/spamassassin
			sed -i '/^ENABLED=/s/=.*/="1"/' /etc/default/spamassassin
			sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" /etc/spamassassin/local.cf
			sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" /etc/spamassassin/local.cf
			sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" /etc/spamassassin/local.cf
			sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /etc/spamassassin/local.cf
			# Thanks to mf3hd@GitHub
			[[ -z $(grep RANDOM_DELAY /etc/crontab) ]] && sed -i '/SHELL/a RANDOM_DELAY=30' /etc/crontab
			install -m 755 ~/sources/mailcow/spamassassin/conf/spamlearn /etc/cron.daily/spamlearn
			install -m 755 ~/sources/mailcow/spamassassin/conf/spamassassin_heinlein /etc/cron.daily/spamassassin_heinlein
			# Thanks to mf3hd@GitHub, again!
			chmod g+s /etc/spamassassin
			chown -R debian-spamd: /etc/spamassassin
			chmod 600 /etc/spamassassin/local.cf
			razor-admin -create -home /etc/razor -conf=/etc/razor/razor-agent.conf
			razor-admin -discover -home /etc/razor
			razor-admin -register -home /etc/razor
			su debian-spamd -c "pyzor --homedir /etc/mail/spamassassin/.pyzor discover"
			su debian-spamd -c "sa-update"
			if [[ -f /lib/systemd/systemd ]]; then
				systemctl enable spamassassin
			fi

echo "${info} Point 17" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
		#webserver
			mkdir -p /var/www/ 
				# Some systems miss the default php fpm listener, reinstall it now
				apt-get -o Dpkg::Options::="--force-confmiss" install -y --reinstall php5-fpm > /dev/null
				rm /etc/nginx/sites-enabled/*mailcow* 2>/dev/null
				cp ~/sources/mailcow/webserver/nginx/conf/sites-available/mailcow_rc /etc/nginx/sites-available/mailcow.conf
				cp ~/sources/mailcow/webserver/php-fpm/conf/5/pool/mail.conf /etc/php5/fpm/pool.d/mail.conf
				cp ~/sources/mailcow/webserver/php-fpm/conf/5/php-fpm.conf /etc/php5/fpm/php-fpm.conf
				sed -i "/date.timezone/c\php_admin_value[date.timezone] = ${sys_timezone}" /etc/php5/fpm/pool.d/mail.conf
				ln -s /etc/nginx/sites-available/mailcow.conf /etc/nginx/sites-enabled/mailcow.conf 2>/dev/null
				[[ ! -z $(grep "server_names_hash_bucket_size" /etc/nginx/nginx.conf) ]] && \
					sed -i "/server_names_hash_bucket_size/c\ \ \ \ \ \ \ \ server_names_hash_bucket_size 64;" /etc/nginx/nginx.conf || \
					sed -i "/http {/a\ \ \ \ \ \ \ \ server_names_hash_bucket_size 64;" /etc/nginx/nginx.conf
				sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN;/${sys_hostname}.${sys_domain};/g" /etc/nginx/sites-available/mailcow.conf
				sed -i "s/MAILCOW_DOMAIN;/${sys_domain};/g" /etc/nginx/sites-available/mailcow.conf
			mkdir /var/lib/php5/sessions 
			cp -R ~/sources/mailcow/webserver/htdocs/mail /var/www/
			find /var/www/mail -type d -exec chmod 755 {} \;
			find /var/www/mail -type f -exec chmod 644 {} \;
			echo none > /var/log/pflogsumm.log
			sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /var/www/mail/inc/vars.inc.php
			sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" /var/www/mail/inc/vars.inc.php
			sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" /var/www/mail/inc/vars.inc.php
			sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" /var/www/mail/inc/vars.inc.php
			sed -i "s/MAILCOW_HASHING/SHA512-CRYPT/g" /var/www/mail/inc/vars.inc.php
			chown -R www-data: /var/www/mail/. /var/lib/php5/sessions
			
echo "${info} Point 18" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
			mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} < ~/sources/mailcow/webserver/htdocs/init.sql
			if [[ -z $(mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "SHOW COLUMNS FROM domain LIKE 'relay_all_recipients';" -N -B) ]]; then
				mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "ALTER TABLE domain ADD relay_all_recipients tinyint(1) NOT NULL DEFAULT '0';" -N -B
			fi
			if [[ -z $(mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "SHOW COLUMNS FROM mailbox LIKE 'tls_enforce_in';" -N -B) ]]; then
				mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "ALTER TABLE mailbox ADD tls_enforce_in tinyint(1) NOT NULL DEFAULT '0';" -N -B
				mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "ALTER TABLE mailbox ADD tls_enforce_out tinyint(1) NOT NULL DEFAULT '0';" -N -B
			fi
			mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "DELETE FROM spamalias"
			mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "ALTER TABLE spamalias MODIFY COLUMN validity int(11) NOT NULL"
			if [[ $(mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -s -N -e "SELECT * FROM admin;" | wc -l) -lt 1 ]]; then
				mailcow_admin_pass_hashed=$(doveadm pw -s SHA512-CRYPT -p ${mailcow_admin_pass})
				mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "INSERT INTO admin VALUES ('$mailcow_admin_user','${mailcow_admin_pass_hashed}', '1', NOW(), NOW(), '1');"
				mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "INSERT INTO domain_admins (username, domain, created, active) VALUES ('$mailcow_admin_user', 'ALL', NOW(), '1');"
			else
				echo "$(textb [INFO]) - An administrator exists, will not create another mailcow administrator"
			fi

echo "${info} Point 19" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
		#roundcube
			mkdir -p /var/www/mail/rc
			tar xf ~/sources/mailcow/roundcube/inst/1.2.1.tar -C ~/sources/mailcow/roundcube/inst/
			cp -R ~/sources/mailcow/roundcube/inst/1.2.1/* /var/www/mail/rc/
				cp -R ~/sources/mailcow/roundcube/conf/* /var/www/mail/rc/
				sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /var/www/mail/rc/config/config.inc.php
				sed -i "s/my_rcuser/${MYSQL_RCDB_USER}/g" /var/www/mail/rc/config/config.inc.php
				sed -i "s/my_rcpass/${MYSQL_RCDB_PASS}/g" /var/www/mail/rc/config/config.inc.php
				sed -i "s/my_rcdb/${MYSQL_RCDB_NAME}/g" /var/www/mail/rc/config/config.inc.php
				sed -i "s/conf_rcdeskey/$(generatepw)/g" /var/www/mail/rc/config/config.inc.php
				sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYDOMAIN}/g" /var/www/mail/rc/config/config.inc.php
				mysql --host ${MYSQL_HOSTNAME} -u ${MYSQL_RCDB_USER} -p${MYSQL_RCDB_PASS} ${MYSQL_RCDB_NAME} < /var/www/mail/rc/SQL/mysql.initial.sql
			chown -R www-data: /var/www/mail/rc
			rm -rf roundcube/inst/1.2.1
			rm -rf /var/www/mail/rc/installer/

echo "${info} Point 20" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'				
		#restartservices
			[[ -f /lib/systemd/systemd ]] && echo "$(textb [INFO]) - Restarting services, this may take a few seconds..."
			
			for var in jetty8 nginx php5-fpm spamassassin fuglu dovecot postfix opendkim clamav-daemon mailgraph
			do
				service ${var} stop
				sleep 1.5
				service ${var} start
			done	
fi

}

source ~/userconfig.cfg
source ~/checksystem.sh
