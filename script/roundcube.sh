#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

roundcube() {
echo "${info} Installing Roundcube..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

mkdir -p /var/www/mail/rc
cd /var/www/mail/rc
wget https://github.com/roundcube/roundcubemail/releases/download/${ROUNDCUBE_VERSION}/roundcubemail-${ROUNDCUBE_VERSION}-complete.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
tar zxvf roundcubemail-${ROUNDCUBE_VERSION}-complete.tar.gz -C /var/www/mail/rc/ >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
mv /var/www/mail/rc/roundcubemail*/* /var/www/mail/rc/
cp -R ~/files/mailcow/roundcube/conf/* /var/www/mail/rc/
sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" /var/www/mail/rc/plugins/password/config.inc.php
sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" /var/www/mail/rc/plugins/password/config.inc.php
sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" /var/www/mail/rc/plugins/password/config.inc.php
sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /var/www/mail/rc/plugins/password/config.inc.php
sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /var/www/mail/rc/config/config.inc.php
sed -i "s/my_rcuser/${MYSQL_RCDB_USER}/g" /var/www/mail/rc/config/config.inc.php
sed -i "s/my_rcpass/${MYSQL_RCDB_PASS}/g" /var/www/mail/rc/config/config.inc.php
sed -i "s/my_rcdb/${MYSQL_RCDB_NAME}/g" /var/www/mail/rc/config/config.inc.php
sed -i "s/conf_rcdeskey/$(generatepw)/g" /var/www/mail/rc/config/config.inc.php

mysql -u${MYSQL_RCDB_USER} -p${MYSQL_RCDB_PASS} -h${MYSQL_HOSTNAME} ${MYSQL_RCDB_NAME} < /var/www/mail/rc/SQL/mysql.initial.sql
chown -R www-data: /var/www/mail/rc
 
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

if [ ${USE_PHP7} == '1' ]; then
	sed -i 's/fastcgi_pass unix:\/var\/run\/php5-fpm.sock\;/fastcgi_pass unix:\/var\/run\/php\/php7.0-fpm.sock\;/g' /etc/nginx/sites-custom/roundcube.conf
fi
}
source ~/configs/userconfig.cfg
source ~/configs/versions.cfg