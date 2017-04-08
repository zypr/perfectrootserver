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

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

roundcube() {
echo "${info} Installing Roundcube..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

#Create Database
mysql --defaults-file=/etc/mysql/debian.cnf -e "CREATE DATABASE roundcube; GRANT ALL ON roundcube.* TO 'roundcube'@'localhost' IDENTIFIED BY '$ROUNDCUBE_MYSQL_PASS'; FLUSH PRIVILEGES;" >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

#Download from source 
cd /var/www/html
wget https://github.com/roundcube/roundcubemail/releases/download/${ROUNDCUBE_VERSION}/roundcubemail-${ROUNDCUBE_VERSION}-complete.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
mkdir -p /var/www/html/webmail
tar zxvf roundcubemail-${ROUNDCUBE_VERSION}-complete.tar.gz -C /var/www/html/webmail >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
mv /var/www/html/webmail/roundcubemail*/* /var/www/html/webmail
rm roundcubemail-${ROUNDCUBE_VERSION}-complete.tar.gz

#Add config
cat >> /var/www/html/webmail/config/config.inc.php << 'EOF1'
<?php
$config = array();
$config['db_dsnw'] = 'mysql://roundcube:changeme@localhost/roundcube';
/* Auch lokal wird mit TLS gearbeitet (Stichwort: Sniffer) 
Der FQDN sollte "localhost" vorgezogen werden (Zertifikatsvalidierung) */
$config['default_host'] = 'tls://mail.domain.tld';
$config['smtp_server'] = 'tls://mail.domain.tld';
$config['smtp_port'] = 587;
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
$config['support_url'] = '';
$config['product_name'] = $_SERVER['HTTP_HOST'];
/* Roundcube erhält die Möglichkeit, ACLs und Sieve Filter durch Plugins zu verwalten. */
$config['plugins'] = array(
	'acl',
	'managesieve',
);
$config['login_autocomplete'] = 2;
$config['imap_cache'] = 'apc';
$config['username_domain'] = '%d';
$config['default_list_mode'] = 'threads';
$config['preview_pane'] = true;
/* Da ein selbst-signiertes Zertifikat verwendet wird, gestaltet sich
die Zertifikatsvalidierung weniger restriktiv */
$config['imap_conn_options'] = array(
    'ssl' => array(
      'allow_self_signed' => true,
      'verify_peer'       => false,
      'verify_peer_name'  => false,
    ),
);
$config['smtp_conn_options'] = array(
   'ssl'         => array(
      'allow_self_signed' => true,
      'verify_peer'       => false,
      'verify_peer_name'  => false,
   ),
);
EOF1
sed -i "s/changeme/${ROUNDCUBE_MYSQL_PASS}/g" /var/www/html/webmail/config/config.inc.php
sed -i "s/domain.tld/${MYDOMAIN}/g" /var/www/html/webmail/config/config.inc.php

#Create Roundcube MYSQl Tables
mysql --defaults-file=/etc/mysql/debian.cnf roundcube < /var/www/html/webmail/SQL/mysql.initial.sql >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

#Nginx custom site config 
cat > /etc/nginx/sites-custom/roundcube.conf <<END
location /webmail {
    #auth_basic "Restricted";
    alias /var/www/html/webmail;
    index index.php;
    location ~ ^/webmail/(.+\.php)$ {
        alias /var/www/html/webmail/\$1;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        include fastcgi_params;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME /var/www/html/webmail/\$1;
        fastcgi_pass unix:/var/run/php5-fpm.sock;
    }
    location ~* ^/webmail/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
        alias /var/www/html/webmail/\$1;
    }
    #location ~ ^/webmail/save/ {
    #    deny all;
    #}
    #location ~ ^/webmail/upload/ {
    #    deny all;
    #}
}
END
if [ ${USE_PHP7} == '1' ]; then
	sed -i 's/fastcgi_pass unix:\/var\/run\/php5-fpm.sock\;/fastcgi_pass unix:\/var\/run\/php\/php7.0-fpm.sock\;/g' /etc/nginx/sites-custom/roundcube.conf
fi

chown -R www-data: /var/www/html
chown -R vmail:vmail /var/vmail/ #fix???
}
source ~/configs/userconfig.cfg
source ~/configs/versions.cfg