#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

piwikinstall() {


cd /usr/local/
wget https://builds.piwik.org/piwik.zip
unzip piwik.zip
rm -rf piwik.zip

cat > /etc/nginx/sites-custom/piwik.conf <<END
location /piwik {
    #auth_basic "Restricted";
	#Installationspfad
    alias /usr/local/piwik;
    index index.php;

    location ~ ^/piwik/(.+\.php)$ {
        alias /usr/local/piwik/$1;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        include fastcgi_params;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME /usr/local/piwik/$1;
        fastcgi_pass unix:/var/run/php5-fpm.sock;
    }
}

END

mkdir -p /usr/local/piwik/tmp/assets/
mkdir -p /usr/local/piwik/tmp/cache/
mkdir -p /usr/local/piwik/tmp/logs/
mkdir -p /usr/local/piwik/tmp/tcpdf/
mkdir -p /usr/local/piwik/tmp/templates_c/

chown -R www-data:www-data /usr/local/piwik
chmod -R 0755 /usr/local/piwik/tmp
chmod -R 0755 /usr/local/piwik/tmp/assets/
chmod -R 0755 /usr/local/piwik/tmp/cache/
chmod -R 0755 /usr/local/piwik/tmp/logs/
chmod -R 0755 /usr/local/piwik/tmp/tcpdf/
chmod -R 0755 /usr/local/piwik/tmp/templates_c/


sed 's/;always_populate_raw_post_data = -1/always_populate_raw_post_data = -1/' /etc/php5/fpm/php.ini

service nginx restart
service php5-fpm restart


}