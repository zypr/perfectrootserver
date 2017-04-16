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
################################################################
################## ATTENTION ! NOT UP TO DATE ##################
################## ATTENTION ! NOT UP TO DATE ##################
############################ 04.2017 ###########################
################################################################
# >>> -.. ---     -. --- -     ..- ... .     .. -     -·-·--<<< #
#----------------------------------------------------------------------#
#-------------------DO NOT EDIT SOMETHING BELOW THIS-------------------#
#----------------------------------------------------------------------#

piwikinstall() {
echo "${info} Installing Prestashop" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

if [ ${USE_PIWIK} == '1' ]; then

# Check if Perfectrootserver Script is installed
if [ ! -f /root/credentials.txt ]; then
    echo "${error} Can not find file /root/credentials.txt!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 0
fi

touch  /root/logs/stderrorPIWIK.log 
touch /root/logs/stdoutPIWIK.log


cd /usr/local/ >>/root/logs/stderrorPIWIK.log 2>&1 >>/root/logs/stdoutPIWIK.log
wget https://builds.piwik.org/piwik.zip >>/root/logs/stderrorPIWIK.log 2>&1 >>/root/logs/stdoutPIWIK.log
unzip piwik.zip >>/root/logs/stderrorPIWIK.log 2>&1 >>/root/logs/stdoutPIWIK.log
rm -rf piwik.zip >>/root/logs/stderrorPIWIK.log 2>&1 >>/root/logs/stdoutPIWIK.log

cat > /etc/nginx/sites-custom/piwik.conf <<END
location /piwik {
    #auth_basic "Restricted";
	#Installationspfad
    alias /usr/local/piwik;
    index index.php;
	
	#allow   127.0.0.1;
	#allow   127.0.0.1;
	#deny    all;

    location ~ ^/piwik/(.+\.php)$ {
        alias /usr/local/piwik/$1;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        include fastcgi_params;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME /usr/local/piwik/$1;
        fastcgi_pass unix:/var/run/php5-fpm.sock;
    }

    location ~* ^/piwik/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
        alias /usr/local/piwik/$1;
    }

    location ~ ^/piwik/save/ {
        deny all;
    }

    location ~ ^/piwik/upload/ {
        deny all;
    }
}
END

if [ ${USE_PHP7} == '1' ] && [ ${USE_PHP5} == '0' ]; then

	sed -i 's/fastcgi_pass unix:\/var\/run\/php5-fpm.sock\;/fastcgi_pass unix:\/var\/run\/php\/php7.0-fpm.sock\;/g' /etc/nginx/sites-available/${MYDOMAIN}.conf

	#fastcgi_pass unix:\/var\/run\/php5-fpm.sock;

	#fastcgi_pass unix:\/var\/run\/php\/php7.0-fpm.sock;
fi

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


sed 's/;always_populate_raw_post_data = -1/always_populate_raw_post_data = -1/' /etc/php5/fpm/php.ini >>/root/logs/stderrorPIWIK.log 2>&1 >>/root/logs/stdoutPIWIK.log



#Restarting services
if [ ${USE_PHP7} == '1' ]; then
		systemctl restart {nginx,php7.0-fpm} >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
fi

if [ ${USE_PHP5} == '1' ]; then
		systemctl restart {nginx,php5-fpm} >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
fi


fi # End var USE_PIWIK
}
source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg
