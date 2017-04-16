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
prestashopinstall() {


if [ ${USE_PRESTASHOP} == '1' ]; then

# Check if Perfectrootserver Script is installed
if [ ! -f /root/credentials.txt ]; then
    echo "${error} Can not find file /root/credentials.txt!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 0
fi

touch  /root/logs/stderrorPRESTASHOP.log 
touch /root/logs/stdoutPRESTASHOP.log



if [ $PRESTASHOPDOMAIN} == "domain.tld" ]; then
unset $PRESTASHOPDOMAIN
PRESTASHOPDOMAIN=${MYDOMAIN}
fi

# ToDo!
# Check Domain VAR at install / at the moment there is domain.tld/ :/
# Check how to show Adminurl - admin folder is random in root folder like admin....



##########################################################################
###################### DO NOT EDIT ANYTHING BELOW! #######################
##########################################################################
#If you change it, the script will maybe broken


PATH_TO_WEBFOLDER="/etc/nginx/html"

# --------------------------------------------------------------------------------------------------------------------------------------------------

datum=$(date +"%d-%m-%Y_%H_%M_%S")
PATH_TO_PASSWORDS="/root/credentials.txt"
MYSQL_PASSWORD=$(grep -Pom 1 "(?<=^password = ).*$" $PATH_TO_PASSWORDS)
MYSQL=/usr/bin/mysql
MYSQLDUMP=/usr/bin/mysqldump


echo "${info} Prestashop installation Script is loading..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
cd $PATH_TO_WEBFOLDER
folders=`for i in $(ls -d */ | grep -Ev "(backups)"); do echo ${i%%/}; done`


		echo "${info} Please choose a Website for Prestashop:" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		select websites_for_prestashop in $folders;
		do
			 echo "You picked $websites_for_prestashop."
			 break
		done
PRESTASHOPDOMAIN="$websites_for_prestashop"		
install_path="$PATH_TO_WEBFOLDER/$websites_for_prestashop"

echo "$install_path"
cd "$install_path"
dirname="$PRESTASHOP_INSTALL_FOLDER_NAME"


# No! this is the lastest 1.7.x version. NO! Not yet!
 # if [ "$PRESTASHOP_VERSION" == "" ]; then
   # version=$(curl -s https://api.github.com/repos/PrestaShop/PrestaShop/releases | grep -Po '(?<="tag_name": ")[^"]1.6.1*' | head -n 1)
 # fi

mkdir -p $dirname
echo "${info} Download Prestashop Version: $PRESTASHOP_VERSION" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget -O $install_path/$dirname/prestashop.zip https://download.prestashop.com/download/releases/prestashop_${PRESTASHOP_VERSION}_de.zip >>/root/logs/stderrorPRESTASHOP.log 2>&1 >>/root/logs/stdoutPRESTASHOP.log
cd $install_path/$dirname
unzip prestashop.zip >>/root/logs/stderrorPRESTASHOP.log 2>&1 >>/root/logs/stdoutPRESTASHOP.log
rm -rf prestashop.zip >>/root/logs/stderrorPRESTASHOP.log 2>&1 >>/root/logs/stdoutPRESTASHOP.log





# Do not edit!
DB_USER="root"
DB_PASSWORD=$(grep -Pom 1 "(?<=^password = ).*$" $PATH_TO_PASSWORDS)

# ToDo
# Add new sql user
#mysql -u "root" -p"$DB_PASSWORD" <<MYSQL_SCRIPT
#CREATE DATABASE $PRESTASHOP_DB_NAME;
#CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$PASS';
#GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, CREATE TEMPORARY TABLES ON drupal.* TO '$DB_USER'@'localhost';
#FLUSH PRIVILEGES;
#MYSQL_SCRIPT


PRESTASHOP_DB_NAME="$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 10 | head -n 1)"
PRESTASHOP_CRYPT_PRF="_$(cat /dev/urandom | tr -dc 'a-z' | fold -w 5 | head -n 1)"
PRESTASHOP_DB_ENGINE="InnoDB"

PRESTASHOP_STRONG_PASSWORD=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')

mv $install_path/$dirname/prestashop/* $install_path/$dirname/ >>/root/logs/stderrorPRESTASHOP.log 2>&1 >>/root/logs/stdoutPRESTASHOP.log
rm -rf prestashop >>/root/logs/stderrorPRESTASHOP.log 2>&1 >>/root/logs/stdoutPRESTASHOP.log
cd install >>/root/logs/stderrorPRESTASHOP.log 2>&1 >>/root/logs/stdoutPRESTASHOP.log

echo "${info} Start installation" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
php index_cli.php --language=${PRESTASHOP_LANGUAGE} \
--timezone=${PRESTASHOP_TIMEZONE} \
--domain=${PRESTASHOPDOMAIN} \
--db_server=${PRESTASHOP_DB_SERVER} \
--db_user=${DB_USER} \
--db_password=${DB_PASSWORD} \
--db_name=${PRESTASHOP_DB_NAME} \
--db_clear=${PRESTASHOP_DB_CLEAR} \
--db_create=${PRESTASHOP_CREATE_DB} \
--prefix=${PRESTASHOP_CRYPT_PRF} \
--engine=${PRESTASHOP_DB_ENGINE} \
--name=${PRESTASHOPS_NAME} \
--country=${PRESTASHOP_COUNTRY} \
--firstname=${PRESTASHOP_OWNER_FIRSTNAME} \
--lastname=${PRESTASHOP_OWNER_LASTNAME} \
--password=${PRESTASHOP_STRONG_PASSWORD} \
--email=${PRESTASHOP_OWNER_EMAIL} \
--license=${PRESTASHOP_SHOW_LICENSE} \
--newsletter=${PRESTASHOP_NEWSLETTER} \
--send_email=${PRESTASHOP_SEND_EMAIL} \
--step >>/root/logs/stderrorPRESTASHOP.log 2>&1 >>/root/logs/stdoutPRESTASHOP.log


echo "${info} Set permissions." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
cd "$install_path/$dirname"

find "$install_path/$dirname/" -type d -exec chmod 755 {} \; >>/root/logs/stderrorPRESTASHOP.log 2>&1 >>/root/logs/stdoutPRESTASHOP.log
find "$install_path/$dirname/" -type f -exec chmod 644 {} \; >>/root/logs/stderrorPRESTASHOP.log 2>&1 >>/root/logs/stdoutPRESTASHOP.log

echo "${info} Installation complete!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
rm -rf $install_path/$dirname/install >>/root/logs/stderrorPRESTASHOP.log 2>&1 >>/root/logs/stdoutPRESTASHOP.log

echo
echo
echo "Please note your new Credentials!"
echo
echo "Your Username to Login ist:$PRESTASHOP_OWNER_EMAIL"
echo "Your Password to Login ist:$PRESTASHOP_STRONG_PASSWORD"
echo "Your Domain to Login ist:www.$PRESTASHOPDOMAIN/"



fi # End var USE_PRESTASHOP
}
source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg
