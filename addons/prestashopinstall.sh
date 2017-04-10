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
#set -x
declare -i USE_PRESTASHOP
USE_PRESTASHOP=1
if [ ${USE_PRESTASHOP} == '1' ]; then




# Important!
PRESTASHOP_VERSION="1.6.1.12"
PRESTASHOPDOMAIN="domain.tld"
PRESTASHOP_OWNER_FIRSTNAME="Perfect"
PRESTASHOP_OWNER_LASTNAME="Rootserver"
PRESTASHOP_OWNER_EMAIL="prestashop@perfectrootserver.de"
PRESTASHOPS_NAME="perfectrootserver script"

# Does not need to be changed
PRESTASHOP_LANGUAGE="de"
PRESTASHOP_COUNTRY="de"
PRESTASHOP_DB_SERVER="localhost"
PRESTASHOP_TIMEZONE="berlin"

#0 or 1
# Does not need to be changed
PRESTASHOP_DB_CLEAR="1"
PRESTASHOP_CREATE_DB="1"
PRESTASHOP_SHOW_LICENSE="0"
PRESTASHOP_NEWSLETTER="1"
PRESTASHOP_SEND_EMAIL="1"






##########################################################################
###################### DO NOT EDIT ANYTHING BELOW! #######################
##########################################################################
#If you change it, the script will maybe broken
# Some nice colors
red() { echo "$(tput setaf 1)$*$(tput setaf 9)"; }
green() { echo "$(tput setaf 2)$*$(tput setaf 9)"; }
yellow() { echo "$(tput setaf 3)$*$(tput setaf 9)"; }
magenta() { echo "$(tput setaf 5)$*$(tput setaf 9)"; }
cyan() { echo "$(tput setaf 6)$*$(tput setaf 9)"; }
textb() { echo $(tput bold)${1}$(tput sgr0); }
greenb() { echo $(tput bold)$(tput setaf 2)${1}$(tput sgr0); }
redb() { echo $(tput bold)$(tput setaf 1)${1}$(tput sgr0); }
yellowb() { echo $(tput bold)$(tput setaf 3)${1}$(tput sgr0); }
pinkb() { echo $(tput bold)$(tput setaf 5)${1}$(tput sgr0); }

# Some nice variables
info="$(textb [INFO] -)"
warn="$(yellowb [WARN] -)"
error="$(redb [ERROR] -)"
fyi="$(pinkb [INFO] -)"
ok="$(greenb [OKAY] -)"


datum=$(date +"%d-%m-%Y_%H_%M_%S")
PATH_TO_WEBFOLDER="/etc/nginx/html"

echo
echo
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo "$(date +"[%T]") |  $(textb Prestashop) $(textb E-Commerce) $(textb System) $(textb installation)"
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo
echo "$(date +"[%T]") | ${info} Welcome to the Perfect Rootserver installation!"
echo "$(date +"[%T]") | ${info} This script install Prestashops E-Commerce System!"
echo "$(date +"[%T]") | ${info} Please wait while the installer is preparing for the first use..."
echo

# --------------------------------------------------------------------------------------------------------------------------------------------------
# Check if Perfectrootserver Script is installed
if [ ! -f /root/credentials.txt ]; then
    echo "${error} Can not find file /root/credentials.txt!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 0
fi
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
install_path="$PATH_TO_WEBFOLDER/$websites_for_prestashop"

echo "$install_path"
cd "$install_path"
dirname="Prestashopinstallationfoldercrypted"


# No! this is the lastest 1.7.x version. NO!
 # if [ "$PRESTASHOP_VERSION" == "" ]; then
   # version=$(curl -s https://api.github.com/repos/PrestaShop/PrestaShop/releases | grep -Po '(?<="tag_name": ")[^"]1.6.1*' | head -n 1)
 # fi

mkdir -p $dirname
echo "${info} Download lastest Prestashop Version" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget -O $install_path/$dirname/prestashop.zip https://download.prestashop.com/download/releases/prestashop_${PRESTASHOP_VERSION}_de.zip
cd $install_path/$dirname
unzip prestashop.zip
rm -rf prestashop.zip

# Do not edit!
DB_USER="root"
DB_PASSWORD=$(grep -Pom 1 "(?<=^password = ).*$" $PATH_TO_PASSWORDS)
PRESTASHOP_DB_NAME="$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 10 | head -n 1)"
PRESTASHOP_CRYPT_PRF="_$(cat /dev/urandom | tr -dc 'a-z' | fold -w 5 | head -n 1)"
PRESTASHOP_DB_ENGINE="InnoDB"


#PRESTASHOP_STRONG_PASSWORD="123456FDSSA"
PRESTASHOP_STRONG_PASSWORD=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')




echo "$PRESTASHOP_CRYPT_PRF"

exit 0

mv $install_path/$dirname/prestashop/* $install_path/$dirname/
rm -rf prestashop
cd install


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
--step


echo "${info} Set permissions." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
cd $install_path/$dirname
  chmod a+w -R config/
  chmod a+w -R cache/
  chmod a+w -R log/
  chmod a+w -R img/
  chmod a+w -R mails/
  chmod a+w -R modules/
  chmod a+w -R themes/default-bootstrap/lang/
  chmod a+w -R themes/default-bootstrap/pdf/lang/
  chmod a+w -R themes/default-bootstrap/cache/
  chmod a+w -R translations/
  chmod a+w -R upload/
  chmod a+w -R download/

echo "${info} Installation complete!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
rm -rf $install_path/$dirname/install

echo
echo
echo "Please note your new Credentials!"
echo
echo "Your Username to Login ist:$PRESTASHOP_OWNER_EMAIL"
echo "Your Password to Login ist:$PRESTASHOP_STRONG_PASSWORD"
echo "Your Domain to Login ist:www.$PRESTASHOPDOMAIN/"



fi # End var USE_PRESTASHOP
