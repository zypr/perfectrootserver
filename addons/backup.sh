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

##########################################################################
###################### DO NOT EDIT ANYTHING BELOW! #######################
##########################################################################

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

echo
echo
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo "$(date +"[%T]") |  $(textb Perfect) $(textb Rootserver) $(textb Backup) $(textb script)"
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo
echo "$(date +"[%T]") | ${info} Welcome to the Perfect Rootserver Backupscript!"
echo "$(date +"[%T]") | ${info} This script creates an Backup"
echo "$(date +"[%T]") | ${info} Please wait while the Script is create and Backup"


# --------------------------------------------------------------------------------------------------------------------------------------------------

# Variable deklarieren
datum=$(date +"%d-%m-%Y_%H_%M_%S")
PATH_TO_PASSWORDS="/root/credentials.txt"
PATH_TO_WEBFOLDER="/etc/nginx/html"
BACKUP_PATH="/etc/nginx/html/backups/$datum"
MYSQL_USER="root"

MAX_SPACE=$(df -Th /dev/sda3 | tail -1 | awk '{print $3}' | sed '$s/.$//')
USED_SPACE=$(df -Th /dev/sda3 | tail -1 | awk '{print $4}' | sed '$s/.$//')
FREE_SPACE=$(df -Th /dev/sda3 | tail -1 | awk '{print $5}' | sed '$s/.$//')
USED_HTML_SPACE=$(du -hs /etc/nginx/html/ | tail -1 | awk '{print $1}' | sed '$s/.$//')



# --------------------------------------------------------------------------------------------------------------------------------------------------

#Lese Db passwort aus und speichere es
#Todo: Explizites aufsuchen des 1. Treffers
MYSQL_PASSWORD=$(grep -Pom 1 "(?<=^password = ).*$" $PATH_TO_PASSWORDS)
MYSQL=/usr/bin/mysql
MYSQLDUMP=/usr/bin/mysqldump

# --------------------------------------------------------------------------------------------------------------------------------------------------
# ToDo
# Check disk space !

# --------------------------------------------------------------------------------------------------------------------------------------------------

# Check if Perfectrootserver Script is installed
if [ ! -f /root/credentials.txt ]; then
    echo "${error} Can not find file /root/credentials.txt!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 0
fi


echo "$(date +"[%T]") | ${info} Free Diskspace is: $FREE_SPACE GB"
echo "$(date +"[%T]") | ${info} Used Diskspace is: $USED_SPACE GB"
echo "$(date +"[%T]") | ${info} Max Diskspace is: $MAX_SPACE GB"
echo "$(date +"[%T]") | ${info} FTP Folder Space is: $USED_HTML_SPACE GB"

if [ "$USED_SPACE" -gt "$FREE_SPACE" ]; then
    echo "${error} You have not enough Disk Space!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 0
fi

# --------------------------------------------------------------------------------------------------------------------------------------------------

mkdir -p $BACKUP_PATH
mkdir -p $BACKUP_PATH/DATABESES
mkdir -p $BACKUP_PATH/FTPBACKUP
mkdir -p /root/logs/

touch /root/logs/stdoutBACKUP.log
touch /root/logs/stderrorBACKUP.log

# --------------------------------------------------------------------------------------------------------------------------------------------------


echo "${info} Start MySql Backup" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
databases=`$MYSQL --user=$MYSQL_USER -p$MYSQL_PASSWORD -e "SHOW DATABASES;" | grep -Ev "(Database|mysql|information_schema|performance_schema)"`

for db in $databases; do
echo "${info} Backup Database $db" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
  $MYSQLDUMP --force --opt --user=$MYSQL_USER -p$MYSQL_PASSWORD --databases $db | gzip > "$BACKUP_PATH/DATABESES/$db-$datum.tgz"
done

# --------------------------------------------------------------------------------------------------------------------------------------------------

echo "${info} Start create FILE Backup." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
cd $PATH_TO_WEBFOLDER
# ToDo:
# fix folders var and dont use ls
folders=`for i in $(ls -d */ | grep -Ev "(backups)"); do echo ${i%%/}; done`
for ftp in $folders; do
cd $ftp
echo "${info} Compress folder $ftp." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
  #tar -cvvzf $ftp-$datum.tar.gz *
  tar -cvvzf "$BACKUP_PATH/FTPBACKUP/$ftp-$datum.tgz" * >>/root/logs/stderrorBACKUP.log 2>&1 >>/root/logs/stdoutBACKUP.log
  cd $PATH_TO_WEBFOLDER
done
cd /root
# --------------------------------------------------------------------------------------------------------------------------------------------------

# ToDo
# Check old backup files
# Delete files older than 30 days
#find $BACKUP_PATH/* -mtime +30 -exec rm {} \;


#Backup, in die install einfügen
# http://www.sysadminslife.com/linux/cronjob-unter-debian-und-ubuntu-erstellen/
#crontab -e
#00 20 * * * /path/to/backup.sh

echo "${ok} Backup finished!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
