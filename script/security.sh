#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

createpw() {

	apt-get -qq update && apt-get -q -y --force-yes install openssl >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
	
       while [[ $pw == "" ]]; do
               pw=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
       done
       #echo "$pw"
	   unset pw

#Check SSH PORT
declare -A BLOCKED_PORTS='(
        [21]="1"
        [22]="1"
        [25]="1"
        [53]="1"
        [80]="1"
        [143]="1"
        [587]="1"
        [990]="1"
        [993]="1"
        [443]="1"
        [2008]="1"
        [10011]="1"
        [30033]="1"
        [41144]="1")'


if [ ${SSH_PORT} == 'generateport' ]; then

    #Generate SSH Port
    randomNumber="$(($RANDOM % 1023))"

    #return a string
    SSH_PORT=$([[ ! -n "${BLOCKED_PORTS["$randomNumber"]}" ]] && printf "%s\n" "$randomNumber")
    sed -i "s/SSH_PORT=\"generateport\"/SSH_PORT=\"$SSH_PORT\"/g" ~/configs/userconfig.cfg

else
    if [[ ${SSH_PORT} =~ ^-?[0-9]+$ ]]; then

                if [[ -v BLOCKED_PORTS[$SSH_PORT] ]]; then
					echo "$SSH_PORT is known. Choose an other Port!"
					exit 1
				else
					#You can use this Port
					echo "${ok} Great, your Port is $SSH_PORT" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				fi

            else
                echo "${error} SSH Port is not an integer, chose another one!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
                exit 1
    fi
fi
#End Check SSH PORT


#Generate Passwords
if [ ${SSH_PASS} == "generatepw" ]; then
	   SSH_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')

  	 sed -i "s/SSH_PASS=\"generatepw\"/SSH_PASS=\"$SSH_PASS\"/g" ~/configs/userconfig.cfg
fi

if [ ${POSTFIX_ADMIN_PASS} == "generatepw" ]; then
	   POSTFIX_ADMIN_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')

  	 sed -i "s/POSTFIX_ADMIN_PASS=\"generatepw\"/POSTFIX_ADMIN_PASS=\"$POSTFIX_ADMIN_PASS\"/g" ~/configs/userconfig.cfg
fi

if [ ${VIMB_MYSQL_PASS} == "generatepw" ]; then
	   VIMB_MYSQL_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')

  	 sed -i "s/VIMB_MYSQL_PASS=\"generatepw\"/VIMB_MYSQL_PASS=\"$VIMB_MYSQL_PASS\"/g" ~/configs/userconfig.cfg
fi

if [ ${ROUNDCUBE_MYSQL_PASS} == "generatepw" ]; then
	   ROUNDCUBE_MYSQL_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')

  	 sed -i "s/ROUNDCUBE_MYSQL_PASS=\"generatepw\"/ROUNDCUBE_MYSQL_PASS=\"$ROUNDCUBE_MYSQL_PASS\"/g" ~/configs/userconfig.cfg
fi

if [ ${USE_PMA="1"} == '1' ]; then
  if [ ${PMA_HTTPAUTH_PASS} == 'generatepw' ]; then
	   PMA_HTTPAUTH_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
  	 sed -i "s/PMA_HTTPAUTH_PASS=\"generatepw\"/PMA_HTTPAUTH_PASS=\"$PMA_HTTPAUTH_PASS\"/g" ~/configs/userconfig.cfg
  fi

  if [ ${PMA_BFSECURE_PASS} == 'generatepw' ]; then
	   PMA_BFSECURE_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
  	 sed -i "s/PMA_BFSECURE_PASS=\"generatepw\"/PMA_BFSECURE_PASS=\"$PMA_BFSECURE_PASS\"/g" ~/configs/userconfig.cfg
  fi
fi

if [ ${MYSQL_ROOT_PASS} == 'generatepw' ]; then
	   MYSQL_ROOT_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')

  	 sed -i "s/MYSQL_ROOT_PASS=\"generatepw\"/MYSQL_ROOT_PASS=\"$MYSQL_ROOT_PASS\"/g" ~/configs/userconfig.cfg
fi

if [ ${MYSQL_PMADB_PASS} == 'generatepw' ]; then
	   MYSQL_PMADB_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
  	 sed -i "s/MYSQL_PMADB_PASS=\"generatepw\"/MYSQL_PMADB_PASS=\"$MYSQL_PMADB_PASS\"/g" ~/configs/userconfig.cfg
fi

}

source ~/configs/userconfig.cfg
