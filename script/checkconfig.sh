#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

checkconfig() {

	echo "${info} Checking your configuration..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	for var in TIMEZONE MYDOMAIN SSH_PORT SSH_PASS USE_VALID_SSL SSLMAIL USE_MAILSERVER USE_PHP5 USE_PHP7 USE_WEBMAIL POSTFIX_ADMIN_PASS VIMB_MYSQL_PASS ROUNDCUBE_MYSQL_PASS USE_PMA PMA_HTTPAUTH_USER PMA_HTTPAUTH_PASS PMA_BFSECURE_PASS PMA_RESTRICT MYSQL_ROOT_PASS MYSQL_PMADB_NAME MYSQL_PMADB_USER MYSQL_PMADB_PASS MYSQL_HOSTNAME CLOUDFLARE SET_UP_RSA_KEY ALLOWHTTPCONNECTIONS DEBUG_IS_SET                 
	do
		if [[ -z ${!var} ]]; then
			echo "${error} Parameter $(textb ${var}) must not be empty." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			exit 1
		fi
	done

	if [ "$CONFIG_COMPLETED" != '1' ]; then
        echo "${error} Please check the userconfig and set a valid value for the variable \"$(textb CONFIG_COMPLETED)\" to continue." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
        exit 1
	fi
	
	if [ ${MYDOMAIN} == 'domain.tld' ]; then
		echo "${error} Please enter a valid Domain!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		exit 1
		fi

	if [ $(dpkg-query -l | grep libcrack2 | wc -l) -ne 1 ]; then
		apt-get update -y >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log && apt-get -y --force-yes install libcrack2 >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
	fi

	for var in ${SSH_PASS} ${POSTFIX_ADMIN_PASS} ${VIMB_MYSQL_PASS} ${ROUNDCUBE_MYSQL_PASS} ${PMA_HTTPAUTH_PASS} ${PMA_BFSECURE_PASS} ${MYSQL_ROOT_PASS} ${MYSQL_PMADB_PASS}
	do
		if echo "${var}" | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])' >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log; then
			if [[ "$(awk -F': ' '{ print $2}' <<<"$(cracklib-check <<<"${var}")")" == "OK" ]]; then
				echo >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
			else
				echo "${error} One of your passwords was rejected!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				echo "${info} Your password must be a minimum of 8 characters and must include at least 1 number, 1 uppercase and 1 lowercase letter." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				echo "${info} Recommended password settings: Leave \`generatepw\` to generate a strong password." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				echo
				while true; do
					echo "${info} Press $(textb ENTER) to show the weak password or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
					stopit="stop"
					read -s -n 1 i
					case $i in
					* ) echo;echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "$(cracklib-check <<<\"${var}\")" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo;break;;
					esac
				done
			fi
		else
			echo "${error} One of your passwords is too weak." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			echo "${info} Your password must be a minimum of 8 characters and must include at least 1 number, 1 uppercase and 1 lowercase letter." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			echo "${info} Recommended password settings: Leave \`generatepw\` to generate a strong password." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			echo
			while true; do
				echo "${info} Press $(textb ENTER) to show the weak password or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				stopit="stop"
				read -s -n 1 i
				case $i in
				* ) echo;echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "$(textb ${var})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo;break;;
				esac
				done
		fi
	done
		if [ "$stopit" == "stop" ]; then
			exit 1
		fi
		
		
		if [ ${USE_PHP5} == '1' ] && [ ${USE_PHP7} == '1' ]; then
		echo "${error} You can not choose two different PHP Versions" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		exit 1
		fi
		
		if [ ${USE_PHP5} == '0' ] && [ ${USE_PHP7} == '0' ]; then
		echo "${error} You have to choose a PHP Version" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		exit 1
		fi

}
source ~/configs/userconfig.cfg
