checkconfig() {

source ~/userconfig.cfg
source ~/addonconfig.cfg
source sources/script/functions.sh

	echo "${info} Checking your configuration..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	for var in NGINX_VERSION OPENSSL_VERSION OPENSSH_VERSION NPS_VERSION TIMEZONE MYDOMAIN SSH USE_MAILSERVER MAILCOW_ADMIN_USER USE_WEBMAIL USE_PMA PMA_HTTPAUTH_USER PMA_RESTRICT MYSQL_MCDB_NAME MYSQL_MCDB_USER MYSQL_RCDB_NAME MYSQL_RCDB_USER MYSQL_PMADB_NAME MYSQL_PMADB_USER MYSQL_HOSTNAME CLOUDFLARE
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
	
	if [ "$ADDONCONFIG_COMPLETED" != '1' ]; then
        echo "${error} Please check the addonconfig and set a valid value for the variable \"$(textb ADDONCONFIG_COMPLETED)\" to continue." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
        exit 1
	fi
	
	if [ ${USE_VSFTPD} == '1' ]; then
	#Check for username
	while [[ "$FTP_USERNAME" =~ [^a-z] ]]; do
		echo "Your Username $FTP_USERNAME is not valid! Please user only lower case letters."
		echo "${error} Your Username $FTP_USERNAME is not valid. Please use only lower case letters and try again:" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			read FTP_USERNAME
	done
	echo "${ok} Great! Your new FTP Username is:$FTP_USERNAME" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

	if [ $(dpkg-query -l | grep libcrack2 | wc -l) -ne 1 ]; then
		apt-get update -y >/dev/null 2>&1 && apt-get -y --force-yes install libcrack2 >/dev/null 2>&1
	fi

	for var in ${MAILCOW_ADMIN_PASS} ${PMA_HTTPAUTH_PASS} ${PMA_BFSECURE_PASS} ${SSH_PASS} ${MYSQL_ROOT_PASS} ${MYSQL_MCDB_PASS} ${MYSQL_RCDB_PASS} ${MYSQL_RCDB_PASS} ${MYSQL_PMADB_PASS}
	do
		if echo "${var}" | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])' > /dev/null; then
			if [[ "$(awk -F': ' '{ print $2}' <<<"$(cracklib-check <<<"${var}")")" == "OK" ]]; then
				echo >> /dev/null
			else
				echo "${error} One of your passwords was rejected!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				echo "${info} Your password must be a minimum of 8 characters and must include at least 1 number, 1 uppercase and 1 lowercase letter." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				echo "${info} Recommended password settings: Leave \`generatepw\` to generate a strong password." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				echo
				while true; do
					echo "${info} Press $(textb ENTER) to show the weak password or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
					read -s -n 1 i
					case $i in
					* ) echo;echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "$(cracklib-check <<<\"${var}\")" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo;break;;
					esac
				done
				exit 1
			fi
		else
			echo "${error} One of your passwords is too weak." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			echo "${info} Your password must be a minimum of 8 characters and must include at least 1 number, 1 uppercase and 1 lowercase letter." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			echo "${info} Recommended password settings: Leave \`generatepw\` to generate a strong password." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			echo
			while true; do
				echo "${info} Press $(textb ENTER) to show the weak password or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				read -s -n 1 i
				case $i in
				* ) echo;echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "$(textb ${var})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo;break;;
				esac
				done
				exit 1
		fi
	done
	if [ ${SSH} == '21' ] || [ ${SSH} == '25' ] || [ ${SSH} == '53' ] || [ ${SSH} == '80' ] || [ ${SSH} == '143' ] ||  [ ${SSH} == '443' ] || [ ${SSH} == '587' ] || [ ${SSH} == '990' ] || [ ${SSH} == '993' ] || [ ${SSH} -gt 1024 ] || [ ${SSH} -le 0 ]; then
		echo "${error} You are using an unsupportet SSH port, please chose another one!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		exit 1
	else
		if [ ${SSH} == '22' ]; then
			echo "${warn} Do you really want to use the standard SSH port? -> $(textb 22)" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			echo "${info} Press $(textb ENTER) to skip this warning and proceed or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
        	read -s -n 1 i
        else
        	if [[ $SSH =~ ^-?[0-9]+$ ]]; then
            	echo >> /dev/null
            else
            	echo "${error} SSH Port is not an integer, chose another one!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
            	exit 1
            fi
        fi
	fi
	echo "${ok} Userconfig is correct." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo
}
