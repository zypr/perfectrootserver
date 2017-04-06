#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

instructions() {

	SSH_PASSWD=$(sed -n '/^## SSH_PORT$/{n;n;n;p}' ~/credentials.txt | awk '{print $3}')
	echo
	echo "${info} Your server is ready to go! Do you want to start the configuration assistant?" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo "${info} Press $(textb ENTER) to proceed or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
    read -s -n 1 i
    echo
    echo "${warn} You have to set up your SSH client, otherwise you will not be able to connect to your system!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
    echo "${info} Press $(textb ENTER) to show your SSH private key" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
    echo
   	echo "$(textb \###########################################################)" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo "$(textb \#) This is your private key. Copy the entire key           $(textb \#)" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo "$(textb \#) including the -----BEGIN and -----END line and          $(textb \#)" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo "$(textb \#) save it on your Desktop. The file name does not matter! $(textb \#)" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo "$(textb \###########################################################)" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	yellow "Import the file by using Putty key generator and save your" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	yellow "private key as *.ppk file. Now you can use the key to" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	yellow "authenticate with your server using Putty." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo
	echo "Password for your ssh key = ${SSH_PASS}" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo
	echo
	cat ~/ssh_privatekey.txt
	echo
	echo
	echo "${info} Press $(textb ENTER) to continue" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
    read -s -n 1 i
    echo
    if [ ${USE_MAILSERVER} == '1' ]; then
		echo "${info} Before the mailserver can be used, the following requirements must be met:" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo "The subomain mail.${MYDOMAIN}" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "must have an \"A\" record that resolves to your IP adress: ${IPADR}" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		while true; do
			echo
			echo
			if [ ${CLOUDFLARE} == '0' ]; then
				if [[ $FQDNIP != $IPADR ]]; then
					echo "${error} ${MYDOMAIN} does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				else
					echo "${ok} ${MYDOMAIN} resolve to the IP adress of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				fi
			fi
			sleep 1
			if [[ $MAILIP != $IPADR ]]; then
				echo "${warn} mail.${MYDOMAIN} does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			else	
				echo "${ok} mail.${MYDOMAIN} resolve to the IP adress of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			fi
			sleep 1
			if [[ $CHECKRDNS != mail.${MYDOMAIN}. ]]; then
				echo "${warn} Your reverse DNS does not match the SMTP Banner. Please set your Reverse DNS to $(textb mail.${MYDOMAIN})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			else	
				echo "${ok} Your reverse DNS is a valid Hostname ($(textb ${CHECKRDNS}))" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			fi
			echo
			echo "${info} Repeat this check? Press $(textb ENTER) for yes or $(textb [N]) to skip" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			read -s -n 1 i
			if [[ $i == "" ]]; then
				echo > /dev/null
			else
				if [[ $i == "n" ]] || [[ $i == "N" ]]; then
					break
				fi
			fi
		done
		echo
		echo
		echo "${info} Verify that the following MX record is set:" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "NAME       TYPE          VALUE" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "-----------------------------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "${MYDOMAIN}	  MX	  10:mail.${MYDOMAIN}" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		while true; do
			if [[ -z $CHECKMX ]]; then
				echo
				echo
				echo "${warn} MX record for ${MYDOMAIN} was not found!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			else
				echo
				echo
				echo "${ok} MX record for ${MYDOMAIN} was found!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			fi
			echo
			echo "${info} Repeat this check? Press $(textb ENTER) for yes or $(textb [N]) to skip" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			read -s -n 1 i
			if [[ $i == "" ]]; then
				echo > /dev/null
			else
				if [[ $i == "n" ]] || [[ $i == "N" ]]; then
					break
				fi
			fi
		done
		echo
		echo
		echo "${info} In the next step you have to set three DNS TXT records for your domain." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		yellow "The first record should look like this:" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo "NAME       TYPE          VALUE" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "-----------------------------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		if [ $CLOUDFLARE == '1' ]; then
			echo " @         TXT       \"v=spf1 ip4:${IPADR} -all\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		else
			echo " @         TXT       \"v=spf1 mx -all\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		fi
		echo
		echo
		yellow "The second record sould look like this:" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo "      NAME           TYPE              VALUE" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "----------------------------------------------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo " mail._domainkey     TXT     \"v=DKIM1; k=rsa; t=s; s=email; p=DKIMPUBLICKEY\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo "Visit https://${MYDOMAIN}/vma and copy the salts to /srv/vimbadmin/application/configs/application.ini" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "Now create an admin account" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		#while true; do
		#	echo
		#	echo
		#	if [[ -z $CHECKSPF ]]; then
		#		echo "${warn} TXT record for SPF was not found!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		#	else
		#		echo "${ok} TXT record for SPF was found!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'	
		#	fi
		#	sleep 1
		#	if [[ -z $CHECKDKIM ]]; then
		#		echo "${warn} TXT record for DKIM was not found!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		#	else
		#		echo "${ok} TXT record for DKIM was found!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'	
		#	fi
		#	echo
		#	echo "${info} Repeat this check? Press $(textb ENTER) for yes or $(textb [N]) to skip" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		#	read -s -n 1 i
		#	if [[ $i == "" ]]; then
		#		echo > /dev/null
		#	else
		#		if [[ $i == "n" ]] || [[ $i == "N" ]]; then
		#			break
		#		fi
		#	fi
		#done
		echo
		echo
	fi
	echo
    echo "${ok} You are done. You can run the assistant again, just write \"$(textb bash) $(textb ~/assistant.sh)\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
    echo "The credentials are located in the file $(textb ~/credentials.txt)!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo "The add on credentials are located in the file $(textb ~/addoninformation.txt)!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

}
source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg