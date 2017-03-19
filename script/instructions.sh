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
	echo "${info} Press $(textb ENTER) to continue" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
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
	echo
	yellow "Your SSH Port to connect is" $SSH_PORT
	
	echo "${info} Press $(textb ENTER) to continue" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
    read -s -n 1 i
	echo
    echo "${ok} You are done. You can run the assistant again, just write \"$(textb bash) $(textb ~/assistant.sh)\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
    echo "The credentials are located in the file $(textb ~/credentials.txt)!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo "The add on credentials are located in the file $(textb ~/addoninformation.txt)!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
}
source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg