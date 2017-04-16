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

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

addoncheckconfig() {

if [ "$ADDONCONFIG_COMPLETED" != '1' ]; then
      echo "${error} Please check the addonconfig and set a valid value for the variable \"$(textb ADDONCONFIG_COMPLETED)\" to continue." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
      exit 1
fi

echo "${info} Checking your configuration..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	for var in MYOTHERDOMAIN ADD_NEW_SITE DISABLE_ROOT_LOGIN SSHUSER USE_TEAMSPEAK USE_MINECRAFT USE_AJENTI AJENTI_PASS USE_VSFTPD FTP_USERNAME 
	do
		if [[ -z ${!var} ]]; then
			echo "${error} Parameter $(textb ${var}) must not be empty." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			exit 1
		fi
	done

for var in ${AJENTI_PASS}
	do
		if echo "${var}" | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])' >>"$main_log" 2>>"$err_log"; then
			if [[ "$(awk -F': ' '{ print $2}' <<<"$(cracklib-check <<<"${var}")")" == "OK" ]]; then
				echo >>"$main_log" 2>>"$err_log"
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
	
	if [ ${USE_AJENTI} == '1' ] && [ ${USE_VALID_SSL} == '0' ]; then
	echo "${error} Use Ajenti only with a Let's Encrypt certificate" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 1
	fi	
		

if [ ${USE_VSFTPD} == '1' ]; then
	#Check for username
        	if [[ "$FTP_USERNAME" =~ [^a-z] ]]; then
		while [[ "$FTP_USERNAME" =~ [^a-z] ]]; do
			echo "Your Username $FTP_USERNAME is not valid! Please user only lower case letters."
			echo "${error} Your Username $FTP_USERNAME is not valid. Please use only lower case letters and try again:" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				read FTP_USERNAME
		done
		fi
		echo "${ok} Great! Your FTP Username is: $FTP_USERNAME" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		#Now insert new FTP Username into config to be able in script
		sed -i '/^FTP_USERNAME=/d' /root/configs/addonconfig.cfg
		sleep 1
		sed -i "/^USE_VSFTPD=*/a FTP_USERNAME=\"$FTP_USERNAME\" " /root/configs/addonconfig.cfg
fi

echo "${ok} Addonconfig is correct." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
echo

}
source ~/configs/addonconfig.cfg