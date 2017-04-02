#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

addoncheckconfig() {

if [ "$ADDONCONFIG_COMPLETED" != '1' ]; then
      echo "${error} Please check the addonconfig and set a valid value for the variable \"$(textb ADDONCONFIG_COMPLETED)\" to continue." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
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
