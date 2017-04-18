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

checksystem() {
	echo
	echo
	echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
	echo "$(date +"[%T]") |  $(textb P) $(textb e) $(textb r) $(textb f) $(textb e) $(textb c) $(textb t)   $(textb R) $(textb o) $(textb o) $(textb t) $(textb s) $(textb e) $(textb r) $(textb v) $(textb e) $(textb r) "
	echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
	echo
	echo "$(date +"[%T]") | ${info} Welcome to the Perfect Rootserver installation!"
	echo "$(date +"[%T]") | ${info} Please wait while the installer is preparing for the first use..."

	if [ $(dpkg-query -l | grep dnsutils | wc -l) -ne 1 ]; then
		apt-get update -y >>"$main_log" 2>>"$err_log" && apt-get -y --force-yes install dnsutils >>"$main_log" 2>>"$err_log"
	fi

	if [ $(dpkg-query -l | grep openssl | wc -l) -ne 1 ]; then
		apt-get update -y >>"$main_log" 2>>"$err_log" && apt-get -y --force-yes install openssl >>"$main_log" 2>>"$err_log"
	fi

	echo "$(date +"[%T]") | ${info} Checking your system..."

	if [ $(dpkg-query -l | grep gawk | wc -l) -ne 1 ]; then
	apt-get update -y >>"$main_log" 2>>"$err_log" && apt-get -y --force-yes install gawk >>"$main_log" 2>>"$err_log"
	fi

	if [ $USER != 'root' ]; then
        echo "${error} Please run the script as root" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
        exit 1
	fi

	if [[ -z $(which nc) ]]; then
		echo "${error} Please install $(textb netcat) before running this script" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		exit 1
	fi

	if [ $(dpkg-query -l | grep lsb-release | wc -l) -ne 1 ]; then
	apt-get update -y >>"$main_log" 2>>"$err_log" && apt-get -y --force-yes install lsb-release >>"$main_log" 2>>"$err_log"
	fi

	if [ $(lsb_release -cs) != 'jessie' ] || [ $(lsb_release -is) != 'Debian' ]; then
        echo "${error} The script for now works only on $(textb Debian) $(textb 8.x)" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
        exit 1
	fi

	if [ $(grep MemTotal /proc/meminfo | awk '{print $2}') -lt 1000000 ]; then
		echo "${warn} At least ~1000MB of memory is highly recommended" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "${info} Press $(textb ENTER) to skip this warning or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		read -s -n 1 i
	fi

	if [ $(dpkg-query -l | grep dmidecode | wc -l) -ne 1 ]; then
    	echo "${error} This script does not support the virtualization technology!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
    	exit 1
	fi

	if [ "$(dmidecode -s system-product-name)" == 'Bochs' ] || [ "$(dmidecode -s system-product-name)" == 'KVM' ] || [ "$(dmidecode -s system-product-name)" == 'All Series' ] || [ "$(dmidecode -s system-product-name)" == 'OpenStack Nova' ] || [ "$(dmidecode -s system-product-name)" == 'Standard' ]; then
		echo > /dev/null
	else
		if [ $(dpkg-query -l | grep facter | wc -l) -ne 1 ]; then
			apt-get update -y >>"$main_log" 2>>"$err_log" && apt-get -y --force-yes install facter >>"$main_log" 2>>"$err_log"
		fi

		if	[ "$(facter virtual)" == 'physical' ] || [ "$(facter virtual)" == 'kvm' ]; then
			echo > /dev/null
		else
	        echo "${warn} This script does not support the virtualization technology ($(dmidecode -s system-product-name))" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	        echo "${info} Press $(textb ENTER) to skip this warning and proceed at your own risk or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	        read -s -n 1 i
        fi
	fi
	#Set TCP Alife
	#echo -e "TCPKeepAlive yes" >> /etc/ssh/sshd_config
	echo -e "ClientAliveInterval 120" >> /etc/ssh/sshd_config
	echo -e "ClientAliveCountMax 15" >> /etc/ssh/sshd_config
	service sshd restart

	#Check CPU System and set RSA Size
	unset $RSA_KEY_SIZE
	#default
	if [ ${HIGH_SECURITY} = '0' ]; then
		RSA_KEY_SIZE="2048"
	fi
	
	#only if you need it!
	if [ ${HIGH_SECURITY} = '1' ]; then
		RSA_KEY_SIZE="4096"
	fi
	
	if [ ${HIGH_SECURITY} = '3' ] && [ ${DEBUG_IS_SET} = '0' ]; then
		  echo "${error} To set the RSA value to 256, you have to get into the debug mode! I'm sorry bro" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
        exit 1
	fi

	#only debug!
	if [ ${HIGH_SECURITY} = '3' ]; then
		RSA_KEY_SIZE="256"
	fi

	if [ ${CLOUDFLARE} != '1' ]; then
		if [[ $FQDNIP != $IPADR ]]; then
			echo "${error} The domain (${MYDOMAIN} - ${FQDNIP}) does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			echo "${error} Please check the userconfig and/or your DNS-Records." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			exit 1
		else
			if [ ${USE_VALID_SSL} == '1' ]; then
				if [[ $(echo ${SSLMAIL} | egrep "^(([-a-zA-Z0-9\!#\$%\&\'*+/=?^_\`{\|}~])+\.)*[-a-zA-Z0-9\!#\$%\&\'*+/=?^_\`{\|}~]+@\w((-|\w)*\w)*\.(\w((-|\w)*\w)*\.)*\w{2,4}$") != ${SSLMAIL} ]]; then
					echo "${error} Please chose a valid e-mail adress for your letsencrypt ssl certificate!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
					exit 1
				fi
				
					while true; do
						if [[ $WWWIP != $IPADR ]]; then
							echo "${error} www.${MYDOMAIN} does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
							echo
							echo "${warn} Please check your DNS-Records." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
							echo "${info} Press $(textb ENTER) to repeat this check or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
							read -s -n 1 i
						else
							break
						fi
					done
			fi
		fi
	fi
	echo "${ok} The system meets the minimum requirements." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	mkdir ~/sources
	
}
source ~/configs/userconfig.cfg
