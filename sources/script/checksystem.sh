source ~/userconfig.cfg
source ~/addonconfig.cfg

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
echo "$(date +"[%T]") |  $(textb P) $(textb e) $(textb r) $(textb f) $(textb e) $(textb c) $(textb t)   $(textb R) $(textb o) $(textb o) $(textb t) $(textb s) $(textb e) $(textb r) $(textb v) $(textb e) $(textb r) "
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo
echo "$(date +"[%T]") | ${info} Welcome to the Perfect Rootserver installation!"
echo "$(date +"[%T]") | ${info} Please wait while the installer is preparing for the first use..."

if [ $(dpkg-query -l | grep dnsutils | wc -l) -ne 1 ]; then
	apt-get update -y >/dev/null 2>&1 && apt-get -y --force-yes install dnsutils >/dev/null 2>&1
fi

if [ $(dpkg-query -l | grep openssl | wc -l) -ne 1 ]; then
	apt-get update -y >/dev/null 2>&1 && apt-get -y --force-yes install openssl >/dev/null 2>&1
fi

IPADR=$(ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)
INTERFACE=$(ip route get 8.8.8.8 | head -1 | cut -d' ' -f5)
FQDNIP=$(source ~/userconfig.cfg; dig @8.8.8.8 +short ${MYDOMAIN})
WWWIP=$(source ~/userconfig.cfg; dig @8.8.8.8 +short www.${MYDOMAIN})
ACIP=$(source ~/userconfig.cfg; dig @8.8.8.8 +short autoconfig.${MYDOMAIN})
ADIP=$(source ~/userconfig.cfg; dig @8.8.8.8 +short autodiscover.${MYDOMAIN})
DAVIP=$(source ~/userconfig.cfg; dig @8.8.8.8 +short dav.${MYDOMAIN})
MAILIP=$(source ~/userconfig.cfg; dig @8.8.8.8 +short mail.${MYDOMAIN})
CHECKAC=$(source ~/userconfig.cfg; dig @8.8.8.8 ${MYDOMAIN} txt | grep -i mailconf=)
CHECKMX=$(source ~/userconfig.cfg; dig @8.8.8.8 mx ${MYDOMAIN} +short)
CHECKSPF=$(source ~/userconfig.cfg; dig @8.8.8.8 ${MYDOMAIN} txt | grep -i spf)
CHECKDKIM=$(source ~/userconfig.cfg; dig @8.8.8.8 mail._domainkey.${MYDOMAIN} txt | grep -i DKIM1)
CHECKRDNS=$(dig @8.8.8.8 -x ${IPADR} +short)

generatepw() {
	while [[ $pw == "" ]]; do
		pw=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
	done
	echo "$pw" && unset pw
}

checksystem() {
	echo "$(date +"[%T]") | ${info} Checking your system..."

	if [ $(dpkg-query -l | grep gawk | wc -l) -ne 1 ]; then
	apt-get update -y >/dev/null 2>&1 && apt-get -y --force-yes install gawk >/dev/null 2>&1
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
	apt-get update -y >/dev/null 2>&1 && apt-get -y --force-yes install lsb-release >/dev/null 2>&1
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
		echo >> /dev/null
	else
		if [ $(dpkg-query -l | grep facter | wc -l) -ne 1 ]; then
			apt-get update -y >/dev/null 2>&1 && apt-get -y --force-yes install facter >/dev/null 2>&1
		fi

		if	[ "$(facter virtual)" == 'physical' ] || [ "$(facter virtual)" == 'kvm' ]; then
			echo >> /dev/null
		else
	        echo "${warn} This script does not support the virtualization technology ($(dmidecode -s system-product-name))" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	        echo "${info} Press $(textb ENTER) to skip this warning and proceed at your own risk or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	        read -s -n 1 i
        fi
	fi
	
	#Check CPU System and set RSA Size
	if [ $(grep -c ^processor /proc/cpuinfo) -ge 2 ]; then
		RSA_KEY_SIZE="4096"
			else
			#if this was acitvate by user
				if [ ${SET_UP_RSA_KEY} = '1' ]; then
					RSA_KEY_SIZE="4096"
					else
					RSA_KEY_SIZE="2048"
				fi
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
				if [ ${USE_MAILSERVER} == '1' ]; then
						while true; do
							p=0
							if [[ $MAILIP != $IPADR ]]; then
								echo "${error} mail.${MYDOMAIN} does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
							else	
								p=$((p + 1))
							fi
							sleep 1
							if [[ $ACIP != $IPADR ]]; then
								echo "${error} autoconfig.${MYDOMAIN} does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
							else	
								p=$((p + 1))
							fi
							sleep 1
							if [[ $ADIP != $IPADR ]]; then
								echo "${error} autodiscover.${MYDOMAIN} does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
							else	
								p=$((p + 1))
							fi
							sleep 1
							if [[ $DAVIP != $IPADR ]]; then
								echo "${error} dav.${MYDOMAIN} does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
							else	
								p=$((p + 1))
							fi
							sleep 1
							if [[ $WWWIP != $IPADR ]]; then
								echo "${error} www.${MYDOMAIN} does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
							else	
								p=$((p + 1))
							fi
							if [ ${p} -eq 5 ]; then
								break
							else
								echo
								echo "${warn} Please check your DNS-Records." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
								echo "${info} Press $(textb ENTER) to repeat this check or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
								read -s -n 1 i
							fi
						done
				else
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
	fi
	echo "${ok} The system meets the minimum requirements." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
}
