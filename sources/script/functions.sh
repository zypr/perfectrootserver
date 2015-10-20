# The perfect rootserver
# by zypr
# https://github.com/zypr/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

generatepw() {
	openssl rand -base64 30 | tr -d /=+ | cut -c -24
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

	if [ $(lsb_release -cs) != 'jessie' ] || [ $(lsb_release -is) != 'Debian' ]; then
        echo "${error} The script for now works only on $(textb Debian) $(textb 8.x)" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
        exit 1
	fi

	if [ $(grep MemTotal /proc/meminfo | awk '{print $2}') -lt 1000000 ]; then
		echo "${warn} At least ~1000MB of memory is highly recommended" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "$info Press $(textb ENTER) to skip this warning or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		read -s -n 1 i
	fi

	if [ "$(dmidecode -s system-product-name)" == 'Bochs' ] || [ "$(dmidecode -s system-product-name)" == 'KVM' ] || [ "$(dmidecode -s system-product-name)" == 'All Series' ] || [ "$(dmidecode -s system-product-name)" == 'OpenStack Nova' ]; then
		echo >> /dev/null
	else	
        echo "${warn} This script does not support the virtualization technology ($(textb $(dmidecode -s system-product-name)))" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
        echo "$info Press $(textb ENTER) to skip this warning and proceed at your own risk or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
        read -s -n 1 i
	fi

	if [ ${CLOUDFLARE} != '1' ]; then
		if [[ $FQDNIP != $IPADR ]]; then
			echo "${error} The domain (${MYDOMAIN} - ${FQDNIP}) does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			echo "${error} Please check the userconfig and/or your DNS-Records." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			exit 1
		fi
	fi
	echo "${ok} The system meets the minimum requirements." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
}

checkconfig() {
	echo "${info} Checking your configuration..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	for var in NGINX_VERSION OPENSSL_VERSION OPENSSH_VERSION NPS_VERSION NAXSI_VERSION MYDOMAIN CLOUDFLARE USE_PMA MYSQL_MCDB_NAME MYSQL_MCDB_USER MYSQL_RCDB_NAME MYSQL_RCDB_USER MYSQL_PMADB_NAME MYSQL_PMADB_USER WORKER MYSQL_HOSTNAME USE_MAILSERVER USE_WEBMAIL PMA_HTTPAUTH_USER
	do
		if [[ -z ${!var} ]]; then
			echo "${error} Parameter $(textb $var) must not be empty." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			exit 1
		fi
	done

	if [ "$CONFIG_COMPLETED" != '1' ]; then
        echo "${error} Please check the userconfig and set a valid value for the variable \"$(textb CONFIG_COMPLETED)\" to continue." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
        exit 1
	fi

	if [ $(dpkg-query -l | grep libcrack2 | wc -l) -ne 1 ]; then
		apt-get update -y >/dev/null 2>&1 && apt-get -y --force-yes install libcrack2 >/dev/null 2>&1
	fi

	for var in ${MAILCOW_ADMIN_PASS} ${MYSQL_ROOT_PASS} ${MYSQL_MCDB_PASS} ${MYSQL_RCDB_PASS} ${MYSQL_PMADB_PASS} ${PMA_BFSECURE_PASS} ${PMA_HTTPAUTH_PASS} ${SSH_PASS} ${MAILCOW_ADMIN_PASS}
	do
		if echo "$var" | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])' > /dev/null; then
			if [[ "$(awk -F': ' '{ print $2}' <<<"$(cracklib-check <<<"$var")")" == "OK" ]]
			then
				echo >> /dev/null
			else
				echo "${error} One of your passwords was rejected!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				echo "${info} Your password must be a minimum of 8 characters and must include at least 1 number, 1 uppercase and 1 lowercase letter." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				echo "${info} Recommended password settings: Leave \`generatepw\` to generate a strong password." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				echo
				while true; do
					echo "$info Press $(textb ENTER) to show the weak password or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
					read -s -n 1 i
					case $i in
					* ) echo;echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "$(cracklib-check <<<\"$var\")" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo;break;;
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
				echo "$info Press $(textb ENTER) to show the weak password or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				read -s -n 1 i
				case $i in
				* ) echo;echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "$(textb $var)" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo "-----------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }';echo;break;;
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
			echo "$info Press $(textb ENTER) to skip this warning and proceed or $(textb CTRL-C) to cancel the process" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
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

installation() {
echo "${info} Starting installation!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

cat > /etc/hosts <<END
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
END
echo -e "${IPADR} mail.${MYDOMAIN} mail" >> /etc/hosts
if [ -f /etc/mailname ]; then
	echo "mail.${MYDOMAIN}" > /etc/mailname
else
	touch /etc/mailname
	echo "mail.${MYDOMAIN}" > /etc/mailname
fi
echo "${info} Setting your hostname..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
if [[ -f /lib/systemd/systemd ]]; then
	if [[ -z $(dpkg --get-selections | grep -E "^dbus.*install$") ]]; then
		apt-get update -y >/dev/null 2>&1 && apt-get -y --force-yes install dbus >/dev/null 2>&1
	fi
		hostnamectl set-hostname mail
else
		echo mail > /etc/hostname
		hostname mail >/dev/null 2>&1
		service hostname.sh start >/dev/null 2>&1
fi
echo "${info} Setting your timezone..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
if [[ -f /usr/share/zoneinfo/${TIMEZONE} ]] ; then
	echo ${TIMEZONE} > /etc/timezone
	dpkg-reconfigure -f noninteractive tzdata >/dev/null 2>&1
	if [ "$?" -ne "0" ]; then
		echo "${error} Timezone configuration failed: dpkg returned exit code != 0" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		exit 1
		fi
	else
		echo "${error} Cannot set your timezone: timezone is unknown" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		exit 1
fi
echo "${info} Installing prerequisites..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
echo "${warn} Some of the tasks could take a long time, please be patient!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
rm /etc/apt/sources.list
cat > /etc/apt/sources.list <<END
# Stable
deb http://ftp.debian.org/debian stable main contrib non-free
deb-src http://ftp.debian.org/debian stable main contrib non-free

# Security updates
deb http://security.debian.org/ stable/updates main contrib non-free
deb http://security.debian.org/ testing/updates main contrib non-free
deb-src http://security.debian.org/ stable/updates main contrib non-free
deb-src http://security.debian.org/ testing/updates main contrib non-free

# Testing
deb http://ftp.debian.org/debian testing main contrib non-free
deb-src http://ftp.debian.org/debian testing main contrib non-free

# Unstable
deb http://ftp.debian.org/debian unstable main contrib non-free
deb-src http://ftp.debian.org/debian unstable main contrib non-free

# Dotdeb
deb http://packages.dotdeb.org jessie all
deb-src http://packages.dotdeb.org jessie all

# Doveocot
deb http://xi.rename-it.nl/debian/ stable-auto/dovecot-2.2 main
END

cat > /etc/apt/preferences.d/preferences <<END
Package: *
Pin: release a=stable
Pin-Priority: 700

Package: *
Pin: release a=testing
Pin-Priority: 650

Package: *
Pin: release a=unstable
Pin-Priority: 600
END

wget -O ~/sources/dovecot.key http://xi.rename-it.nl/debian/archive.key  >/dev/null 2>&1 && apt-key add ~/sources/dovecot.key >/dev/null 2>&1
wget -O ~/sources/dotdeb.gpg http://www.dotdeb.org/dotdeb.gpg >/dev/null 2>&1 && apt-key add ~/sources/dotdeb.gpg >/dev/null 2>&1
apt-get update -y >/dev/null 2>&1 && apt-get -y upgrade >/dev/null 2>&1
apt-get -y --force-yes install aptitude >/dev/null 2>&1
apt-get -y --force-yes install ssl-cert whiptail apt-utils jq >/dev/null 2>&1
/usr/sbin/make-ssl-cert generate-default-snakeoil --force-overwrite
DEBIAN_FRONTEND=noninteractive aptitude -y install apache2-threaded-dev apache2-utils apt-listchanges arj autoconf automake bison bsd-mailx build-essential bzip2 ca-certificates cabextract checkinstall curl dnsutils file flex gcc git htop libapr1-dev libaprutil1 libaprutil1-dev libauthen-sasl-perl-Daemon libawl-php libcrypt-ssleay-perl libcurl4-openssl-dev libdbi-perl libio-socket-ssl-perl libio-string-perl liblockfile-simple-perl liblogger-syslog-perl libmail-dkim-perl libmail-spf-perl libmime-base64-urlsafe-perl libnet-dns-perl libnet-ident-perl libnet-LDAP-perl libnet1 libnet1-dev libpam-dev libpcre-ocaml-dev libpcre3 libpcre3-dev libreadline6-dev libtest-tempdir-perl libtool libwww-perl libxml2 libxml2-dev libxml2-utils libxslt1-dev libyaml-dev lsb-release lzop mariadb-server mlocate nomarch opendkim opendkim-tools php-auth-sasl php-auth-sasl php-http-request php-http-request php-mail php-mail-mime php-mail-mimedecode php-net-dime php-net-smtp php-net-url php-pear php-soap php5 php5-apcu php5-cli php5-common php5-common php5-curl php5-dev php5-fpm php5-gd php5-imap php5-intl php5-mcrypt php5-mysql php5-sqlite php5-xmlrpc php5-xsl python-setuptools python-software-properties rkhunter software-properties-common subversion sudo unzip vim-nox zip zlib1g zlib1g-dbg zlib1g-de zoo >/dev/null 2>&1

if [ "$?" -ne "0" ]; then
	echo "${error} Package installation failed!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 1
fi

mysqladmin -u root password ${MYSQL_ROOT_PASS}

sed -i 's/.*max_allowed_packet.*/max_allowed_packet = 128M/g' /etc/mysql/my.cnf
sed -i '32s/.*/innodb_file_per_table = 1\n&/' /etc/mysql/my.cnf
sed -i '33s/.*/innodb_additional_mem_pool_size = 50M\n&/' /etc/mysql/my.cnf
sed -i '34s/.*/innodb_thread_concurrency = 4\n&/' /etc/mysql/my.cnf
sed -i '35s/.*/innodb_flush_method = O_DSYNC\n&/' /etc/mysql/my.cnf
sed -i '36s/.*/innodb_flush_log_at_trx_commit = 0\n&/' /etc/mysql/my.cnf
sed -i '37s/.*/#innodb_buffer_pool_size = 2G #reserved RAM, reduce i\/o\n&/' /etc/mysql/my.cnf
sed -i '38s/.*/innodb_log_files_in_group = 2\n&/' /etc/mysql/my.cnf
sed -i '39s/.*/innodb_log_file_size = 32M\n&/' /etc/mysql/my.cnf
sed -i '40s/.*/innodb_log_buffer_size = 16M\n&/' /etc/mysql/my.cnf
sed -i '41s/.*/#innodb_table_locks = 0 #disable table lock, uncomment if you do not want to crash all applications, if one does\n&/' /etc/mysql/my.cnf

# Automated mysql_secure_installation
mysql -u root -p${MYSQL_ROOT_PASS} -e "DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; FLUSH PRIVILEGES; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;" >/dev/null 2>&1

cd ~/sources
mkdir bash && cd $_
echo "${info} Downloading GNU bash & latest security patches..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget -N https://ftp.gnu.org/gnu/bash/bash-4.3.tar.gz >/dev/null 2>&1
for i in $(seq -f "%03g" 1 42); do wget http://ftp.gnu.org/gnu/bash/bash-4.3-patches/bash43-$i; done >/dev/null 2>&1
tar zxf bash-4.3.tar.gz && cd bash-4.3 >/dev/null 2>&1
echo "${info} Patching sourcefiles..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
for i in ../bash43-[0-9][0-9][0-9]; do patch -p0 -s < $i; done
echo "${info} Compiling GNU bash..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
./configure --prefix=/usr/local >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
cp -f /usr/local/bin/bash /bin/bash
echo "${info} Installing OpenSSL libs & headers..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
DEBIAN_FRONTEND=noninteractive apt-get -y --force-yes install openssl/unstable libssl-dev/unstable >/dev/null 2>&1
cd ~/sources
wget http://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz >/dev/null 2>&1
tar -xzf openssl-${OPENSSL_VERSION}.tar.gz >/dev/null 2>&1
echo "${info} Downloading OpenSSH..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget http://ftp.hostserver.de/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}p1.tar.gz >/dev/null 2>&1
tar -xzf openssh-${OPENSSH_VERSION}p1.tar.gz >/dev/null 2>&1
cd openssh-${OPENSSH_VERSION}p1
echo "${info} Compiling OpenSSH..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
./configure --prefix=/usr --with-pam --with-zlib --with-ssl-engine --with-ssl-dir=/etc/ssl --sysconfdir=/etc/ssh >/dev/null 2>&1
make >/dev/null 2>&1 && mv /etc/ssh{,.bak} && make install >/dev/null 2>&1
sed -i 's/^#Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i 's/^#AddressFamily any/AddressFamily inet/g' /etc/ssh/sshd_config
sed -i 's/^#Protocol 2/Protocol 2/g' /etc/ssh/sshd_config
sed -i 's/^#HostKey \/etc\/ssh\/ssh_host_rsa_key/HostKey \/etc\/ssh\/ssh_host_rsa_key/g' /etc/ssh/sshd_config
sed -i 's/^#HostKey \/etc\/ssh\/ssh_host_ecdsa_key/HostKey \/etc\/ssh\/ssh_host_ecdsa_key/g' /etc/ssh/sshd_config
sed -i 's/^#HostKey \/etc\/ssh\/ssh_host_ed25519_key/HostKey \/etc\/ssh\/ssh_host_ed25519_key/g' /etc/ssh/sshd_config
sed -i 's/^#ServerKeyBits 1024/ServerKeyBits 2048/' /etc/ssh/sshd_config
sed -i 's/^#RekeyLimit default none/RekeyLimit 256M/' /etc/ssh/sshd_config
sed -i 's/^#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
sed -i 's/^#KeyRegenerationInterval 1h/KeyRegenerationInterval 1800/g' /etc/ssh/sshd_config
sed -i 's/^#SyslogFacility AUTH/SyslogFacility AUTH/g' /etc/ssh/sshd_config
sed -i 's/^#LoginGraceTime 2m/LoginGraceTime 30/g' /etc/ssh/sshd_config
sed -i 's/^#MaxAuthTries 6/MaxAuthTries 20/g' /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin yes/PermitRootLogin yes/g' /etc/ssh/sshd_config
sed -i 's/^#StrictModes yes/StrictModes yes/g' /etc/ssh/sshd_config
sed -i 's/^#RSAAuthentication yes/RSAAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/^AuthorizedKeysFile	.ssh\/authorized_keys/#AuthorizedKeysFile	.ssh\/authorized_keys/g' /etc/ssh/sshd_config
sed -i 's/^#RhostsRSAAuthentication no/RhostsRSAAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/^#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/^#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/^#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/^#X11Forwarding no/X11Forwarding yes/g' /etc/ssh/sshd_config
sed -i 's/^#X11DisplayOffset 10/X11DisplayOffset 10/g' /etc/ssh/sshd_config
sed -i 's/^#PrintMotd yes/PrintMotd no/g' /etc/ssh/sshd_config
sed -i 's/^#PrintLastLog yes/PrintLastLog yes/g' /etc/ssh/sshd_config
sed -i 's/^#TCPKeepAlive yes/TCPKeepAlive yes/g' /etc/ssh/sshd_config
sed -i 's/^#UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config
sed -i 's/^#Banner none/Banner \/etc\/issue/g' /etc/ssh/sshd_config
sed -i 's/^#MaxStartups 10:30:100/MaxStartups 2/g' /etc/ssh/sshd_config
sed -i 's/^#MaxSessions 10/MaxSessions 3/g' /etc/ssh/sshd_config
sed -i 's/^Subsystem	sftp	\/usr\/libexec\/sftp-server/Subsystem sftp \/usr\/lib\/openssh\/sftp-server/g' /etc/ssh/sshd_config
echo -e "" >> /etc/ssh/sshd_config
echo -e "# Allow client to pass locale environment variables" >> /etc/ssh/sshd_config
echo -e "AcceptEnv LANG LC_* TZ" >> /etc/ssh/sshd_config
echo -e "" >> /etc/ssh/sshd_config
echo -e "# KEX algorithms">> /etc/ssh/sshd_config
echo -e "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256">> /etc/ssh/sshd_config
echo -e "" >> /etc/ssh/sshd_config
echo -e "# Ciphers">> /etc/ssh/sshd_config
echo -e "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr">> /etc/ssh/sshd_config
echo -e "" >> /etc/ssh/sshd_config
echo -e "# MAC algorithms">> /etc/ssh/sshd_config
echo -e "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com">> /etc/ssh/sshd_config

rm /etc/issue
cat > $_ <<END

####################################################################
# Unauthorized access to this system is forbidden and will be      #
# prosecuted by law. By accessing this system, you agree that your #
# actions may be monitored if unauthorized usage is suspected.     #
####################################################################

END
systemctl -q restart ssh.service

cd ~/sources
echo "${info} Downloading Nginx Pagespeed..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget https://github.com/pagespeed/ngx_pagespeed/archive/release-${NPS_VERSION}-beta.zip >/dev/null 2>&1
unzip -qq release-${NPS_VERSION}-beta.zip
cd ngx_pagespeed-release-${NPS_VERSION}-beta/
wget https://dl.google.com/dl/page-speed/psol/${NPS_VERSION}.tar.gz >/dev/null 2>&1
tar -xzf ${NPS_VERSION}.tar.gz
cd ~/sources
echo "${info} Downloading Ngnx HTTP Auth Digest..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
git clone https://github.com/maneulyori/nginx-http-auth-digest.git -q
echo "${info} Downloading Naxsi..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget --no-check-certificate https://github.com/nbs-system/naxsi/archive/${NAXSI_VERSION}.tar.gz >/dev/null 2>&1
tar -xzf ${NAXSI_VERSION}.tar.gz
echo "${info} Downloading Nginx..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz >/dev/null 2>&1
tar -xzf nginx-${NGINX_VERSION}.tar.gz
cd nginx-${NGINX_VERSION}

echo "${info} Compiling Nginx..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

sed -i '49s/.*/static char ngx_http_server_string[] = "";/' src/http/ngx_http_header_filter_module.c
sed -i '50s/.*/static char ngx_http_server_full_string[] = "";/' src/http/ngx_http_header_filter_module.c
sed -i '281s/.*/        len += clcf->server_tokens ? sizeof(ngx_http_server_full_string) - 0:/' src/http/ngx_http_header_filter_module.c
sed -i '282s/.*/                                     sizeof(ngx_http_server_string) - 0;/' src/http/ngx_http_header_filter_module.c
sed -i '215s/.*/\/*    if (r->headers_out.server == NULL) {/' src/http/v2/ngx_http_v2_filter_module.c
sed -i '218s/.*/    } *\//' src/http/v2/ngx_http_v2_filter_module.c
sed -i '413s/.*/\/*    if (r->headers_out.server == NULL) {/' src/http/v2/ngx_http_v2_filter_module.c
sed -i '424s/.*/    } *\//' src/http/v2/ngx_http_v2_filter_module.c

sed -i '20,298d' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_507_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_504_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_503_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_502_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_501_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_500_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_497_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_496_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_495_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_494_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_416_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_415_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_414_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_413_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_412_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_411_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_410_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_409_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_408_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_406_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_405_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_404_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_403_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_402_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_401_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_400_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_307_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_303_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_302_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static char ngx_http_error_301_page[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static u_char ngx_http_msie_refresh_tail[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static u_char ngx_http_msie_refresh_head[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static u_char ngx_http_msie_padding[] ="";\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static u_char ngx_http_error_tail[] =""CRLF;\n&/' src/http/ngx_http_special_response.c
sed -i '20s/.*/static u_char ngx_http_error_full_tail[] =""CRLF;\n&/' src/http/ngx_http_special_response.c

sed -i '120s/.*/#define NGX_SSL_BUFSIZE  1400/' src/event/ngx_event_openssl.h
sed -i '720s/.*/                (void) BIO_set_write_buffer_size(wbio, 16384);/' src/event/ngx_event_openssl.c

./configure --prefix=/etc/nginx \
--sbin-path=/usr/sbin/nginx \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--pid-path=/var/run/nginx.pid \
--lock-path=/var/run/nginx.lock \
--http-client-body-temp-path=/var/lib/nginx/body \
--http-proxy-temp-path=/var/lib/nginx/proxy \
--http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
--http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
--http-scgi-temp-path=/var/lib/nginx/scgi \
--user=www-data \
--group=www-data \
--without-http_autoindex_module \
--without-http_browser_module \
--without-http_empty_gif_module \
--without-http_map_module \
--without-http_userid_module \
--without-http_split_clients_module \
--with-http_ssl_module \
--with-http_v2_module \
--with-http_realip_module \
--with-http_addition_module \
--with-http_sub_module \
--with-http_dav_module \
--with-http_flv_module \
--with-http_mp4_module \
--with-http_gunzip_module \
--with-http_gzip_static_module \
--with-http_random_index_module \
--with-http_secure_link_module \
--with-http_stub_status_module \
--with-http_auth_request_module \
--with-mail \
--with-mail_ssl_module \
--with-file-aio \
--with-ipv6 \
--with-debug \
--with-cc-opt='-O2 -g -pipe -Wall -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic' \
--with-openssl=$HOME/sources/openssl-${OPENSSL_VERSION} \
--add-module=$HOME/sources/ngx_pagespeed-release-${NPS_VERSION}-beta \
--add-module=$HOME/sources/nginx-http-auth-digest \
--add-module=$HOME/sources/naxsi-${NAXSI_VERSION}/naxsi_src >/dev/null 2>&1

# make the package
make >/dev/null 2>&1

# Create a .deb package
checkinstall --install=no -y >/dev/null 2>&1

# Install the package
echo "${info} Installing Nginx..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
dpkg -i nginx_${NGINX_VERSION}-1_amd64.deb >/dev/null 2>&1
mv nginx_${NGINX_VERSION}-1_amd64.deb ../

# Create directories
mkdir -p /var/lib/nginx/body && cd $_
mkdir ../proxy
mkdir ../fastcgi
mkdir ../uwsgi
mkdir ../cgi
mkdir ../nps_cache
mkdir /var/log/nginx
mkdir /etc/nginx/sites-available && cd $_
mkdir ../sites-enabled
mkdir ../sites-custom
mkdir ../htpasswd
touch ../htpasswd/.htpasswd
mkdir ../logs
mkdir ../ssl
chown -R www-data:www-data /var/lib/nginx
chown www-data:www-data /etc/nginx/logs

# Install the Nginx service script
wget -O /etc/init.d/nginx --no-check-certificate https://raw.githubusercontent.com/Fleshgrinder/nginx-sysvinit-script/master/init >/dev/null 2>&1
chmod 0755 /etc/init.d/nginx
chown root:root /etc/init.d/nginx
update-rc.d nginx defaults

# Edit/create Nginx config files
echo "${info} Configuring Nginx..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
rm -rf /etc/nginx/nginx.conf
cat > /etc/nginx/nginx.conf <<END
user www-data;
worker_processes ${WORKER};
pid /var/run/nginx.pid;

events {
	worker_connections  4024;
	multi_accept on;
	use epoll;
}

http {
		include 			/etc/nginx/naxsi_core.rules;
		include       		/etc/nginx/mime.types;
		default_type  		application/octet-stream;
		server_tokens       off;
		keepalive_timeout   70;
		sendfile			on;
		send_timeout 60;
		tcp_nopush on;
		tcp_nodelay on;
		client_max_body_size 50m;
		client_body_timeout 15;
		client_header_timeout 15;
		client_body_buffer_size 1K;
		client_header_buffer_size 1k;
		large_client_header_buffers 4 8k;
		reset_timedout_connection on;
		server_names_hash_bucket_size 100;
		types_hash_max_size 2048;

		open_file_cache max=2000 inactive=20s;
		open_file_cache_valid 60s;
		open_file_cache_min_uses 5;
		open_file_cache_errors off;

		gzip on;
		gzip_static on;
		gzip_disable "msie6";
		gzip_vary on;
		gzip_proxied any;
		gzip_comp_level 6;
		gzip_min_length 1100;
		gzip_buffers 16 8k;
		gzip_http_version 1.1;
		gzip_types text/css text/javascript text/xml text/plain text/x-component application/javascript application/x-javascript application/json application/xml application/rss+xml font/truetype application/x-font-ttf font/opentype application/vnd.ms-fontobject image/svg+xml;

		log_format main     '\$remote_addr - \$remote_user [\$time_local] "\$request" '
							'\$status \$body_bytes_sent "\$http_referer" '
							'"\$http_user_agent" "\$http_x_forwarded_for"';

		access_log		logs/access.log main buffer=16k;
		error_log       	logs/error.log;

		include			/etc/nginx/sites-enabled/*.conf;
}
END

# Create server config
rm -rf /etc/nginx/sites-available/${MYDOMAIN}.conf
cat > /etc/nginx/sites-available/${MYDOMAIN}.conf <<END
server {
			listen 80 default_server;
			server_name ${IPADR} ${MYDOMAIN};
			return 301 https://${MYDOMAIN}\$request_uri;
}

server {
			listen 443;
			server_name ${IPADR} mail.${MYDOMAIN};
			return 301 https://${MYDOMAIN}\$request_uri;
}

server {
			listen 443 ssl http2 default deferred;
			server_name ${MYDOMAIN};

			root /etc/nginx/html;
			index index.php index.html index.htm;

			charset utf-8;

			error_page 404 /index.php;

			ssl_certificate 	ssl/${MYDOMAIN}.pem;
			ssl_certificate_key ssl/${MYDOMAIN}.key;
			#ssl_trusted_certificate ssl/trustedbundle.pem;
			ssl_dhparam	     	ssl/dh.pem;
			ssl_ecdh_curve		secp384r1;
			ssl_session_cache   shared:SSL:10m;
			ssl_session_timeout 10m;
			ssl_session_tickets off;
			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
			ssl_prefer_server_ciphers on;
			ssl_buffer_size 	4k;

			#ssl_stapling on;
			#ssl_stapling_verify on;
			#resolver 8.8.8.8 8.8.4.4 valid=300s;
			#resolver_timeout 5s;

			ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";

			#add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
			add_header X-Frame-Options SAMEORIGIN;
			add_header Alternate-Protocol  443:npn-http/2;
			add_header X-Content-Type-Options nosniff;
			add_header X-XSS-Protection "1; mode=block";
			add_header Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com cdnjs.cloudflare.com assets.zendesk.com connect.facebook.net; frame-src 'self' *.youtube.com assets.zendesk.com *.facebook.com s-static.ak.facebook.com tautt.zendesk.com; object-src 'self'";

			pagespeed on;
			pagespeed FetchHttps enable,allow_self_signed;
			pagespeed FileCachePath /var/lib/nginx/nps_cache;
			pagespeed RewriteLevel PassThrough;
			pagespeed EnableFilters collapse_whitespace;
			pagespeed EnableFilters canonicalize_javascript_libraries;
			pagespeed EnableFilters combine_css;
			pagespeed EnableFilters combine_javascript;
			pagespeed EnableFilters elide_attributes;
			pagespeed EnableFilters extend_cache;
			pagespeed EnableFilters flatten_css_imports;
			pagespeed CssFlattenMaxBytes 5120;
			pagespeed EnableFilters lazyload_images;
			pagespeed EnableFilters rewrite_javascript;
			pagespeed EnableFilters rewrite_images;
			pagespeed EnableFilters insert_dns_prefetch;
			pagespeed EnableFilters prioritize_critical_css;

			# This will correctly rewrite your subresources with https:// URLs and thus avoid mixed content warnings.
			# Note, that you should only enable this option if you are behind a load-balancer that will set this header,
			# otherwise your users will be able to set the protocol PageSpeed uses to interpret the request.
			#
			#pagespeed RespectXForwardedProto on;

			auth_basic_user_file htpasswd/.htpasswd;

			location ~ \.php\$ {
				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
				try_files \$fastcgi_script_name =404;
				set \$path_info \$fastcgi_path_info;
				fastcgi_param PATH_INFO \$path_info;
				fastcgi_param APP_ENV production;
				fastcgi_pass unix:/var/run/php5-fpm.sock;
				fastcgi_index index.php;
				include fastcgi.conf;
				fastcgi_intercept_errors on;
				fastcgi_ignore_client_abort off;
				fastcgi_buffers 256 16k;
				fastcgi_buffer_size 128k;
				fastcgi_connect_timeout 3s;
				fastcgi_send_timeout 120s;
				fastcgi_read_timeout 120s;
				fastcgi_busy_buffers_size 256k;
				fastcgi_temp_file_write_size 256k;
			}

			include /etc/nginx/sites-custom/*.conf;

			location / {
			   	include /etc/nginx/naxsi.rules;
			}

			location ~ /\. {
				deny all;
				access_log off;
				log_not_found off;
			}

			location = /favicon.ico {
				access_log off;
				log_not_found off;
			}
				
			location = /robots.txt {
				allow all;
				access_log off;
				log_not_found off;
			}

			# Uncomment, if you need to remove index.php from the
			# URL. Usefull if you use Codeigniter, Zendframework, etc.
			# or just need to remove the index.php
			#
			#location / {
			#   try_files \$uri \$uri/ /index.php?\$args;
			#}

			location ~* ^.+\.(css|js)\$ {
				rewrite ^(.+)\.(\d+)\.(css|js)\$ \$1.\$3 last;
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

			location ~* \.(asf|asx|wax|wmv|wmx|avi|bmp|class|divx|doc|docx|eot|exe|gif|gz|gzip|ico|jpg|jpeg|jpe|mdb|mid|midi|mov|qt|mp3|m4a|mp4|m4v|mpeg|mpg|mpe|mpp|odb|odc|odf|odg|odp|ods|odt|ogg|ogv|otf|pdf|png|pot|pps|ppt|pptx|ra|ram|svg|svgz|swf|tar|t?gz|tif|tiff|ttf|wav|webm|wma|woff|wri|xla|xls|xlsx|xlt|xlw|zip)\$ {
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

}
END

if [ ${CLOUDFLARE} == '1' ]; then
	sed -i "3s/.*/			server_name ${MYDOMAIN};/" /etc/nginx/sites-available/${MYDOMAIN}.conf
	sed -i '6s/.*/\n&/' /etc/nginx/sites-available/${MYDOMAIN}.conf
	sed -i '7s/.*/server {\n&/' /etc/nginx/sites-available/${MYDOMAIN}.conf
	sed -i '8s/.*/			listen 80;\n&/' /etc/nginx/sites-available/${MYDOMAIN}.conf
	sed -i "9s/.*/			server_name ${IPADR};\n&/" /etc/nginx/sites-available/${MYDOMAIN}.conf
	sed -i '10s/.*/			return 503;\n&/' /etc/nginx/sites-available/${MYDOMAIN}.conf
	sed -i '11s/.*/}\n&/' /etc/nginx/sites-available/${MYDOMAIN}.conf
	sed -i '16s/.*/			return 503;/' /etc/nginx/sites-available/${MYDOMAIN}.conf
fi

ln -s /etc/nginx/sites-available/${MYDOMAIN}.conf /etc/nginx/sites-enabled/${MYDOMAIN}.conf

# Configure PHP
echo "${info} Configuring PHP..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
sed -i 's/.*disable_functions =.*/disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,escapeshellarg,passthru,proc_close,proc_get_status,proc_nice,proc_open,proc_terminate,/' /etc/php5/fpm/php.ini
sed -i 's/.*ignore_user_abort =.*/ignore_user_abort = Off/' /etc/php5/fpm/php.ini
sed -i 's/.*expose_php =.*/expose_php = Off/' /etc/php5/fpm/php.ini
sed -i 's/.*post_max_size =.*/post_max_size = 15M/' /etc/php5/fpm/php.ini
sed -i 's/.*default_charset =.*/default_charset = "UTF-8"/' /etc/php5/fpm/php.ini
sed -i 's/.*cgi.fix_pathinfo=.*/cgi.fix_pathinfo=0/' /etc/php5/fpm/php.ini
sed -i 's/.*upload_max_filesize =.*/upload_max_filesize = 15M/' /etc/php5/fpm/php.ini
sed -i 's/.*default_socket_timeout =.*/default_socket_timeout = 30/' /etc/php5/fpm/php.ini
sed -i 's/.*date.timezone =.*/date.timezone = Europe\/Berlin/' /etc/php5/fpm/php.ini
sed -i 's/.*mysql.allow_persistent =.*/mysql.allow_persistent = Off/' /etc/php5/fpm/php.ini
sed -i 's/.*session.cookie_httponly =.*/session.cookie_httponly = 1/' /etc/php5/fpm/php.ini

# Configure PHP-FPM
sed -i 's/.*emergency_restart_threshold =.*/emergency_restart_threshold = 10/' /etc/php5/fpm/php-fpm.conf
sed -i 's/.*emergency_restart_interval =.*/emergency_restart_interval = 1m/' /etc/php5/fpm/php-fpm.conf
sed -i 's/.*process_control_timeout =.*/process_control_timeout = 10/' /etc/php5/fpm/php-fpm.conf
sed -i 's/.*events.mechanism =.*/events.mechanism = epoll/' /etc/php5/fpm/php-fpm.conf
sed -i 's/.*listen.mode =.*/listen.mode = 0666/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*listen.allowed_clients =.*/listen.allowed_clients = 127.0.0.1/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*pm.max_children =.*/pm.max_children = 50/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*pm.start_servers =.*/pm.start_servers = 15/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*pm.min_spare_servers =.*/pm.min_spare_servers = 5/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*pm.max_spare_servers =.*/pm.max_spare_servers = 25/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*pm.process_idle_timeout =.*/pm.process_idle_timeout = 60s;/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*request_terminate_timeout =.*/request_terminate_timeout = 30/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*security.limit_extensions =.*/security.limit_extensions = .php/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*php_flag[display_errors] =.*/php_flag[display_errors] = off/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*php_admin_value[error_log] =.*/php_admin_value[error_log] = \/var\/log\/fpm5-php.www.log/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*php_admin_flag[log_errors] =.*/php_admin_flag[log_errors] = on/' /etc/php5/fpm/pool.d/www.conf
sed -i 's/.*php_admin_value[memory_limit] =.*/php_admin_value[memory_limit] = 128M/' /etc/php5/fpm/pool.d/www.conf
echo -e "php_flag[display_errors] = off" >> /etc/php5/fpm/pool.d/www.conf

# Configure APCu
rm -rf /etc/php5/mods-available/apcu.ini
rm -rf /etc/php5/mods-available/20-apcu.ini

cat > /etc/php5/mods-available/apcu.ini <<END
extension=apcu.so
apc.enabled=1
apc.stat = "0"
apc.max_file_size = "1M"
apc.localcache = "1"
apc.localcache.size = "256"
apc.shm_segments = "1"
apc.ttl = "3600"
apc.user_ttl = "7200"
apc.enable_cli=0
apc.gc_ttl = "3600"
apc.cache_by_default = "1"
apc.filters = ""
apc.write_lock = "1"
apc.num_files_hint= "512"
apc.user_entries_hint="4096"
apc.shm_size = "256M"
apc.mmap_file_mask=/tmp/apc.XXXXXX
apc.include_once_override = "0"
apc.file_update_protection="2"
apc.canonicalize = "1"
apc.report_autofilter="0"
apc.stat_ctime="0"
END

ln -s /etc/php5/mods-available/apcu.ini /etc/php5/mods-available/20-apcu.ini

# Configure Naxsi
echo "${info} Configuring Naxsi..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
cp -f ~/sources/naxsi-${NAXSI_VERSION}/naxsi_config/naxsi_core.rules /etc/nginx/
cat > /etc/nginx/naxsi.rules <<END
LearningMode;
SecRulesEnabled;
DeniedUrl "/RequestDenied";

# Rules
CheckRule "\$SQL >= 8" BLOCK;
CheckRule "\$RFI >= 8" BLOCK;
CheckRule "\$TRAVERSAL >= 4" BLOCK;
CheckRule "\$EVADE >= 4" BLOCK;
CheckRule "\$XSS >= 8" BLOCK;
END


# Create a self-signed SSL certificate
echo "${info} Creating self-signed SSL certificates..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
openssl ecparam -genkey -name secp384r1 -out /etc/nginx/ssl/${MYDOMAIN}.key >/dev/null 2>&1
openssl req -new -sha256 -key /etc/nginx/ssl/${MYDOMAIN}.key -out /etc/nginx/ssl/csr.pem -subj "/C=/ST=/L=/O=/OU=/CN=*.${MYDOMAIN}" >/dev/null 2>&1
openssl req -x509 -days 365 -key /etc/nginx/ssl/${MYDOMAIN}.key -in /etc/nginx/ssl/csr.pem -out /etc/nginx/ssl/${MYDOMAIN}.pem >/dev/null 2>&1

echo "${info} Creating strong Diffie-Hellman parameters, please wait..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
openssl dhparam -out /etc/nginx/ssl/dh.pem 2048 >/dev/null 2>&1

# Restart FPM & Nginx
systemctl -q start nginx.service
systemctl -q restart php5-fpm.service

if [ ${USE_MAILSERVER} == '1' ]; then
	echo "${info} Installing mailserver..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

	# Prerequisites
	update-alternatives --set mailx /usr/bin/bsd-mailx --quiet >/dev/null 2>&1
	DEBIAN_FRONTEND=noninteractive aptitude -y install clamav-daemon dovecot-common dovecot-core dovecot-imapd dovecot-lmtpd dovecot-managesieved dovecot-mysql dovecot-pop3d dovecot-sieve fetchmail imagemagick mailutils mpack pflogsumm postfix postfix-mysql postfix-pcre postgrey pyzor razor spamassassin spamc wkhtmltopdf >/dev/null 2>&1

	# Create SSL
	mkdir -p /etc/ssl/mail 2> /dev/null
	rm /etc/ssl/mail/* 2> /dev/null
	cp /etc/nginx/ssl/dh.pem /etc/ssl/mail/dhparams.pem
	openssl req -new -newkey rsa:4096 -sha256 -days 1095 -nodes -x509 -subj "/C=/ST=/L=/O=/OU=/CN=mail.${MYDOMAIN}" -keyout /etc/ssl/mail/mail.key -out /etc/ssl/mail/mail.crt >/dev/null 2>&1
	chmod 600 /etc/ssl/mail/mail.key
	cp /etc/ssl/mail/mail.crt /usr/local/share/ca-certificates/
	update-ca-certificates >/dev/null 2>&1

	# Create MySQL databases
	echo "${info} Creating MySQL databases..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} -e "CREATE DATABASE ${MYSQL_MCDB_NAME}; GRANT SELECT, INSERT, UPDATE, DELETE ON ${MYSQL_MCDB_NAME}.* TO '${MYSQL_MCDB_USER}'@'%' IDENTIFIED BY '${MYSQL_MCDB_PASS}';"
	mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} -e "CREATE DATABASE ${MYSQL_RCDB_NAME}; GRANT ALL PRIVILEGES ON ${MYSQL_RCDB_NAME}.* TO '${MYSQL_RCDB_USER}'@'%' IDENTIFIED BY '${MYSQL_RCDB_PASS}';"
	mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} -e "GRANT SELECT ON ${MYSQL_MCDB_NAME}.* TO 'vmail'@'%'; FLUSH PRIVILEGES;"

	# Postfix
	echo "${info} Installing Postfix..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	cp -R ~/sources/mailcow/postfix/conf/* /etc/postfix/
	chown root:postfix "/etc/postfix/sql"; chmod 750 "/etc/postfix/sql"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_alias_domain_catchall_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_alias_domain_catchall_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_alias_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_alias_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_alias_domain_mailbox_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_alias_domain_mailbox_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_mailbox_limit_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_mailbox_limit_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_mailbox_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_mailbox_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_mxdomain_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_mxdomain_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_alias_domain_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_alias_domain_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_spamalias_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_spamalias_maps.cf"
	chown root:postfix "/etc/postfix/sql/mysql_virtual_domains_maps.cf"; chmod 640 "/etc/postfix/sql/mysql_virtual_domains_maps.cf"
	chown root:root "/etc/postfix/master.cf"; chmod 644 "/etc/postfix/master.cf"
	chown root:root "/etc/postfix/main.cf"; chmod 644 "/etc/postfix/main.cf"
	sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYDOMAIN}/g" /etc/postfix/* 2> /dev/null
	cp ~/sources/mailcow/misc/mc_clean_spam_aliases /etc/cron.daily/mc_clean_spam_aliases
	cp ~/sources/mailcow/misc/mc_pfset /usr/local/sbin/mc_pfset
	cp ~/sources/mailcow/misc/mc_pflog_renew /usr/local/sbin/mc_pflog_renew
	chmod +x /usr/local/sbin/mc_pfset /usr/local/sbin/mc_pflog_renew
	chmod 700 /etc/cron.daily/mc_clean_spam_aliases
	sed -i "s/MAILCOW_DOMAIN/${MYDOMAIN}/g" /etc/postfix/* 2> /dev/null
	sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
	sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
	sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
	sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /etc/postfix/sql/* /etc/cron.daily/mc_clean_spam_aliases
	sed -i '/^POSTGREY_OPTS=/s/=.*/="--inet=127.0.0.1:10023"/' /etc/default/postgrey
	chown www-data: /etc/postfix/mailcow_*
	chmod 755 /var/spool/
	sed -i "/%www-data/d" /etc/sudoers 2> /dev/null
	sed -i "/%vmail/d" /etc/sudoers 2> /dev/null
	echo '%www-data ALL=(ALL) NOPASSWD: /usr/bin/doveadm * sync *, /usr/local/sbin/mc_pfset *, /usr/bin/doveadm quota recalc -A, /usr/sbin/dovecot reload, /usr/sbin/postfix reload, /usr/local/sbin/mc_dkim_ctrl, /usr/local/sbin/mc_msg_size, /usr/local/sbin/mc_pflog_renew, /usr/local/sbin/mc_setup_backup' >> /etc/sudoers

	# fuglu
	echo "${info} Installing Fuglu..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	if [[ -z $(grep fuglu /etc/passwd) ]]; then
		userdel fuglu >/dev/null 2>&1
		groupadd fuglu >/dev/null 2>&1
		useradd -g fuglu -s /bin/false fuglu
		usermod -a -G debian-spamd fuglu
		usermod -a -G clamav fuglu
	fi
	rm /tmp/fuglu_control.sock >/dev/null 2>&1
	mkdir /var/log/fuglu >/dev/null 2>&1
	chown fuglu:fuglu /var/log/fuglu
	tar xf ~/sources/mailcow/fuglu/inst/0.6.4.tar -C ~/sources/mailcow/fuglu/inst/ >/dev/null 2>&1
	(cd ~/sources/mailcow/fuglu/inst/0.6.4 ; python setup.py -q install)
	cp -R ~/sources/mailcow/fuglu/conf/* /etc/fuglu/
	cp ~/sources/mailcow/fuglu/inst/0.6.4/scripts/startscripts/debian/8/fuglu.service /lib/systemd/system/fuglu.service
	systemctl enable fuglu 2> /dev/null
	rm -rf ~/sources/mailcow/fuglu/inst/0.6.4

	# Dovecot
	echo "${info} Installing Dovecot..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	if [[ -f /lib/systemd/systemd ]]; then
		systemctl -q disable dovecot.socket
	fi
	rm -rf /etc/dovecot/*
	cp -R ~/sources/mailcow/dovecot/conf/*.conf /etc/dovecot/
	userdel vmail >/dev/null 2>&1
	groupdel vmail >/dev/null 2>&1
	groupadd -g 5000 vmail >/dev/null 2>&1
	useradd -g vmail -u 5000 vmail -d /var/vmail >/dev/null 2>&1
	chmod 755 "/etc/dovecot/"
	chown root:dovecot "/etc/dovecot/dovecot-dict-sql.conf"; chmod 640 "/etc/dovecot/dovecot-dict-sql.conf"
	chown root:vmail "/etc/dovecot/dovecot-mysql.conf"; chmod 640 "/etc/dovecot/dovecot-mysql.conf"
	chown root:root "/etc/dovecot/dovecot.conf"; chmod 644 "/etc/dovecot/dovecot.conf"
	touch "/etc/dovecot/mailcow_public_folder.conf"; chmod 664 "/etc/dovecot/mailcow_public_folder.conf"
	chown root:www-data "/etc/dovecot/mailcow_public_folder.conf"
	sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYDOMAIN}/g" /etc/dovecot/*
	sed -i "s/MAILCOW_DOMAIN/${MYDOMAIN}/g" /etc/dovecot/*
	sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" /etc/dovecot/*
	sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" /etc/dovecot/*
	sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" /etc/dovecot/*
	sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /etc/dovecot/*
	mkdir /etc/dovecot/conf.d 2> /dev/null
	mkdir -p /var/vmail/sieve 2> /dev/null
	mkdir -p /var/vmail/public 2> /dev/null
	if [ ! -f /var/vmail/public/dovecot-acl ]; then
		echo "anyone lrwstipekxa" > /var/vmail/public/dovecot-acl
	fi
	cp ~/sources/mailcow/dovecot/conf/global.sieve /var/vmail/sieve/global.sieve
	touch /var/vmail/sieve/default.sieve
	install -m 755 ~/sources/mailcow/misc/mc_msg_size /usr/local/sbin/mc_msg_size
	sievec /var/vmail/sieve/global.sieve
	chown -R vmail:vmail /var/vmail
	install -m 755 ~/sources/mailcow/dovecot/conf/doverecalcq /etc/cron.daily/

	# clamav
	echo "${info} Installing ClamaV..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	usermod -a -G vmail clamav >/dev/null 2>&1
	service clamav-freshclam stop >/dev/null 2>&1
	killall freshclam >/dev/null 2>&1
	rm -f /var/lib/clamav/* 2> /dev/null >/dev/null 2>&1
	sed -i '/DatabaseMirror/d' /etc/clamav/freshclam.conf
	sed -i '/MaxFileSize/c\MaxFileSize 10240M' /etc/clamav/clamd.conf
	sed -i '/StreamMaxLength/c\StreamMaxLength 10240M' /etc/clamav/clamd.conf
	echo "DatabaseMirror clamav.netcologne.de
DatabaseMirror clamav.internet24.eu
DatabaseMirror clamav.inode.at" >> /etc/clamav/freshclam.conf
	if [[ -f /etc/apparmor.d/usr.sbin.clamd || -f /etc/apparmor.d/local/usr.sbin.clamd ]]; then
		rm /etc/apparmor.d/usr.sbin.clamd >/dev/null 2>&1
		rm /etc/apparmor.d/local/usr.sbin.clamd >/dev/null 2>&1
		service apparmor restart >/dev/null 2>&1
	fi
	cp -f ~/sources/mailcow/clamav/clamav-unofficial-sigs.sh /usr/local/bin/clamav-unofficial-sigs.sh
	chmod +x /usr/local/bin/clamav-unofficial-sigs.sh
	cp -f ~/sources/mailcow/clamav/clamav-unofficial-sigs.conf /etc/clamav-unofficial-sigs.conf
	cp -f ~/sources/mailcow/clamav/clamav-unofficial-sigs.8 /usr/share/man/man8/clamav-unofficial-sigs.8
	cp -f ~/sources/mailcow/clamav/clamav-unofficial-sigs-cron /etc/cron.d/clamav-unofficial-sigs-cron
	cp -f ~/sources/mailcow/clamav/clamav-unofficial-sigs-logrotate /etc/logrotate.d/clamav-unofficial-sigs-logrotate
	mkdir -p /var/log/clamav-unofficial-sigs 2> /dev/null
	sed -i '/MaxFileSize/c\MaxFileSize 10M' /etc/clamav/clamd.conf
	sed -i '/StreamMaxLength/c\StreamMaxLength 10M' /etc/clamav/clamd.conf
	freshclam >/dev/null 2>&1

	# OpenDKIM
	echo "${info} Installing OpenDKIM..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo 'SOCKET="inet:10040@localhost"' > /etc/default/opendkim
	mkdir -p /etc/opendkim/{keyfiles,dnstxt} 2> /dev/null
	touch /etc/opendkim/{KeyTable,SigningTable}
	install -m 755 ~/sources/mailcow/misc/mc_dkim_ctrl /usr/local/sbin/
	install -m 644 ~/sources/mailcow/opendkim/conf/opendkim.conf /etc/opendkim.conf

	#SpamAssassin
	echo "${info} Installing SpamAssassin..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	cp ~/sources/mailcow/spamassassin/conf/local.cf /etc/spamassassin/local.cf
	sed -i '/^OPTIONS=/s/=.*/="--create-prefs --max-children 5 --helper-home-dir --username debian-spamd --socketpath \/var\/run\/spamd.sock --socketowner debian-spamd --socketgroup debian-spamd"/' /etc/default/spamassassin
	sed -i '/^CRON=/s/=.*/="1"/' /etc/default/spamassassin
	sed -i '/^ENABLED=/s/=.*/="1"/' /etc/default/spamassassin
	# Thanks to mf3hd@GitHub
	[[ -z $(grep RANDOM_DELAY /etc/crontab) ]] && sed -i '/SHELL/a RANDOM_DELAY=30' /etc/crontab
	install -m 755 ~/sources/mailcow/spamassassin/conf/spamlearn /etc/cron.daily/spamlearn
	install -m 755 ~/sources/mailcow/spamassassin/conf/spamassassin_heinlein /etc/cron.daily/spamassassin_heinlein
	# Thanks to mf3hd@GitHub, again!
	chmod g+s /etc/spamassassin
	chown -R debian-spamd: /etc/spamassassin
	razor-admin -create -home /etc/razor -conf=/etc/razor/razor-agent.conf >/dev/null 2>&1
	razor-admin -discover -home /etc/razor >/dev/null 2>&1
	razor-admin -register -home /etc/razor >/dev/null 2>&1
	su debian-spamd -c "pyzor --homedir /etc/mail/spamassassin/.pyzor discover >/dev/null 2>&1"
	su debian-spamd -c "sa-update >/dev/null 2>&1"
	if [[ -f /lib/systemd/systemd ]]; then
		systemctl enable spamassassin 2> /dev/null
	fi

	# Webserver
	echo "${info} Installing Mailcow..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	mkdir -p /var/www/ >/dev/null 2>&1
	cp ~/sources/mailcow/webserver/php5-fpm/conf/pool/mail.conf /etc/php5/fpm/pool.d/mail.conf
	sed -i "/date.timezone/c\php_admin_value[date.timezone] = ${TIMEZONE}" /etc/php5/fpm/pool.d/mail.conf
	mkdir /var/lib/php5/sessions >/dev/null 2>&1
	chown -R www-data:www-data /var/lib/php5/sessions
	install -m 755 ~/sources/mailcow/misc/mc_setup_backup /usr/local/sbin/mc_setup_backup
	cp -R ~/sources/mailcow/webserver/htdocs/{mail,dav,zpush} /var/www/
	tar xf /var/www/dav/vendor.tar -C /var/www/dav/ ; rm /var/www/dav/vendor.tar
	tar xzf /var/www/zpush/vendor.tar.gz -C /var/www/zpush/ ; rm /var/www/zpush/vendor.tar.gz
	find /var/www/{dav,mail,zpush} -type d -exec chmod 755 {} \;
	find /var/www/{dav,mail,zpush} -type f -exec chmod 644 {} \;
	sed -i "/date_default_timezone_set/c\date_default_timezone_set('${TIMEZONE}');" /var/www/dav/server.php
	touch /var/www/MAILBOX_BACKUP
	echo none > /var/www/PFLOG
	cp ~/sources/mailcow/misc/mc_resetadmin /usr/local/sbin/mc_resetadmin ; chmod 700 /usr/local/sbin/mc_resetadmin
	sed -i "s/mailcow_sub/mail/g" /var/www/mail/autoconfig.xml
	sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /var/www/mail/inc/vars.inc.php /var/www/dav/server.php /usr/local/sbin/mc_resetadmin /var/www/zpush/config.php /var/www/zpush/backend/imap/config.php
	sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" /var/www/mail/inc/vars.inc.php /var/www/dav/server.php /usr/local/sbin/mc_resetadmin /var/www/zpush/config.php /var/www/zpush/backend/imap/config.php
	sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" /var/www/mail/inc/vars.inc.php /var/www/dav/server.php /usr/local/sbin/mc_resetadmin /var/www/zpush/config.php /var/www/zpush/backend/imap/config.php
	sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" /var/www/mail/inc/vars.inc.php /var/www/dav/server.php /usr/local/sbin/mc_resetadmin /var/www/zpush/config.php /var/www/zpush/backend/imap/config.php
	sed -i "s/httpd_dav_subdomain/dav/g" /var/www/mail/inc/vars.inc.php
	chown -R www-data: /var/www/{.,mail,dav,MAILBOX_BACKUP} /var/lib/php5/sessions
	mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} < ~/sources/mailcow/webserver/htdocs/init.sql
	if [[ -z $(mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "SHOW INDEX FROM propertystorage WHERE KEY_NAME = 'path_property';" -N -B) ]]; then
		mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "CREATE UNIQUE INDEX path_property ON propertystorage (path(600), name(100));" -N -B
	fi
	if [[ -z $(mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "SHOW INDEX FROM zpush_states WHERE KEY_NAME = 'idx_zpush_states_unique';" -N -B) ]]; then
		mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "CREATE unique index idx_zpush_states_unique on zpush_states (device_id, uuid, state_type, counter);" -N -B
	fi
	if [[ -z $(mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "SHOW INDEX FROM zpush_preauth_users WHERE KEY_NAME = 'index_zpush_preauth_users_on_username_and_device_id';" -N -B) ]]; then
		mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "CREATE unique index index_zpush_preauth_users_on_username_and_device_id on zpush_preauth_users (username, device_id);" -N -B
	fi
	if [[ $(mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -s -N -e "SELECT * FROM admin;" | wc -l) -lt 1 ]]; then
		mailcow_admin_pass_hashed=$(doveadm pw -s SHA512-CRYPT -p ${MAILCOW_ADMIN_PASS})
		mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "INSERT INTO admin VALUES ('${MAILCOW_ADMIN_USER}','$mailcow_admin_pass_hashed',1,now(),now(),1);"
		mysql --host ${MYSQL_HOSTNAME} -u root -p${MYSQL_ROOT_PASS} ${MYSQL_MCDB_NAME} -e "INSERT INTO domain_admins (username, domain, created, active) VALUES ('${MAILCOW_ADMIN_USER}', 'ALL', now(), '1');"
	else
		echo "${info} At least one administrator exists, will not create another mailcow administrator" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	fi

	# zpush
	echo "${info} Installing Z-Push..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	sed -i "s#MAILCOW_TIMEZONE#${TIMEZONE}#g" /var/www/zpush/config.php
	sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYDOMAIN}/g" /var/www/zpush/backend/imap/config.php
	sed -i "s/MAILCOW_DAV_HOST.MAILCOW_DOMAIN/dav.${MYDOMAIN}/g" /var/www/zpush/backend/caldav/config.php
	sed -i "s/MAILCOW_DAV_HOST.MAILCOW_DOMAIN/dav.${MYDOMAIN}/g" /var/www/zpush/backend/carddav/config.php
	mkdir /var/{lib,log}/z-push 2>/dev/null
	chown -R www-data: /var/{lib,log}/z-push

	# Cleaning up old files
	sed -i '/test -d /var/run/fetchmail/d' /etc/rc.local >/dev/null 2>&1
	rm /etc/cron.d/pfadminfetchmail >/dev/null 2>&1
	rm /etc/mail/postfixadmin/fetchmail.conf >/dev/null 2>&1
	rm /usr/local/bin/fetchmail.pl >/dev/null 2>&1

	# Create Nginx Config
	cat > /etc/nginx/sites-custom/mailcow.conf <<END
location /admin {
    alias /var/www/mail;
    index index.php;

    location ~ ^/admin/(.+\.php)$ {
        alias /var/www/mail/\$1;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        include fastcgi_params;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME /var/www/mail/\$1;
        fastcgi_pass unix:/var/run/php5-fpm-mail.sock;
    }

    location ~* ^/admin/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
        alias /var/www/mail/\$1;
    }
}

location ~ ^/(admin/rc)/ {
    deny all;
    return 301 /admin;
}
END

	cat > /etc/nginx/sites-available/autodiscover.${MYDOMAIN}.conf <<END
server {
			listen 80;
			server_name autodiscover.${MYDOMAIN};
			return 301 https://autodiscover.${MYDOMAIN}\$request_uri;
}

server {
			listen 443 ssl http2;
			server_name autodiscover.${MYDOMAIN};

			root /var/www/zpush;
			index index.php;
			charset utf-8;

			error_page 404 /index.php;

			ssl_certificate 	ssl/${MYDOMAIN}.pem;
			ssl_certificate_key ssl/${MYDOMAIN}.key;
			#ssl_trusted_certificate ssl/trustedbundle.pem;
			ssl_dhparam	     	ssl/dh.pem;
			ssl_ecdh_curve		secp384r1;
			ssl_session_cache   shared:SSL:10m;
			ssl_session_timeout 10m;
			ssl_session_tickets off;
			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
			ssl_prefer_server_ciphers on;
			ssl_buffer_size 	4k;

			#ssl_stapling on;
			#ssl_stapling_verify on;
			#resolver 8.8.8.8 8.8.4.4 valid=300s;
			#resolver_timeout 5s;

			ssl_ciphers "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";

			#add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
			add_header X-Frame-Options SAMEORIGIN;
			add_header Alternate-Protocol  443:npn-http/2;
			add_header X-Content-Type-Options nosniff;
			add_header X-XSS-Protection "1; mode=block";
			add_header Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com cdnjs.cloudflare.com assets.zendesk.com connect.facebook.net; frame-src 'self' *.youtube.com assets.zendesk.com *.facebook.com s-static.ak.facebook.com tautt.zendesk.com; object-src 'self'";

			auth_basic_user_file htpasswd/.htpasswd;

			location ~ ^(.+\.php)(.*)\$ {
				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
				try_files \$fastcgi_script_name =404;
				set \$path_info \$fastcgi_path_info;
				fastcgi_param PATH_INFO \$path_info;
				fastcgi_param APP_ENV production;
				fastcgi_pass unix:/var/run/php5-fpm.sock;
				fastcgi_index index.php;
				include fastcgi.conf;
				fastcgi_intercept_errors on;
				fastcgi_ignore_client_abort off;
				fastcgi_buffers 256 16k;
				fastcgi_buffer_size 128k;
				fastcgi_connect_timeout 3s;
				fastcgi_send_timeout 120s;
				fastcgi_read_timeout 120s;
				fastcgi_busy_buffers_size 256k;
				fastcgi_temp_file_write_size 256k;
			}

			rewrite (?i)^/autodiscover/autodiscover\.xml\$ /autodiscover/autodiscover.php;

			location / {
				try_files \$uri \$uri/ /index.php;
			}

			location /Microsoft-Server-ActiveSync {
            	rewrite ^(.*)\$  /index.php last;
        	}

			location ~ /(\.ht|Core|Specific) {
                deny all;
                return 404;
        	}

			location = /favicon.ico {
				access_log off;
				log_not_found off;
			}
				
			location = /robots.txt {
				allow all;
				access_log off;
				log_not_found off;
			}

			location ~* ^.+\.(css|js)\$ {
				rewrite ^(.+)\.(\d+)\.(css|js)\$ \$1.\$3 last;
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

			location ~* \.(asf|asx|wax|wmv|wmx|avi|bmp|class|divx|doc|docx|eot|exe|gif|gz|gzip|ico|jpg|jpeg|jpe|mdb|mid|midi|mov|qt|mp3|m4a|mp4|m4v|mpeg|mpg|mpe|mpp|odb|odc|odf|odg|odp|ods|odt|ogg|ogv|otf|pdf|png|pot|pps|ppt|pptx|ra|ram|svg|svgz|swf|tar|t?gz|tif|tiff|ttf|wav|webm|wma|woff|wri|xla|xls|xlsx|xlt|xlw|zip)\$ {
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

}
END

	cat > /etc/nginx/sites-available/dav.${MYDOMAIN}.conf <<END
server {
			listen 80;
			server_name dav.${MYDOMAIN};
			return 301 https://dav.${MYDOMAIN}\$request_uri;
}

server {
			listen 443 ssl http2;
			server_name dav.${MYDOMAIN};

			root /var/www/dav;
			index server.php;
			charset utf-8;

			error_page 404 /index.php;

			ssl_certificate 	ssl/${MYDOMAIN}.pem;
			ssl_certificate_key ssl/${MYDOMAIN}.key;
			#ssl_trusted_certificate ssl/trustedbundle.pem;
			ssl_dhparam	     	ssl/dh.pem;
			ssl_ecdh_curve		secp384r1;
			ssl_session_cache   shared:SSL:10m;
			ssl_session_timeout 10m;
			ssl_session_tickets off;
			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
			ssl_prefer_server_ciphers on;
			ssl_buffer_size 	4k;

			#ssl_stapling on;
			#ssl_stapling_verify on;
			#resolver 8.8.8.8 8.8.4.4 valid=300s;
			#resolver_timeout 5s;

			ssl_ciphers "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";

			#add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
			add_header X-Frame-Options SAMEORIGIN;
			add_header Alternate-Protocol  443:npn-http/2;
			add_header X-Content-Type-Options nosniff;
			add_header X-XSS-Protection "1; mode=block";
			add_header Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com cdnjs.cloudflare.com assets.zendesk.com connect.facebook.net; frame-src 'self' *.youtube.com assets.zendesk.com *.facebook.com s-static.ak.facebook.com tautt.zendesk.com; object-src 'self'";

			auth_basic_user_file htpasswd/.htpasswd;

			location ~ ^(.+\.php)(.*)\$ {
				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
				try_files \$fastcgi_script_name =404;
				set \$path_info \$fastcgi_path_info;
				fastcgi_param PATH_INFO \$path_info;
				fastcgi_param APP_ENV production;
				fastcgi_pass unix:/var/run/php5-fpm.sock;
				fastcgi_index index.php;
				include fastcgi.conf;
				fastcgi_intercept_errors on;
				fastcgi_ignore_client_abort off;
				fastcgi_buffers 256 16k;
				fastcgi_buffer_size 128k;
				fastcgi_connect_timeout 3s;
				fastcgi_send_timeout 120s;
				fastcgi_read_timeout 120s;
				fastcgi_busy_buffers_size 256k;
				fastcgi_temp_file_write_size 256k;
			}

			rewrite ^/.well-known/caldav /server.php redirect;
			rewrite ^/.well-known/carddav /server.php redirect;

			location / {
				try_files \$uri \$uri/ /server.php?\$args;
			}

			location ~ /(\.ht|Core|Specific) {
                deny all;
                return 404;
        	}

			location = /favicon.ico {
				access_log off;
				log_not_found off;
			}
				
			location = /robots.txt {
				allow all;
				access_log off;
				log_not_found off;
			}

			location ~* ^.+\.(css|js)\$ {
				rewrite ^(.+)\.(\d+)\.(css|js)\$ \$1.\$3 last;
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

			location ~* \.(asf|asx|wax|wmv|wmx|avi|bmp|class|divx|doc|docx|eot|exe|gif|gz|gzip|ico|jpg|jpeg|jpe|mdb|mid|midi|mov|qt|mp3|m4a|mp4|m4v|mpeg|mpg|mpe|mpp|odb|odc|odf|odg|odp|ods|odt|ogg|ogv|otf|pdf|png|pot|pps|ppt|pptx|ra|ram|svg|svgz|swf|tar|t?gz|tif|tiff|ttf|wav|webm|wma|woff|wri|xla|xls|xlsx|xlt|xlw|zip)\$ {
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

}
END

	ln -s /etc/nginx/sites-available/autodiscover.${MYDOMAIN}.conf /etc/nginx/sites-enabled/autodiscover.${MYDOMAIN}.conf
	ln -s /etc/nginx/sites-available/dav.${MYDOMAIN}.conf /etc/nginx/sites-enabled/dav.${MYDOMAIN}.conf

	# RoundCube
	echo "${info} Installing RoundCube..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	if [ ${USE_WEBMAIL} == '1' ]; then
		mkdir -p /var/www/mail/rc
		tar xf ~/sources/mailcow/roundcube/inst/1.1.3.tar -C ~/sources/mailcow/roundcube/inst/
		cp -R ~/sources/mailcow/roundcube/inst/1.1.3/* /var/www/mail/rc/
		cp -R ~/sources/mailcow/roundcube/conf/* /var/www/mail/rc/
		sed -i "s/my_mailcowuser/${MYSQL_MCDB_USER}/g" /var/www/mail/rc/plugins/password/config.inc.php
		sed -i "s/my_mailcowpass/${MYSQL_MCDB_PASS}/g" /var/www/mail/rc/plugins/password/config.inc.php
		sed -i "s/my_mailcowdb/${MYSQL_MCDB_NAME}/g" /var/www/mail/rc/plugins/password/config.inc.php
		sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /var/www/mail/rc/plugins/password/config.inc.php
		sed -i "s/my_dbhost/${MYSQL_HOSTNAME}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/my_rcuser/${MYSQL_RCDB_USER}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/my_rcpass/${MYSQL_RCDB_PASS}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/my_rcdb/${MYSQL_RCDB_NAME}/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/conf_rcdeskey/$(generatepw)/g" /var/www/mail/rc/config/config.inc.php
		sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYDOMAIN}/g" /var/www/mail/rc/config/config.inc.php
		mysql --host ${MYSQL_HOSTNAME} -u ${MYSQL_RCDB_USER} -p${MYSQL_RCDB_PASS} ${MYSQL_RCDB_NAME} < /var/www/mail/rc/SQL/mysql.initial.sql
		chown -R www-data: /var/www/
		rm -rf ~/sources/mailcow/roundcube/inst/1.1.3
		rm -rf /var/www/mail/rc/installer/

		# Create Nginx Config
		cat > /etc/nginx/sites-custom/roundcube.conf <<END
location /mail {
    alias /var/www/mail/rc;
    index index.php;

    location ~ ^/mail/(.+\.php)$ {
        alias /var/www/mail/rc/\$1;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        include fastcgi_params;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME /var/www/mail/rc/\$1;
        fastcgi_pass unix:/var/run/php5-fpm-mail.sock;
    }

    location ~* ^/mail/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
        alias /var/www/mail/rc/\$1;
    }
}

location ~ ^/(mail/temp|mail/SQL|mail/config|mail/logs)/ {
    deny all;
    return 301 /mail;
}
END
	fi

	# Rsyslogd
	if [[ -d /etc/rsyslog.d ]]; then
		rm /etc/rsyslog.d/10-fufix >/dev/null 2>&1
		cp ~/sources/mailcow/rsyslog/conf/10-mailcow /etc/rsyslog.d/
		service rsyslog restart >/dev/null 2>&1
		postlog -p warn dummy >/dev/null 2>&1
		postlog -p info dummy >/dev/null 2>&1
		postlog -p err dummy >/dev/null 2>&1
	fi
fi

# phpMyAdmin
if [ $USE_PMA == '1' ]; then
	echo "${info} Installing phpMyAdmin..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	htpasswd -b /etc/nginx/htpasswd/.htpasswd ${PMA_HTTPAUTH_USER} ${PMA_HTTPAUTH_PASS} >/dev/null 2>&1
	cd /usr/local
	git clone -b STABLE https://github.com/phpmyadmin/phpmyadmin.git -q
	mkdir phpmyadmin/save
	mkdir phpmyadmin/upload
	chmod 0700 phpmyadmin/save
	chmod g-s phpmyadmin/save
	chmod 0700 phpmyadmin/upload
	chmod g-s phpmyadmin/upload
	mysql -u root -p${MYSQL_ROOT_PASS} mysql < phpmyadmin/sql/create_tables.sql >/dev/null 2>&1
	mysql -u root -p${MYSQL_ROOT_PASS} -e "GRANT USAGE ON mysql.* TO '${MYSQL_PMADB_USER}'@'${MYSQL_HOSTNAME}' IDENTIFIED BY '${MYSQL_PMADB_PASS}'; GRANT SELECT ( Host, User, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv ) ON mysql.user TO '${MYSQL_PMADB_USER}'@'${MYSQL_HOSTNAME}'; GRANT SELECT ON mysql.db TO '${MYSQL_PMADB_USER}'@'${MYSQL_HOSTNAME}'; GRANT SELECT (Host, Db, User, Table_name, Table_priv, Column_priv) ON mysql.tables_priv TO '${MYSQL_PMADB_USER}'@'${MYSQL_HOSTNAME}'; GRANT SELECT, INSERT, DELETE, UPDATE, ALTER ON ${MYSQL_PMADB_NAME}.* TO '${MYSQL_PMADB_USER}'@'${MYSQL_HOSTNAME}'; FLUSH PRIVILEGES;" >/dev/null 2>&1
	cat > phpmyadmin/config.inc.php <<END
<?php
\$cfg['blowfish_secret'] = '$PMA_BFSECURE_PASS';
\$i = 0;
\$i++;
\$cfg['UploadDir'] = 'upload';
\$cfg['SaveDir'] = 'save';
\$cfg['ForceSSL'] = true;
\$cfg['AllowArbitraryServer'] = true;
\$cfg['AllowThirdPartyFraming'] = true;
\$cfg['ShowServerInfo'] = false;
\$cfg['ShowDbStructureCreation'] = true;
\$cfg['ShowDbStructureLastUpdate'] = true;
\$cfg['ShowDbStructureLastCheck'] = true;
\$cfg['UserprefsDisallow'] = array(
    'ShowServerInfo',
    'ShowDbStructureCreation',
    'ShowDbStructureLastUpdate',
    'ShowDbStructureLastCheck',
    'Export/quick_export_onserver',
    'Export/quick_export_onserver_overwrite',
    'Export/onserver');
\$cfg['Import']['charset'] = 'utf-8';
\$cfg['Export']['quick_export_onserver'] = true;
\$cfg['Export']['quick_export_onserver_overwrite'] = true;
\$cfg['Export']['compression'] = 'gzip';
\$cfg['Export']['charset'] = 'utf-8';
\$cfg['Export']['onserver'] = true;
\$cfg['Export']['sql_drop_database'] = true;
\$cfg['DefaultLang'] = 'en';
\$cfg['ServerDefault'] = 1;
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['host'] = '${MYSQL_HOSTNAME}';
\$cfg['Servers'][\$i]['connect_type'] = 'tcp';
\$cfg['Servers'][\$i]['compress'] = false;
\$cfg['Servers'][\$i]['extension'] = 'mysqli';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['Servers'][\$i]['controluser'] = '$MYSQL_PMADB_USER';
\$cfg['Servers'][\$i]['controlpass'] = '$MYSQL_PMADB_PASS';
\$cfg['Servers'][\$i]['pmadb'] = '$MYSQL_PMADB_NAME';
\$cfg['Servers'][\$i]['bookmarktable'] = 'pma__bookmark';
\$cfg['Servers'][\$i]['relation'] = 'pma__relation';
\$cfg['Servers'][\$i]['table_info'] = 'pma__table_info';
\$cfg['Servers'][\$i]['table_coords'] = 'pma__table_coords';
\$cfg['Servers'][\$i]['pdf_pages'] = 'pma__pdf_pages';
\$cfg['Servers'][\$i]['column_info'] = 'pma__column_info';
\$cfg['Servers'][\$i]['history'] = 'pma__history';
\$cfg['Servers'][\$i]['table_uiprefs'] = 'pma__table_uiprefs';
\$cfg['Servers'][\$i]['tracking'] = 'pma__tracking';
\$cfg['Servers'][\$i]['userconfig'] = 'pma__userconfig';
\$cfg['Servers'][\$i]['recent'] = 'pma__recent';
\$cfg['Servers'][\$i]['favorite'] = 'pma__favorite';
\$cfg['Servers'][\$i]['users'] = 'pma__users';
\$cfg['Servers'][\$i]['usergroups'] = 'pma__usergroups';
\$cfg['Servers'][\$i]['navigationhiding'] = 'pma__navigationhiding';
\$cfg['Servers'][\$i]['savedsearches'] = 'pma__savedsearches';
\$cfg['Servers'][\$i]['central_columns'] = 'pma__central_columns';
\$cfg['Servers'][\$i]['designer_settings'] = 'pma__designer_settings';
\$cfg['Servers'][\$i]['export_templates'] = 'pma__export_templates';
?>
END
	chown -R www-data:www-data phpmyadmin/
	cat > /etc/nginx/sites-custom/phpmyadmin.conf <<END
location /pma {
    auth_basic "Restricted";
    alias /usr/local/phpmyadmin;
    index index.php;

    location ~ ^/pma/(.+\.php)$ {
        alias /usr/local/phpmyadmin/\$1;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        include fastcgi_params;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME /usr/local/phpmyadmin/\$1;
        fastcgi_pass unix:/var/run/php5-fpm.sock;
    }

    location ~* ^/pma/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
        alias /usr/local/phpmyadmin/\$1;
    }

    location ~ ^/pma/save/ {
        deny all;
    }

    location ~ ^/pma/upload/ {
        deny all;
    }
}
END
systemctl -q reload nginx.service
fi

# FIREWALL & SYSTEM TUNING
#
# Arno-Iptables-Firewall
# Fail2Ban
# System Tuning
#

#
# Arno-Iptable-Firewall
#

# Get the latest version
echo "${info} Installing Arno-Iptables-Firewall..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
git clone https://github.com/arno-iptables-firewall/aif.git ~/sources/aif -q

# Create folders and copy files
cd ~/sources/aif
echo "${info} Configuring Arno-Iptables-Firewall..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
mkdir -p /usr/local/share/arno-iptables-firewall/plugins
mkdir -p /usr/local/share/man/man1
mkdir -p /usr/local/share/man/man8
mkdir -p /usr/local/share/doc/arno-iptables-firewall
mkdir -p /etc/arno-iptables-firewall/plugins
mkdir -p /etc/arno-iptables-firewall/conf.d
cp bin/arno-iptables-firewall /usr/local/sbin/
cp bin/arno-fwfilter /usr/local/bin/
cp -R share/arno-iptables-firewall/* /usr/local/share/arno-iptables-firewall/
ln -s /usr/local/share/arno-iptables-firewall/plugins/traffic-accounting-show /usr/local/sbin/traffic-accounting-show
gzip -c share/man/man1/arno-fwfilter.1 >/usr/local/share/man/man1/arno-fwfilter.1.gz >/dev/null 2>&1
gzip -c share/man/man8/arno-iptables-firewall.8 >/usr/local/share/man/man8/arno-iptables-firewall.8.gz >/dev/null 2>&1
cp README /usr/local/share/doc/arno-iptables-firewall/
cp etc/init.d/arno-iptables-firewall /etc/init.d/
if [ -d "/usr/lib/systemd/system/" ]; then
  cp lib/systemd/system/arno-iptables-firewall.service /usr/lib/systemd/system/
fi
cp etc/arno-iptables-firewall/firewall.conf /etc/arno-iptables-firewall/
cp etc/arno-iptables-firewall/custom-rules /etc/arno-iptables-firewall/
cp -R etc/arno-iptables-firewall/plugins/ /etc/arno-iptables-firewall/
cp share/arno-iptables-firewall/environment /usr/local/share/

chmod +x /usr/local/sbin/arno-iptables-firewall
chown 0:0 /etc/arno-iptables-firewall/firewall.conf
chown 0:0 /etc/arno-iptables-firewall/custom-rules
chmod +x /usr/local/share/environment

# Start Arno-Iptables-Firewall at boot
update-rc.d -f arno-iptables-firewall start 11 S . stop 10 0 6 >/dev/null 2>&1

# Configure firewall.conf
bash /usr/local/share/environment >/dev/null 2>&1
sed -i "s/^Port 22/Port ${SSH}/g" /etc/ssh/sshd_config
sed -i 's/.*EXT_IF=.*/EXT_IF="eth0"/' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/.*EXT_IF_DHCP_IP=.*/EXT_IF_DHCP_IP="0"/' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/.*FIREWALL_LOG=.*/FIREWALL_LOG="\/var\/log\/firewall.log"/' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/.*DRDOS_PROTECT=.*/DRDOS_PROTECT="1"/' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/.*IPV6_SUPPORT=.*/IPV6_SUPPORT="0"/' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/.*OPEN_ICMP=.*/OPEN_ICMP="1"/' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/.*BLOCK_HOSTS_FILE=.*/BLOCK_HOSTS_FILE="\/etc\/arno-iptables-firewall\/blocked-hosts"/' /etc/arno-iptables-firewall/firewall.conf
if [ ${USE_MAILSERVER} == '1' ]; then
	sed -i "s/.*OPEN_TCP=.*/OPEN_TCP=\"${SSH}, 25, 80, 110, 143, 443, 465, 587, 993, 995\"/" /etc/arno-iptables-firewall/firewall.conf
else
	sed -i "s/.*OPEN_TCP=.*/OPEN_TCP=\"${SSH}, 80, 443\"/" /etc/arno-iptables-firewall/firewall.conf
fi
sed -i 's/.*OPEN_UDP=.*/OPEN_UDP=""/' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/.*VERBOSE=.*/VERBOSE=1/' /etc/init.d/arno-iptables-firewall

# Start the firewall
systemctl -q daemon-reload
systemctl -q start arno-iptables-firewall.service

# Blacklist some bad guys
mkdir ~/sources/blacklist
sed -i 's/.*BLOCK_HOSTS_FILE=.*/BLOCK_HOSTS_FILE="\/etc\/arno-iptables-firewall\/blocked-hosts"/' /etc/arno-iptables-firewall/firewall.conf
cat > /etc/cron.daily/blocked-hosts <<END
#!/bin/bash
BLACKLIST_DIR="/root/sources/blacklist"
BLACKLIST="/etc/arno-iptables-firewall/blocked-hosts"
BLACKLIST_TEMP="\$BLACKLIST_DIR/blacklist

LIST=(
"http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1"
"http://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
"http://www.maxmind.com/en/anonymous_proxies"
"http://danger.rulez.sk/projects/bruteforceblocker/blist.php"
"http://rules.emergingthreats.net/blockrules/compromised-ips.txt"
"http://www.spamhaus.org/drop/drop.lasso"
"http://cinsscore.com/list/ci-badguys.txt"
"http://www.openbl.org/lists/base.txt"
"http://www.autoshun.org/files/shunlist.csv"
"http://lists.blocklist.de/lists/all.txt"
)

for i in "\${LIST[@]}"
do
    wget -T 10 -t 2 -O - \$i | grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' >> \$BLACKLIST_TEMP
done

sort \$BLACKLIST_TEMP -n | uniq > \$BLACKLIST
rm \$BLACKLIST_TEMP
systemctl force-reload arno-iptables-firewall.service
END
chmod +x /etc/cron.daily/blocked-hosts

# Fail2Ban
echo "${info} Installing fail2ban..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
tar xf ~/sources/mailcow/fail2ban/inst/0.9.3.tar -C ~/sources/mailcow/fail2ban/inst/ 2> /dev/null
rm -rf /etc/fail2ban/ 2> /dev/null
(cd ~/sources/mailcow/fail2ban/inst/0.9.3 ; python setup.py -q install 2> /dev/null)
if [[ -f /lib/systemd/systemd ]]; then
	mkdir -p /var/run/fail2ban
	cp ~/sources/mailcow/fail2ban/conf/fail2ban.service /lib/systemd/system/fail2ban.service
	systemctl enable fail2ban 2> /dev/null
else
	cp ~/sources/mailcow/fail2ban/conf/fail2ban.init /etc/init.d/fail2ban
	chmod +x /etc/init.d/fail2ban
	update-rc.d fail2ban defaults 2> /dev/null
fi
if [[ ! -f /var/log/mail.warn ]]; then
	touch /var/log/mail.warn
fi
if [[ ! -f /etc/fail2ban/jail.local ]]; then
	cp ~/sources/mailcow/fail2ban/conf/jail.local /etc/fail2ban/jail.local
fi
cp ~/sources/mailcow/fail2ban/conf/jail.d/*.conf /etc/fail2ban/jail.d/
rm -rf ~/sources/mailcow/fail2ban/inst/0.9.3
[[ -z $(grep fail2ban /etc/rc.local) ]] && sed -i '/^exit 0/i\test -d /var/run/fail2ban || install -m 755 -d /var/run/fail2ban/' /etc/rc.local
mkdir /var/run/fail2ban/ 2> /dev/null

# System Tuning
echo "${info} Kernel hardening & system tuning..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
cat > /etc/sysctl.conf <<END
kernel.randomize_va_space=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_fin_timeout = 1
net.ipv4.tcp_tw_recycle = 1
kernel.shmmax = 1073741824
net.ipv4.tcp_rmem = 4096 25165824 25165824
net.core.rmem_max = 25165824
net.core.rmem_default = 25165824
net.ipv4.tcp_wmem = 4096 65536 25165824
net.core.wmem_max = 25165824
net.core.wmem_default = 65536
net.core.optmem_max = 25165824
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.core.default_qdisc=fq_codel
fs.inotify.max_user_instances=2048

# Disable IPV6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
END

# Enable changes
sysctl -p >/dev/null 2>&1


# Public Key Authentication
echo "${info} Generating key for public key authentication..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
ssh-keygen -f ~/ssh.key -b 3072 -t rsa -N ${SSH_PASS} >/dev/null 2>&1
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat ~/ssh.key.pub > ~/.ssh/authorized_keys2 && rm ~/ssh.key.pub
chmod 600 ~/.ssh/authorized_keys2
mv ~/ssh.key ~/ssh_privatekey.txt

sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/^UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config
echo -e "" >> /etc/ssh/sshd_config
echo -e "# Disable password based logins" >> /etc/ssh/sshd_config
echo -e "AuthenticationMethods publickey" >> /etc/ssh/sshd_config
systemctl -q restart ssh.service

truncate -s 0 /var/log/daemon.log
truncate -s 0 /var/log/syslog

# Restart all services
if [ ${USE_MAILSERVER} == '1' ]; then
	systemctl -q restart {fail2ban,rsyslog,nginx,php5-fpm,spamassassin,dovecot,postfix,opendkim,clamav-daemon,fuglu}
else
	systemctl -q restart {fail2ban,nginx,php5-fpm}
fi

}

logininformation() {
touch ~/credentials.txt
echo "///////////////////////////////////////////////////////////////////////////" >> ~/credentials.txt
echo "// Passwords, Usernames, Databases" >> ~/credentials.txt
echo "///////////////////////////////////////////////////////////////////////////" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "_______________________________________________________________________________________" >> ~/credentials.txt
echo "### MYSQL & WEB" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt
echo "MySQL root" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt
echo "hostname = ${MYSQL_HOSTNAME}" >> ~/credentials.txt
echo "username = root" >> ~/credentials.txt
echo "password = ${MYSQL_ROOT_PASS}" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "" >> ~/credentials.txt
if [ ${USE_MAILSERVER} == '1' ]; then
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "mailcow admin" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "username = ${MAILCOW_ADMIN_USER}" >> ~/credentials.txt
	echo "password = ${MAILCOW_ADMIN_PASS}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "mailcow database" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "database = ${MYSQL_MCDB_NAME}" >> ~/credentials.txt
	echo "username = ${MYSQL_MCDB_USER}" >> ~/credentials.txt
	echo "password = ${MYSQL_MCDB_PASS}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
		if [ ${USE_WEBMAIL} == '1' ]; then
			echo "--------------------------------------------" >> ~/credentials.txt
			echo "roundcube database" >> ~/credentials.txt
			echo "--------------------------------------------" >> ~/credentials.txt
			echo "database = ${MYSQL_RCDB_NAME}" >> ~/credentials.txt
			echo "username = ${MYSQL_RCDB_USER}" >> ~/credentials.txt
			echo "password = ${MYSQL_RCDB_PASS}" >> ~/credentials.txt
			echo "" >> ~/credentials.txt
			echo "" >> ~/credentials.txt
		fi
fi
if [ ${USE_PMA} == '1' ]; then
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "phpMyAdmin database" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "database = ${MYSQL_PMADB_NAME}" >> ~/credentials.txt
	echo "username = ${MYSQL_PMADB_USER}" >> ~/credentials.txt
	echo "password = ${MYSQL_PMADB_PASS}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "phpMyAdmin web" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "username = ${PMA_HTTPAUTH_USER}" >> ~/credentials.txt
	echo "password = ${PMA_HTTPAUTH_PASS}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "blowfish = ${PMA_BFSECURE_PASS}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
fi
echo "_______________________________________________________________________________________" >> ~/credentials.txt
echo "## SSH" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "port       = ${SSH}" >> ~/credentials.txt
echo "password   = ${SSH_PASS}" >> ~/credentials.txt
echo "privatekey = check /root/ssh_privatekey.txt" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "_______________________________________________________________________________________" >> ~/credentials.txt
echo "## URLs" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt
echo "your domain" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt
echo "https://${MYDOMAIN}" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "" >> ~/credentials.txt
if [ ${USE_MAILSERVER} == '1' ]; then
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "mailcow (mailserver admin)" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "https://${MYDOMAIN}/admin" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	if [ ${USE_WEBMAIL} == '1' ]; then
		echo "--------------------------------------------" >> ~/credentials.txt
		echo "roundcube (webmail)" >> ~/credentials.txt
		echo "--------------------------------------------" >> ~/credentials.txt
		echo "https://${MYDOMAIN}/mail" >> ~/credentials.txt
		echo "" >> ~/credentials.txt
		echo "" >> ~/credentials.txt
	fi
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "caldav" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "https://dav.${MYDOMAIN}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "autoconfigure" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "https://autoconfigure.${MYDOMAIN}" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
fi
if [ ${USE_PMA} == '1' ]; then
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "phpMyAdmin" >> ~/credentials.txt
	echo "--------------------------------------------" >> ~/credentials.txt
	echo "https://${MYDOMAIN}/pma" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
fi
echo "_______________________________________________________________________________________" >> ~/credentials.txt
echo "## SYSTEM INFORMATION" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt
echo "open ports" >> ~/credentials.txt
echo "--------------------------------------------" >> ~/credentials.txt
if [ ${USE_MAILSERVER} == '1' ]; then
	echo "TCP = 25 (SMTP), 80 (HTTP), 110 (POP3), 143(IMAP), 443 (HTTPS), 465 (SMPTS)" >> ~/credentials.txt 
	echo "TCP = 587 (Submission), 993 (IMAPS), 995 (POP3S), ${SSH} (SSH)" >> ~/credentials.txt
	echo "UDP = All ports are closed" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
else
	echo "TCP = 80 (HTTP), 443 (HTTPS), ${SSH} (SSH)" >> ~/credentials.txt
	echo "UDP = All ports are closed" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
	echo "" >> ~/credentials.txt
fi
echo "You can add additional ports, just edit \"/etc/arno-iptables-firewall/firewall.conf\" (lines 1164 & 1165)" >> ~/credentials.txt
echo "and restart your firewall -> \"systemctl force-reload arno-iptables-firewall\"" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "" >> ~/credentials.txt
echo "_______________________________________________________________________________________" >> ~/credentials.txt
echo "${ok} Done! The credentials are located in the file $(textb /root/credentials.txt)!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
}

instructions() {
	SSH_PASSWD=$(sed -n '/^## SSH$/{n;n;n;p}' ~/credentials.txt | awk '{print $3}')
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
	echo "Password for your ssh key = ${SSH_PASSWD}" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	echo
	echo
	cat ~/ssh_privatekey.txt
	echo
	echo
	echo "${info} Press $(textb ENTER) to continue" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
    read -s -n 1 i
    echo
    if [ ${USE_MAILSERVER} == '1' ]; then
    	MCAU=$(sed -n '/^mailcow admin$/{n;n;p}' ~/credentials.txt | awk '{print $3}')
		MCAP=$(sed -n '/^mailcow admin$/{n;n;n;p}' ~/credentials.txt | awk '{print $3}')
		echo "${info} Before the mailserver can be used, the following requirements must be met:" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo "The subomains mail.${MYDOMAIN}, dav.${MYDOMAIN} and autodiscover.${MYDOMAIN}" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
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
			if [[ $ADIP != $IPADR ]]; then
				echo "${warn} autodiscover.${MYDOMAIN} does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			else	
				echo "${ok} autodiscover.${MYDOMAIN} resolve to the IP adress of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			fi
			sleep 1
			if [[ $DAVIP != $IPADR ]]; then
				echo "${warn} dav.${MYDOMAIN} does not resolve to the IP address of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			else	
				echo "${ok} dav.${MYDOMAIN} resolve to the IP adress of your server (${IPADR})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			fi
			echo
			echo "${info} Repeat this check? Press $(textb ENTER) for yes or $(textb [N]) to skip" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			read -s -n 1 i
			if [[ $i == "" ]]; then
				echo >> /dev/null
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
				echo >> /dev/null
			else
				if [[ $i == "n" ]] || [[ $i == "N" ]]; then
					break
				fi
			fi
		done
		echo
		echo
		echo "${info} In the next step you have to set two DNS TXT records for your domain." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
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
		echo "Visit https://${MYDOMAIN}/admin and login with username = ${MCAU} and password = ${MCAP}" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "Generate your DKIMPUBLICKEY (mailcow admin -> DKMIM signing)" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "Domain:   ${MYDOMAIN}" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "Selector: mail" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		while true; do
			echo
			echo
			if [[ -z $CHECKSPF ]]; then
				echo "${warn} TXT record for SPF was not found!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			else
				echo "${ok} TXT record for SPF was found!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'	
			fi
			sleep 1
			if [[ -z $CHECKDKIM ]]; then
				echo "${warn} TXT record for DKIM was not found!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			else
				echo "${ok} TXT record for DKIM was found!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'	
			fi
			echo
			echo "${info} Repeat this check? Press $(textb ENTER) for yes or $(textb [N]) to skip" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			read -s -n 1 i
			if [[ $i == "" ]]; then
				echo >> /dev/null
			else
				if [[ $i == "n" ]] || [[ $i == "N" ]]; then
					break
				fi
			fi
		done
		echo
		echo
	    echo "${info} Your server supports ActiveSync. To make it work you have to enable autodiscovery." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	    echo "${info} It is the ability for Outlook (and ofc other software) to automatically configure itself." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	    echo "${info} You had to set specific DNS _SRV records to bring it up:" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	    echo
	    echo "      NAME           TYPE              VALUE" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "----------------------------------------------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo " _autodiscover._tcp     SRV     \"SRV 1 1 443 autodiscover.${MYDOMAIN}.\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo
		echo "      NAME           TYPE              VALUE" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "----------------------------------------------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo " _carddavs._tcp     SRV     \"SRV 1 1 443 dav.${MYDOMAIN}.\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo
		echo "      NAME           TYPE              VALUE" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "----------------------------------------------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo " _caldavs._tcp     SRV     \"SRV 1 1 443 dav.${MYDOMAIN}.\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo
	    echo "      NAME           TYPE              VALUE" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "----------------------------------------------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo " _pop3._tcp     SRV     \"SRV 1 1 110 mail.${MYDOMAIN}.\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo
		echo "      NAME           TYPE              VALUE" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "----------------------------------------------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo " _imap._tcp     SRV     \"SRV 1 1 143 mail.${MYDOMAIN}.\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo
		echo "      NAME           TYPE              VALUE" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "----------------------------------------------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo " _submission._tcp     SRV     \"SRV 1 1 587 mail.${MYDOMAIN}.\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo
		echo "      NAME           TYPE              VALUE" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "----------------------------------------------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo " _imaps._tcp     SRV     \"SRV 1 1 993 mail.${MYDOMAIN}.\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo
		echo "      NAME           TYPE              VALUE" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "----------------------------------------------------------" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo " _pop3s._tcp     SRV     \"SRV 1 1 995 mail.${MYDOMAIN}.\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo
		echo "${info} Please read http://wki.pe/SRV_record for more information" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		echo "${info} Press $(textb ENTER) to continue.." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
		read -s -n 1 i
		while true; do
			echo
			echo
			for srv in _autodiscover _carddavs _caldavs _imap _imaps _submission _pop3 _pop3s
			do
				sleep 1.5
				if [[ -z $(dig srv ${srv}._tcp.${MYDOMAIN} @4.2.2.1 +short) ]]; then
					echo "${warn} SRV record not found: $(textb ${srv}._tcp.${MYDOMAIN})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				else
					echo "${ok} Valid SRV record found: $(textb ${srv}._tcp.${MYDOMAIN})" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
				fi
			done
			echo
			echo "${info} Repeat this check? Press $(textb ENTER) for yes or $(textb [N]) to skip" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
			read -s -n 1 i
			if [[ $i == "" ]]; then
				echo >> /dev/null
			else
				if [[ $i == "n" ]] || [[ $i == "N" ]]; then
					break
				fi
			fi
		done
	fi
	echo
    echo "${ok} You are done. You can run the assistant again, just write \"$(textb bash) $(textb ~/assistant.sh)\"" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
    echo "The credentials are located in the file $(textb ~/credentials.txt)!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
}

source ~/userconfig.cfg

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

if [ $(dpkg-query -l | grep dig | wc -l) -ne 1 ]; then
	apt-get update -y >/dev/null 2>&1 && apt-get -y --force-yes install dnsutils >/dev/null 2>&1
fi

FQDNIP=$(source ~/userconfig.cfg; dig @4.2.2.1 +short ${MYDOMAIN})
ADIP=$(source ~/userconfig.cfg; dig @4.2.2.1 +short autodiscover.${MYDOMAIN})
DAVIP=$(source ~/userconfig.cfg; dig @4.2.2.1 +short dav.${MYDOMAIN})
MAILIP=$(source ~/userconfig.cfg; dig @4.2.2.1 +short mail.${MYDOMAIN})
CHECKMX=$(source ~/userconfig.cfg; dig mx ${MYDOMAIN} @4.2.2.1 +short)
CHECKSPF=$(source ~/userconfig.cfg; dig ${MYDOMAIN} txt @4.2.2.1 | grep -i spf)
CHECKDKIM=$(source ~/userconfig.cfg; dig mail._domainkey.${MYDOMAIN} txt @4.2.2.1 | grep -i DKIM1)
IPADR=$(ifconfig eth0 | awk -F ' *|:' '/inet /{print $4}')