# The perfect rootserver
# by zypr
# https://github.com/zypr/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

generatepw() {
        while [[ $pw == "" ]]; do
                pw=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
        done
        echo "$pw" && unset pw
}

system() {
echo "${info} Starting installation!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

cat > /etc/hosts <<END
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
END

if [[ -z $(dpkg --get-selections | grep -E "^dbus.*install$") ]]; then
	apt-get update -y >/dev/null 2>&1 && apt-get -y --force-yes install dbus >/dev/null 2>&1
fi

if [ ${USE_MAILSERVER} == '1' ]; then
	echo -e "${IPADR} mail.${MYDOMAIN} mail" >> /etc/hosts
	hostnamectl set-hostname mail
else
	echo -e "${IPADR} ${MYDOMAIN} $(echo ${MYDOMAIN} | cut -f 1 -d '.')" >> /etc/hosts
	hostnamectl set-hostname $(echo ${MYDOMAIN} | cut -f 1 -d '.')
fi

if [ ${USE_MAILSERVER} == '1' ]; then
	echo "mail.${MYDOMAIN}" > /etc/mailname
else
	echo "${MYDOMAIN}" > /etc/mailname
fi

echo "${info} Setting your hostname & timezone..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
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
# Dotdeb
deb http://packages.dotdeb.org jessie all
deb-src http://packages.dotdeb.org jessie all

# Doveocot
deb http://xi.rename-it.nl/debian/ stable-auto/dovecot-2.3 main
END

cat > /etc/apt/sources.list.d/security.list <<END
deb http://security.debian.org/ stable/updates main contrib non-free
deb http://security.debian.org/ testing/updates main contrib non-free
END

cat > /etc/apt/sources.list.d/stable.list <<END
deb	http://ftp.debian.org/debian/ stable main contrib non-free
deb-src http://ftp.debian.org/debian/ stable main contrib non-free
END

cat > /etc/apt/sources.list.d/testing.list <<END
deb	http://ftp.debian.org/debian/ testing main contrib non-free
deb-src http://ftp.debian.org/debian/ testing main contrib non-free
END

cat > /etc/apt/sources.list.d/unstable.list <<END
deb	http://ftp.debian.org/debian/ unstable main contrib non-free
deb-src http://ftp.debian.org/debian/ unstable main contrib non-free
END

cat > /etc/apt/sources.list.d/experimental.list <<END
deb	http://ftp.debian.org/debian/ experimental main contrib non-free
deb-src http://ftp.debian.org/debian/ experimental main contrib non-free
END

cat > /etc/apt/preferences.d/security.pref <<END
Package: *
Pin: release l=Debian-Security
Pin-Priority: 1000
END

cat > /etc/apt/preferences.d/stable.pref <<END
Package: *
Pin: release a=stable
Pin-Priority: 900
END

cat > /etc/apt/preferences.d/testing.pref <<END
Package: *
Pin: release a=testing
Pin-Priority: 750
END

cat > /etc/apt/preferences.d/unstable.pref <<END
Package: *
Pin: release a=unstable
Pin-Priority: 50
END

cat > /etc/apt/preferences.d/experimental.pref <<END
Package: *
Pin: release a=experimental
Pin-Priority: 1
END

wget -O ~/sources/dovecot.key http://xi.rename-it.nl/debian/archive.key >/dev/null 2>&1 && apt-key add ~/sources/dovecot.key >/dev/null 2>&1
wget -O ~/sources/dotdeb.gpg http://www.dotdeb.org/dotdeb.gpg >/dev/null 2>&1 && apt-key add ~/sources/dotdeb.gpg >/dev/null 2>&1
apt-get update -y >/dev/null 2>&1 && apt-get -y upgrade >/dev/null 2>&1
apt-get -y --force-yes install aptitude ssl-cert whiptail apt-utils jq libc6-dev/stable >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive aptitude -y install apache2-threaded-dev apache2-utils apt-listchanges arj autoconf automake bison bsd-mailx build-essential bzip2 ca-certificates cabextract checkinstall curl dnsutils file flex git htop libapr1-dev libaprutil1 libaprutil1-dev libauthen-sasl-perl-Daemon libawl-php libcunit1-dev libcrypt-ssleay-perl libcurl4-openssl-dev libdbi-perl libgeoip-dev libio-socket-ssl-perl libio-string-perl liblockfile-simple-perl liblogger-syslog-perl libmail-dkim-perl libmail-spf-perl libmime-base64-urlsafe-perl libnet-dns-perl libnet-ident-perl libnet-LDAP-perl libnet1 libnet1-dev libpam-dev libpcre-ocaml-dev libpcre3 libpcre3-dev libreadline6-dev libtest-tempdir-perl libtool libuv-dev libwww-perl libxml2 libxml2-dev libxml2-utils libxslt1-dev libyaml-dev lzop mariadb-server mc memcached mlocate nettle-dev nomarch php-auth-sasl php-auth-sasl php-http-request php-http-request php-mail php-mail-mime php-mail-mimedecode php-net-dime php-net-smtp php-net-url php-pear php-soap php5 php5-apcu php5-cli php5-common php5-common php5-curl php5-dev php5-fpm php5-geoip php5-gd php5-igbinary php5-imap php5-intl php5-mcrypt php5-mysql php5-sqlite php5-xmlrpc php5-xsl pkg-config python-setuptools python-software-properties rkhunter software-properties-common subversion sudo unzip vim-nox zip zlib1g zlib1g-dbg zlib1g-de zoo >/dev/null 2>&1

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

# Bash
cd ~/sources
mkdir bash && cd $_
echo "${info} Downloading GNU bash & latest security patches..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget https://ftp.gnu.org/gnu/bash/bash-4.3.tar.gz >/dev/null 2>&1
for i in $(seq -f "%03g" 1 46); do wget http://ftp.gnu.org/gnu/bash/bash-4.3-patches/bash43-$i; done >/dev/null 2>&1
tar zxf bash-4.3.tar.gz && cd bash-4.3 >/dev/null 2>&1
echo "${info} Patching sourcefiles..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
for i in ../bash43-[0-9][0-9][0-9]; do patch -p0 -s < $i; done
echo "${info} Compiling GNU bash..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
./configure --prefix=/usr/local >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
cp -f /usr/local/bin/bash /bin/bash

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
net.ipv6.conf.${INTERFACE}.disable_ipv6 = 1
END

# Enable changes
sysctl -p >/dev/null 2>&1

# Restart all services
if [ ${USE_MAILSERVER} == '1' ]; then
	systemctl -q restart {fail2ban,rsyslog,nginx,php5-fpm,spamassassin,dovecot,postfix,opendkim,clamav-daemon,fuglu,mailgraph}
else
	systemctl -q restart {fail2ban,nginx,php5-fpm}
fi

}

addoninformation() {
touch ~/addoninformation.txt
echo "///////////////////////////////////////////////////////////////////////////" >> ~/addoninformation.txt
echo "// Passwords, Usernames, Databases" >> ~/addoninformation.txt
echo "///////////////////////////////////////////////////////////////////////////" >> ~/addoninformation.txt
echo "" >> ~/addoninformation.txt
echo "_______________________________________________________________________________________" >> ~/addoninformation.txt
}

source ~/userconfig.cfg
source ~/addonconfig.cfg
