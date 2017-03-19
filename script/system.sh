#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

system() {
echo "${info} Starting installation!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

cat > /etc/hosts <<END
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
END

if [[ -z $(dpkg --get-selections | grep -E "^dbus.*install$") ]]; then
	apt-get update -y >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log && apt-get -y --force-yes install dbus >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
fi

if [ ${USE_MAILSERVER} == '1' ]; then
	echo -e "${IPADR} mail.${MYDOMAIN} mail" >> /etc/hosts
	hostnamectl set-hostname mail
	echo "mail.${MYDOMAIN}" > /etc/mailname
else
	echo -e "${IPADR} ${MYDOMAIN} $(echo ${MYDOMAIN} | cut -f 1 -d '.')" >> /etc/hosts
	hostnamectl set-hostname $(echo ${MYDOMAIN} | cut -f 1 -d '.')
	echo "${MYDOMAIN}" > /etc/mailname
fi

echo "${info} Setting your hostname & timezone..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
if [[ -f /usr/share/zoneinfo/${TIMEZONE} ]] ; then
	echo ${TIMEZONE} > /etc/timezone
	dpkg-reconfigure -f noninteractive tzdata >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
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

echo 'deb http://xi.dovecot.fi/debian/ stable-auto/dovecot-2.3 main' > /etc/apt/sources.list.d/dovecot.list

rm /etc/apt/sources.list
cat > /etc/apt/sources.list <<END
# Dotdeb
deb http://packages.dotdeb.org jessie all
deb-src http://packages.dotdeb.org jessie all

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

cat > /etc/apt/preferences.d/dotdeb <<END
Package: *
Pin: origin packages.dotdeb.org
Pin-Priority: 1001
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


wget -q http://xi.dovecot.fi/debian/archive.key -O- | apt-key add - >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
wget -O ~/sources/dotdeb.gpg http://www.dotdeb.org/dotdeb.gpg >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log && apt-key add ~/sources/dotdeb.gpg >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

apt-get update -y >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log && apt-get -y upgrade >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

apt-get -y --force-yes install aptitude ssl-cert whiptail apt-utils jq openssl-blacklist glibc-doc libc6-dev/stable >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

DEBIAN_FRONTEND=noninteractive aptitude -y install libldap2-dev/stable apache2-threaded-dev apache2-utils apt-listchanges arj autoconf automake bison bsd-mailx build-essential bzip2 ca-certificates cabextract checkinstall curl dnsutils file flex git htop libapr1-dev libaprutil1 libaprutil1-dev libauthen-sasl-perl daemon libawl-php libcunit1-dev libcrypt-ssleay-perl libcurl4-openssl-dev libdbi-perl libgeoip-dev libio-socket-ssl-perl libio-string-perl liblockfile-simple-perl liblogger-syslog-perl libmail-dkim-perl libmail-spf-perl libmime-base64-urlsafe-perl libnet-dns-perl libnet-ident-perl libnet-LDAP-perl libnet1 libnet1-dev libpam-dev libpcre-ocaml-dev libpcre3 libpcre3-dev libreadline6-dev libtest-tempdir-perl libtool libuv-dev libwww-perl libxml2 libxml2-dev/stable libxml2-utils libxslt1-dev libyaml-dev lzop mariadb-server mc memcached mlocate nettle-dev nomarch pkg-config python-setuptools python-dev python-software-properties rkhunter software-properties-common sudo unzip vim-nox zip zlib1g zlib1g-dbg zlib1g-dev zoo >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

if [ "$?" -ne "0" ]; then
	echo "${error} Package installation failed!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 1
fi

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
sysctl -p >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
}

source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg