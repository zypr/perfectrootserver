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

system() {
echo "${info} Starting installation!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

cat > /etc/hosts <<END
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
END

if [[ -z $(dpkg --get-selections | grep -E "^dbus.*install$") ]]; then
	apt-get update -y >>"$main_log" 2>>"$err_log" && apt-get -y --force-yes install dbus >>"$main_log" 2>>"$err_log"
fi

	echo -e "${IPADR} ${MYDOMAIN} $(echo ${MYDOMAIN} | cut -f 1 -d '.')" >> /etc/hosts
	#hostnamectl set-hostname $(echo ${MYDOMAIN} | cut -f 1 -d '.')
	hostnamectl set-hostname mail.${MYDOMAIN}
	echo "${MYDOMAIN}" > /etc/mailname

echo "${info} Setting your hostname & timezone..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
if [[ -f /usr/share/zoneinfo/${TIMEZONE} ]] ; then
	echo ${TIMEZONE} > /etc/timezone
	dpkg-reconfigure -f noninteractive tzdata >>"$main_log" 2>>"$err_log"
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

cat > /etc/apt/apt.conf.d/default-release <<END
APT::Default-Release "jessie";
END

cat > /etc/apt/sources.list <<END
# Dotdeb
deb http://packages.dotdeb.org jessie all
deb-src http://packages.dotdeb.org jessie all

# MariaDB
deb [arch=amd64,i386] http://mirror.netcologne.de/mariadb/repo/10.1/debian jessie main

# Debian
deb 	http://security.debian.org/ jessie/updates main contrib non-free
deb 	http://security.debian.org/ testing/updates main contrib non-free
deb 	http://ftp.debian.org/debian/ jessie main contrib non-free
deb-src http://ftp.debian.org/debian/ jessie main contrib non-free
deb 	http://ftp.debian.org/debian/ testing main contrib non-free
deb-src http://ftp.debian.org/debian/ testing main contrib non-free
deb     http://ftp.debian.org/debian/ unstable main contrib non-free
deb-src http://ftp.debian.org/debian/ unstable main contrib non-free
deb     http://ftp.debian.org/debian/ experimental main contrib non-free
deb-src http://ftp.debian.org/debian/ experimental main contrib non-free
END

wget -O ~/sources/dotdeb.gpg http://www.dotdeb.org/dotdeb.gpg >>"$main_log" 2>>"$err_log" && apt-key add ~/sources/dotdeb.gpg >>"$main_log" 2>>"$err_log"
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db >>"$main_log" 2>>"$err_log"

apt-get update -y >>"$main_log" 2>>"$err_log" && apt-get -y upgrade >>"$main_log" 2>>"$err_log"

apt-get -y --force-yes install aptitude ssl-cert whiptail apt-utils jq openssl-blacklist glibc-doc libc6-dev/stable >>"$main_log" 2>>"$err_log"

DEBIAN_FRONTEND=noninteractive aptitude -y install libldap2-dev/stable apache2-threaded-dev apache2-utils apt-listchanges arj autoconf automake bison bsd-mailx build-essential bzip2 ca-certificates cabextract checkinstall curl dnsutils file flex git htop libapr1-dev libaprutil1 libaprutil1-dev libauthen-sasl-perl daemon libawl-php libcunit1-dev libcrypt-ssleay-perl libcurl4-openssl-dev libdbi-perl libgeoip-dev libio-socket-ssl-perl libio-string-perl liblockfile-simple-perl liblogger-syslog-perl libmail-dkim-perl libmail-spf-perl libmime-base64-urlsafe-perl libnet-dns-perl libnet-ident-perl libnet-LDAP-perl libnet1 libnet1-dev libpam-dev libpcre-ocaml-dev libpcre3 libpcre3-dev libreadline6-dev libtest-tempdir-perl libtool libuv-dev libwww-perl libxml2 libxml2-dev/stable libxml2-utils libxslt1-dev libyaml-dev lzop mariadb-server mc memcached mlocate nettle-dev nomarch pkg-config python-setuptools python-dev python-software-properties rkhunter software-properties-common sudo unzip vim-nox zip zlib1g zlib1g-dbg zlib1g-dev zoo >>"$main_log" 2>>"$err_log"

if [ "$?" -ne "0" ]; then
	echo "${error} Package installation failed!" | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	exit 1
fi

# System Tuning
echo "${info} Kernel hardening & system tuning..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
cat > /etc/sysctl.conf <<END
fs.file-max = 209708
fs.inotify.max_user_instances = 2048
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.kptr_restrict = 1
kernel.msgmax = 65535
kernel.msgmnb = 65535
kernel.pid_max = 65535
kernel.randomize_va_space = 2
kernel.shmall = 268435456
kernel.shmmax = 268435456
kernel.sysrq = 0
net.core.default_qdisc = fq_codel
net.core.dev_weight = 64
net.core.netdev_max_backlog = 16384
net.core.optmem_max = 65535
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.somaxconn = 32768
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.forwarding = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.ip_local_port_range = 16384 65535
net.ipv4.ipfrag_high_thresh = 512000
net.ipv4.ipfrag_low_thresh = 446464
net.ipv4.neigh.default.gc_interval = 30
net.ipv4.neigh.default.gc_thresh1 = 32
net.ipv4.neigh.default.gc_thresh2 = 1024
net.ipv4.neigh.default.gc_thresh3 = 2048
net.ipv4.neigh.default.proxy_qlen = 96
net.ipv4.neigh.default.unres_qlen = 6
net.ipv4.route.flush = 1
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fin_timeout = 7
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_max_orphans = 16384
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_orphan_retries = 0
net.ipv4.tcp_reordering = 3
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_retries2 = 15
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_rmem = 8192 87380 16777216
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.default.autoconf=0
net.ipv6.conf.default.forwarding = 0
net.ipv6.conf.eth0.accept_ra=0
net.ipv6.conf.eth0.autoconf=0
net.ipv6.route.flush = 1
net.unix.max_dgram_qlen = 50
vm.dirty_background_ratio = 5
vm.dirty_ratio = 30
vm.min_free_kbytes = 65535
vm.mmap_min_addr = 4096
vm.overcommit_memory = 0
vm.overcommit_ratio = 50
vm.swappiness = 30

# Disable IPV6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.${INTERFACE}.disable_ipv6 = 1
END

# Enable changes
sysctl -p >>"$main_log" 2>>"$err_log"
}

source ~/configs/userconfig.cfg
source ~/configs/addonconfig.cfg
