# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow and https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

firewall() {

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
sed -i "s/^Port 22/Port ${SSH_PORT}/g" /etc/ssh/sshd_config
sed -i "s/^EXT_IF=.*/EXT_IF="${INTERFACE}"/g" /etc/arno-iptables-firewall/firewall.conf
sed -i 's/^EXT_IF_DHCP_IP=.*/EXT_IF_DHCP_IP="0"/g' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/^#FIREWALL_LOG=.*/FIREWALL_LOG="\/var\/log\/firewall.log"/g' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/^DRDOS_PROTECT=.*/DRDOS_PROTECT="1"/g' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/^OPEN_ICMP=.*/OPEN_ICMP="1"/g' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/^#BLOCK_HOSTS_FILE=.*/BLOCK_HOSTS_FILE="\/etc\/arno-iptables-firewall\/blocked-hosts"/g' /etc/arno-iptables-firewall/firewall.conf

systemctl -q restart ssh.service

if [ ${USE_MAILSERVER} == '1' ]; then
	sed -i "s/^OPEN_TCP=.*/OPEN_TCP=\"${SSH_PORT}, 25, 80, 110, 143, 443, 465, 587, 993, 995\"/" /etc/arno-iptables-firewall/firewall.conf
else
	sed -i "s/^OPEN_TCP=.*/OPEN_TCP=\"${SSH_PORT}, 80, 443\"/" /etc/arno-iptables-firewall/firewall.conf
fi
sed -i 's/^OPEN_UDP=.*/OPEN_UDP=""/' /etc/arno-iptables-firewall/firewall.conf
sed -i 's/^VERBOSE=.*/VERBOSE=1/' /etc/init.d/arno-iptables-firewall

# Start the firewall
systemctl -q daemon-reload
systemctl -q start arno-iptables-firewall.service

#Fix error with /etc/rc.local
touch /etc/rc.local

# Blacklist some bad guys
mkdir ~/sources/blacklist
sed -i 's/.*BLOCK_HOSTS_FILE=.*/BLOCK_HOSTS_FILE="\/etc\/arno-iptables-firewall\/blocked-hosts"/' /etc/arno-iptables-firewall/firewall.conf
cat > /etc/cron.daily/blocked-hosts <<END
#!/bin/bash
BLACKLIST_DIR="/root/sources/blacklist"
BLACKLIST="/etc/arno-iptables-firewall/blocked-hosts"
BLACKLIST_TEMP="\$BLACKLIST_DIR/blacklist"
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
"http://blocklist.greensnow.co/greensnow.txt"
"https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt"
)
for i in "\${LIST[@]}"
do
    wget -T 10 -t 2 -O - \$i | grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' >> \$BLACKLIST_TEMP
done
sort \$BLACKLIST_TEMP -n | uniq > \$BLACKLIST
cp \$BLACKLIST_TEMP \${BLACKLIST_DIR}/blacklist\_\$(date '+%d.%m.%Y_%T' | tr -d :) && rm \$BLACKLIST_TEMP
systemctl force-reload arno-iptables-firewall.service
END
chmod +x /etc/cron.daily/blocked-hosts

# Fail2Ban
tar xf ~/sources/mailcow/fail2ban/inst/0.9.3.tar -C ~/sources/mailcow/fail2ban/inst/
rm -rf /etc/fail2ban/ >/dev/null 2>&1
(cd ~/sources/mailcow/fail2ban/inst/0.9.3 ; python setup.py -q install >/dev/null 2>&1)
mkdir -p /var/run/fail2ban
cp ~/sources/mailcow/fail2ban/conf/fail2ban.service /etc/systemd/system/fail2ban.service
[[ -f /lib/systemd/system/fail2ban.service ]] && rm /lib/systemd/system/fail2ban.service
systemctl -q daemon-reload
systemctl -q enable fail2ban
if [[ ! -f /var/log/mail.warn ]]; then
	touch /var/log/mail.warn
fi
if [[ ! -f /etc/fail2ban/jail.local ]]; then
	cp ~/sources/mailcow/fail2ban/conf/jail.local /etc/fail2ban/jail.local
fi
cp ~/sources/mailcow/fail2ban/conf/jail.d/*.conf /etc/fail2ban/jail.d/
rm -rf ~/sources/mailcow/fail2ban/inst/0.9.3
[[ -z $(grep fail2ban /etc/rc.local) ]] && sed -i '/^exit 0/i\test -d /var/run/fail2ban || install -m 755 -d /var/run/fail2ban/' /etc/rc.local
mkdir /var/run/fail2ban/ >/dev/null 2>&1


# Restart all services
if [ ${USE_MAILSERVER} == '1' ]; then
	systemctl -q restart {fail2ban,rsyslog,nginx,php7.0-fpm,spamassassin,dovecot,postfix,opendkim,clamav-daemon,fuglu,mailgraph}
else
	systemctl -q restart {fail2ban,nginx,php7.0-fpm}
fi

}
source ~/userconfig.cfg
