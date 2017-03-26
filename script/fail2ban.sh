#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

fail2ban() {
mkdir -p ~/sources/${FAIL2BAN_VERSION}/ >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
cd ~/sources/${FAIL2BAN_VERSION}/ >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
wget https://github.com/fail2ban/fail2ban/archive/${FAIL2BAN_VERSION}.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

tar -xzf ${FAIL2BAN_VERSION}.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
cd fail2ban-${FAIL2BAN_VERSION}
python setup.py -q install >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

mkdir -p /var/run/fail2ban >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
cp ~/files/fail2ban/conf/fail2ban.service /etc/systemd/system/fail2ban.service >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
[[ -f /lib/systemd/system/fail2ban.service ]] && rm /lib/systemd/system/fail2ban.service
if [[ ! -f /var/log/mail.warn ]]; then
	touch /var/log/mail.warn
fi
if [[ ! -f /etc/fail2ban/jail.local ]]; then
	cp ~/files/fail2ban/conf/jail.local /etc/fail2ban/jail.local
fi
cp ~/files/fail2ban/conf/jail.d/*.conf /etc/fail2ban/jail.d/
#rm -rf ~/sources/files/fail2ban/inst/${FAIL2BAN_VERSION}
[[ -z $(grep fail2ban /etc/rc.local) ]] && sed -i '/^exit 0/i\test -d /var/run/fail2ban || install -m 755 -d /var/run/fail2ban/' /etc/rc.local
mkdir -p /var/run/fail2ban/
service fail2ban start >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
systemctl -q daemon-reload >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
systemctl -q enable fail2ban >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
}
source ~/configs/versions.cfg

