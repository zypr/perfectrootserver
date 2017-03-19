#!/bin/bash
usage() {
    echo "Usage:

    --help | -h
        Print this text

    --all | -a
        Completly purge mailcow and ALL of its components including databases, mail dreictory etc.
    "
}

case $1 in
    "-a" | "--all" )
		FULLWIPE="yes"
        ;;
    "-h" | "--help" )
		usage
		exit 0
        ;;
esac


if [[ $FULLWIPE == "yes" ]]; then
echo '
###############
# # WARNING # #
###############
# Open and review this script before running it!
# Use with caution! You are about to perform a FULL WIPE of mailcow.
# This may remove packages and data you do not want to be removed.
###############
'
else
echo '
###############
# # WARNING # #
###############
# Use with caution!
# Web server + web root, MySQL server + databases as well as
# your mail directory (/var/vmail) will not be removed.
#
# Use "--all" parameter to perform a full wipe.
#
###############
'
fi

read -p "Type \"confirm\" to continue: " confirminput
[[ $confirminput == "confirm" ]] || exit 0
echo "Please wait..."
service fail2ban stop
service rsyslog stop
service spamassassin stop
service dovecot stop
service postfix stop
service solr stop
service fuglu stop
update-rc.d -f fail2ban remove
update-rc.d -f fuglu remove
update-rc.d -f solr remove
systemctl disable fail2ban
systemctl disable fuglu
rm /etc/systemd/system/fail2ban.service
rm /etc/systemd/system/fuglu.service
# dovecot purge fails at first
if [[ $FULLWIPE == "yes" ]]; then
apt-get -y purge zip jq dnsutils python-sqlalchemy python-beautifulsoup python-setuptools \
python-magic libmail-spf-perl libmail-dkim-perl php-auth-sasl php-http-request php-mail php-mail-mime php-mail-mimedecode php-net-dime php-net-smtp \
php-net-socket php-net-url php-pear php-soap php5 php5-cli php5-common php5-curl php5-fpm php5-gd php5-imap php-apc subversion \
php5-intl php5-mcrypt php5-mysql php5-sqlite libawl-php php5-xmlrpc mysql-client mariadb-server mariadb-client mysql-server mailutils nginx-common nginx-extras apache2 \
postfix-mysql postfix-pcre spamassassin spamc sudo bzip2 curl mpack opendkim opendkim-tools unzip clamav-daemon \
fetchmail liblockfile-simple-perl libdbi-perl libmime-base64-urlsafe-perl libtest-tempdir-perl liblogger-syslog-perl bsd-mailx
fi
apt-get -y purge zip php5 python-sqlalchemy python-beautifulsoup python-setuptools \
python-magic php-auth-sasl php-http-request php-mail php-mail-mime php-mail-mimedecode php-net-dime php-net-smtp \
php-net-socket php-net-url php-pear php-soap php5 php5-cli php5-common php5-curl php5-fpm php5-gd php5-imap subversion \
php5-intl php5-mcrypt php5-sqlite dovecot-common dovecot-core clamav-daemon clamav clamav-base clamav-freshclam \
dovecot-imapd dovecot-solr dovecot-lmtpd dovecot-managesieved dovecot-sieve dovecot-mysql dovecot-pop3d postfix \
postfix-mysql postfix-pcre spamassassin curl mpack
apt-get -y purge dovecot-imapd dovecot-solr dovecot-lmtpd dovecot-managesieved dovecot-pop3d dovecot-sieve
apt-get -y autoremove --purge
apt-get -y purge dovecot-imapd dovecot-solr dovecot-lmtpd dovecot-managesieved dovecot-pop3d dovecot-sieve
apt-get -y autoremove --purge
killall -u vmail
userdel vmail
if [[ $FULLWIPE == "yes" ]]; then
rm -rf /var/lib/mysql
rm -rf /opt/vfilter
rm -rf /var/vmail
rm -rf /var/www
fi
rm -rf /etc/fuglu
rm -rf /usr/local/lib/python2.7/dist-packages/fuglu*
rm -rf /opt/solr/
rm -rf /var/solr/
rm -rf /etc/ssl/mail/
rm -rf /etc/spamassassin/
rm -rf /etc/dovecot/
rm -rf /etc/postfix/
rm -rf /var/{lib,log}/z-push/
rm -rf /etc/fail2ban/
rm -f /etc/fufix_version
rm -f /etc/mailcow_version
rm -f /etc/{cron.daily,cron.weekly,cron.hourly,cron.monthly}/mailcow_backup
rm -rf /etc/mail/postfixadmin
rm -rf /var/www/{mail,zpush,dav}
rm -f /usr/local/sbin/mc_*
rm -f /etc/cron.daily/mc_clean_spam_aliases
rm -rf /var/run/fetchmail
rm -rf /usr/local/lib/python2.7/dist-packages/fail2ban-*
rm -f /usr/local/bin/fail2ban*
rm -f /etc/init.d/fail2ban
rm -f /etc/init.d/solr
rm -rf /var/run/fail2ban/
rm -f /var/log/fail2ban.log
cat /dev/null > /var/log/mail.warn
cat /dev/null > /var/log/mail.err
cat /dev/null > /var/log/mail.info
cat /dev/null > /var/log/mail.log
rm -rf /var/lib/fail2ban/
rm -rf /var/lib/dovecot/
rm -f /var/log/mail*1
rm -f /var/log/mail*gz
rm -rf /opt/vfilter/
rm -f /etc/cron.d/pfadminfetchmail
rm -f /etc/cron.d/clamav-unofficial-sigs-cron
rm -f /etc/cron.d/solrmaint
rm -f /etc/cron.daily/dovemaint
rm -f /etc/cron.daily/doverecalcq
rm -f /etc/cron.daily/spam*
rm -rf /etc/opendkim*
rm -f /usr/local/bin/mc_*
