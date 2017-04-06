#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

vimbadmin() {
echo "${info} Installing Vimbadmin..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

#Create Database
mysql --defaults-file=/etc/mysql/debian.cnf -e "CREATE DATABASE vimbadmin; GRANT ALL ON vimbadmin.* TO 'vimbadmin'@'localhost' IDENTIFIED BY '${VIMB_MYSQL_PASS}'; FLUSH PRIVILEGES;" >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

#Download Vimbadmin via Composer
apt-get -q -y --force-yes install git curl >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
cd ~/sources
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
php -r "if (hash_file('SHA384', 'composer-setup.php') === '669656bab3166a7aff8a7506b8cb2d1c292f042046c5a994c43155c0be6190fa0355160742ab2e1c88d40d5be660b410') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;" >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
php composer-setup.php >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
php -r "unlink('composer-setup.php');"
mv composer.phar /usr/local/bin/composer
composer create-project opensolutions/vimbadmin /srv/vimbadmin -s dev -n --keep-vcs >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

chown -R www-data: /srv/vimbadmin/public
chown -R www-data: /srv/vimbadmin/var
ln -s /srv/vimbadmin/public/ /etc/nginx/html/${MYDOMAIN}/vma >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

#Changes in Vimbadmin Conf
cp /srv/vimbadmin/application/configs/application.ini.dist /srv/vimbadmin/application/configs/application.ini

sed -i "s/xxx/${VIMB_MYSQL_PASS}/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/defaults.mailbox.uid = 2000/defaults.mailbox.uid = 5000/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/defaults.mailbox.gid = 2000/defaults.mailbox.gid = 5000/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/defaults.mailbox.maildir = \"maildir:\/srv\/vmail\/%d\/%u\/mail:LAYOUT=fs\"/defaults.mailbox.maildir = \"maildir:\/var\/vmail\/%d\/%u\/Maildir:LAYOUT=fs\"/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/defaults.mailbox.homedir = \"\/srv\/vmail\/%d\/%u\"/defaults.mailbox.homedir = \"\/var\/vmail\/%d\/%u\"/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/defaults.domain.transport = \"virtual\"/defaults.domain.transport = \"lmtps:unix:private\/dovecot-lmtp\"/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/mailbox_deletion_fs_enabled = false/mailbox_deletion_fs_enabled = true/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/defaults.mailbox.password_scheme = \"dovecot:BLF-CRYPT\"/defaults.mailbox.password_scheme = \"crypt:sha512\"/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/defaults.mailbox.dovecot_pw_binary = \"\/usr\/bin\/doveadm pw\"/defaults.mailbox.dovecot_pw_binary = \"\/usr\/bin\/doveadm pw\"/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/server.smtp.port    = \"465\"/server.smtp.port    = \"587\"/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/server.smtp.crypt   = \"SSL\"/server.smtp.crypt   = \"TLS\"/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/server.pop3.enabled = 1/server.pop3.enabled = 0/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/server.imap.host  = \"gpo.%d\"/server.imap.host  = \"mail.%d\"/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/server.imap.port  = \"993\"/server.imap.port  = \"143\"/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/server.imap.crypt = \"SSL\"/server.imap.crypt = \"TLS\"/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/server.webmail.host  = \"https:\/\/webmail.%d\"/server.webmail.host  = \"https:\/\/mail.%d\/webmail\"/g" /srv/vimbadmin/application/configs/application.ini
sed -i "s/example.com/${MYDOMAIN}/g" /srv/vimbadmin/application/configs/application.ini
#sed -i "s/SEARCH/REPLACE/g" /srv/vimbadmin/application/configs/application.ini
mkdir -p /srv/archives
cp /srv/vimbadmin/public/.htaccess.dist /srv/vimbadmin/public/.htaccess

cd /srv/vimbadmin/
./bin/doctrine2-cli.php orm:schema-tool:create >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

#Crontabs
(crontab -l && echo "# Die 10. Minute jeder 2. Stunde") | crontab -
(crontab -l && echo "10 */2 * * * /srv/vimbadmin/bin/vimbtool.php -a archive.cli-archive-pendings") | crontab -
(crontab -l && echo "# Die 30. Minute jeder 2. Stunde") | crontab -
(crontab -l && echo "30 */2 * * * /srv/vimbadmin/bin/vimbtool.php -a archive.cli-restore-pendings") | crontab -
(crontab -l && echo "# Die 50. Minute jeder 2. Stunde") | crontab -
(crontab -l && echo "50 */2 * * * /srv/vimbadmin/bin/vimbtool.php -a archive.cli-delete-pendings") | crontab -
(crontab -l && echo "# 3:15 AM") | crontab -
(crontab -l && echo "15 3 * * * /srv/vimbadmin/bin/vimbtool.php -a mailbox.cli-delete-pending") | crontab -

#Nginx custom site config
cat >> /etc/nginx/sites-custom/vimbadmin.conf << 'EOF1'
location ~ ^/vma {
    alias /srv/vimbadmin/public/$1;
    location ~ ^/vma/(.*\.(js|css|gif|jpg|png|ico))$ {
        alias /srv/vimbadmin/public/$1;
    }
    rewrite ^/vma(.*)$ /vma/index.php last;
    location ~ ^/vma(.+\.php)$ {
        alias /srv/vimbadmin/public/$1;
        fastcgi_pass unix:/var/run/php5-fpm.sock;
        fastcgi_index index.php;
        charset utf8;
        include fastcgi_params;
        fastcgi_param DOCUMENT_ROOT /srv/vimbadmin/public/$1;
    }
}
EOF1
if [ ${USE_PHP7} == '1' ]; then
	sed -i 's/fastcgi_pass unix:\/var\/run\/php5-fpm.sock\;/fastcgi_pass unix:\/var\/run\/php\/php7.0-fpm.sock\;/g' /etc/nginx/sites-custom/vimbadmin.conf
fi

#Restarting services
if [ ${USE_PHP7} == '1' ]; then
		systemctl restart {dovecot,postfix,amavis,spamassassin,clamav-daemon,nginx,php7.0-fpm,mysql} >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
fi

if [ ${USE_PHP5} == '1' ]; then
		systemctl restart {dovecot,postfix,amavis,spamassassin,clamav-daemon,nginx,php5-fpm,mysql} >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
fi
}
source ~/configs/userconfig.cfg