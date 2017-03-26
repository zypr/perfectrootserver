#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

php7() {

PHPVERSION7="7.0"
echo "${info} Installing PHP7..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
#Note CHECK PHP_FPM SOCK PATH

# apt-get -q -y --force-yes install libtinfo5
# apt-get -q -y --force-yes install libltdl7
# apt-get -q -y --force-yes install libncursesw5
#apt-get -qq update && apt-get -q -y --force-yes install php-mail-mimedecode php-auth-sasl/unstable php-http-request/unstable php-mail/unstable php-mail-mime/unstable php-net-dime/unstable php-net-smtp/unstable php-net-url/unstable php-pear/unstable php-apcu/unstable php-geoip/unstable php-igbinary/unstable php$PHPVERSION7/unstable php$PHPVERSION7-cli/unstable php$PHPVERSION7-common/unstable php$PHPVERSION7-curl/unstable php$PHPVERSION7-dev/unstable php$PHPVERSION7-fpm/unstable php$PHPVERSION7-gd/unstable php$PHPVERSION7-intl/unstable php$PHPVERSION7-mcrypt/unstable php$PHPVERSION7-mysql/unstable php$PHPVERSION7-soap/unstable php$PHPVERSION7-sqlite3/unstable php$PHPVERSION7-xsl/unstable php$PHPVERSION7-xmlrpc/unstable php$PHPVERSION7-imap/unstable php-mbstring/unstable php-xml/unstable php$PHPVERSION7-json/unstable php$PHPVERSION7-opcache/unstable php$PHPVERSION7-readline/unstable php$PHPVERSION7-xml/unstable php$PHPVERSION7-mbstring/unstable >/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
#$PURGE_PHP5=$(dpkg -l | grep php5)
apt-get purge -y php5* >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
apt-get install -f -y -t testing php-auth-sasl php-http-request php$PHPVERSION7-gd php$PHPVERSION7-bcmath php$PHPVERSION7-zip php-mail php-net-dime php-net-url php-pear php-apcu php$PHPVERSION7 php$PHPVERSION7-cli php$PHPVERSION7-common php$PHPVERSION7-curl php$PHPVERSION7-dev php$PHPVERSION7-fpm php$PHPVERSION7-intl php$PHPVERSION7-mcrypt php$PHPVERSION7-mysql php$PHPVERSION7-soap php$PHPVERSION7-sqlite3 php$PHPVERSION7-xsl php$PHPVERSION7-xmlrpc php-mbstring php-xml php$PHPVERSION7-json php$PHPVERSION7-opcache php$PHPVERSION7-readline php$PHPVERSION7-xml php$PHPVERSION7-mbstring php$PHPVERSION7-memcached >/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log



# Configure PHP
echo "${info} Configuring PHP7..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
sed -i 's/.*disable_functions =.*/disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,escapeshellarg,passthru,proc_close,proc_get_status,proc_nice,proc_open,proc_terminate,/' /etc/php/$PHPVERSION7/fpm/php.ini
sed -i 's/.*ignore_user_abort =.*/ignore_user_abort = Off/' /etc/php/$PHPVERSION7/fpm/php.ini
sed -i 's/.*expose_php =.*/expose_php = Off/' /etc/php/$PHPVERSION7/fpm/php.ini
sed -i 's/.*post_max_size =.*/post_max_size = 125M/' /etc/php/$PHPVERSION7/fpm/php.ini
sed -i 's/.*default_charset =.*/default_charset = "UTF-8"/' /etc/php/$PHPVERSION7/fpm/php.ini
sed -i 's/.*cgi.fix_pathinfo=.*/cgi.fix_pathinfo=1/' /etc/php/$PHPVERSION7/fpm/php.ini
sed -i 's/.*upload_max_filesize =.*/upload_max_filesize = 125M/' /etc/php/$PHPVERSION7/fpm/php.ini
sed -i 's/.*default_socket_timeout =.*/default_socket_timeout = 60/' /etc/php/$PHPVERSION7/fpm/php.ini
sed -i 's/.*date.timezone =.*/date.timezone = Europe\/Berlin/' /etc/php/$PHPVERSION7/fpm/php.ini
sed -i 's/.*mysql.allow_persistent =.*/mysql.allow_persistent = Off/' /etc/php/$PHPVERSION7/fpm/php.ini
sed -i 's/.*session.cookie_httponly =.*/session.cookie_httponly = 1/' /etc/php/$PHPVERSION7/fpm/php.ini

# Configure PHP-FPM
sed -i 's/.*emergency_restart_threshold =.*/emergency_restart_threshold = 10/' /etc/php/$PHPVERSION7/fpm/php-fpm.conf
sed -i 's/.*emergency_restart_interval =.*/emergency_restart_interval = 1m/' /etc/php/$PHPVERSION7/fpm/php-fpm.conf
sed -i 's/.*process_control_timeout =.*/process_control_timeout = 10/' /etc/php/$PHPVERSION7/fpm/php-fpm.conf
sed -i 's/.*events.mechanism =.*/events.mechanism = epoll/' /etc/php/$PHPVERSION7/fpm/php-fpm.conf
sed -i 's/.*listen.mode =.*/listen.mode = 0666/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*listen.allowed_clients =.*/listen.allowed_clients = 12$PHPVERSION7.0.1/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*pm.max_children =.*/pm.max_children = 50/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*pm.start_servers =.*/pm.start_servers = 15/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*pm.min_spare_servers =.*/pm.min_spare_servers = 5/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*pm.max_spare_servers =.*/pm.max_spare_servers = 25/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*pm.process_idle_timeout =.*/pm.process_idle_timeout = 60s;/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*request_terminate_timeout =.*/request_terminate_timeout = 360/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*security.limit_extensions =.*/security.limit_extensions = .php/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*php_flag[display_errors] =.*/php_flag[display_errors] = off/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*php_admin_value[error_log] =.*/php_admin_value[error_log] = \/var\/log\/fpm5-php.www.log/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*php_admin_flag[log_errors] =.*/php_admin_flag[log_errors] = on/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
sed -i 's/.*php_admin_value[memory_limit] =.*/php_admin_value[memory_limit] = 128M/' /etc/php/$PHPVERSION7/fpm/pool.d/www.conf
echo -e 'php_flag[display_errors] = off' >> /etc/php/$PHPVERSION7/fpm/pool.d/www.conf

# Configure APCu
rm -rf /etc/php/$PHPVERSION7/mods-available/apcu.ini
rm -rf /etc/php/$PHPVERSION7/mods-available/20-apcu.ini

cat > /etc/php/$PHPVERSION7/mods-available/apcu.ini <<END
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

ln -s /etc/php/$PHPVERSION7/mods-available/apcu.ini /etc/php/$PHPVERSION7/mods-available/20-apcu.ini

systemctl -q start nginx.service
systemctl -q restart php7.0-fpm.service
}

#Brauchen wir gar nicht oder?
#source ~/configs/userconfig.cfg
