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

php5() {
echo "${info} Installing PHP5.x..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
DEBIAN_FRONTEND=noninteractive aptitude -y install ca-certificates php-auth-sasl php-auth-sasl php-http-request php-mail php-mail-mime php-mail-mimedecode php-net-dime php-net-smtp php-net-url php-pear php-soap php5 php5-apcu php5-cli php5-common php5-curl php5-dev php5-fpm php5-geoip php5-gd php5-igbinary php5-imap php5-intl php5-mcrypt php5-mysql php5-sqlite php5-xmlrpc php5-xsl >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

# Configure PHP
echo "${info} Configuring PHP5.x..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
sed -i 's/.*disable_functions =.*/disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,escapeshellarg,passthru,proc_close,proc_get_status,proc_nice,proc_open,proc_terminate,/' /etc/php5/fpm/php.ini
sed -i 's/.*ignore_user_abort =.*/ignore_user_abort = Off/' /etc/php5/fpm/php.ini
sed -i 's/.*expose_php =.*/expose_php = Off/' /etc/php5/fpm/php.ini
sed -i 's/.*post_max_size =.*/post_max_size = 15M/' /etc/php5/fpm/php.ini
sed -i 's/.*default_charset =.*/default_charset = "UTF-8"/' /etc/php5/fpm/php.ini
sed -i 's/.*cgi.fix_pathinfo=.*/cgi.fix_pathinfo=1/' /etc/php5/fpm/php.ini
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
sed -i 's/.*request_terminate_timeout =.*/request_terminate_timeout = 360/' /etc/php5/fpm/pool.d/www.conf
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


# Restart FPM & Nginx
systemctl -q start nginx.service
systemctl -q restart php5-fpm.service
}

source ~/configs/userconfig.cfg
source ~/configs/versions.cfg
