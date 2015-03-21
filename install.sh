#!/bin/bash

# Stops the script on the first error
set -e

# Define the following variables.
# Check for the latest version
# http://nginx.org/en/download.html
# http://openssl.org/source/
# http://www.openssh.com/
# https://developers.google.com/speed/pagespeed/module/build_ngx_pagespeed_from_source
#
# Please note that older Nginx versions are not compatible with this script
#
NGINX_VERSION=1.7.10
OPENSSL_VERSION=1.0.2a
OPENSSH_VERSION=6.8
NPS_VERSION=1.9.32.3




#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

# Some nice colors
red() { echo "$(tput setaf 1)$*$(tput setaf 9)"; }
green() { echo "$(tput setaf 2)$*$(tput setaf 9)"; }
yellow() { echo "$(tput setaf 3)$*$(tput setaf 9)"; }
magenta() { echo "$(tput setaf 5)$*$(tput setaf 9)"; }
cyan() { echo "$(tput setaf 6)$*$(tput setaf 9)"; }

WORKER=$(grep -c ^processor /proc/cpuinfo)
IPADR=$(ifconfig eth0 | awk -F ' *|:' '/inet /{print $4}')

touch ~/status


part0(){
echo
yellow "#########################"
yellow "## USER INPUT REQUIRED ##"
yellow "#########################"
echo "Please enter your domain without a subdomain (www)"
echo "unless you know what you are doing!"
echo
read -p "Enter Domain: " FQDNTMP
FQDNIP=$(host ${FQDNTMP} | awk '/has address/ { print $4 ; exit }')
echo
echo
yellow "#########################"
yellow "## USER INPUT REQUIRED ##"
yellow "#########################"
echo
red "Do you want to use a service like CloudFlare to protect your Website?"
stty echo
while true; do
	read -p "Yes [Y] / No [N]: " i
	case $i in
	[Yy]* ) CLOUDFLARE=1;break;;
	[Nn]* ) CLOUDFLARE=0;break;;
	* ) red "Please use [Y] or [N]";echo;;
	esac
done
if [ $CLOUDFLARE == '1' ]; then
	echo
else
	while [ $FQDNIP != $IPADR ]; do
		echo
		echo
	        red "*****************************************************"
	        red "* The domain or hostname does not resolve to the IP *"
	        red "* address of your server. Please retry!             *"
	        red "*****************************************************"
	        red "* Enter the domain without a subdomain (www) unless *"
	        red "* you know what you are doing!                      *"
	        red "*****************************************************"
	        echo
	        read -p "Enter domain or hostname: " FQDNTMP
	        FQDNIP=$(host ${FQDNTMP} | awk '/has address/ { print $4 ; exit }')
	done
fi
FQDN=$FQDNTMP

echo -e "1" >> ~/status
echo -e "$FQDN" >> ~/status
echo -e "$CLOUDFLARE" >> ~/status

host=$(hostname)
sed -i "s/$host/$FQDN/g" /etc/hosts
sed -i "1s/.*/$FQDN/" /etc/hostname
if [ -f /etc/mailname ]; then
	sed -i "1s/.*/mail.$FQDN/" /etc/mailname
else
	touch /etc/mailname
	echo -e "mail.$FQDN" >> /etc/mailname
fi
/etc/init.d/hostname.sh
}


part1(){
FQDN=$(sed '2q;d' ~/status)

# Update package lists & fetch new versions
rm /etc/apt/sources.list
cat > /etc/apt/sources.list <<END
deb http://ftp.debian.org/debian/ wheezy contrib main non-free
deb-src http://ftp.debian.org/debian/ wheezy contrib non-free
deb http://security.debian.org/ wheezy/updates main contrib non-free
deb-src http://security.debian.org/ wheezy/updates main contrib non-free
deb http://ftp.debian.org/debian/ wheezy-backports main contrib non-free
deb-src http://ftp.debian.org/debian/ wheezy-backports main contrib non-free
deb http://packages.dotdeb.org wheezy all
deb-src http://packages.dotdeb.org wheezy all
deb http://packages.dotdeb.org wheezy-php55 all
deb-src http://packages.dotdeb.org wheezy-php55 all
END

# Import gpg key
wget -O ~/dotdeb.gpg http://www.dotdeb.org/dotdeb.gpg
cat ~/dotdeb.gpg | apt-key add -

# Update package lists & fetch new software
apt-get update && apt-get -y upgrade

# Install aptitude
apt-get -y install aptitude

# Install required software
aptitude -y install build-essential git curl unzip vim-nox subversion php5-fpm php5-imap php5-gd php5-mysql php5-apcu php5-cli php5-common php5-curl php5-mcrypt php5-intl php5-dev checkinstall automake autoconf apache2-threaded-dev libtool libxml2 libxml2-dev libxml2-utils libaprutil1 libaprutil1-dev libpcre-ocaml-dev libssl-dev libpcre3 libpcre3-dev libpam-dev zlib1g zlib1g-dbg zlib1g-dev

# Upgrade & patch bash - check https://shellshocker.net/
curl https://shellshocker.net/fixbash | sh

# Create directories
mkdir -p ~/sources/

# Download OpenSSL
cd ~/sources
wget http://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
tar -xzvf openssl-${OPENSSL_VERSION}.tar.gz

# Update OpenSSL system-wide
# cd openssl-${OPENSSL_VERSION}
# cat > openssl.ld <<END
# OPENSSL_1.0.0 {
#     global:
#     *;
# };
END
# ./config --prefix=/usr/local --openssldir=/usr/local/ssl shared -Wl,--version-script=/root/sources/openssl-${OPENSSL_VERSION}/openssl.ld -Wl,-Bsymbolic-functions
./config --prefix=/usr/local --openssldir=/usr/local/ssl shared
make && make test && make install
rm -r -f /usr/bin/openssl.old
rm -r -f /usr/include/openssl
rm -r -f /usr/lib/libssl.so
rm -r -f /etc/ld.so.conf
mv /usr/bin/openssl /usr/bin/openssl.old
ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl
ln -s /usr/local/ssl/include/openssl /usr/include/openssl
ln -s /usr/local/ssl/lib/libssl.so.1.0.0 /usr/lib/libssl.so
cp include/openssl/* /usr/include
mkdir -p /usr/local/ssl/include/openssl
cp include/openssl/* /usr/local/ssl/include
cp include/openssl/* /usr/local/ssl/include/openssl
touch /etc/ld.so.conf
echo -e "include /etc/ld.so.conf.d/*.conf" >> /etc/ld.so.conf
echo -e "/usr/local/ssl/lib" >> /etc/ld.so.conf
/sbin/ldconfig -v
/usr/bin/updatedb
make clean

# Update OpenSSH and compile with latest OpenSSL source
cd ~/sources
wget http://ftp.hostserver.de/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}p1.tar.gz
tar -xzvf openssh-${OPENSSH_VERSION}p1.tar.gz
cd openssh-${OPENSSH_VERSION}p1
./configure --prefix=/usr --sysconfdir=/etc/ssh --with-pam --with-ssl-dir=~/sources/openssl-${OPENSSL_VERSION}
make
mv /etc/ssh /etc/ssh.bak
make install

# Configure OpenSSH
sed -i 's/^#Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i 's/^#AddressFamily any/AddressFamily inet/g' /etc/ssh/sshd_config
sed -i 's/^#Protocol 2/Protocol 2/g' /etc/ssh/sshd_config 
sed -i 's/^#HostKey \/etc\/ssh\/ssh_host_rsa_key/HostKey \/etc\/ssh\/ssh_host_rsa_key/g' /etc/ssh/sshd_config 
sed -i 's/^#HostKey \/etc\/ssh\/ssh_host_dsa_key/HostKey \/etc\/ssh\/ssh_host_dsa_key/g' /etc/ssh/sshd_config 
sed -i 's/^#HostKey \/etc\/ssh\/ssh_host_ecdsa_key/HostKey \/etc\/ssh\/ssh_host_ecdsa_key/g' /etc/ssh/sshd_config 
sed -i 's/^#HostKey \/etc\/ssh\/ssh_host_ed25519_key/HostKey \/etc\/ssh\/ssh_host_ed25519_key/g' /etc/ssh/sshd_config 
sed -i 's/^#ServerKeyBits 1024/ServerKeyBits 2048/' /etc/ssh/sshd_config
sed -i 's/^#RekeyLimit default none/RekeyLimit 256M/' /etc/ssh/sshd_config
sed -i 's/^UsePrivilegeSeparation sandbox/UsePrivilegeSeparation yes/' /etc/ssh/sshd_config
sed -i 's/^#KeyRegenerationInterval 1h/HostKey \/etc\/ssh\/ssh_host_ed25519_key/g' /etc/ssh/sshd_config
sed -i 's/^#ServerKeyBits 1024/ServerKeyBits 768/g' /etc/ssh/sshd_config
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
echo -e "AcceptEnv LANG LC_*" >> /etc/ssh/sshd_config
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

# Restart service
service ssh restart

#
# Configure and compile Nginx
#

# Download PageSpeed
cd ~/sources
wget https://github.com/pagespeed/ngx_pagespeed/archive/release-${NPS_VERSION}-beta.zip
unzip release-${NPS_VERSION}-beta.zip
cd ngx_pagespeed-release-${NPS_VERSION}-beta/
wget https://dl.google.com/dl/page-speed/psol/${NPS_VERSION}.tar.gz
tar -xzvf ${NPS_VERSION}.tar.gz

# Download the Nginx HTTP Auth Digest
cd ~/sources
git clone https://github.com/maneulyori/nginx-http-auth-digest.git

# Download & configure ModSecurity
git clone git://github.com/SpiderLabs/ModSecurity.git
cd ~/sources/ModSecurity
./autogen.sh
./configure --enable-standalone-module
make

# Download Nginx
cd ~/sources
wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
tar -xzvf nginx-${NGINX_VERSION}.tar.gz
cd nginx-${NGINX_VERSION}

# Modify some code
# Step 1: Remove the server string from the host
# Step 2: Remove the server string from the auto generated error pages
# Step 3: Modify the TLS record size - check https://www.igvita.com/2013/12/16/optimizing-nginx-tls-time-to-first-byte/

# Step 1
sed -i '49s/.*/static char ngx_http_server_string[] = "";/' src/http/ngx_http_header_filter_module.c
sed -i '50s/.*/static char ngx_http_server_full_string[] = "";/' src/http/ngx_http_header_filter_module.c
sed -i '281s/.*/        len += clcf->server_tokens ? sizeof(ngx_http_server_full_string) - 0:/' src/http/ngx_http_header_filter_module.c
sed -i '282s/.*/                                     sizeof(ngx_http_server_string) - 0;/' src/http/ngx_http_header_filter_module.c
sed -i '178s/.*/\/*    if (r->headers_out.server == NULL) {/' src/http/ngx_http_spdy_filter_module.c
sed -i '183s/.*/*\//' src/http/ngx_http_spdy_filter_module.c
sed -i '329s/.*/\/*    if (r->headers_out.server == NULL) {/' src/http/ngx_http_spdy_filter_module.c
sed -i '337s/.*/*\//' src/http/ngx_http_spdy_filter_module.c

# Step 2
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

# Step 3
sed -i '120s/.*/#define NGX_SSL_BUFSIZE  1400/' src/event/ngx_event_openssl.h
sed -i '720s/.*/                (void) BIO_set_write_buffer_size(wbio, 16384);/' src/event/ngx_event_openssl.c

# Configure Nginx
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
--without-http_proxy_module \
--without-http_memcached_module \
--without-http_userid_module \
--without-http_split_clients_module \
--without-http_uwsgi_module \
--with-http_ssl_module \
--with-http_spdy_module \
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
--add-module=$HOME/sources/ModSecurity/nginx/modsecurity

# make the package
make

# Create a .deb package
checkinstall --install=no -y

# Install the package
dpkg -i nginx_${NGINX_VERSION}-1_amd64.deb
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
mkdir -p ../modsecurity/audit
mkdir ../logs
mkdir ../ssl
chown -R www-data:www-data /var/lib/nginx
chown www-data:www-data /etc/nginx/logs
chown www-data:www-data /etc/nginx/modsecurity/audit

# Install the Nginx service script
wget -O /etc/init.d/nginx --no-check-certificate https://raw.githubusercontent.com/Fleshgrinder/nginx-sysvinit-script/master/nginx
chmod 0755 /etc/init.d/nginx
chown root:root /etc/init.d/nginx
update-rc.d nginx defaults

# Configure PHP
sed -i '303s/.*/disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,escapeshellarg,escapeshellcmd,passthru,proc_close,proc_get_status,proc_nice,proc_open,proc_terminate,/' /etc/php5/fpm/php.ini
sed -i '324s/.*/ignore_user_abort = Off/' /etc/php5/fpm/php.ini
sed -i '363s/.*/expose_php = Off/' /etc/php5/fpm/php.ini
sed -i '660s/.*/post_max_size = 15M/' /etc/php5/fpm/php.ini
sed -i '680s/.*/default_charset = "UTF-8"/' /etc/php5/fpm/php.ini
sed -i '755s/.*/cgi.fix_pathinfo=0/' /etc/php5/fpm/php.ini
sed -i '792s/.*/upload_max_filesize = 15M/' /etc/php5/fpm/php.ini
sed -i '820s/.*/default_socket_timeout = 30/' /etc/php5/fpm/php.ini
sed -i '866s/.*/date.timezone = Europe\/Berlin/' /etc/php5/fpm/php.ini
sed -i '1058s/.*/mysql.allow_persistent = Off/' /etc/php5/fpm/php.ini
sed -i '1389s/.*/session.cookie_httponly = 1/' /etc/php5/fpm/php.ini

# Configure PHP-FPM
sed -i '56s/.*/emergency_restart_threshold = 10/' /etc/php5/fpm/php-fpm.conf
sed -i '64s/.*/emergency_restart_interval = 1m/' /etc/php5/fpm/php-fpm.conf
sed -i '70s/.*/process_control_timeout = 10/' /etc/php5/fpm/php-fpm.conf
sed -i '108s/.*/events.mechanism = epoll/' /etc/php5/fpm/php-fpm.conf
sed -i '51s/.*/listen.mode = 0666/' /etc/php5/fpm/pool.d/www.conf
sed -i '59s/.*/listen.allowed_clients = 127.0.0.1/' /etc/php5/fpm/pool.d/www.conf
sed -i '104s/.*/pm.max_children = 50/' /etc/php5/fpm/pool.d/www.conf
sed -i '109s/.*/pm.start_servers = 15/' /etc/php5/fpm/pool.d/www.conf
sed -i '114s/.*/pm.min_spare_servers = 5/' /etc/php5/fpm/pool.d/www.conf
sed -i '119s/.*/pm.max_spare_servers = 25/' /etc/php5/fpm/pool.d/www.conf
sed -i '124s/.*/pm.process_idle_timeout = 60s;/' /etc/php5/fpm/pool.d/www.conf
sed -i '323s/.*/request_terminate_timeout = 30/' /etc/php5/fpm/pool.d/www.conf
sed -i '372s/.*/security.limit_extensions = .php/' /etc/php5/fpm/pool.d/www.conf
sed -i '403s/.*/php_flag[display_errors] = off/' /etc/php5/fpm/pool.d/www.conf
sed -i '404s/.*/php_admin_value[error_log] = \/var\/log\/fpm5-php.www.log/' /etc/php5/fpm/pool.d/www.conf
sed -i '405s/.*/php_admin_flag[log_errors] = on/' /etc/php5/fpm/pool.d/www.conf
sed -i '406s/.*/php_admin_value[memory_limit] = 128M/' /etc/php5/fpm/pool.d/www.conf
echo -e "php_flag[display_errors] = off" >> /etc/php5/fpm/pool.d/www.conf

# Configure APCu
rm -r -f /etc/php5/mods-available/apcu.ini
rm -r -f /etc/php5/mods-available/20-apcu.ini

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

# System Tuning
echo -e "# Recycle Zombie connections" >> /etc/sysctl.conf
echo -e "net.inet.tcp.fast_finwait2_recycle=1" >> /etc/sysctl.conf
echo -e "net.inet.tcp.maxtcptw=200000" >> /etc/sysctl.conf
echo -e "" >> /etc/sysctl.conf
echo -e "# Increase number of files" >> /etc/sysctl.conf 
echo -e "kern.maxfiles=65535" >> /etc/sysctl.conf 
echo -e "kern.maxfilesperproc=16384" >> /etc/sysctl.conf 
echo -e "" >> /etc/sysctl.conf
echo -e "# Increase page share factor per process" >> /etc/sysctl.conf
echo -e "vm.pmap.pv_entry_max=54272521" >> /etc/sysctl.conf
echo -e "vm.pmap.shpgperproc=20000" >> /etc/sysctl.conf
echo -e "" >> /etc/sysctl.conf
echo -e "# Increase number of connections" >> /etc/sysctl.conf
echo -e "vfs.vmiodirenable=1" >> /etc/sysctl.conf
echo -e "kern.ipc.somaxconn=3240000" >> /etc/sysctl.conf
echo -e "net.inet.tcp.rfc1323=1" >> /etc/sysctl.conf
echo -e "net.inet.tcp.delayed_ack=0" >> /etc/sysctl.conf
echo -e "net.inet.tcp.restrict_rst=1" >> /etc/sysctl.conf
echo -e "kern.ipc.maxsockbuf=2097152" >> /etc/sysctl.conf
echo -e "kern.ipc.shmmax=268435456" >> /etc/sysctl.conf
echo -e "" >> /etc/sysctl.conf
echo -e "# Host cache" >> /etc/sysctl.conf
echo -e "net.inet.tcp.hostcache.hashsize=4096" >> /etc/sysctl.conf
echo -e "net.inet.tcp.hostcache.cachelimit=131072" >> /etc/sysctl.conf
echo -e "net.inet.tcp.hostcache.bucketlimit=120" >> /etc/sysctl.conf
echo -e "" >> /etc/sysctl.conf
echo -e "# Increase number of ports" >> /etc/sysctl.conf
echo -e "net.inet.ip.portrange.first=2000" >> /etc/sysctl.conf
echo -e "net.inet.ip.portrange.last=100000" >> /etc/sysctl.conf
echo -e "net.inet.ip.portrange.hifirst=2000" >> /etc/sysctl.conf
echo -e "net.inet.ip.portrange.hilast=100000" >> /etc/sysctl.conf
echo -e "kern.ipc.semvmx=131068" >> /etc/sysctl.conf
echo -e "" >> /etc/sysctl.conf
echo -e "# Disable Ping-flood attacks" >> /etc/sysctl.conf
echo -e "net.inet.tcp.msl=2000" >> /etc/sysctl.conf
echo -e "net.inet.icmp.bmcastecho=1" >> /etc/sysctl.conf
echo -e "net.inet.icmp.icmplim=1" >> /etc/sysctl.conf
echo -e "net.inet.tcp.blackhole=2" >> /etc/sysctl.conf
echo -e "net.inet.udp.blackhole=1" >> /etc/sysctl.conf
echo -e "" >> /etc/sysctl.conf
echo -e "# Kernel & IP hardening" >> /etc/sysctl.conf
echo -e "kernel.sysrq = 0" >> /etc/sysctl.conf
echo -e "kernel.pid_max = 65536" >> /etc/sysctl.conf
echo -e "kernel.exec-shield = 1" >> /etc/sysctl.conf
echo -e "kernel.core_uses_pid = 1" >> /etc/sysctl.conf
echo -e "kernel.randomize_va_space = 1" >> /etc/sysctl.conf
echo -e "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo -e "net.ipv4.ip_local_port_range = 2000 65000" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo -e "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
echo -e "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo -e "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
echo -e "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo -e "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo -e "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.router_solicitations = 0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.accept_ra_rtr_pref = 0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.accept_ra_pinfo = 0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.accept_ra_defrtr = 0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.autoconf = 0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.dad_transmits = 0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.max_addresses = 1" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.autoconf=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.accept_dad=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.accept_ra=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.accept_ra_defrtr=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.accept_ra_rtr_pref=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.accept_ra_pinfo=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.accept_source_route=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.default.forwarding=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.all.autoconf=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.all.accept_dad=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.all.accept_ra=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.all.accept_ra_defrtr=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.all.accept_ra_rtr_pref=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.all.accept_ra_pinfo=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.all.accept_source_route=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.all.accept_redirects=0" >> /etc/sysctl.conf
echo -e "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.conf
sysctl -p

# Edit/create Nginx config files
rm -r -f /etc/nginx/nginx.conf
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

		include       		/etc/nginx/mime.types;
		default_type  		application/octet-stream;
		server_tokens       off;
		keepalive_timeout   20;
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
rm -r -f /etc/nginx/sites-available/${FQDN}.conf
cat > /etc/nginx/sites-available/${FQDN}.conf <<END
server {
			listen 80 default_server;
			server_name ${IPADR} ${FQDN};
			return 301 https://${FQDN}\$request_uri;
}

server {
			listen 443;
			server_name ${IPADR};
			return 301 https://${FQDN}\$request_uri;
}

server {
			listen 443 ssl spdy default deferred;
			server_name ${FQDN};
		
			root /etc/nginx/html;
			index index.php index.html index.htm;
		
			error_page 404 /index.php;			

			ssl_certificate 	ssl/${FQDN}.pem;
			ssl_certificate_key ssl/${FQDN}.key;
			#ssl_trusted_certificate ssl/trustedbundle.pem;
			ssl_dhparam	     	ssl/dh.pem;
			ssl_ecdh_curve		secp384r1;
			ssl_session_cache   shared:SSL:10m;
			ssl_session_timeout 10m;
			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
			#ssl_prefer_server_ciphers on;
			
			#ssl_stapling on;
			#ssl_stapling_verify on;
			#resolver 8.8.8.8 8.8.4.4 valid=300s;
			#resolver_timeout 5s;

			ssl_ciphers "AES256+EECDH:AES256+EDH";				

			add_header Strict-Transport-Security "max-age=15768000; includeSubdomains";
			add_header X-Frame-Options DENY;
			add_header Alternate-Protocol  443:npn-spdy/2;
			add_header X-Content-Type-Options nosniff;
			add_header X-XSS-Protection "1; mode=block";
			add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ssl.google-analytics.com https://assets.zendesk.com https://connect.facebook.net; img-src 'self' https://ssl.google-analytics.com https://s-static.ak.facebook.com https://assets.zendesk.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://assets.zendesk.com; font-src 'self' https://themes.googleusercontent.com; frame-src https://assets.zendesk.com https://www.facebook.com https://s-static.ak.facebook.com https://tautt.zendesk.com; object-src 'none'";
			
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
			pagespeed RespectXForwardedProto on;

			auth_basic_user_file htpasswd/.htpasswd;
			
			include /etc/nginx/sites-custom/*.conf;

			location ~ \.php\$ {
				try_files \$uri =404;
				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
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
			
			location / {
			   	ModSecurityEnabled on;
			   	ModSecurityConfig modsecurity/modsecurity.conf;
			}
			
			location ~ /\. {
				deny all;
				access_log off;
				log_not_found off;
			}
			
			location = /robots.txt {
				allow all;
				log_not_found off;
				access_log off;
			}

			# Uncomment, if you need to remove index.php from the
			# URL. Usefull if you use Codeigniter, Zendframework, etc.
			# or just need to remove the index.php
			#
			#location / {
			#	if (!-f \$request_filename) {
			#		rewrite ^(.*)\$ /index.php?q=\$1 last;
			#		break;
			#	}
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

if [ $CLOUDFLARE == '1' ]; then
	sed -i "3s/.*/			server_name ${FQDN};/" /etc/nginx/sites-available/${FQDN}.conf
	sed -i '6s/.*/\n&/' /etc/nginx/sites-available/${FQDN}.conf
	sed -i '7s/.*/server {\n&/' /etc/nginx/sites-available/${FQDN}.conf
	sed -i '8s/.*/			listen 80;\n&/' /etc/nginx/sites-available/${FQDN}.conf
	sed -i "9s/.*/			server_name ${IPADR};\n&/" /etc/nginx/sites-available/${FQDN}.conf
	sed -i '10s/.*/			return 503;\n&/' /etc/nginx/sites-available/${FQDN}.conf
	sed -i '11s/.*/}\n&/' /etc/nginx/sites-available/${FQDN}.conf
	sed -i '16s/.*/			return 503;/' /etc/nginx/sites-available/${FQDN}.conf
	sed -i '43s/.*/			ssl_ciphers "AES128+EECDH:AES128+EDH:AES256+EECDH:AES256+EDH";/' /etc/nginx/sites-available/${FQDN}.conf
fi

ln -s /etc/nginx/sites-available/${FQDN}.conf /etc/nginx/sites-enabled/${FQDN}.conf

# Configure ModSecurity and install OWASP rules
cd ~/sources/ModSecurity/ 
git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git owasp && cd $_
cat ../modsecurity.conf-recommended modsecurity_crs_10_setup.conf.example base_rules/*.conf > /etc/nginx/modsecurity/modsecurity.conf
cp base_rules/*.data /etc/nginx/modsecurity/
cp ../unicode.mapping /etc/nginx/modsecurity/

sed -i '7s/.*/SecRuleEngine On/' /etc/nginx/modsecurity/modsecurity.conf
sed -i '173s/.*/SecDebugLog \/etc\/nginx\/logs\/modsecurity.log/' /etc/nginx/modsecurity/modsecurity.conf
sed -i '174s/.*/SecDebugLogLevel 3/' /etc/nginx/modsecurity/modsecurity.conf
sed -i '183s/.*/#SecAuditEngine RelevantOnly/' /etc/nginx/modsecurity/modsecurity.conf
sed -i '184s/.*/#SecAuditLogRelevantStatus "^(?:5|4(?!04))"/' /etc/nginx/modsecurity/modsecurity.conf
sed -i '187s/.*/#SecAuditLogParts ABIJDEFHZ/' /etc/nginx/modsecurity/modsecurity.conf
sed -i '192s/.*/#SecAuditLogType Serial/' /etc/nginx/modsecurity/modsecurity.conf
sed -i '193s/.*/#SecAuditLog \/var\/log\/modsec_audit.log/' /etc/nginx/modsecurity/modsecurity.conf
sed -i '196s/.*/#SecAuditLogStorageDir \/etc\/nginx\/modsecurity\/audit\//' /etc/nginx/modsecurity/modsecurity.conf

# Create a self-signed SSL certificate
#openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out /etc/nginx/ssl/${FQDN}.pem -keyout /etc/nginx/ssl/${FQDN}.key -subj "/C=/ST=/L=/O=/OU=/CN=*.${FQDN}"
openssl ecparam -genkey -name secp384r1 -out /etc/nginx/ssl/${FQDN}.key
openssl req -new -sha256 -key /etc/nginx/ssl/${FQDN}.key -out /etc/nginx/ssl/csr.pem -subj "/C=/ST=/L=/O=/OU=/CN=${FQDN}"
openssl req -x509 -days 365 -key /etc/nginx/ssl/${FQDN}.key -in /etc/nginx/ssl/csr.pem -out /etc/nginx/ssl/${FQDN}.pem

# Create strong Diffie-Hellman parameters
openssl dhparam -out /etc/nginx/ssl/dh.pem 4096

# Restart FPM & Nginx
service nginx start
service php5-fpm restart

#
#  Install Encfs
#

# Install required software
aptitude -y install encfs

# EncFS
mkdir -p /var/mail/encrypted /var/mail/decrypted
chgrp mail /var/mail/decrypted
groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /var/mail/decrypted
usermod -a -G fuse vmail
chgrp fuse /dev/fuse
chmod g+rw /dev/fuse
chmod -R g+rw /var/mail/decrypted

echo
yellow "#########################"
yellow "## USER INPUT REQUIRED ##"
yellow "#########################"
echo
echo "The server must be restarted before the changes can take effect."
red "Run the script again after the reboot, the script will start at the last point."
while true; do
	read -p "Continue? [y/n]" i
	case $i in
	[Yy]* ) echo;echo;sed -i '1s/.*/2/' ~/status && shutdown -r now;break;;
	* ) red "You have no choice!";;
	esac
done
sleep 10
}

part2(){
FQDN=$(sed '2q;d' ~/status)
CLOUDFLARE=$(sed '3q;d' ~/status)
# Mount folder
#encfs /var/mail/encrypted /var/mail/decrypted -o big_writes -o max_write=131072 -o max_readahead=131072 -o nonempty --public
echo
echo
echo
green "######################################################################"
green "##                       USER INPUT REQUIRED                        ##"
green "######################################################################"
green "## Answer the questions as follows:                                 ##"
green "######################################################################"
echo "Enter \"p\" for pre-configured paranoia mode"
yellow "?> p"
echo
encfs /var/mail/encrypted /var/mail/decrypted -o nonempty --public

# Create vhosts and set permissions
mkdir -p /var/mail/decrypted/vhosts/${FQDN}
chown -R vmail:vmail /var/mail/decrypted

#
# Install & configure our mailserver
#

# Install MySQL
aptitude -y install mysql-server

sed -i '32s/.*/innodb_file_per_table = 1/' /etc/mysql/my.cnf

# echo
# echo "#########################"
# echo "## USER INPUT REQUIRED ##"
# echo "#########################"
# echo
# echo "Type the database name for your mailserver, followed by [ENTER]:"
# read -p "Enter database name: " DATABASE

# NB: 2015-02-02 - due to #124, the database currently needs to be called vimbadmin.
# https://github.com/opensolutions/ViMbAdmin/issues/124
DATABASE=vimbadmin

echo
yellow "#########################"
yellow "## USER INPUT REQUIRED ##"
yellow "#########################"
echo
echo "Type the name for your mail database user, followed by [ENTER]:"
read -p "Enter database user: " DATABASEUSR
echo
yellow "#########################"
yellow "## USER INPUT REQUIRED ##"
yellow "#########################"
echo
echo "Type the PASSWORD for your unprivileged mail database user, followed by [ENTER]:"
unset DATABASEPWD
unset CHARCOUNT
echo -n "Enter password: "
stty echo
CHARCOUNT=0
while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
do
    if [[ $CHAR == $'\0' ]] ; then
        break
    fi
    if [[ $CHAR == $'\177' ]] ; then
        if [ $CHARCOUNT -gt 0 ] ; then
            CHARCOUNT=$((CHARCOUNT-1))
            PROMPT=$'\b \b'
            DATABASEPWD="${DATABASEPWD%?}"
        else
            PROMPT=''
        fi
    else
        CHARCOUNT=$((CHARCOUNT+1))
        PROMPT='*'
        DATABASEPWD+="$CHAR"
    fi
done
echo
stty echo
unset DATABASEPWD2
unset CHARCOUNT
unset PROMPT
echo -n "Repeat password: "
stty echo
CHARCOUNT=0
while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
do
    if [[ $CHAR == $'\0' ]] ; then
        break
    fi
    if [[ $CHAR == $'\177' ]] ; then
        if [ $CHARCOUNT -gt 0 ] ; then
            CHARCOUNT=$((CHARCOUNT-1))
            PROMPT=$'\b \b'
            DATABASEPWD2="${DATABASEPWD2%?}"
        else
            PROMPT=''
        fi
    else
        CHARCOUNT=$((CHARCOUNT+1))
        PROMPT='*'
        DATABASEPWD2+="$CHAR"
    fi
done
stty echo
echo
while [[ "$DATABASEPWD" != "$DATABASEPWD2" ]]; do
        red "*********************************************"
        red "* Passwords do not match! Please try again! *"
        red "*********************************************"
        echo "Type the PASSWORD for your unprivileged mail database user, followed by [ENTER]:"
		unset DATABASEPWD
		unset CHARCOUNT
		unset PROMPT
		echo -n "Enter password: "
		stty echo
		CHARCOUNT=0
		while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
		do
			if [[ $CHAR == $'\0' ]] ; then
				break
			fi
			if [[ $CHAR == $'\177' ]] ; then
				if [ $CHARCOUNT -gt 0 ] ; then
					CHARCOUNT=$((CHARCOUNT-1))
					PROMPT=$'\b \b'
					DATABASEPWD="${DATABASEPWD%?}"
				else
					PROMPT=''
				fi
			else
				CHARCOUNT=$((CHARCOUNT+1))
				PROMPT='*'
				DATABASEPWD+="$CHAR"
			fi
		done
				echo
				stty echo
				unset DATABASEPWD2
				unset CHARCOUNT
				unset PROMT
				echo -n "Repeat password: "
				stty echo
				CHARCOUNT=0
				while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
				do
			if [[ $CHAR == $'\0' ]] ; then
				break
			fi
			if [[ $CHAR == $'\177' ]] ; then
				if [ $CHARCOUNT -gt 0 ] ; then
					CHARCOUNT=$((CHARCOUNT-1))
					PROMPT=$'\b \b'
					DATABASEPWD2="${DATABASEPWD2%?}"
				else
					PROMPT=''
				fi
			else
				CHARCOUNT=$((CHARCOUNT+1))
				PROMPT='*'
				DATABASEPWD2+="$CHAR"
			fi
		done
		stty echo
done

echo
echo
yellow "#########################"
yellow "## USER INPUT REQUIRED ##"
yellow "#########################"
echo
echo "Type the MYSQL ROOT PASSWORD to create the mail database, followed by [ENTER]:"
unset DATABASEROOTPWD
unset CHARCOUNT
unset PROMPT
echo -n "Enter mysql root password: "
stty echo
CHARCOUNT=0
while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
do
    if [[ $CHAR == $'\0' ]] ; then
        break
    fi
    if [[ $CHAR == $'\177' ]] ; then
        if [ $CHARCOUNT -gt 0 ] ; then
            CHARCOUNT=$((CHARCOUNT-1))
            PROMPT=$'\b \b'
            DATABASEROOTPWD="${DATABASEROOTPWD%?}"
        else
            PROMPT=''
        fi
    else
        CHARCOUNT=$((CHARCOUNT+1))
        PROMPT='*'
        DATABASEROOTPWD+="$CHAR"
    fi
done

while ! mysql -u root -p$DATABASEROOTPWD  -e ";" ; do
	stty echo
	echo
        red "*****************************"
        red "* Can't connect, try again! *"
        red "*****************************"
        echo "Type the MYSQL ROOT PASSWORD to create the mail database, followed by [ENTER]:"
		unset DATABASEROOTPWD
		unset CHARCOUNT
		unset PROMPT
		echo -n "Enter mysql root password: "
		stty echo
		CHARCOUNT=0
		while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
		do
			if [[ $CHAR == $'\0' ]] ; then
				break
			fi
			if [[ $CHAR == $'\177' ]] ; then
				if [ $CHARCOUNT -gt 0 ] ; then
					CHARCOUNT=$((CHARCOUNT-1))
					PROMPT=$'\b \b'
					DATABASEROOTPWD="${DATABASEROOTPWD%?}"
				else
					PROMPT=''
				fi
			else
				CHARCOUNT=$((CHARCOUNT+1))
				PROMPT='*'
				DATABASEROOTPWD+="$CHAR"
			fi
		done
		stty echo
done

# Automated mysql_secure_installation
mysql -u root -p${DATABASEROOTPWD} -e "DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; FLUSH PRIVILEGES; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;"

# Create database and user
mysql -u root -p${DATABASEROOTPWD} -e "create database ${DATABASE}; GRANT ALL PRIVILEGES ON ${DATABASE}.* TO ${DATABASEUSR}@127.0.0.1 IDENTIFIED BY '${DATABASEPWD}'; FLUSH PRIVILEGES;"

echo
echo
green "------------------------------------------"
green " Database has been created successfully "
green "------------------------------------------"
echo
echo

# SSL
openssl genrsa -out /etc/ssl/private/mail.key 4096
openssl req -new -key /etc/ssl/private/mail.key -out /tmp/mail.csr -subj "/C=/ST=/L=/O=/OU=/CN=mail.${FQDN}"
openssl x509 -req -days 365 -in /tmp/mail.csr -signkey /etc/ssl/private/mail.key -out /etc/ssl/certs/mail.crt
openssl gendh -out /etc/ssl/private/dh512.pem -2 512
openssl gendh -out /etc/ssl/private/dh1024.pem -2 1024

# Postfix
aptitude -y install postfix postfix-mysql postfix-policyd-spf-perl postfix-pcre

mv /etc/postfix/main.cf{,.orig}
cat > /etc/postfix/main.cf <<END
smtpd_banner = \$myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
smtpd_use_tls = yes
smtpd_tls_cert_file = /etc/ssl/certs/mail.crt
smtpd_tls_key_file = /etc/ssl/private/mail.key
smtpd_tls_dh512_param_file = /etc/ssl/private/dh512.pem
smtpd_tls_dh1024_param_file = /etc/ssl/private/dh1024.pem
smtpd_tls_eecdh_grade = ultra
smtpd_tls_auth_only = yes
smtpd_tls_security_level = encrypt
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtpd_tls_session_cache_timeout = 3600s
smtpd_helo_required = yes
smtpd_tls_received_header = yes
smtpd_tls_security_level = may
smtpd_tls_mandatory_ciphers = medium
smtpd_tls_mandatory_exclude_ciphers = aNULL, MD5, RC4
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3 , !TLSv1, !TLSv1.1
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
tls_medium_cipherlist = AES128+EECDH:AES128+EDH
smtpd_tls_loglevel = 1
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$myhostname
tls_random_source = dev:/dev/urandom
tls_preempt_cipherlist = yes
broken_sasl_auth_clients = yes
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_rbl_client zen.spamhaus.org,
    reject_rbl_client bl.spamcop.net,
    reject_unknown_sender_domain,
    check_policy_service unix:private/policy-spf
smtpd_sender_restrictions =
    permit_sasl_authenticated,
    permit_mynetworks
policy-spf_time_limit = 3600s
myhostname = mail.${FQDN}
myorigin = /etc/mailname
mydestination = localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = mysql:/etc/postfix/mysql/virtual_domains_maps.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql/virtual_mailbox_maps.cf
virtual_alias_maps = mysql:/etc/postfix/mysql/virtual_alias_maps.cf
smtpd_recipient_limit = 2000
smtpd_milters =
    unix:clamav/clamav-milter.ctl,
    unix:spamass/spamass.sock
milter_connect_macros = j {daemon_name} v {if_name} _
milter_default_action = tempfail
inet_interfaces = all
inet_protocols = ipv4
alias_maps = hash:/etc/aliases
END

mkdir /etc/postfix/mysql
cat > /etc/postfix/mysql/virtual_alias_maps.cf <<END
user = ${DATABASEUSR}
password = ${DATABASEPWD}
hosts = 127.0.0.1
dbname = ${DATABASE}
query = SELECT goto FROM alias WHERE address = '%s' AND active = '1'
END

cat > /etc/postfix/mysql/virtual_domains_maps.cf <<END
user = ${DATABASEUSR}
password = ${DATABASEPWD}
hosts = 127.0.0.1
dbname = ${DATABASE}
query = SELECT domain FROM domain WHERE domain = '%s' AND backupmx = '0' AND active = '1'
END

cat > /etc/postfix/mysql/virtual_mailbox_maps.cf <<END
user = ${DATABASEUSR}
password = ${DATABASEPWD}
hosts = 127.0.0.1
dbname = ${DATABASE}
query = SELECT maildir FROM mailbox WHERE username = '%s' AND active = '1'
END

mv /etc/postfix/master.cf{,.org}
cat > /etc/postfix/master.cf <<END
smtp      inet  n       -       -       -       -       smtpd
    -o strict_rfc821_envelopes=yes
submission inet n       -       -       -       -       smtpd
    -o syslog_name=postfix/submission
    -o smtpd_tls_security_level=encrypt
    -o tls_preempt_cipherlist=yes
    -o smtpd_sasl_auth_enable=yes
    -o content_filter=dksign:[127.0.0.1]:10027
    -o smtpd_client_restrictions=permit_sasl_authenticated,reject
    -o milter_macro_daemon_name=ORIGINATING
    -o cleanup_service_name=cleanheader
smtps     inet  n       -       -       -       -       smtpd
    -o syslog_name=postfix/smtps
    -o smtpd_tls_wrappermode=yes
    -o smtpd_sasl_auth_enable=yes
    -o content_filter=dksign:[127.0.0.1]:10027
    -o smtpd_client_restrictions=permit_sasl_authenticated,reject
    -o milter_macro_daemon_name=ORIGINATING
pickup    fifo  n       -       -       60      1       pickup
cleanup   unix  n       -       -       -       0       cleanup
qmgr      fifo  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       -       1000?   1       tlsmgr
rewrite   unix  -       -       -       -       -       trivial-rewrite
bounce    unix  -       -       -       -       0       bounce
defer     unix  -       -       -       -       0       bounce
trace     unix  -       -       -       -       0       bounce
verify    unix  -       -       -       -       1       verify
flush     unix  n       -       -       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       -       -       -       smtp
relay     unix  -       -       -       -       -       smtp
showq     unix  n       -       -       -       -       showq
error     unix  -       -       -       -       -       error
retry     unix  -       -       -       -       -       error
discard   unix  -       -       -       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       -       -       -       lmtp
anvil     unix  -       -       -       -       1       anvil
scache    unix  -       -       -       -       1       scache
maildrop  unix  -       n       n       -       -       pipe
    flags=DRhu user=vmail argv=/usr/bin/maildrop -d \${recipient}
uucp      unix  -       n       n       -       -       pipe
    flags=Fqhu user=uucp argv=uux -r -n -z -a\$sender - \$nexthop!rmail (\$recipient)
ifmail    unix  -       n       n       -       -       pipe
    flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r \$nexthop (\$recipient)
bsmtp     unix  -       n       n       -       -       pipe
    flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t\$nexthop -f\$sender \$recipient
scalemail-backend unix      -       n       n       -       2       pipe
    flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store \${nexthop} \${user} \${extension}
mailman   unix  -       n       n       -       -       pipe
    flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
    \${nexthop} \${user}
policy-spf unix -       n       n       -       -       spawn
    user=nobody argv=/usr/sbin/postfix-policyd-spf-perl
dksign    unix  -       -       n       -       4       smtp
    -o smtp_send_xforward_command=yes
    -o smtp_discard_ehlo_keywords=8bitmime,starttls
127.0.0.1:10028 inet n  -        n      -       10      smtpd
    -o content_filter=
    -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
    -o smtpd_helo_restrictions=
    -o smtpd_client_restrictions=
    -o smtpd_sender_restrictions=
    -o smtpd_recipient_restrictions=permit_mynetworks,reject
    -o mynetworks=127.0.0.0/8
    -o smtpd_authorized_xforward_hosts=127.0.0.0/8
cleanheader unix n       -       -       -       0       cleanup
    -o header_checks=pcre:/etc/postfix/header_checks
END

cat > /etc/postfix/header_checks <<END
/^\\s*(Received: from)[^\\n]*(.*)/ REPLACE \$1 [127.0.0.1] (localhost [127.0.0.1])\$2
/^\\s*Mime-Version: 1.0.*/ REPLACE Mime-Version: 1.0
/^\\s*User-Agent/        IGNORE
/^\\s*X-Enigmail/        IGNORE
/^\\s*X-Mailer/          IGNORE
/^\\s*X-Originating-IP/  IGNORE
END

# Apply changes
service postfix reload

# Dovecot
aptitude -y install dovecot-core dovecot-imapd dovecot-lmtpd dovecot-mysql

cp /etc/dovecot/dovecot.conf{,.orig}
cp /etc/dovecot/conf.d/10-mail.conf{,.orig}
cp /etc/dovecot/conf.d/10-auth.conf{,.orig}
cp /etc/dovecot/conf.d/10-master.conf{,.orig}
cp /etc/dovecot/conf.d/10-ssl.conf {,.orig}

sed -i '21s/.*/protocols = imap lmtp\n&/' /etc/dovecot/dovecot.conf

sed -i '30s/.*/mail_location = maildir:\/var\/mail\/decrypted\/vhosts\/%d\/%n\/maildir/' /etc/dovecot/conf.d/10-mail.conf
sed -i '112s/.*/mail_privileged_group = mail/' /etc/dovecot/conf.d/10-mail.conf
sed -i '9s/.*/disable_plaintext_auth = yes/' /etc/dovecot/conf.d/10-auth.conf
sed -i '99s/.*/auth_mechanisms = plain login/' /etc/dovecot/conf.d/10-auth.conf
sed -i '121s/.*/#!include auth-system.conf.ext/' /etc/dovecot/conf.d/10-auth.conf
sed -i '122s/.*/!include auth-sql.conf.ext/' /etc/dovecot/conf.d/10-auth.conf

mv /etc/dovecot/conf.d/auth-sql.conf.ext{,.orig}
cat > /etc/dovecot/conf.d/auth-sql.conf.ext <<END
passdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
    driver = static
    args = uid=vmail gid=vmail home=/var/mail/decrypted/vhosts/%d/%n/maildir
}
END

mv /etc/dovecot/dovecot-sql.conf.ext{,.orig}
cat > /etc/dovecot/dovecot-sql.conf.ext <<END
driver = mysql
connect = host=127.0.0.1 dbname=${DATABASE} user=${DATABASEUSR} password=${DATABASEPWD}
default_pass_scheme = SHA512-CRYPT
password_query = \\
  SELECT username AS user, password, \\
    homedir AS userdb_home, uid AS userdb_uid, gid AS userdb_gid \\
  FROM mailbox WHERE username = '%u'
iterate_query = SELECT username AS user FROM mailbox
END

mv /etc/dovecot/conf.d/10-master.conf{,.orig}
cat > /etc/dovecot/conf.d/10-master.conf <<END
service imap-login {
    inet_listener imaps {
        port = 993
        ssl = yes
    }
}

service lmtp {
    unix_listener /var/spool/postfix/private/dovecot-lmtp {
        mode = 0600
        user = postfix
        group = postfix
    }
}

service auth {
    unix_listener /var/spool/postfix/private/auth {
        mode = 0666
        user = postfix
        group = postfix
    }
    unix_listener auth-userdb {
        mode = 0600
        user = vmail
    }
    user = dovecot
}

service auth-worker {
    user = vmail
}
END

mv /etc/dovecot/conf.d/10-ssl.conf{,.orig}
cat > /etc/dovecot/conf.d/10-ssl.conf <<END
ssl = required
ssl_cert = </etc/ssl/certs/mail.crt
ssl_key = </etc/ssl/private/mail.key
ssl_protocols = !SSLv2 !SSLv3
ssl_cipher_list = AES128+EECDH:AES128+EDH
#ssl_prefer_server_ciphers = yes
END

# # Dovecot Solr
# aptitude -y install dovecot-solr solr-tomcat

# cd ~/sources
# wget http://ftp.de.debian.org/debian/pool/main/d/dovecot/dovecot_2.1.7.orig.tar.gz
# tar xzvf dovecot_2.1.7.orig.tar.gz
# cp dovecot-2.1.7/doc/solr-schema.xml /etc/solr/conf/schema.xml
# mkdir /var/mail/decrypted/solr

# sed -i '117s/.*/  <dataDir>\/var\/mail\/decrypted\/solr<\/dataDir>/' /etc/solr/conf/solrconfig.xml

# sed -i '71s/.*/<Connector address="127.0.0.1" port="8080" protocol="HTTP\/1.1"/' /etc/tomcat6/server.xml

# sed -i '16s/.*/  mail_plugins = \$mail_plugins fts fts_solr/' /etc/dovecot/conf.d/20-imap.conf

# sed -i '10s/.*/    fts = solr\n&/' /etc/dovecot/conf.d/90-plugin.conf
# sed -i '11s/.*/    fts_solr = break-imap-search url=http:\/\/localhost:8080\/solr\//' /etc/dovecot/conf.d/90-plugin.conf

# touch /etc/cron.daily/solr
# echo -e "#!/bin/sh" >> /etc/cron.daily/solr
# echo -e "curl http://localhost:8080/solr/update?optimize=true" >> /etc/cron.daily/solr

# touch /etc/cron.hourly/solr
# echo -e "#!/bin/sh" >> /etc/cron.hourly/solr
# echo -e "curl http://localhost:8080/solr/update?commit=true" >> /etc/cron.hourly/solr

# chmod +x /etc/cron.daily/solr /etc/cron.hourly/solr

# service dovecot restart
# service tomcat6 restart

# ClamAV & SpamAssassin
aptitude -y install clamav-milter clamav-unofficial-sigs spamass-milter

freshclam
service clamav-daemon start

touch /etc/default/clamav-milter
echo -e "SOCKET_RWGROUP=postfix" >> /etc/default/clamav-milter

mkdir /var/spool/postfix/clamav
chown clamav /var/spool/postfix/clamav

mv /etc/clamav/clamav-milter.conf{,.orig}
cat > /etc/clamav/clamav-milter.conf <<END
MilterSocket /var/spool/postfix/clamav/clamav-milter.ctl
FixStaleSocket true
User clamav
AllowSupplementaryGroups true
ReadTimeout 120
Foreground false
PidFile /var/run/clamav/clamav-milter.pid
ClamdSocket unix:/var/run/clamav/clamd.ctl
OnClean Accept
OnInfected Reject
OnFail Defer
AddHeader Replace
LogSyslog false
LogFacility LOG_LOCAL6
LogVerbose false
LogInfected Off
LogClean Off
LogRotate true
MaxFileSize 100M
SupportMultipleRecipients true
RejectMsg Rejecting harmful e-mail: %v found.
TemporaryDirectory /tmp
LogFile /var/log/clamav/clamav-milter.log
LogTime true
LogFileUnlock false
LogFileMaxSize 0
MilterSocketGroup clamav
MilterSocketMode 666
END

sed -i '12s/.*/OPTIONS="-u spamass-milter -i 127.0.0.1 -m -r -1 -I"/' /etc/default/spamass-milter

sed -i '18s/.*/ENABLED=1/' /etc/default/spamassassin
sed -i '31s/.*/CRON=1/' /etc/default/spamassassin

sa-update
chown -R debian-spamd:debian-spamd /var/lib/spamassassin/
service spamassassin start

# DKIMProxy
aptitude -y install dkimproxy

openssl genrsa -out /etc/dkimproxy/private.key 1024
openssl rsa -in /etc/dkimproxy/private.key -out /etc/dkimproxy/public.key -pubout -outform PEM

sed -i '2s/.*/listen 127.0.0.1:10025/' /etc/dkimproxy/dkimproxy_in.conf
sed -i '2s/.*/relay 27.0.0.1:10026/' /etc/dkimproxy/dkimproxy_in.conf

sed -i '2s/.*/listen 127.0.0.1:10027/' /etc/dkimproxy/dkimproxy_out.conf
sed -i '5s/.*/relay 127.0.0.1:10028/' /etc/dkimproxy/dkimproxy_out.conf
sed -i "8s/.*/domain ${FQDN}/" /etc/dkimproxy/dkimproxy_out.conf
sed -i '15s/.*/keyfile \/etc\/dkimproxy\/private.key/' /etc/dkimproxy/dkimproxy_out.conf
sed -i '18s/.*/selector mail/' /etc/dkimproxy/dkimproxy_out.conf

sed -i "107s/.*/DKIMPROXY_OUT_ARGS=\"\${COMMON_ARGS} --pidfile=\${PIDDKIMPROXY_OUT} --min_servers=\${DKIMPROXY_OUT_MIN_SERVERS} --domain=${FQDN} --method=simple --conf_file=\${DKOUT_CONF} --keyfile=\/etc\/dkimproxy\/private.key --selector=mail --signature=dkim(a=rsa-sha256) --signature=domainkeys(a=rsa-sha1)\"/" /etc/init.d/dkimproxy

service dkimproxy restart

# Check if /var/mail/decrypted is mounted
sed -i '33s/.*/. \/lib\/lsb\/init-functions\n&/' /etc/init.d/postfix
sed -i '34s/.*/if ! mount | grep "on \/var\/mail\/decrypted" > \/dev\/null\n&/' /etc/init.d/postfix
sed -i '35s/.*/then\n&/' /etc/init.d/postfix
sed -i '36s/.*/    log_daemon_msg "\/var\/mail\/decrypted not mounted";\n&/' /etc/init.d/postfix
sed -i '37s/.*/    log_end_msg 1;\n&/' /etc/init.d/postfix
sed -i '38s/.*/    exit 1;\n&/' /etc/init.d/postfix
sed -i '39s/.*/fi/' /etc/init.d/postfix

sed -i '47s/.*/. \/lib\/lsb\/init-functions\n&/' /etc/init.d/dovecot
sed -i '48s/.*/if ! mount | grep "on \/var\/mail\/decrypted" > \/dev\/null\n&/' /etc/init.d/dovecot
sed -i '49s/.*/then\n&/' /etc/init.d/dovecot
sed -i '50s/.*/    log_daemon_msg "\/var\/mail\/decrypted not mounted";\n&/' /etc/init.d/dovecot
sed -i '51s/.*/    log_end_msg 1;\n&/' /etc/init.d/dovecot
sed -i '52s/.*/    exit 1;\n&/' /etc/init.d/dovecot
sed -i '53s/.*/fi/' /etc/init.d/dovecot

# sed -i '42s/.*/. \/lib\/lsb\/init-functions\n&/' /etc/init.d/tomcat6
# sed -i '43s/.*/if ! mount | grep "on \/var\/mail\/decrypted" > \/dev\/null\n&/' /etc/init.d/tomcat6
# sed -i '44s/.*/then\n&/' /etc/init.d/tomcat6
# sed -i '45s/.*/    log_daemon_msg "\/var\/mail\/decrypted not mounted";\n&/' /etc/init.d/tomcat6
# sed -i '46s/.*/    log_end_msg 1;\n&/' /etc/init.d/tomcat6
# sed -i '47s/.*/    exit 1;\n&/' /etc/init.d/tomcat6
# sed -i '48s/.*/fi/' /etc/init.d/tomcat6

service postfix restart
service dovecot restart
#service tomcat6 restart

# ViMbAdmin v3 Installation
cd /usr/local
git clone git://github.com/opensolutions/ViMbAdmin.git vimbadmin
cd vimbadmin/
curl -sS https://getcomposer.org/installer | php
php composer.phar install
cp application/configs/application.ini.dist application/configs/application.ini

sed -i "46s/.*/resources.doctrine2.connection.options.dbname   = '${DATABASE}'/" /usr/local/vimbadmin/application/configs/application.ini
sed -i "47s/.*/resources.doctrine2.connection.options.user     = '${DATABASEUSR}'/" /usr/local/vimbadmin/application/configs/application.ini
sed -i "48s/.*/resources.doctrine2.connection.options.password = '${DATABASEPWD}'/" /usr/local/vimbadmin/application/configs/application.ini
sed -i "49s/.*/resources.doctrine2.connection.options.host     = '127.0.0.1'/" /usr/local/vimbadmin/application/configs/application.ini
sed -i '117s/.*/defaults.mailbox.uid = 5000/' /usr/local/vimbadmin/application/configs/application.ini
sed -i '118s/.*/defaults.mailbox.gid = 5000/' /usr/local/vimbadmin/application/configs/application.ini
sed -i '132s/.*/defaults.mailbox.homedir = "\/var\/mail\/decrypted\/"/' /usr/local/vimbadmin/application/configs/application.ini
sed -i '149s/.*/defaults.mailbox.password_scheme = "crypt:sha512"/' /usr/local/vimbadmin/application/configs/application.ini
sed -i '229s/.*/server.smtp.port    = "587"/' /usr/local/vimbadmin/application/configs/application.ini
sed -i '230s/.*/server.smtp.crypt   = "STARTTLS"/' /usr/local/vimbadmin/application/configs/application.ini
sed -i '232s/.*/server.pop3.enabled = 0/' /usr/local/vimbadmin/application/configs/application.ini
sed -i '239s/.*/server.imap.host  = "mail.%d"/' /usr/local/vimbadmin/application/configs/application.ini
sed -i '244s/.*/server.webmail.enabled = 0/' /usr/local/vimbadmin/application/configs/application.ini

# Create MySQL tables
cp /usr/local/vimbadmin/public/.htaccess.dist /usr/local/vimbadmin/public/.htaccess
/usr/local/vimbadmin/bin/doctrine2-cli.php orm:schema-tool:create

chown -R www-data:www-data ../vimbadmin

# Create Nginx VHost
cat > /etc/nginx/sites-available/vma.${FQDN}.conf <<END
server {
			listen 80;
			server_name vma.${FQDN};
			return 301 https://vma.${FQDN}\$request_uri;
}

server {
			listen 443 ssl;
			server_name vma.${FQDN};
		
			root /usr/local/vimbadmin/public;
			index index.php;
		
			error_page 404 /index.php;

			ssl_certificate      ssl/${FQDN}.pem;
			ssl_certificate_key  ssl/${FQDN}.key;
			ssl_dhparam	     	 ssl/dh.pem;
			#ssl_trusted_certificate ssl/trustedbundle.pem;
			ssl_session_cache   shared:SSL:10m;
			ssl_session_timeout 10m;
			ssl_protocols        TLSv1 TLSv1.1 TLSv1.2;
			#ssl_prefer_server_ciphers on;
	
			#ssl_stapling on;
			#ssl_stapling_verify on;
			#resolver 8.8.8.8 8.8.4.4 valid=300s;
			#resolver_timeout 5s;

			ssl_ciphers "AES256+EECDH:AES256+EDH";			

			add_header Strict-Transport-Security "max-age=63072000; includeSubdomains";
			add_header X-Frame-Options DENY;
			add_header Alternate-Protocol  443:npn-spdy/2;
			add_header X-Content-Type-Options nosniff;
			add_header X-XSS-Protection "1; mode=block";
			add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://ssl.google-analytics.com https://assets.zendesk.com https://connect.facebook.net; img-src 'self' https://ssl.google-analytics.com https://s-static.ak.facebook.com https://assets.zendesk.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://assets.zendesk.com; font-src 'self' https://themes.googleusercontent.com; frame-src https://assets.zendesk.com https://www.facebook.com https://s-static.ak.facebook.com https://tautt.zendesk.com; object-src 'none'";				

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
			# pagespeed RespectXForwardedProto on;
			
			location ~ \.php\$ {
				try_files \$uri =404;
				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
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

			location / {
			   	ModSecurityEnabled on;
			   	ModSecurityConfig modsecurity/modsecurity.conf;
			   	if (!-f \$request_filename) {
					rewrite ^(.*)\$ /index.php?q=\$1 last;
					break;
				}
				try_files \$uri \$uri/ /index.php?\$args;
			}
			
			location ~ /\. {
				deny all;
				access_log off;
				log_not_found off;
			}
			
			location = /robots.txt {
				allow all;
				log_not_found off;
				access_log off;
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

if [ $CLOUDFLARE == '1' ]; then
	sed -i '30s/.*/			ssl_ciphers "AES128+EECDH:AES128+EDH:AES256+EECDH:AES256+EDH";/' /etc/nginx/sites-available/vma.${FQDN}.conf
fi

ln -s /etc/nginx/sites-available/vma.${FQDN}.conf /etc/nginx/sites-enabled/vma.${FQDN}.conf
sed -i '1s/.*/3/' ~/status

}


part3(){
FQDN=$(sed '2q;d' ~/status)

#
# Arno-Iptables-Firewall
# Fail2Ban
# Snort & Snorty
#

#
# Arno-Iptable-Firewall
#

# Get the latest version
git clone https://github.com/arno-iptables-firewall/aif.git ~/sources/aif

# Create folders and copy files
cd $_
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
gzip -c share/man/man1/arno-fwfilter.1 >/usr/local/share/man/man1/arno-fwfilter.1.gz
gzip -c share/man/man8/arno-iptables-firewall.8 >/usr/local/share/man/man8/arno-iptables-firewall.8.gz
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
update-rc.d -f arno-iptables-firewall start 11 S . stop 10 0 6

# Configure firewall.conf
bash /usr/local/share/environment
sed -i '39s/.*/EXT_IF="eth0"/' /etc/arno-iptables-firewall/firewall.conf
sed -i '44s/.*/EXT_IF_DHCP_IP="0"/' /etc/arno-iptables-firewall/firewall.conf
sed -i '307s/.*/DRDOS_PROTECT="1"/' /etc/arno-iptables-firewall/firewall.conf
sed -i '312s/.*/IPV6_SUPPORT="0"/' /etc/arno-iptables-firewall/firewall.conf

# Blacklist some bad guys
mkdir ~/sources/blacklist && cd $_
cat > update.sh <<END
#!/bin/bash
cd ~/sources/blacklist
wget -N http://infiltrated.net/blacklisted
wget -N http://lists.blocklist.de/lists/all.txt
cat blacklisted all.txt > /etc/arno-iptables-firewall/blocked-hosts
END
bash update.sh
echo -e "/etc/init.d/arno-iptables-firewall force-reload" >> update.sh
sed -i '1211s/.*/BLOCK_HOSTS_FILE="\/etc\/arno-iptables-firewall\/blocked-hosts"/' /etc/arno-iptables-firewall/firewall.conf

touch /etc/cron.daily/blocked-hosts
echo -e "#!/bin/sh" >> /etc/cron.daily/blocked-hosts
echo -e "bash ~/sources/blacklist/update.sh" >> /etc/cron.daily/blocked-hosts
chmod +x /etc/cron.daily/blocked-hosts

echo
yellow "#########################"
yellow "## USER INPUT REQUIRED ##"
yellow "#########################"
echo
echo "Change the default SSH port for some security reasons."
echo "Please use only a priviliged Port! (1 - 1024)"
echo
stty echo
read -p "Enter a new port, followed by [ENTER]: " SSH
SSHW=1
SSHS=1
SSHC=1
while [ $SSHW == '1' ]; do
	while [ $SSHC == '1' ]; do
		if [ $SSH == '22' ] && [ $SSHS == '1' ]; then
			while true; do
				echo
				cyan "*************************************************"
				cyan "Do you really want to use the standard SSH port? [y/n]"
				read -p "" i
				case $i in
				[Yy]* ) SSHS=0;break;;
				[Nn]* ) echo;read -p "Enter a new port, followed by [ENTER]: " SSH;break;;
				* ) red "Please use [y/n]";;
				esac
			done
		fi
		while [ $SSH == '21' ]; do
			echo
			red "*************************************************"
			red "This is the standard FTP port, chose another one!"
			read -p "Enter a new port, followed by [ENTER]: " SSH
		done
		while [ $SSH == '25' ]; do
			echo
			red "*************************************************"
			red "This is the standard SMTP port, chose another one!"
			read -p "Enter a new port, followed by [ENTER]: " SSH
		done
		while [ $SSH == '80' ]; do
			echo
			red "*************************************************"
			red "This is the standard HTTP port, chose another one!"
			read -p "Enter a new port, followed by [ENTER]: " SSH
		done
		while [ $SSH == '443' ]; do
			echo
			red "*************************************************"
			red "This is the standard HTTPS port, chose another one!"
			read -p "Enter a new port, followed by [ENTER]: " SSH
		done
		while [ $SSH == '587' ]; do
			echo
			red "*************************************************"
			red "This is the standard Submission port, chose another one!"
			read -p "Enter a new port, followed by [ENTER]: " SSH
		done
		while [ $SSH == '990' ]; do
			echo
			red "*************************************************"
			red "This is the standard FTPS port, chose another one!"
			read -p "Enter a new port, followed by [ENTER]: " SSH
		done
		while [ $SSH == '993' ]; do
			echo
			red "*************************************************"
			red "This is the standard IMAPS port, chose another one!"
			read -p "Enter a new port, followed by [ENTER]: " SSH
		done
		while [ $SSH -gt 1024 ] || [ $SSH -le 0  ]; do
			echo
			red "*************************************************"
			red "Don't use any unprivileged port, chose another one!"
			read -p "Enter a new port, followed by [ENTER]: " SSH
		done
		if [ $SSHS == '1' ]; then
			if [ $SSH == '22' ]; then
				echo
			else
				SSHS=0
			fi
		fi
		if [ $SSH == '21' ] || [ $SSH == '25' ] || [ $SSH == '80' ] || [ $SSH == '443' ] || [ $SSH == '587' ] || [ $SSH == '990' ] || [ $SSH == '993' ] || [ $SSH -gt 1024 ] || [ $SSH -le 0 ]; then
                        echo
                        red "*************************************************"
                        red "You are still using an unsupportet port, please chose another one!"
                        read -p "Enter a new port, followed by [ENTER]: " SSH
                else
                	if [[ $SSH =~ ^-?[0-9]+$ ]]; then
                		SSHC=0
                        else
                        	echo
                        	red "*************************************************"
                        	red "SSH Port is not a integer, chose another one!"
                        	read -p "Enter a new port, followed by [ENTER]: " SSH
                	fi
                fi
	done
SSHW="0"
done

sed -i '1153s/.*/OPEN_ICMP="1"/' /etc/arno-iptables-firewall/firewall.conf
sed -i "1163s/.*/OPEN_TCP=\"${SSH}, 25, 80, 443, 587, 993\"/" /etc/arno-iptables-firewall/firewall.conf
sed -i '1164s/.*/OPEN_UDP="53"/' /etc/arno-iptables-firewall/firewall.conf

sed -i '27s/.*/VERBOSE="1"/' /etc/init.d/arno-iptables-firewall

# Start the firewall!
/etc/init.d/arno-iptables-firewall start

# Change SSH Port
sed -i "s/^Port 22/Port ${SSH}/g" /etc/ssh/sshd_config
service ssh restart

# Disable IPv6
#sed -i '/::/s/^/#/' /etc/hosts
#sed -i '/::/s/^/#/' /etc/network/interfaces
#sed -i '/netmask 64/s/^/#/' /etc/network/interfaces
#sed -i '/netmask 80/s/^/#/' /etc/network/interfaces
#sed -i '/inet6/s/^/#/' /etc/network/interfaces
echo -e "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.conf

# Enable changes and restart network
sysctl -p

# Restart all Systems
service nginx reload
service postfix restart
service dovecot restart
service clamav-milter restart
#service tomcat6 restart

# Fail2Ban
aptitude -y install fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i '21s/.*/ignoreip = 127.0.0.1/' /etc/fail2ban/jail.local
sed -i '21s/.*/maxretry = 6/' /etc/fail2ban/jail.local
sed -i '99s/.*/maxretry = 3/' /etc/fail2ban/jail.local
sed -i '229s/.*/enabled  = true\n&/' /etc/fail2ban/jail.local
sed -i '230s/.*/maxretry = 10/' /etc/fail2ban/jail.local
sed -i '259s/.*/enabled  = true\n&/' /etc/fail2ban/jail.local
sed -i '260s/.*/maxretry = 10/' /etc/fail2ban/jail.local
sed -i '270s/.*/enabled  = true\n&/' /etc/fail2ban/jail.local
sed -i '271s/.*/maxretry = 10/' /etc/fail2ban/jail.local
service fail2ban restart

# Use public-key authentication for SSH
echo
yellow "#########################"
yellow "## USER INPUT REQUIRED ##"
yellow "#########################"
echo
echo "OpenSSH has a robust and well-tested public key authentication"
echo "system built right in. When set up properly, it's more secure"
echo "than using passwords and a lot easier to use."
echo "Let's switch to the secure public-key authentication.."
echo
red "I definitely recommend to do that!"
echo
stty echo
while true; do
	read -p "Continue? [y/n]" i
	case $i in
	[Yy]* ) SSHKEY=1;break;;
	[Nn]* ) SSHKEY=0;break;;
	* ) red "Please use [Y] or [N]";echo;;
	esac
done
if [ $SSHKEY == '0' ]; then
	echo
else
	stty echo
	echo "Enter the password for your private key, followed by [ENTER]:"
	unset SSHKEYPWD
	unset CHARCOUNT
	unset PROMPT
	echo -n "Enter password: "
	stty echo
	CHARCOUNT=0
	while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
	do
	    if [[ $CHAR == $'\0' ]] ; then
	        break
	    fi
	    if [[ $CHAR == $'\177' ]] ; then
	        if [ $CHARCOUNT -gt 0 ] ; then
	            CHARCOUNT=$((CHARCOUNT-1))
	            PROMPT=$'\b \b'
	            SSHKEYPWD="${SSHKEYPWD%?}"
	        else
	            PROMPT=''
	        fi
	    else
	        CHARCOUNT=$((CHARCOUNT+1))
	        PROMPT='*'
	        SSHKEYPWD+="$CHAR"
	    fi
	done
	echo
	stty echo
	unset SSHKEYPWD2
	unset CHARCOUNT
	unset PROMPT
	echo -n "Repeat password: "
	stty echo
	CHARCOUNT=0
	while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
	do
	    if [[ $CHAR == $'\0' ]] ; then
	        break
	    fi
	    if [[ $CHAR == $'\177' ]] ; then
	        if [ $CHARCOUNT -gt 0 ] ; then
	            CHARCOUNT=$((CHARCOUNT-1))
	            PROMPT=$'\b \b'
	            SSHKEYPWD2="${SSHKEYPWD2%?}"
	        else
	            PROMPT=''
	        fi
	    else
	        CHARCOUNT=$((CHARCOUNT+1))
	        PROMPT='*'
	        SSHKEYPWD2+="$CHAR"
	    fi
	done
	stty echo
	echo
	while [[ "$SSHKEYPWD" != "$SSHKEYPWD2" ]]; do
	        red "*********************************************"
	        red "* Passwords do not match! Please try again! *"
	        red "*********************************************"
	        echo "Enter the password for your private key, followed by [ENTER]:"
			unset SSHKEYPWD
			unset CHARCOUNT
			unset PROMPT
			stty echo
			echo -n "Enter password: "
			stty echo
			CHARCOUNT=0
			while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
			do
				if [[ $CHAR == $'\0' ]] ; then
					break
				fi
				if [[ $CHAR == $'\177' ]] ; then
					if [ $CHARCOUNT -gt 0 ] ; then
						CHARCOUNT=$((CHARCOUNT-1))
						PROMPT=$'\b \b'
						SSHKEYPWD="${SSHKEYPWD%?}"
					else
						PROMPT=''
					fi
				else
					CHARCOUNT=$((CHARCOUNT+1))
					PROMPT='*'
					SSHKEYPWD+="$CHAR"
				fi
			done
			stty echo
			echo
			unset SSHKEYPWD2
			unset CHARCOUNT
			unset PROMT
			echo -n "Repeat password: "
			stty echo
			CHARCOUNT=0
			while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
			do
				if [[ $CHAR == $'\0' ]] ; then
					break
				fi
				if [[ $CHAR == $'\177' ]] ; then
					if [ $CHARCOUNT -gt 0 ] ; then
						CHARCOUNT=$((CHARCOUNT-1))
						PROMPT=$'\b \b'
						SSHKEYPWD2="${SSHKEYPWD2%?}"
					else
						PROMPT=''
					fi
				else
					CHARCOUNT=$((CHARCOUNT+1))
					PROMPT='*'
					SSHKEYPWD2+="$CHAR"
				fi
			done
			stty echo
	done
	ssh-keygen -f ~/ssh.key -b 2048 -t rsa -N $SSHKEYPWD > /dev/null
	mkdir -p ~/.ssh && chmod 700 ~/.ssh
	cat ~/ssh.key.pub > ~/.ssh/authorized_keys2 && rm ~/ssh.key.pub
	chmod 600 ~/.ssh/authorized_keys2
	clear
	green "#########################################################"
	green "#This is your private key. Copy the entire key          #"
	green "#including the -----BEGIN and -----END line and         #"
	green "#save it on your Desktop. The file name does not matter!#"
	green "#########################################################"
	yellow "Import the file by using PuTTy Key Generator and save your"
	yellow "private key as *.ppk. Now you can use the key to"
	yellow "authenticate with your server using Putty."
	echo
	echo
	cat ~/ssh.key
	echo
	echo
	while true; do
		read -p "Press any key to continue.." i
		case $i in
		* ) break;;
		esac
	done
	sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
	sed -i 's/^UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config
	service ssh restart
	rm ~/ssh.key
fi
clear
yellow "#########################"
yellow "## USER INPUT REQUIRED ##"
yellow "#########################"
echo "Before the mail server can be used, the following requirements must be met:"
echo
echo
yellow "## 1 ##"
echo "The Subomain vma.${FQDN} and mail.${FQDN}"
echo "must be resolve to your IP: ${IPADR}"
if [ $CLOUDFLARE == '1' ]; then
	echo "If you use CloudFlare, only mail.${FQDN} have to resolve directly to your IP"
	echo "Don't forget: You have to set an A record for each subdomain!"
fi
echo
echo
if [ $CLOUDFLARE == '1' ]; then
	echo
else
	yellow "## 2 ##"
	echo "Verify that the following MX record is set:"
	echo
	echo "NAME       TYPE          VALUE"
	echo "-----------------------------------------"
	echo "${FQDN}	  MX	  10:mail.${FQDN}"
	echo
	echo
fi
if [ $CLOUDFLARE == '1' ]; then
	yellow "## 2 ##"
else
	yellow "## 3 ##"
fi
echo "In the next step you have to set two DNS TXT records for your domain."
red "DONT FORGET THE QUOTES \" \""
echo
echo
echo
magenta "The first rule should look like this:"
echo
echo "NAME       TYPE          VALUE"
echo "-----------------------------------------"
if [ $CLOUDFLARE == '1' ]; then
	echo " @         TXT       \"v=spf1 ip4:${IPADR} -all\""
else
	echo " @         TXT       \"v=spf1 mx -all\""
fi
echo
echo
echo
magenta "The second rule sould look like this:"
echo
echo "      NAME           TYPE              VALUE"
echo "----------------------------------------------------------"
echo " mail._domainkey     TXT     \"k=rsa; t=s; p=DKIMPUBLICKEY\""
echo
green "Copy the dkimproxy public key and put it right after p="
red "It's a single line!"
echo
cp /etc/dkimproxy/public.key ~/dkim.key
sed -i '1d' ~/dkim.key
sed -i '5d' ~/dkim.key
while true; do
 	out=()
 	for (( i=0; i<4; i++ )); do
    read && out+=( "$REPLY" )
  	done
 	 if (( ${#out[@]} > 0 )); then
    	printf '%s' "${out[@]}"
    	echo
  	fi
  	if (( ${#out[@]} < 4 )); then break; fi
done <~/dkim.key >~/dkim2.key
cat ~/dkim2.key
echo
echo
while true; do
	read -p "Press any key to continue.." i
	case $i in
	* ) rm ~/dkim.key;rm ~/dkim2.key;break;;
	esac
done
sed -i '1s/.*/4/' ~/status
}


part4(){

#
# phpMyAdmin
#

echo
yellow "#########################"
yellow "## USER INPUT REQUIRED ##"
yellow "#########################"
echo
stty echo
while true; do
	read -p "Do you want to use phpMyAdmin? [y/n]: " i
	case $i in
	[Yy]* ) PMA=1;break;;
	[Nn]* ) PMA=0;break;;
	* ) red "Please use [Y] or [N]";echo;;
	esac
done
if [ $PMA == '0' ]; then
	echo
else
	while true; do
		echo
		yellow "Do you want to secure the login with the http auth method?"
		red "I HIGHLY RECOMMEND IT!"
		echo
		read -p "[y/n]: " i
		case $i in
		[Yy]* ) PMAS=1;break;;
		[Nn]* ) PMAS=0;break;;
		* ) red "Please use [Y] or [N]";echo;;
		esac
	done
	if [ $PMAS == '0' ]; then
		cat > /etc/nginx/sites-custom/phpmyadmin.conf <<END
location /pma {
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
	else
		PMAUA=1
		while [ $PMAUA == '1' ]; do
			echo
			yellow "#########################"
			yellow "## USER INPUT REQUIRED ##"
			yellow "#########################"
			echo
			read -p "Enter user: " PMAU
			echo
			yellow "#########################"
			yellow "## USER INPUT REQUIRED ##"
			yellow "#########################"
			echo
			unset PMAP
			unset CHARCOUNT
			unset PROMPT
			echo -n "Enter password: "
			stty echo
			CHARCOUNT=0
			while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
			do
			    if [[ $CHAR == $'\0' ]] ; then
			        break
			    fi
			    if [[ $CHAR == $'\177' ]] ; then
			        if [ $CHARCOUNT -gt 0 ] ; then
			            CHARCOUNT=$((CHARCOUNT-1))
			            PROMPT=$'\b \b'
			            PMAP="${PMAP%?}"
			        else
			            PROMPT=''
			        fi
			    else
			        CHARCOUNT=$((CHARCOUNT+1))
			        PROMPT='*'
			        PMAP+="$CHAR"
			    fi
			done
			echo
			stty echo
			unset PMAP2
			unset CHARCOUNT
			unset PROMPT
			echo -n "Repeat password: "
			stty echo
			CHARCOUNT=0
			while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
			do
			    if [[ $CHAR == $'\0' ]] ; then
			        break
			    fi
			    if [[ $CHAR == $'\177' ]] ; then
			        if [ $CHARCOUNT -gt 0 ] ; then
			            CHARCOUNT=$((CHARCOUNT-1))
			            PROMPT=$'\b \b'
			            PMAP2="${PMAP2%?}"
			        else
			            PROMPT=''
			        fi
			    else
			        CHARCOUNT=$((CHARCOUNT+1))
			        PROMPT='*'
			        PMAP2+="$CHAR"
			    fi
			done
			stty echo
			echo
			while [[ "$PMAP" != "$PMAP2" ]]; do
			        red "*********************************************"
			        red "* Passwords do not match! Please try again! *"
			        red "*********************************************"
					unset PMAP
					unset CHARCOUNT
					unset PROMPT
					echo -n "Enter password: "
					stty echo
					CHARCOUNT=0
					while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
					do
						if [[ $CHAR == $'\0' ]] ; then
							break
						fi
						if [[ $CHAR == $'\177' ]] ; then
							if [ $CHARCOUNT -gt 0 ] ; then
								CHARCOUNT=$((CHARCOUNT-1))
								PROMPT=$'\b \b'
								PMAP="${PMAP%?}"
							else
								PROMPT=''
							fi
						else
							CHARCOUNT=$((CHARCOUNT+1))
							PROMPT='*'
							PMAP+="$CHAR"
						fi
					done
						echo
						stty echo
						unset PMAP2
						unset CHARCOUNT
						unset PROMT
						echo -n "Repeat password: "
						stty echo
						CHARCOUNT=0
						while IFS= read -p "$PROMPT" -r -s -n 1 CHAR
						do
							if [[ $CHAR == $'\0' ]] ; then
								break
							fi
							if [[ $CHAR == $'\177' ]] ; then
								if [ $CHARCOUNT -gt 0 ] ; then
									CHARCOUNT=$((CHARCOUNT-1))
									PROMPT=$'\b \b'
									PMAP2="${PMAP2%?}"
								else
									PROMPT=''
								fi
							else
								CHARCOUNT=$((CHARCOUNT+1))
								PROMPT='*'
								PMAP2+="$CHAR"
							fi
						done
					stty echo
			done
			htpasswd -b /etc/nginx/htpasswd/.htpasswd $PMAU $PMAP
			echo
			while true; do
				read -p "Add more users? [y/n]: " i
				case $i in
				[Yy]* ) break;;
				[Nn]* ) echo;yellow "You can add more users by using the following command:";echo "htpasswd -b /etc/nginx/htpasswd/.htpasswd USER PASSWORD";PMAUA=0;break;;
				* ) red "Please use [Y] or [N]";echo;echo;;
				esac
			done
		done
	fi
	cd /usr/local
	git clone https://github.com/phpmyadmin/phpmyadmin.git
	mkdir phpmyadmin/save
	mkdir phpmyadmin/upload
	chmod 0700 phpmyadmin/save
	chmod g-s phpmyadmin/save
	chmod 0700 phpmyadmin/upload
	chmod g-s phpmyadmin/upload
	randompwd=$(openssl rand -base64 32)
	randompwd2=$(openssl rand -base64 32)
	mysql -u root -p${DATABASEROOTPWD} mysql < phpmyadmin/sql/create_tables.sql
	mysql -u root -p${DATABASEROOTPWD} -e "GRANT USAGE ON mysql.* TO 'pma'@'localhost' IDENTIFIED BY '$randompwd2'; GRANT SELECT ( Host, User, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv ) ON mysql.user TO 'pma'@'localhost'; GRANT SELECT ON mysql.db TO 'pma'@'localhost'; GRANT SELECT (Host, Db, User, Table_name, Table_priv, Column_priv) ON mysql.tables_priv TO 'pma'@'localhost'; GRANT SELECT, INSERT, DELETE, UPDATE, ALTER ON phpmyadmin.* TO 'pma'@'localhost'; FLUSH PRIVILEGES;"
	cat > phpmyadmin/config.inc.php <<END
<?php
\$cfg['blowfish_secret'] = '$randompwd';
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
\$cfg['Servers'][\$i]['host'] = '127.0.0.1';
\$cfg['Servers'][\$i]['connect_type'] = 'tcp';
\$cfg['Servers'][\$i]['compress'] = false;
\$cfg['Servers'][\$i]['extension'] = 'mysqli';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['Servers'][\$i]['controluser'] = 'pma';
\$cfg['Servers'][\$i]['controlpass'] = '$randompwd2';
\$cfg['Servers'][\$i]['pmadb'] = 'phpmyadmin';
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
fi

service nginx reload

echo
echo
green "--------------------------------------------"
green " phpMyAdmin has been successfully installed "
green "--------------------------------------------"
yellow " URL: ${FQDN}/pma/"
green "--------------------------------------------"
echo
echo
echo "Now visit vma.${FQDN} and follow the instructions!"
echo "Copy the security salts into the ViMbAdmin config file:"
magenta "/usr/local/vimbadmin/application/configs/application.ini"
echo
echo "Create a domain and a mailbox. Now you can login with your"
echo "e-mail client with the following data:"
echo
echo "Host: mail.${FQDN}"
echo "Username: yourmailbox@${FQDN}"
echo "IMAP: 993 with SSL/TLS"
echo "SMTP: 587 with STARTTLS"
echo
echo
echo "When you are done, you have to configure your identity and your mail relay settings."
echo "Check lines 254 - 260 and 292 - 297 in your application.ini:"
magenta "/usr/local/vimbadmin/application/configs/application.ini"

sed -i '1s/.*/5/' ~/status	
}

part5(){
	echo
	echo
	echo
	green "Finished!"
	green "Nothing to do.. :)"
	stty echo
}



# Need to extend this..
if [[ $(sed '1q;d' ~/status) == '' ]]; then
        part0
fi

if [[ $(sed '1q;d' ~/status) == '1' ]]; then
        part1
fi

if [[ $(sed '1q;d' ~/status) == '2' ]]; then
        part2
fi

if [[ $(sed '1q;d' ~/status) == '3' ]]; then
        part3
fi

if [[ $(sed '1q;d' ~/status) == '4' ]]; then
        part4
fi

if [[ $(sed '1q;d' ~/status) == '5' ]]; then
        part5
fi