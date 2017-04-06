#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

nginx() {

# Nginx
cd ~/sources
echo "${info} Downloading Nginx Pagespeed..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget https://github.com/pagespeed/ngx_pagespeed/archive/v${NPS_VERSION}-beta.zip >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
unzip v${NPS_VERSION}-beta.zip >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

echo "${info} Downloading Nginx Pagespeed psol..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
cd ngx_pagespeed-${NPS_VERSION}-beta/ >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

#Todo: fix choice

	#x64
	wget https://dl.google.com/dl/page-speed/psol/${NPS_VERSION}-x64.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
	tar -xzf ${NPS_VERSION}-x64.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

	#x32
	#wget https://dl.google.com/dl/page-speed/psol/${NPS_VERSION}-ia32.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
	#tar -xzf ${NPS_VERSION}-ia32.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log


cd ~/sources
echo "${info} Downloading Nginx..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
tar -xzf nginx-${NGINX_VERSION}.tar.gz
cd nginx-${NGINX_VERSION}

echo "${info} Compiling Nginx..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
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
--without-http_userid_module \
--without-http_split_clients_module \
--with-http_ssl_module \
--with-http_v2_module \
--with-http_realip_module \
--with-http_geoip_module \
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
--with-pcre \
--with-cc-opt='-O2 -g -pipe -Wall -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic' \
--with-openssl=$HOME/sources/openssl-${OPENSSL_VERSION} \
--add-module=$HOME/sources/ngx_pagespeed-${NPS_VERSION}-beta >>/root/logs/make.log 2>&1

#habe "--with-debug \" erstmal raus genommen. Gibt Probleme
#
# You have set --with-debug for building nginx, but precompiled Debug binaries for
# PSOL, which ngx_pagespeed depends on, aren't available.  If you're trying to
# debug PSOL you need to build it from source.  If you just want to run nginx with
# debug-level logging you can use the Release binaries.
#
# Use the available Release binaries? [Y/n]
#
# ToDo: Autimatic installer maybe....
# make the package
make >>/root/logs/make.log 2>&1
# Create a .deb package
checkinstall --install=no -y >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
# Install the package
echo "${info} Installing Nginx..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
dpkg -i nginx_${NGINX_VERSION}-1_amd64.deb >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
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
mkdir ../logs
mkdir ../ssl
chown -R www-data:www-data /var/lib/nginx
chown www-data:www-data /etc/nginx/logs

# Install the Nginx service script
wget -O /etc/init.d/nginx --no-check-certificate https://raw.githubusercontent.com/Fleshgrinder/nginx-sysvinit-script/master/init >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
chmod 0755 /etc/init.d/nginx
chown root:root /etc/init.d/nginx
update-rc.d nginx defaults

# Edit/create Nginx config files
echo "${info} Configuring Nginx..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

rm -rf /etc/nginx/nginx.conf
cat > /etc/nginx/nginx.conf <<END
user www-data;
worker_processes auto;
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
		keepalive_timeout   70;
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
		map \$http_referer \$bad_referer {
			default 0;
			~(?i)(adult|babes|click|diamond|forsale|girl|jewelry|love|nudit|organic|poker|porn|poweroversoftware|sex|teen|webcam|zippo|casino|replica) 1;
		}
		map \$http_cookie \$cache_uid {
		  default nil;
		  ~SESS[[:alnum:]]+=(?<session_id>[[:alnum:]]+) \$session_id;
		}

		map \$request_method \$no_cache {
		  default 1;
		  HEAD 0;
		}
		include			/etc/nginx/sites-enabled/*.conf;
}
END


# SSL certificate
service nginx stop
if [ ${CLOUDFLARE} == '0' ] && [ ${USE_VALID_SSL} == '1' ]; then
	echo "${info} Creating valid SSL certificates..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	git clone https://github.com/letsencrypt/letsencrypt ~/sources/letsencrypt -q
	cd ~/sources/letsencrypt

	./letsencrypt-auto --agree-tos --renew-by-default --non-interactive --standalone --email ${SSLMAIL} --rsa-key-size ${RSA_KEY_SIZE} -d ${MYDOMAIN} -d www.${MYDOMAIN} certonly >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

	ln -s /etc/letsencrypt/live/${MYDOMAIN}/fullchain.pem /etc/nginx/ssl/${MYDOMAIN}.pem
	ln -s /etc/letsencrypt/live/${MYDOMAIN}/privkey.pem /etc/nginx/ssl/${MYDOMAIN}.key.pem
else
	echo "${info} Creating self-signed SSL certificates..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	openssl ecparam -genkey -name secp384r1 -out /etc/nginx/ssl/${MYDOMAIN}.key.pem >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
	openssl req -new -sha256 -key /etc/nginx/ssl/${MYDOMAIN}.key.pem -out /etc/nginx/ssl/csr.pem -subj "/C=DE/ST=Private/L=Private/O=Private/OU=Private/CN=*.${MYDOMAIN}" >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
	openssl req -x509 -days 365 -key /etc/nginx/ssl/${MYDOMAIN}.key.pem -in /etc/nginx/ssl/csr.pem -out /etc/nginx/ssl/${MYDOMAIN}.pem >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
fi

HPKP1=$(openssl x509 -pubkey < /etc/nginx/ssl/${MYDOMAIN}.pem | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
HPKP2=$(openssl rand -base64 32)

echo "${info} Creating strong Diffie-Hellman parameters, please wait..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
openssl dhparam -out /etc/nginx/ssl/dh.pem ${RSA_KEY_SIZE} >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

mkdir -p /etc/nginx/html/${MYDOMAIN}

#ToDo
# Ne bessere Abfrage
rm -rf /etc/nginx/sites-available/${MYDOMAIN}.conf

if [ ${ALLOWHTTPCONNECTIONS} == '1' ]; then
# Create server config
cat > /etc/nginx/sites-available/${MYDOMAIN}.conf <<END
server {
			listen 				80 default_server;
			listen 				443 ssl http2 default deferred;
			server_name 		${MYDOMAIN} www.${MYDOMAIN} mail.${MYDOMAIN};
			root 				/etc/nginx/html/${MYDOMAIN};
			index 				index.php index.html index.htm;
			charset 			utf-8;
			error_page 404 		/index.php;
			ssl_certificate 	ssl/${MYDOMAIN}.pem;
			ssl_certificate_key ssl/${MYDOMAIN}.key.pem;
			#ssl_trusted_certificate ssl/${MYDOMAIN}.pem;
			ssl_dhparam	     	ssl/dh.pem;
			ssl_ecdh_curve		secp384r1;
			ssl_session_cache   shared:SSL:10m;
			ssl_session_timeout 10m;
			ssl_session_tickets off;
			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
			ssl_prefer_server_ciphers on;
			ssl_buffer_size 	1400;
			#ssl_stapling 		on;
			#ssl_stapling_verify on;
			#resolver 			8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220 valid=60s;
			#resolver_timeout 	2s;
			ssl_ciphers 		"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
			#add_header 		Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
			##add_header 		Public-Key-Pins 'pin-sha256="PIN1"; pin-sha256="PIN2"; max-age=5184000; includeSubDomains';
			add_header 			Cache-Control "public";
			add_header 			X-Frame-Options SAMEORIGIN;
			add_header 			Alternate-Protocol  443:npn-http/2;
			add_header 			X-Content-Type-Options nosniff;
			add_header 			X-XSS-Protection "1; mode=block";
			add_header 			X-Permitted-Cross-Domain-Policies "master-only";
			add_header 			"X-UA-Compatible" "IE=Edge";
			add_header 			"Access-Control-Allow-Origin" "*";
			add_header 			Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com cdnjs.cloudflare.com assets.zendesk.com connect.facebook.net; frame-src 'self' *.youtube.com assets.zendesk.com *.facebook.com s-static.ak.facebook.com tautt.zendesk.com; object-src 'self'";
			pagespeed 			on;
			pagespeed 			EnableFilters collapse_whitespace;
			pagespeed 			EnableFilters canonicalize_javascript_libraries;
			pagespeed 			EnableFilters combine_css;
			pagespeed 			EnableFilters combine_javascript;
			pagespeed 			EnableFilters elide_attributes;
			pagespeed 			EnableFilters extend_cache;
			pagespeed 			EnableFilters flatten_css_imports;
			pagespeed 			EnableFilters lazyload_images;
			pagespeed 			EnableFilters rewrite_javascript;
			pagespeed 			EnableFilters rewrite_images;
			pagespeed 			EnableFilters insert_dns_prefetch;
			pagespeed 			EnableFilters prioritize_critical_css;
			pagespeed 			FetchHttps enable,allow_self_signed;
			pagespeed 			FileCachePath /var/lib/nginx/nps_cache;
			pagespeed 			RewriteLevel CoreFilters;
			pagespeed 			CssFlattenMaxBytes 5120;
			pagespeed 			LogDir /var/log/pagespeed;
			pagespeed 			EnableCachePurge on;
			pagespeed 			PurgeMethod PURGE;
			pagespeed 			DownstreamCachePurgeMethod PURGE;
			pagespeed 			DownstreamCachePurgeLocationPrefix http://127.0.0.1:80/;
			pagespeed 			DownstreamCacheRewrittenPercentageThreshold 95;
			pagespeed 			LazyloadImagesAfterOnload on;
			pagespeed 			LazyloadImagesBlankUrl "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
			pagespeed 			MemcachedThreads 1;
			pagespeed 			MemcachedServers "localhost:11211";
			pagespeed 			MemcachedTimeoutUs 100000;
			pagespeed 			RespectVary on;
			pagespeed 			Disallow "*/pma/*";
			# This will correctly rewrite your subresources with https:// URLs and thus avoid mixed content warnings.
			# Note, that you should only enable this option if you are behind a load-balancer that will set this header,
			# otherwise your users will be able to set the protocol PageSpeed uses to interpret the request.
			#
			#pagespeed 			RespectXForwardedProto on;
			auth_basic_user_file htpasswd/.htpasswd;
			location ~ \.php\$ {
				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
				if (!-e \$document_root\$fastcgi_script_name) {
					return 404;
			  	}
				try_files \$fastcgi_script_name =404;
				fastcgi_param PATH_INFO \$fastcgi_path_info;
				fastcgi_param PATH_TRANSLATED \$document_root\$fastcgi_path_info;
				fastcgi_param APP_ENV production;
				fastcgi_pass unix:/var/run/php5-fpm.sock;
				fastcgi_index index.php;
				include fastcgi.conf;
				fastcgi_intercept_errors off;
				fastcgi_ignore_client_abort off;
				fastcgi_buffers 256 16k;
				fastcgi_buffer_size 128k;
				fastcgi_connect_timeout 3s;
				fastcgi_send_timeout 120s;
				fastcgi_read_timeout 120s;
				fastcgi_busy_buffers_size 256k;
				fastcgi_temp_file_write_size 256k;
			}
			include /etc/nginx/sites-custom/*.conf;
			location / {
			   	# Uncomment, if you need to remove index.php from the
				# URL. Usefull if you use Codeigniter, Zendframework, etc.
				# or just need to remove the index.php
				#
			   	#try_files \$uri \$uri/ /index.php?\$args;
			}
			location ~* /\.(?!well-known\/) {
			    deny all;
			    access_log off;
				log_not_found off;
			}
			location ~* (?:\.(?:bak|conf|dist|fla|in[ci]|log|psd|sh|sql|sw[op])|~)$ {
			    deny all;
			    access_log off;
				log_not_found off;
			}
			location = /favicon.ico {
				access_log off;
				log_not_found off;
			}

			location = /robots.txt {
				allow all;
				access_log off;
				log_not_found off;
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
			if (\$http_user_agent ~* "FeedDemon|JikeSpider|Indy Library|Alexa Toolbar|AskTbFXTV|AhrefsBot|CrawlDaddy|CoolpadWebkit|Java|Feedly|UniversalFeedParser|ApacheBench|Microsoft URL Control|Swiftbot|ZmEu|oBot|jaunty|Python-urllib|lightDeckReports Bot|YYSpider|DigExt|YisouSpider|HttpClient|MJ12bot|heritrix|EasouSpider|Ezooms|Scrapy") {
            	return 403;
            }
}
END

else

# Create server config
cat > /etc/nginx/sites-available/${MYDOMAIN}.conf <<END
server {
			listen 				80 default_server;
			server_name 		${IPADR} ${MYDOMAIN};
			return 301 			https://${MYDOMAIN}\$request_uri;
}
server {
			listen 				443;
			server_name 		${IPADR} www.${MYDOMAIN} mail.${MYDOMAIN};
			return 301 			https://${MYDOMAIN}\$request_uri;
}
server {
			listen 				443 ssl http2 default deferred;
			server_name 		${MYDOMAIN};
			root 				/etc/nginx/html;
			index 				index.php index.html index.htm;
			charset 			utf-8;
			error_page 404 		/index.php;
			ssl_certificate 	ssl/${MYDOMAIN}.pem;
			ssl_certificate_key ssl/${MYDOMAIN}.key.pem;
			#ssl_trusted_certificate ssl/${MYDOMAIN}.pem;
			ssl_dhparam	     	ssl/dh.pem;
			ssl_ecdh_curve		secp384r1;
			ssl_session_cache   shared:SSL:10m;
			ssl_session_timeout 10m;
			ssl_session_tickets off;
			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
			ssl_prefer_server_ciphers on;
			ssl_buffer_size 	1400;
			#ssl_stapling 		on;
			#ssl_stapling_verify on;
			#resolver 			8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220 valid=60s;
			#resolver_timeout 	2s;
			ssl_ciphers 		"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
			#add_header 		Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
			##add_header 		Public-Key-Pins 'pin-sha256="PIN1"; pin-sha256="PIN2"; max-age=5184000; includeSubDomains';
			add_header 			Cache-Control "public";
			add_header 			X-Frame-Options SAMEORIGIN;
			add_header 			Alternate-Protocol  443:npn-http/2;
			add_header 			X-Content-Type-Options nosniff;
			add_header 			X-XSS-Protection "1; mode=block";
			add_header 			X-Permitted-Cross-Domain-Policies "master-only";
			add_header 			"X-UA-Compatible" "IE=Edge";
			add_header 			"Access-Control-Allow-Origin" "*";
			add_header 			Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com cdnjs.cloudflare.com assets.zendesk.com connect.facebook.net; frame-src 'self' *.youtube.com assets.zendesk.com *.facebook.com s-static.ak.facebook.com tautt.zendesk.com; object-src 'self'";
			pagespeed 			on;
			pagespeed 			EnableFilters collapse_whitespace;
			pagespeed 			EnableFilters canonicalize_javascript_libraries;
			pagespeed 			EnableFilters combine_css;
			pagespeed 			EnableFilters combine_javascript;
			pagespeed 			EnableFilters elide_attributes;
			pagespeed 			EnableFilters extend_cache;
			pagespeed 			EnableFilters flatten_css_imports;
			pagespeed 			EnableFilters lazyload_images;
			pagespeed 			EnableFilters rewrite_javascript;
			pagespeed 			EnableFilters rewrite_images;
			pagespeed 			EnableFilters insert_dns_prefetch;
			pagespeed 			EnableFilters prioritize_critical_css;
			pagespeed 			FetchHttps enable,allow_self_signed;
			pagespeed 			FileCachePath /var/lib/nginx/nps_cache;
			pagespeed 			RewriteLevel CoreFilters;
			pagespeed 			CssFlattenMaxBytes 5120;
			pagespeed 			LogDir /var/log/pagespeed;
			pagespeed 			EnableCachePurge on;
			pagespeed 			PurgeMethod PURGE;
			pagespeed 			DownstreamCachePurgeMethod PURGE;
			pagespeed 			DownstreamCachePurgeLocationPrefix http://127.0.0.1:80/;
			pagespeed 			DownstreamCacheRewrittenPercentageThreshold 95;
			pagespeed 			LazyloadImagesAfterOnload on;
			pagespeed 			LazyloadImagesBlankUrl "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
			pagespeed 			MemcachedThreads 1;
			pagespeed 			MemcachedServers "localhost:11211";
			pagespeed 			MemcachedTimeoutUs 100000;
			pagespeed 			RespectVary on;
			pagespeed 			Disallow "*/pma/*";
			# This will correctly rewrite your subresources with https:// URLs and thus avoid mixed content warnings.
			# Note, that you should only enable this option if you are behind a load-balancer that will set this header,
			# otherwise your users will be able to set the protocol PageSpeed uses to interpret the request.
			#
			#pagespeed 			RespectXForwardedProto on;
			auth_basic_user_file htpasswd/.htpasswd;
			location ~ \.php\$ {
				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
				if (!-e \$document_root\$fastcgi_script_name) {
					return 404;
			  	}
				try_files \$fastcgi_script_name =404;
				fastcgi_param PATH_INFO \$fastcgi_path_info;
				fastcgi_param PATH_TRANSLATED \$document_root\$fastcgi_path_info;
				fastcgi_param APP_ENV production;
				fastcgi_pass unix:/var/run/php5-fpm.sock;
				fastcgi_index index.php;
				include fastcgi.conf;
				fastcgi_intercept_errors off;
				fastcgi_ignore_client_abort off;
				fastcgi_buffers 256 16k;
				fastcgi_buffer_size 128k;
				fastcgi_connect_timeout 3s;
				fastcgi_send_timeout 120s;
				fastcgi_read_timeout 120s;
				fastcgi_busy_buffers_size 256k;
				fastcgi_temp_file_write_size 256k;
			}
			include /etc/nginx/sites-custom/*.conf;
			location / {
			   	# Uncomment, if you need to remove index.php from the
				# URL. Usefull if you use Codeigniter, Zendframework, etc.
				# or just need to remove the index.php
				#
			   	#try_files \$uri \$uri/ /index.php?\$args;
			}
			location ~* /\.(?!well-known\/) {
			    deny all;
			    access_log off;
				log_not_found off;
			}
			location ~* (?:\.(?:bak|conf|dist|fla|in[ci]|log|psd|sh|sql|sw[op])|~)$ {
			    deny all;
			    access_log off;
				log_not_found off;
			}
			location = /favicon.ico {
				access_log off;
				log_not_found off;
			}

			location = /robots.txt {
				allow all;
				access_log off;
				log_not_found off;
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
			if (\$http_user_agent ~* "FeedDemon|JikeSpider|Indy Library|Alexa Toolbar|AskTbFXTV|AhrefsBot|CrawlDaddy|CoolpadWebkit|Java|Feedly|UniversalFeedParser|ApacheBench|Microsoft URL Control|Swiftbot|ZmEu|oBot|jaunty|Python-urllib|lightDeckReports Bot|YYSpider|DigExt|YisouSpider|HttpClient|MJ12bot|heritrix|EasouSpider|Ezooms|Scrapy") {
            	return 403;
            }
}
END

fi



if [ ${USE_PHP7} == '1' ] && [ ${USE_PHP5} == '0' ]; then

	sed -i 's/fastcgi_pass unix:\/var\/run\/php5-fpm.sock\;/fastcgi_pass unix:\/var\/run\/php\/php7.0-fpm.sock\;/g' /etc/nginx/sites-available/${MYDOMAIN}.conf

	#fastcgi_pass unix:\/var\/run\/php5-fpm.sock;

	#fastcgi_pass unix:\/var\/run\/php\/php7.0-fpm.sock;
fi

ln -s /etc/nginx/sites-available/${MYDOMAIN}.conf /etc/nginx/sites-enabled/${MYDOMAIN}.conf

if [ ${CLOUDFLARE} == '0' ] && [ ${USE_VALID_SSL} == '1' ]; then
	sed -i 's/#ssl/ssl/g' /etc/nginx/sites-available/${MYDOMAIN}.conf
	sed -i 's/#resolver/resolver/g' /etc/nginx/sites-available/${MYDOMAIN}.conf
	sed -i 's/#add/add/g' /etc/nginx/sites-available/${MYDOMAIN}.conf
fi

fuser -k 80/tcp >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
service nginx start
# Restart Nginx
systemctl -q start nginx.service

cat > /etc/nginx/html/${MYDOMAIN}/phpinfo.php <<END
<?php
phpinfo();
?>
END


cat > /etc/nginx/html/${MYDOMAIN}/index.html <<END
<html>
	<head>
		<title></title>
	</head>
	<body>
		<p style="text-align: center;">
			Herzlich willkommen!</p>
		<p style="text-align: center;">
			Der &gt;<a href="http://perfectrootserver.de" target="_blank">Perfectrootserver</a>&lt; wurde erfolgreich auf deinem Server eingerichtet!</p>
		<p style="text-align: center;">
			Du kannst dich mit den Zugangsdaten aus dem Terminal nun in dein System einloggen.</p>
		<p style="text-align: center;">
			&nbsp;</p>
	</body>
</html>

END

#Make folder writeable
chown -R www-data:www-data /etc/nginx/html/${MYDOMAIN}

}
source ~/configs/userconfig.cfg
source ~/configs/versions.cfg
