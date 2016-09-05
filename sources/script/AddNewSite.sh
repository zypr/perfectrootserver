addnewsite() {

source ~/userconfig.cfg

#New Domain
MYOTHERDOMAIN="OTHERDOMAIN.tld"
SSLMAIL="YOUREMAILADDRESS"
USE_MAILSERVER="1"
CLOUDFLARE="0"
USE_VALID_SSL="1"
 
#----------------------------------------------------------------------#
#-------------------DO NOT EDIT SOMETHING BELOW THIS-------------------#
#----------------------------------------------------------------------#

# Some nice colors
red() { echo "$(tput setaf 1)$*$(tput setaf 9)"; }
green() { echo "$(tput setaf 2)$*$(tput setaf 9)"; }
yellow() { echo "$(tput setaf 3)$*$(tput setaf 9)"; }
magenta() { echo "$(tput setaf 5)$*$(tput setaf 9)"; }
cyan() { echo "$(tput setaf 6)$*$(tput setaf 9)"; }
textb() { echo $(tput bold)${1}$(tput sgr0); }
greenb() { echo $(tput bold)$(tput setaf 2)${1}$(tput sgr0); }
redb() { echo $(tput bold)$(tput setaf 1)${1}$(tput sgr0); }
yellowb() { echo $(tput bold)$(tput setaf 3)${1}$(tput sgr0); }
pinkb() { echo $(tput bold)$(tput setaf 5)${1}$(tput sgr0); }

# Some nice variables
info="$(textb [INFO] -)"
warn="$(yellowb [WARN] -)"
error="$(redb [ERROR] -)"
fyi="$(pinkb [INFO] -)"
ok="$(greenb [OKAY] -)"

echo
echo
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo "$(date +"[%T]") |  $(textb Add new Site to Perfect RootServer-Script) "
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo
echo "$(date +"[%T]") | ${info} Welcome to the Perfect Rootserver Addon installation!"
echo "$(date +"[%T]") | ${info} Please wait while the installer is preparing for the first use..."

#Host IP check
IPADR=$(hostname -I)
# SSL certificate
if [ ${CLOUDFLARE} == '0' ] && [ ${USE_VALID_SSL} == '1' ]; then
	echo "${info} Creating valid SSL certificates..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	if [ ${USE_MAILSERVER} == '1' ]; then
		./letsencrypt-auto --agree-tos --renew-by-default --non-interactive --standalone --email ${SSLMAIL} --rsa-key-size 2048 -d ${MYOTHERDOMAIN} -d www.${MYOTHERDOMAIN} -d mail.${MYOTHERDOMAIN} -d autodiscover.${MYOTHERDOMAIN} -d autoconfig.${MYOTHERDOMAIN} -d dav.${MYOTHERDOMAIN} certonly >/dev/null 2>&1
	else
		./letsencrypt-auto --agree-tos --renew-by-default --non-interactive --standalone --email ${SSLMAIL} --rsa-key-size 2048 -d ${MYOTHERDOMAIN} -d www.${MYOTHERDOMAIN} certonly >/dev/null 2>&1
	fi
	ln -s /etc/letsencrypt/live/${MYOTHERDOMAIN}/fullchain.pem /etc/nginx/ssl/${MYOTHERDOMAIN}.pem
	ln -s /etc/letsencrypt/live/${MYOTHERDOMAIN}/privkey.pem /etc/nginx/ssl/${MYOTHERDOMAIN}.key.pem
else
	echo "${info} Creating self-signed SSL certificates..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	openssl ecparam -genkey -name secp384r1 -out /etc/nginx/ssl/${MYOTHERDOMAIN}.key.pem >/dev/null 2>&1
	openssl req -new -sha256 -key /etc/nginx/ssl/${MYOTHERDOMAIN}.key.pem -out /etc/nginx/ssl/csr.pem -subj "/C=/ST=/L=/O=/OU=/CN=*.${MYOTHERDOMAIN}" >/dev/null 2>&1
	openssl req -x509 -days 365 -key /etc/nginx/ssl/${MYOTHERDOMAIN}.key.pem -in /etc/nginx/ssl/csr.pem -out /etc/nginx/ssl/${MYOTHERDOMAIN}.pem >/dev/null 2>&1
fi

HPKP1=$(openssl x509 -pubkey < /etc/nginx/ssl/${MYOTHERDOMAIN}.pem | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
HPKP2=$(openssl rand -base64 32)

echo "${info} Creating strong Diffie-Hellman parameters, please wait..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
openssl dhparam -out /etc/nginx/ssl/dh.pem 2048 >/dev/null 2>&1

#Make some folders
mkdir -p /etc/nginx/html/${MYOTHERDOMAIN} 
mkdir -p /etc/nginx/html/${MYOTHERDOMAIN}/logs/
mkdir -p /etc/nginx/html/${MYOTHERDOMAIN}/htdocs/
chown -R www-data:www-data /etc/nginx/html/${MYOTHERDOMAIN}/
chmod 755 /etc/nginx/html/
#Generate Cert
./letsencrypt-auto --agree-tos --renew-by-default --non-interactive --standalone --email ${SSLMAIL} --rsa-key-size 2048 -d ${MYOTHERDOMAIN} -d www.${MYOTHERDOMAIN} -d mail.${MYOTHERDOMAIN} -d autodiscover.${MYOTHERDOMAIN} -d autoconfig.${MYOTHERDOMAIN} -d dav.${MYOTHERDOMAIN} certonly >/dev/null 2>&1
# Create server config
cat > /etc/nginx/sites-available/${MYOTHERDOMAIN}.conf <<END
server {
			listen 				80 default_server;
			server_name 		${IPADR} ${MYOTHERDOMAIN};
			return 301 			https://${MYOTHERDOMAIN}\$request_uri;
}

server {
			listen 				443;
			server_name 		${IPADR} www.${MYOTHERDOMAIN} mail.${MYOTHERDOMAIN};
			return 301 			https://${MYOTHERDOMAIN}\$request_uri;
}

server {
			listen 				443 ssl http2 default deferred;
			server_name 		${MYOTHERDOMAIN};

			root 				/etc/nginx/html/${MYOTHERDOMAIN};
			index 				index.php index.html index.htm;

			charset 			utf-8;

			error_page 404 		/index.php;

			ssl_certificate 	ssl/${MYOTHERDOMAIN}.pem;
			ssl_certificate_key ssl/${MYOTHERDOMAIN}.key.pem;
			#ssl_trusted_certificate ssl/${MYOTHERDOMAIN}.pem;
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
			
	access_log   /etc/nginx/html/${MYOTHERDOMAIN}/logs/.access.log;
    error_log    /etc/nginx/html/${MYOTHERDOMAIN}/logs/.error.log;
}
END
#Activate new site
ln -s /etc/nginx/sites-available/${MYOTHERDOMAIN}.conf /etc/nginx/sites-enabled/${MYOTHERDOMAIN}.conf
#symbolic link for access log
ln -s /var/log/nginx/${MYOTHERDOMAIN}.access.log /etc/nginx/html/${MYOTHERDOMAIN}/logs/access.log
#symbolic link for error log
ln -s /var/log/nginx/${MYOTHERDOMAIN}.error.log /etc/nginx/html/${MYOTHERDOMAIN}/logs/rror.log
#reload nginx
service nginx reload
#Create index.html
cat > /etc/nginx/html/${MYOTHERDOMAIN} <<END
<html>
  <head>
    <title>www.${MYOTHERDOMAIN}</title>
  </head>
  <body>
    <h1>Success: You Have Set Up a Virtual Host</h1>
  </body>
</html>
END


if [ ${CLOUDFLARE} == '0' ] && [ ${USE_VALID_SSL} == '1' ]; then
	sed -i 's/#ssl/ssl/g' /etc/nginx/sites-available/${MYOTHERDOMAIN}.conf
	sed -i 's/#resolver/resolver/g' /etc/nginx/sites-available/${MYOTHERDOMAIN}.conf
	sed -i 's/#add/add/g' /etc/nginx/sites-available/${MYOTHERDOMAIN}.conf
fi


if [ ${USE_MAILSERVER} == '1' ]; then
	echo "${info} Installing mailserver..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

	# Create SSL
	if [ ${USE_VALID_SSL} == '1' ]; then
		ln -s /etc/letsencrypt/live/${MYOTHERDOMAIN}/fullchain.pem /etc/ssl/mail/mail.crt
		ln -s /etc/letsencrypt/live/${MYOTHERDOMAIN}/privkey.pem /etc/ssl/mail/mail.key
	else
		openssl req -new -newkey rsa:4096 -sha256 -days 1095 -nodes -x509 -subj "/C=/ST=/L=/O=/OU=/CN=mail.${MYOTHERDOMAIN}" -keyout /etc/ssl/mail/mail.key -out /etc/ssl/mail/mail.crt >/dev/null 2>&1
		update-ca-certificates >/dev/null 2>&1
	fi

	# Postfix
	echo "${info} Installing Postfix..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYOTHERDOMAIN}/g" /etc/postfix/main.cf
	sed -i "s/MAILCOW_DOMAIN/${MYOTHERDOMAIN}/g" /etc/postfix/main.cf



	DOVEFILES=$(find /etc/dovecot -maxdepth 1 -type f -printf '/etc/dovecot/%f ')
	sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYOTHERDOMAIN}/g" ${DOVEFILES}
	sed -i "s/MAILCOW_DOMAIN/${MYOTHERDOMAIN}/g" ${DOVEFILES}


	# zpush
	echo "${info} Installing Z-Push..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYOTHERDOMAIN}/g" /var/www/zpush/backend/imap/config.php
	sed -i "s/MAILCOW_DAV_HOST.MAILCOW_DOMAIN/dav.${MYOTHERDOMAIN}/g" /var/www/zpush/backend/caldav/config.php
	sed -i "s/MAILCOW_DAV_HOST.MAILCOW_DOMAIN/dav.${MYOTHERDOMAIN}/g" /var/www/zpush/backend/carddav/config.php
	cat > /var/www/zpush/mail/config-v1.1.xml <<END
<?xml version="1.0" encoding="UTF-8"?>

<clientConfig version="1.1">
  <emailProvider id="${MYOTHERDOMAIN}">
    <domain>${MYOTHERDOMAIN}</domain>
    <displayName>${MYOTHERDOMAIN} Mail</displayName>
    <displayShortName>${MYOTHERDOMAIN}</displayShortName>
    <incomingServer type="imap">
      <hostname>mail.${MYOTHERDOMAIN}</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>mail.${MYOTHERDOMAIN}</hostname>
      <port>143</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>mail.${MYOTHERDOMAIN}</hostname>
      <port>995</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>mail.${MYOTHERDOMAIN}</hostname>
      <port>110</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>mail.${MYOTHERDOMAIN}</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
    <documentation url="https://${MYOTHERDOMAIN}/admin">
      <descr lang="de">Allgemeine Beschreibung der Einstellungen</descr>
      <descr lang="en">Generic settings page</descr>
    </documentation>
    <documentation url="https://${MYOTHERDOMAIN}/admin">
      <descr lang="de">TB 2.0 IMAP-Einstellungen</descr>
      <descr lang="en">TB 2.0 IMAP settings</descr>
    </documentation>
  </emailProvider>
</clientConfig>
END
	chown -R www-data: /var/www/zpush/mail/
fi	
	
	
if [[ -z $(dpkg --get-selections | grep -E "^dbus.*install$") ]]; then
	apt-get update -y >/dev/null 2>&1 && apt-get -y --force-yes install dbus >/dev/null 2>&1
fi

if [ ${USE_MAILSERVER} == '1' ]; then
	echo -e "${IPADR} mail.${MYOTHERDOMAIN} mail" >> /etc/hosts
	hostnamectl set-hostname mail
else
	echo -e "${IPADR} ${MYOTHERDOMAIN} $(echo ${MYOTHERDOMAIN} | cut -f 1 -d '.')" >> /etc/hosts
	hostnamectl set-hostname $(echo ${MYOTHERDOMAIN} | cut -f 1 -d '.')
fi

if [ ${USE_MAILSERVER} == '1' ]; then
	echo "mail.${MYOTHERDOMAIN}" > /etc/mailname
else
	echo "${MYOTHERDOMAIN}" > /etc/mailname
fi





	# Create Nginx Config

	cat > /etc/nginx/sites-available/autodiscover.${MYOTHERDOMAIN}.conf <<END
server {
			listen 80;
			server_name autodiscover.${MYOTHERDOMAIN} autoconfig.${MYOTHERDOMAIN};
			return 301 https://autodiscover.${MYOTHERDOMAIN}\$request_uri;
}

server {
			listen 443 ssl http2;
			server_name autodiscover.${MYOTHERDOMAIN} autoconfig.${MYOTHERDOMAIN};

			root /var/www/zpush;
			index index.php;
			charset utf-8;

			error_page 404 /index.php;

			ssl_certificate 	ssl/${MYOTHERDOMAIN}.pem;
			ssl_certificate_key ssl/${MYOTHERDOMAIN}.key.pem;
			#ssl_trusted_certificate ssl/${MYOTHERDOMAIN}.pem;
			ssl_dhparam	     	ssl/dh.pem;
			#ssl_ecdh_curve		secp384r1;
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

			auth_basic_user_file htpasswd/.htpasswd;

			location ~ ^(.+\.php)(.*)\$ {
				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
				try_files \$fastcgi_script_name =404;
				set \$path_info \$fastcgi_path_info;
				fastcgi_param PATH_INFO \$path_info;
				fastcgi_param APP_ENV production;
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

			rewrite (?i)^/autodiscover/autodiscover\.xml\$ /autodiscover/autodiscover.php;

			location / {
				try_files \$uri \$uri/ /index.php;
			}

			location /Microsoft-Server-ActiveSync {
            	rewrite ^(.*)\$  /index.php last;
        	}

			location ~ /(\.ht|Core|Specific) {
                deny all;
                return 404;
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

	cat > /etc/nginx/sites-available/dav.${MYOTHERDOMAIN}.conf <<END
server {
			listen 80;
			server_name dav.${MYOTHERDOMAIN};
			return 301 https://dav.${MYOTHERDOMAIN}\$request_uri;
}

server {
			listen 443 ssl http2;
			server_name dav.${MYOTHERDOMAIN};

			root /var/www/dav;
			index server.php;
			charset utf-8;

			error_page 404 /index.php;

			ssl_certificate 	ssl/${MYOTHERDOMAIN}.pem;
			ssl_certificate_key ssl/${MYOTHERDOMAIN}.key.pem;
			#ssl_trusted_certificate ssl/${MYOTHERDOMAIN}.pem;
			ssl_dhparam	     	ssl/dh.pem;
			#ssl_ecdh_curve		secp384r1;
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
			
			auth_basic_user_file htpasswd/.htpasswd;

			location ~ ^(.+\.php)(.*)\$ {
				fastcgi_split_path_info ^(.+\.php)(/.+)\$;
				try_files \$fastcgi_script_name =404;
				set \$path_info \$fastcgi_path_info;
				fastcgi_param PATH_INFO \$path_info;
				fastcgi_param APP_ENV production;
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

			rewrite ^/.well-known/caldav /server.php redirect;
			rewrite ^/.well-known/carddav /server.php redirect;

			location / {
				try_files \$uri \$uri/ /server.php?\$args;
			}

			location ~ /(\.ht|Core|Specific) {
                deny all;
                return 404;
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

	if [ ${CLOUDFLARE} == '0' ] && [ ${USE_VALID_SSL} == '1' ]; then
		sed -i 's/#ssl/ssl/g' /etc/nginx/sites-available/autodiscover.${MYOTHERDOMAIN}.conf /etc/nginx/sites-available/dav.${MYOTHERDOMAIN}.conf
		sed -i 's/#resolver/resolver/g' /etc/nginx/sites-available/autodiscover.${MYOTHERDOMAIN}.conf /etc/nginx/sites-available/dav.${MYOTHERDOMAIN}.conf
		sed -i 's/#add/add/g' /etc/nginx/sites-available/autodiscover.${MYOTHERDOMAIN}.conf /etc/nginx/sites-available/dav.${MYOTHERDOMAIN}.conf
	fi

	ln -s /etc/nginx/sites-available/autodiscover.${MYOTHERDOMAIN}.conf /etc/nginx/sites-enabled/autodiscover.${MYOTHERDOMAIN}.conf
	ln -s /etc/nginx/sites-available/dav.${MYOTHERDOMAIN}.conf /etc/nginx/sites-enabled/dav.${MYOTHERDOMAIN}.conf

	# RoundCube
	echo "${info} Installing RoundCube..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	if [ ${USE_WEBMAIL} == '1' ]; then
		sed -i "s/MAILCOW_HOST.MAILCOW_DOMAIN/mail.${MYOTHERDOMAIN}/g" /var/www/mail/rc/config/config.inc.php
	fi
}	
