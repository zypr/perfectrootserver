# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow and https://github.com/zypr/perfectrootserver and TiggaStyle
# Compatible with Debian 8.x (jessie)

#----------------------------------------------------------------------#
#-------------------DO NOT EDIT SOMETHING BELOW THIS-------------------#
#----------------------------------------------------------------------#


addnewsite() {
source ~/addonconfig.cfg

if [ ${ADD_NEW_SITE} == '1' ]; then
echo "${info} Installing AddNewSite..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

#Make some folders
mkdir -p /etc/nginx/html/${MYOTHERDOMAIN} 
mkdir -p /etc/nginx/html/${MYOTHERDOMAIN}/logs/
mkdir -p /etc/nginx/html/${MYOTHERDOMAIN}/htdocs/
chown -R www-data:www-data /etc/nginx/html/${MYOTHERDOMAIN}/htdocs
chmod 755 /etc/nginx/html/

#Stop System
systemctl stop nginx.service

# SSL certificate
if [ ${CLOUDFLARE} == '0' ] && [ ${USE_VALID_SSL} == '1' ]; then
	echo "${info} Creating valid SSL certificates..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
	#git clone https://github.com/letsencrypt/letsencrypt ~/sources/letsencrypt -q
	cd ~/sources/letsencrypt
	#Im _Moment gibt es kein Mailserver zu dieser domain.
	#if [ ${USE_MAILSERVER} == '1' ]; then
		#./letsencrypt-auto --agree-tos --renew-by-default --non-interactive --standalone --email ${SSLMAIL} --rsa-key-size 2048 -d ${MYOTHERDOMAIN} -d www.${MYOTHERDOMAIN} -d mail.${MYOTHERDOMAIN} -d autodiscover.${MYOTHERDOMAIN} -d autoconfig.${MYOTHERDOMAIN} -d dav.${MYOTHERDOMAIN} certonly >/dev/null 2>&1
	#else
	./letsencrypt-auto --agree-tos --renew-by-default --non-interactive --standalone --email ${SSLMAIL} --rsa-key-size 2048 -d ${MYOTHERDOMAIN} -d www.${MYOTHERDOMAIN} certonly >/dev/null 2>&1
	#fi
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

#This works only in installation script, do not use for updatescript
#In Update script hte user havte to type the domain.tld in config part
#Disable default_server in first domain if this script add another one

#The new Conf dontneed that
#sed 's/80 default_server;/80;/g'  /etc/nginx/sites-available/${MYDOMAIN}.conf
#sed 's/server_name 		${IPADR} /server_name 		;/g'  /etc/nginx/sites-available/${MYDOMAIN}.conf
#sed 's/ deferred;/;/g'  /etc/nginx/sites-available/${MYDOMAIN}.conf


# Create server config
cat > /etc/nginx/sites-available/${MYOTHERDOMAIN}.conf <<END
server {
			listen 				80;
			server_name 		${MYOTHERDOMAIN};
			return 301 			https://${MYOTHERDOMAIN}$request_uri;
}

server {
			listen 				443;
			server_name 		www.${MYOTHERDOMAIN} mail.${MYOTHERDOMAIN};
			return 301 			https://${MYOTHERDOMAIN}$request_uri;
}

server {
			listen 				443 ssl http2;
			server_name 		${MYOTHERDOMAIN};

			root 				/etc/nginx/html/${MYOTHERDOMAIN}/htdocs;
			index 				index.php index.html index.htm;

			charset 			utf-8;

			error_page 404 		/index.php;

			ssl_certificate 	ssl/${MYOTHERDOMAIN}.pem;
			ssl_certificate_key ssl/${MYOTHERDOMAIN}.key.pem;
			ssl_trusted_certificate ssl/${MYOTHERDOMAIN}.pem;
			ssl_dhparam	     	ssl/dh.pem;
			ssl_ecdh_curve		secp384r1;
			ssl_session_cache   shared:SSL:10m;
			ssl_session_timeout 10m;
			ssl_session_tickets off;
			ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
			ssl_prefer_server_ciphers on;
			ssl_buffer_size 	1400;

			ssl_stapling 		on;
			ssl_stapling_verify on;
			resolver 			8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220 valid=60s;
			resolver_timeout 	2s;

			ssl_ciphers 		"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";

			add_header 		Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
			#add_header 		Public-Key-Pins 'pin-sha256="PIN1"; pin-sha256="PIN2"; max-age=5184000; includeSubDomains';
			add_header 			Cache-Control "public";
			add_header 			X-Frame-Options SAMEORIGIN;
			add_header 			Alternate-Protocol  443:npn-http/2;
			add_header 			X-Content-Type-Options nosniff;
			add_header 			X-XSS-Protection "1; mode=block";
			add_header 			X-Permitted-Cross-Domain-Policies "master-only";
			add_header 			"X-UA-Compatible" "IE=Edge";
			add_header 			"Access-Control-Allow-Origin" "*";
			add_header 			Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval' *.youtube.com maps.gstatic.com *.googleapis.com *.google-analytics.com cdnjs.cloudflare.com assets.zendesk.com connect.facebook.net; frame-src 'self' *.youtube.com assets.zendesk.com *.facebook.com s-static.ak.facebook.com tautt.zendesk.com; object-src 'self'";

			pagespeed 			off;
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

			location ~ \.php$ {
				fastcgi_split_path_info ^(.+\.php)(/.+)$;
				if (!-e $document_root$fastcgi_script_name) {
					return 404;
			  	}
				try_files $fastcgi_script_name =404;
				fastcgi_param PATH_INFO $fastcgi_path_info;
				fastcgi_param PATH_TRANSLATED $document_root$fastcgi_path_info;
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
			   	#try_files $uri $uri/ /index.php?$args;
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

			location ~* ^.+\.(css|js|jsonp)$ {
				rewrite ^(.+)\.(\d+)\.(css|js)$ $1.$3 last;
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

			location ~* \.(asf|asx|wax|wmv|wmx|avi|bmp|class|divx|doc|docx|eot|exe|gif|gz|gzip|ico|jpg|jpeg|jpe|mdb|mid|midi|mov|qt|mp3|m4a|mp4|m4v|mpeg|mpg|mpe|mpp|odb|odc|odf|odg|odp|ods|odt|ogg|ogv|otf|pdf|png|pot|pps|ppt|pptx|ra|ram|svg|svgz|swf|tar|t?gz|tif|tiff|ttf|wav|webm|wma|woff|wri|xla|xls|xlsx|xlt|xlw|zip)$ {
				expires 30d;
				access_log off;
				log_not_found off;
				add_header Pragma public;
				add_header Cache-Control "max-age=2592000, public";
			}

			if ($http_user_agent ~* "FeedDemon|JikeSpider|Indy Library|Alexa Toolbar|AskTbFXTV|AhrefsBot|CrawlDaddy|CoolpadWebkit|Java|Feedly|UniversalFeedParser|ApacheBench|Microsoft URL Control|Swiftbot|ZmEu|oBot|jaunty|Python-urllib|lightDeckReports Bot|YYSpider|DigExt|YisouSpider|HttpClient|MJ12bot|heritrix|EasouSpider|Ezooms|Scrapy") {
            	return 403;
            }
}
END

#Activate the new site
ln -s /etc/nginx/sites-available/${MYOTHERDOMAIN}.conf /etc/nginx/sites-enabled/${MYOTHERDOMAIN}.conf

#The new conf dont need that
#if [ ${CLOUDFLARE} == '0' ] && [ ${USE_VALID_SSL} == '1' ]; then
#	sed -i 's/#ssl/ssl/g' /etc/nginx/sites-available/${MYOTHERDOMAIN}.conf
#	sed -i 's/#resolver/resolver/g' /etc/nginx/sites-available/${MYOTHERDOMAIN}.conf
#	sed -i 's/#add/add/g' /etc/nginx/sites-available/${MYOTHERDOMAIN}.conf
#fi


#Create index.html
cat > /etc/nginx/html/${MYOTHERDOMAIN}/htdocs/index.html <<END
<html>
  <head>
    <title>www.${MYOTHERDOMAIN}</title>
  </head>
  <body>
    <h1>Success: You Have Set Up a Virtual Host</h1>
    <p>If you have any question, please visit the offical site <a href="https://perfectrootserver.de">perfectrootserver.de</a></p>
  </body>
</html>
END

systemctl start nginx.service
#End if [ ${ADD_NEW_SITE} == '1' ]; then
fi
}
