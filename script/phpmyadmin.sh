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

phpmyadmin() {
# phpMyAdmin
if [ ${USE_PMA} == '1' ]; then

echo "${info} Installing phpMyAdmin..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
htpasswd -b /etc/nginx/htpasswd/.htpasswd ${PMA_HTTPAUTH_USER} ${PMA_HTTPAUTH_PASS} >>"$main_log" 2>>"$err_log"
cd /usr/local
git clone -b STABLE https://github.com/phpmyadmin/phpmyadmin.git -q
mkdir phpmyadmin/save
mkdir phpmyadmin/upload
chmod 0700 phpmyadmin/save
chmod g-s phpmyadmin/save
chmod 0700 phpmyadmin/upload
chmod g-s phpmyadmin/upload
mysql -u root -p${MYSQL_ROOT_PASS} mysql < phpmyadmin/sql/create_tables.sql >>"$main_log" 2>>"$err_log"
mysql -u root -p${MYSQL_ROOT_PASS} -e "GRANT USAGE ON mysql.* TO '${MYSQL_PMADB_USER}'@'${MYSQL_HOSTNAME}' IDENTIFIED BY '${MYSQL_PMADB_PASS}'; GRANT SELECT ( Host, User, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv ) ON mysql.user TO '${MYSQL_PMADB_USER}'@'${MYSQL_HOSTNAME}'; GRANT SELECT ON mysql.db TO '${MYSQL_PMADB_USER}'@'${MYSQL_HOSTNAME}'; GRANT SELECT (Host, Db, User, Table_name, Table_priv, Column_priv) ON mysql.tables_priv TO '${MYSQL_PMADB_USER}'@'${MYSQL_HOSTNAME}'; GRANT SELECT, INSERT, DELETE, UPDATE, ALTER ON ${MYSQL_PMADB_NAME}.* TO '${MYSQL_PMADB_USER}'@'${MYSQL_HOSTNAME}'; FLUSH PRIVILEGES;" >>"$main_log" 2>>"$err_log"

	cat > phpmyadmin/config.inc.php <<END
<?php
\$cfg['blowfish_secret'] = '$PMA_BFSECURE_PASS';
\$i = 0;
\$i++;
\$cfg['UploadDir'] = 'upload';
\$cfg['SaveDir'] = 'save';
\$cfg['ForceSSL'] = true;
\$cfg['ExecTimeLimit'] = 300;
\$cfg['VersionCheck'] = false;
\$cfg['NavigationTreeEnableGrouping'] = false;
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
\$cfg['Servers'][\$i]['auth_http_realm'] = 'phpMyAdmin Login';
\$cfg['Servers'][\$i]['host'] = '${MYSQL_HOSTNAME}';
\$cfg['Servers'][\$i]['connect_type'] = 'tcp';
\$cfg['Servers'][\$i]['compress'] = false;
\$cfg['Servers'][\$i]['extension'] = 'mysqli';
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['Servers'][\$i]['controluser'] = '$MYSQL_PMADB_USER';
\$cfg['Servers'][\$i]['controlpass'] = '$MYSQL_PMADB_PASS';
\$cfg['Servers'][\$i]['pmadb'] = '$MYSQL_PMADB_NAME';
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
\$cfg['Servers'][\$i]['designer_settings'] = 'pma__designer_settings';
\$cfg['Servers'][\$i]['export_templates'] = 'pma__export_templates';
\$cfg['Servers'][\$i]['hide_db'] = 'information_schema';
?>
END

if [ ${PMA_RESTRICT} == '1' ]; then
	sed -i "64s/.*/\$cfg['Servers'][\$i]['AllowDeny']['order'] = 'deny,allow';\n&/" /usr/local/phpmyadmin/config.inc.php
	sed -i "65s/.*/\$cfg['Servers'][\$i]['AllowDeny']['rules'] = array(\n&/" /usr/local/phpmyadmin/config.inc.php
	sed -i "66s/.*/		'deny % from all',\n&/" /usr/local/phpmyadmin/config.inc.php
	sed -i "67s/.*/		'allow % from localhost',\n&/" /usr/local/phpmyadmin/config.inc.php
	sed -i "68s/.*/		'allow % from 127.0.0.1',\n&/" /usr/local/phpmyadmin/config.inc.php
	sed -i "69s/.*/		'allow % from ::1',\n&/" /usr/local/phpmyadmin/config.inc.php
	sed -i "70s/.*/		'allow root from localhost',\n&/" /usr/local/phpmyadmin/config.inc.php
	sed -i "71s/.*/		'allow root from 127.0.0.1',\n&/" /usr/local/phpmyadmin/config.inc.php
	sed -i "72s/.*/		'allow root from ::1',\n&/" /usr/local/phpmyadmin/config.inc.php
	sed -i "73s/.*/);\n&/" /usr/local/phpmyadmin/config.inc.php
	sed -i "74s/.*/?>/" /usr/local/phpmyadmin/config.inc.php

cat > /etc/nginx/sites-custom/phpmyadmin.conf <<END
location /pma {
	allow 127.0.0.1;
	deny all;
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

	else
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
	
if [ ${USE_PHP7} == '1' ] && [ ${USE_PHP5} == '0' ]; then
	sed -i 's/fastcgi_pass unix:\/var\/run\/php5-fpm.sock\;/fastcgi_pass unix:\/var\/run\/php\/php7.0-fpm.sock\;/g' /etc/nginx/sites-custom/phpmyadmin.conf
fi

chown -R www-data:www-data phpmyadmin/
systemctl -q reload nginx.service
fi
}
source ~/configs/userconfig.cfg