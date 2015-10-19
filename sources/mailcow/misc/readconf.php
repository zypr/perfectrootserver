<?php
error_reporting(0);
include_once "/var/www/mail/rc/config/config.inc.php";
include_once "/var/www/mail/inc/vars.inc.php";
include_once "/var/www/mail/pfadmin/config.inc.php";
include_once "/var/www/mail/pfadmin/config.local.php";

if(!empty($database_user)) {
echo $database_host, PHP_EOL;
echo $database_user, PHP_EOL;
echo $database_pass, PHP_EOL;
echo $database_name, PHP_EOL;
}
else {
echo $CONF['database_host'], PHP_EOL;
echo $CONF['database_user'], PHP_EOL;
echo $CONF['database_password'], PHP_EOL;
echo $CONF['database_name'], PHP_EOL;
}
echo $config["des_key"], PHP_EOL;
echo parse_url($config["db_dsnw"])[user], PHP_EOL;
echo parse_url($config["db_dsnw"])[pass], PHP_EOL;
echo substr(parse_url($config["db_dsnw"])[path], 1), PHP_EOL;
if(isset($DAV_SUBDOMAIN)) {
echo $DAV_SUBDOMAIN;
}
else {
echo "dav";
}
?>
