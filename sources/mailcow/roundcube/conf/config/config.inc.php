<?php
$config = array();
$config['db_dsnw'] = 'mysql://my_rcuser:my_rcpass@my_dbhost/my_rcdb';
$config['default_host'] = 'tls://MAILCOW_HOST.MAILCOW_DOMAIN';
$config['smtp_server'] = 'tls://MAILCOW_HOST.MAILCOW_DOMAIN';
$config['smtp_port'] = 587;
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
$config['support_url'] = '';
$config['product_name'] = $_SERVER['HTTP_HOST'];
$config['des_key'] = 'conf_rcdeskey';
$config['plugins'] = array(
	'archive',
	'zipdownload',
	'acl',
	'managesieve',
	'password',
	'attachment_reminder',
	'new_user_dialog',
);
$config['skin'] = 'larry';
$config['login_autocomplete'] = 2;
$config['imap_cache'] = 'apc';
$config['username_domain'] = '%d';
$config['default_list_mode'] = 'threads';
$config['preview_pane'] = true;
$config['imap_conn_options'] = array(
    'ssl' => array(
      'allow_self_signed' => true,
       'verify_peer'      => false,
       'verify_peer_name' => false,
    ),
);
$config['smtp_conn_options'] = array(
   'ssl'         => array(
       'allow_self_signed' => true,
        'verify_peer'      => false,
        'verify_peer_name' => false,
   ),
);
