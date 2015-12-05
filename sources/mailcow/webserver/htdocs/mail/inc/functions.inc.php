<?php
function check_login($link, $user, $pass) {
	if (!ctype_alnum(str_replace(array('@', '.', '-'), '', $user))) {
		return false;
	}
	if (!strpos(shell_exec("file --mime-encoding /usr/bin/doveadm"), "binary")) {
		return false;
	}
	$user = strtolower(trim($user));
	$pass = escapeshellcmd($pass);
	$result = mysqli_query($link, "SELECT password FROM admin WHERE superadmin='1' AND username='$user'");
	while ($row = mysqli_fetch_array($result, MYSQL_NUM)) {
		$row = "'".$row[0]."'";
		exec("echo ".$pass." | doveadm pw -s SHA512-CRYPT -t ".$row, $out, $return);
		if (strpos($out[0], "verified") !== false && $return == "0") {
			unset($_SESSION['ldelay']);
			return "admin";
		}
	}
	$result = mysqli_query($link, "SELECT password FROM admin WHERE superadmin='0' AND active='1' AND username='$user'");
	while ($row = mysqli_fetch_array($result, MYSQL_NUM)) {
		$row = "'".$row[0]."'";
		exec("echo ".$pass." | doveadm pw -s SHA512-CRYPT -t ".$row, $out, $return);
		if (strpos($out[0], "verified") !== false && $return == "0") {
			unset($_SESSION['ldelay']);
			return "domainadmin";
		}
	}
	$result = mysqli_query($link, "SELECT password FROM mailbox WHERE active='1' AND username='$user'");
	while ($row = mysqli_fetch_array($result, MYSQL_NUM)) {
		$row = "'".$row[0]."'";
		exec("echo ".$pass." | doveadm pw -s SHA512-CRYPT -t ".$row, $out, $return);
		if (strpos($out[0], "verified") !== false && $return == "0") {
			unset($_SESSION['ldelay']);
			return "user";
		}
	}
	if (!isset($_SESSION['ldelay'])) {
		$_SESSION['ldelay'] = "0.1";
	}
	else {
		$_SESSION['ldelay'] = $_SESSION['ldelay']+0.08;
	}
	sleep($_SESSION['ldelay']);
}
function formatBytes($size, $precision = 2) {
	$base = log($size, 1024);
	$suffixes = array(' Byte', 'k', 'M', 'G', 'T');
	if ($size == "0") {
		return "0";
	}
	return round(pow(1024, $base - floor($base)), $precision) . $suffixes[floor($base)];
}
function mysqli_result($res,$row=0,$col=0) {
    $numrows = mysqli_num_rows($res);
    if ($numrows && $row <= ($numrows-1) && $row >=0){
        mysqli_data_seek($res,$row);
        $resrow = (is_numeric($col)) ? mysqli_fetch_row($res) : mysqli_fetch_assoc($res);
        if (isset($resrow[$col])){
            return $resrow[$col];
        }
    }
    return false;
}
function return_mailcow_config($s) {
	switch ($s) {
		case "backup_location":
			preg_match("/LOCATION=(.*)/", file_get_contents($GLOBALS['MC_MBOX_BACKUP']) , $result);
			if (!empty($result[1])) { return $result[1]; } else { return "/backup/mail"; }
			break;
		case "backup_runtime":
			preg_match("/RUNTIME=(.*)/", file_get_contents($GLOBALS['MC_MBOX_BACKUP']) , $result);
			if (!empty($result[1])) { return $result[1]; } else { return false; }
			break;
		case "backup_active":
			preg_match("/BACKUP=(.*)/", file_get_contents($GLOBALS['MC_MBOX_BACKUP']) , $result);
			if (!empty($result[1])) { return $result[1]; } else { return false; }
			break;
		case "anonymize":
			$state = file_get_contents($GLOBALS["mailcow_anonymize_headers"]);
			if (!empty($state)) { return "checked"; } else { return false; }
			break;
		case "public_folder_status":
			$state = file_get_contents($GLOBALS["mailcow_public_folder"]);
			if (!empty($state)) { return "checked"; } else { return false; }
			break;
		case "public_folder_name":
			$state = file_get_contents($GLOBALS["mailcow_public_folder"]);
			if (!empty($state)) { return explode(";;", $state)[1]; } else { return false; }
			break;
		case "public_folder_pvt":
			$state = file_get_contents($GLOBALS["mailcow_public_folder"]);
			if (!empty($state)) {
				$PVT = explode(";;", $state)[3];
				if ($PVT == "on") { return "checked"; } else { return false; }
			}
			break;
		case "srr":
			return shell_exec("sudo /usr/local/sbin/mc_pfset get-srr");
			break;
		case "maxmsgsize":
			return shell_exec("echo $(( $(/usr/sbin/postconf -h message_size_limit) / 1048576 ))");
			break;
	}
}
function set_mailcow_config($s, $v = '') {
	switch ($s) {
		case "backup":
			$file="/var/www/MAILBOX_BACKUP";
			if (isset($v['use_backup']) && ($v['use_backup'] != "on" && $v['use_backup'] != "") ||
				($v['runtime'] != "hourly" && $v['runtime'] != "daily" && $v['runtime'] != "weekly" && $v['runtime'] != "monthly")) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Invalid runtime: '.htmlspecialchars($v['runtime'])
				);
				break;
			}
			if (!ctype_alnum(str_replace(array('/', '-', '_'), "", $v['location']))) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Invalid backup location: '.htmlspecialchars($v['location'])
				);
				break;
			}
			if (!isset($v['use_backup']) || empty($v['use_backup'])) {
				$v['use_backup']="off";
			}
			file_put_contents($file, "BACKUP=".$v['use_backup'].PHP_EOL, LOCK_EX);
			file_put_contents($file, "MBOX=(".PHP_EOL, FILE_APPEND | LOCK_EX);
			if (!empty($v['mailboxes'])) {
				foreach ($v['mailboxes'] as $mbox) {
					if (!filter_var($mbox, FILTER_VALIDATE_EMAIL)) {
						$_SESSION['return'] = array(
							'type' => 'danger',
							'msg' => 'Invalid form data'
						);
						break;
					}
					file_put_contents($file, $mbox.PHP_EOL, FILE_APPEND | LOCK_EX);
				}
			}
			file_put_contents($file, ")".PHP_EOL.'RUNTIME='.$v['runtime'].PHP_EOL, FILE_APPEND | LOCK_EX);
			file_put_contents($file, "LOCATION=".$v['location'].PHP_EOL, FILE_APPEND | LOCK_EX);
			exec("sudo /usr/local/sbin/mc_setup_backup", $out, $return);
			if ($return != "0") {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Cannot setup backup'
				);
				break;
			}
			break;
		case "maxmsgsize":
			if (!ctype_alnum($v)) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Invalid max. message size'
				);
				break;
			}
			exec("sudo /usr/local/sbin/mc_msg_size $v", $out, $return);
			if ($return != "0") {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Cannot locate mailcow site configuration'
				);
				break;
			}
			break;
		case "anonymize":
			$template = '/^\s*(Received: from)[^\n]*(.*)/ REPLACE $1 [127.0.0.1] (localhost [127.0.0.1])$2
/^\s*User-Agent/        IGNORE
/^\s*X-Enigmail/        IGNORE
/^\s*X-Mailer/          IGNORE
/^\s*X-Originating-IP/  IGNORE
		';
			if ($v == "on") {
				file_put_contents($GLOBALS["mailcow_anonymize_headers"], $template);
			} else {
				file_put_contents($GLOBALS["mailcow_anonymize_headers"], "");
			}
			break;
		case "public_folder":
			if (!ctype_alnum(str_replace("/", "", $v['public_folder_name'])))
			{
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Public folder name must not be empty'
				);
				break;
			}
			if (isset($v['public_folder_pvt']) && $v['public_folder_pvt'] == "on") {
				$PVT = ':INDEXPVT=~/public';
			}
			else {
				$PVT = '';
			}
			$template = '# ;;'.$v['public_folder_name'].';;
# ;;'.$v['public_folder_pvt'].';;
namespace {
  type = public
  separator = /
  prefix = Public/
  location = maildir:/var/vmail/public'.$PVT.'
  subscriptions = no
  mailbox '.$v['public_folder_name'].' {
    auto = subscribe
  }
}';
			if (isset($v['use_public_folder']) && $v['use_public_folder'] == "on")	{
				file_put_contents($GLOBALS["mailcow_public_folder"], $template);
			}
			else {
				file_put_contents($GLOBALS["mailcow_public_folder"], "");
			}
			break;
		case "srr":
			$srr_parameters = "";
			$valid_srr = array(
				"reject_invalid_helo_hostname",
				"reject_unknown_helo_hostname",
				"reject_unknown_reverse_client_hostname",
				"reject_unknown_client_hostname",
				"reject_non_fqdn_helo_hostname",
				"z1_greylisting"
				);
			$srr = (array_keys($v));
			foreach ($srr as $restriction) {
				if (in_array($restriction, $valid_srr)) {
					$srr_parameters .= $restriction." ";
				}
			}
			exec("sudo /usr/local/sbin/mc_pfset set-srr \"$srr_parameters\"", $out, $return);
			if ($return != "0") {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Cannot set restrictions'
				);
				break;
			}
			break;
	}
	if (!isset($_SESSION['return'])) {
		$_SESSION['return'] = array(
			'type' => 'success',
			'msg' => 'Changes saved successfully '
		);
	}
}
function opendkim_table($action = "show", $which = "") {
	switch ($action) {
		case "show":
			$dnstxt_folder = scandir($GLOBALS["mailcow_opendkim_dnstxt_folder"]);
			$dnstxt_files = array_diff($dnstxt_folder, array('.', '..'));
			foreach($dnstxt_files as $file) {
			echo "<div class=\"row\">
				<div class=\"col-xs-2\">
					<p class=\"text-justify\">
					Domain:<br /><strong>", explode("_", $file)[1], "</strong><br />
					Selector:<br /><strong>", explode("_", $file)[0], "</strong><br />
					</p>
				</div>
				<div class=\"col-xs-9\">
					<pre>", file_get_contents($GLOBALS["mailcow_opendkim_dnstxt_folder"]."/".$file), "</pre>
				</div>
				<div class=\"col-xs-1\">
					<a href=\"?del=", $file, "\" onclick=\"return confirm('Are you sure?')\"><span class=\"glyphicon glyphicon-remove-circle\"></span></a>
				</div>
			</div>";
			}
			break;
		case "delete":
			if(!ctype_alnum(str_replace(array("_", "-", "."), "", $which))) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Invalid DKIM record'
				);
				break;
			}
			$selector = explode("_", $which)[0];
			$domain = explode("_", $which)[1];
			exec("sudo /usr/local/sbin/mc_dkim_ctrl del $selector $domain", $hash, $return);
			if ($return != "0") {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Cannot delete DKIM record'
				);
				break;
			}
			$_SESSION['return'] = array(
				'type' => 'success',
				'msg' => 'Deleted DKIM record for domain '.htmlspecialchars($domain)
			);
			break;
		case "add":
			$selector = explode("_", $which)[0];
			$domain = explode("_", $which)[1];
			if(!ctype_alnum($selector) || !ctype_alnum(str_replace(array("-", "."), "", $domain))) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Invalid domain name or selector'
				);
				break;
			}
			exec("sudo /usr/local/sbin/mc_dkim_ctrl add $selector $domain", $hash, $return);
			if ($return != "0") {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Cannot add domain, does it already exist?'
				);
				break;
			}
			$_SESSION['return'] = array(
				'type' => 'success',
				'msg' => 'Added DKIM record for domain '.$domain.' with selector '.$selector.''
			);
			break;
	}
}
function echo_sys_info($what, $extra="") {
	switch ($what) {
		case "ram":
			echo round(shell_exec('free | grep Mem | awk \'{print $3/$2 * 100.0}\''));
			break;
		case "maildisk":
			// echo preg_replace('/\D/', '', shell_exec('df -h /var/vmail/ | tail -n1 | awk {\'print $5\'}'));
			$df = disk_free_space("/var/vmail");
			$dt = disk_total_space("/var/vmail");
			$du = $dt - $df;
			echo sprintf('%.2f',($du / $dt) * 100);
			break;
		case "pflog":
			$pflog_content = file_get_contents($GLOBALS['PFLOG']);
			if (!file_exists($GLOBALS['PFLOG'])) {
				echo "none";
			}
			else {
				echo file_get_contents($GLOBALS['PFLOG']);
			}
			break;
		case "mailgraph":
			$imageurls = array("0-n", "1-n", "2-n", "3-n");
			foreach ($imageurls as $image) {
				$image = 'http://localhost:81/mailgraph.cgi?'.$image;
				$imageData = base64_encode(file_get_contents($image));
				echo '<img class="img-responsive" alt="'.$image.'" src="data:image/png;base64,'.$imageData.'" />';
			}
			break;
		case "mailq":
			echo shell_exec("mailq");
			break;
	}
}
function postfix_reload() {
	shell_exec("sudo /usr/sbin/postfix reload");
}
function pflog_renew() {
	shell_exec("sudo /usr/local/sbin/mc_pflog_renew");
}
function dovecot_reload() {
	shell_exec("sudo /usr/sbin/dovecot reload");
}
function mailbox_add_domain($link, $postarray) {
	if ($_SESSION['mailcow_cc_role'] != "admin") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	$domain = idn_to_ascii(mysqli_real_escape_string($link, strtolower(trim($postarray['domain']))));
	$description = mysqli_real_escape_string($link, $postarray['description']);
	$aliases = mysqli_real_escape_string($link, $postarray['aliases']);
	$mailboxes = mysqli_real_escape_string($link, $postarray['mailboxes']);
	$maxquota = mysqli_real_escape_string($link, $postarray['maxquota']);
	$quota = mysqli_real_escape_string($link, $postarray['quota']);
	if ($maxquota > $quota) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Max. size per mailbox can not be greater than domain quota'
		);
		return false;
	}
	isset($postarray['active']) ? $active = '1' : $active = '0';
	isset($postarray['relay_all_recipients']) ? $relay_all_recipients = '1' : $relay_all_recipients = '0';
	isset($postarray['backupmx']) ? $backupmx = '1' : $backupmx = '0';
	if (!is_valid_domain_name($domain)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Domain name is invalid'
		);
		return false;
	}
	foreach (array($quota, $maxquota, $mailboxes, $aliases) as $data) {
		if (!is_numeric($data)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Value '.htmlspecialchars($data).' must be numeric'
			);
			return false;
		}
	}
	$mystring = "INSERT INTO domain (domain, description, aliases, mailboxes, maxquota, quota, transport, backupmx, created, modified, active, relay_all_recipients)
		VALUES ('".$domain."', '$description', '$aliases', '$mailboxes', '$maxquota', '$quota', 'virtual', '".$backupmx."', now(), now(), '".$active."', '".$relay_all_recipients."')";
	if (!mysqli_query($link, $mystring)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Added domain '.htmlspecialchars($domain)
	);
}
function mailbox_add_alias($link, $postarray) {
	$addresses = array_map('trim', explode(',', $postarray['address']));
	$gotos = array_map('trim', explode(',', $postarray['goto']));
	isset($postarray['active']) ? $active = '1' : $active = '0';
	global $logged_in_role;
	global $logged_in_as;
	if (empty($addresses)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Alias address must not be empty'
		);
		return false;
	}
	if (empty($gotos)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Destination address must not be empty'
		);
		return false;
	}
	foreach ($addresses as $address) {
		// Should be faster than exploding
		$domain = idn_to_ascii(substr(strstr($address, '@'), 1));
		$local_part = strstr($address, '@', true);
		$address = $local_part.'@'.$domain;
		if ((!filter_var($address, FILTER_VALIDATE_EMAIL) === true) && !empty($local_part)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Alias address format invalid'
			);
			return false;
		}
		if (!mysqli_result(mysqli_query($link, "SELECT domain FROM domain WHERE domain='".$domain."'"))) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Domain '.htmlspecialchars($domain).' not found'
			);
			return false;
		}
		if (!mysqli_result(mysqli_query($link, "SELECT domain FROM domain WHERE domain='".$domain."' AND (domain NOT IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'!='".$logged_in_role."')"))) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Permission denied'
			);
			return false;
		}
		$qstring = "SELECT address FROM alias WHERE address='".$address."'";
		$qresult = mysqli_query($link, $qstring);
		$num_results = mysqli_num_rows($qresult);
		if ($num_results != 0) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Alias '.htmlspecialchars($address).' already exists'
			);
			return false;
		}
		// Passing reference to alter array
		// This shouldn't impact perfomance too much since we usually don't paste many addresses
		foreach ($gotos as &$goto) {
			$goto_domain = idn_to_ascii(substr(strstr($goto, '@'), 1));
			$goto_local_part = strstr($goto, '@', true);
			$goto = $goto_local_part.'@'.$goto_domain;
			if (!filter_var($goto, FILTER_VALIDATE_EMAIL) === true) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Destination address '.htmlspecialchars($goto).' is invalid'
				);
				return false;
			}
			if ($goto == $address) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Alias address and goto address must not be identical'
				);
				return false;
			}
		}
		$goto = implode(",", $gotos);
		if (!filter_var($address, FILTER_VALIDATE_EMAIL) === true) {
			$mystring = "INSERT INTO alias (address, goto, domain, created, modified, active) VALUE ('@".$domain."', '".$goto."', '".$domain."', now(), now(), '".$active."')";
		}
		else {
			$mystring = "INSERT INTO alias (address, goto, domain, created, modified, active) VALUE ('".$address."', '".$goto."', '".$domain."', now(), now(), '".$active."')";
		}
		if (!mysqli_query($link, $mystring)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Successfully added alias address(es)'
	);
}
function mailbox_add_alias_domain($link, $postarray) {
	$alias_domain = mysqli_real_escape_string($link, strtolower(trim($postarray['alias_domain'])));
	$target_domain = mysqli_real_escape_string($link, strtolower(trim($postarray['target_domain'])));
	global $logged_in_role;
	global $logged_in_as;
	if (!mysqli_result(mysqli_query($link, "SELECT domain FROM domain WHERE domain='$target_domain' AND (domain NOT IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'!='".$logged_in_role."')"))) { 
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	isset($postarray['active']) ? $active = '1' : $active = '0';
	if (!is_valid_domain_name($alias_domain) || empty ($alias_domain)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Alias domain name is invalid'
		);
		return false;
	}
	if (!is_valid_domain_name($target_domain) || empty ($target_domain)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Target domain name is invalid'
		);
		return false;
	}
	if ($alias_domain == $target_domain) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Alias domain must not be target domain'
		);
		return false;
	}
	if (!mysqli_result(mysqli_query($link, "SELECT domain FROM domain where domain='$target_domain'"))) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Target domain not found'
		);
		return false;
	}
	if (!mysqli_result(mysqli_query($link, "SELECT domain FROM domain where domain='".$alias_domain."'"))) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Alias domain not found'
		);
		return false;
	}
	if (mysqli_result(mysqli_query($link, "SELECT alias_domain FROM alias_domain where alias_domain='".$alias_domain."'"))) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Alias domain exists'
		);
		return false;
	}
	$mystring = "INSERT INTO alias_domain (alias_domain, target_domain, created, modified, active) VALUE ('".$alias_domain."', '$target_domain', now(), now(), '".$active."')";
	if (!mysqli_query($link, $mystring)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Added alias domain '.htmlspecialchars($alias_domain)
	);
}
function mailbox_add_mailbox($link, $postarray) {
	$password = mysqli_real_escape_string($link, $postarray['password']);
	$password2 = mysqli_real_escape_string($link, $postarray['password2']);
	$domain = mysqli_real_escape_string($link, strtolower(trim($postarray['domain'])));
	$local_part = mysqli_real_escape_string($link, strtolower(trim($postarray['local_part'])));
	$name = mysqli_real_escape_string($link, $postarray['name']);
	$default_cal = mysqli_real_escape_string($link, $postarray['default_cal']);
	$default_card = mysqli_real_escape_string($link, $postarray['default_card']);
	$quota_m = mysqli_real_escape_string($link, $postarray['quota']);

	$quota_b = $quota_m*1048576;
	$maildir = $domain."/".$local_part."/";
	$username = $local_part.'@'.$domain;

	$row_from_domain = mysqli_fetch_assoc(mysqli_query($link, "SELECT mailboxes, maxquota, quota FROM domain WHERE domain='".$domain."'"));
	$row_from_mailbox = mysqli_fetch_assoc(mysqli_query($link, "SELECT count(*) as count, coalesce(round(sum(quota)/1048576), 0) as quota FROM mailbox WHERE domain='".$domain."'"));

	$num_mailboxes = $row_from_mailbox['count'];
	$quota_m_in_use = $row_from_mailbox['quota'];
	$num_max_mailboxes = $row_from_domain['mailboxes'];
	$maxquota_m = $row_from_domain['maxquota'];
	$domain_quota_m = $row_from_domain['quota'];

	global $logged_in_role;
	global $logged_in_as;
	if (!mysqli_result(mysqli_query($link, "SELECT domain FROM domain WHERE domain='".$domain."' AND (domain NOT IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'!='".$logged_in_role."')"))) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	$qstring = "SELECT local_part FROM mailbox WHERE local_part='$local_part' and domain='".$domain."'";
	$qresult = mysqli_query($link, $qstring);
	$num_results = mysqli_num_rows($qresult);
	if ($num_results != 0) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Mailbox already exist'
		);
		return false;
	}
	if (empty($default_cal) || empty($default_card)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Calendar and address book cannot be empty'
		);
		return false;
	}

	if (!is_valid_domain_name($domain) || empty ($domain)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Domain name invalid'
		);
		return false;
	}
	if (!ctype_alnum(str_replace(array('.', '-'), '', $local_part)) || empty ($local_part)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Mailbox alias must be alphanumeric'
		);
		return false;
	}
	if (!is_numeric($quota_m)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Quota is not numeric'
		);
		return false;
	}
	if (!empty($password) && !empty($password2)) {
		if ($password != $password2) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Password mismatch'
			);
			return false;
		}
		$prep_password = escapeshellcmd($password);
		exec("/usr/bin/doveadm pw -s SHA512-CRYPT -p $prep_password", $hash, $return);
		$password_sha512c = $hash[0];
		if ($return != "0") {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Cannot create password hash'
			);
			return false;
		}
	}
	else {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Password cannot be empty'
		);
		return false;
	}
	if ($num_mailboxes >= $num_max_mailboxes) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Mailbox quota exceeded ('.htmlspecialchars($num_mailboxes).' of '.htmlspecialchars($num_max_mailboxes).')'
		);
		return false;
	}
	if (!mysqli_result(mysqli_query($link, "SELECT domain FROM domain where domain='".$domain."'"))) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Domain not found'
		);
		return false;
	}
	if (!filter_var($username, FILTER_VALIDATE_EMAIL)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid mail address'
		);
		return false;
	}
	if ($quota_m > $maxquota_m) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Quota over max. quota limit ('.htmlspecialchars($maxquota_m).'M)'
		);
		return false;
	}
	if (($quota_m_in_use+$quota_m) > $domain_quota_m) {
		$quota_left_m = ($domain_quota_m - $quota_m_in_use);
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Quota exceeds quota left ('.htmlspecialchars($quota_left_m).'M)'
		);
		return false;
	}
	isset($postarray['active']) ? $active = '1' : $active = '0';
	$create_user = "INSERT INTO mailbox (username, password, name, maildir, quota, local_part, domain, created, modified, active) 
			VALUES ('".$username."', '".$password_sha512c."', '".$name."', '$maildir', '".$quota_b."', '$local_part', '".$domain."', now(), now(), '".$active."');";
	$create_user .= "INSERT INTO quota2 (username, bytes, messages)
			VALUES ('".$username."', '', '');";
	$create_user .= "INSERT INTO alias (address, goto, domain, created, modified, active)
			VALUES ('".$username."', '".$username."', '".$domain."', now(), now(), '".$active."');";
	$create_user .= "INSERT INTO users (username, digesta1)
			VALUES('".$username."', MD5(CONCAT('".$username."', ':SabreDAV:', '".$password."')));";
	$create_user .= "INSERT INTO principals (uri,email,displayname)
			VALUES ('principals/$username', '".$username."', '".$name."');";
	$create_user .= "INSERT INTO principals (uri,email,displayname)
			VALUES ('principals/$username/calendar-proxy-read', null, null);";
	$create_user .= "INSERT INTO principals (uri,email,displayname)
			VALUES ('principals/$username/calendar-proxy-write', null, null);";
	$create_user .= "INSERT INTO addressbooks (principaluri, displayname, uri, description, synctoken)
			VALUES ('principals/$username','$default_card','default','','1');";
	$create_user .= "INSERT INTO calendars (principaluri, displayname, uri, description, components, transparent) 
			VALUES ('principals/$username','$default_cal','default','','VEVENT,VTODO', '0');";
	if (!mysqli_multi_query($link, $create_user)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	while ($link->next_result()) {
		if (!$link->more_results()) break;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Added mailbox '.htmlspecialchars($username)
	);
}
function mailbox_add_dav($link, $postarray) {
	$displayname = mysqli_real_escape_string($link, $postarray['displayname']);
	$davtype = mysqli_real_escape_string($link, $postarray['davtype']);
	global $logged_in_role;
	global $logged_in_as;
	if (!filter_var($logged_in_as, FILTER_VALIDATE_EMAIL) || $logged_in_role != "user") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	if (empty($displayname)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Display name cannot be empty'
		);
		return false;
	}
	if ($davtype == "addressbook") {
		$create_davitem = "INSERT INTO addressbooks (principaluri, displayname, uri, description, synctoken)
				VALUES ('principals/$logged_in_as', '$displayname', UUID(), '', '1')";
	}
	elseif ($davtype == "calendar") {
		$create_davitem .= "INSERT INTO calendars (principaluri, displayname, uri, description, components, transparent) 
				VALUES ('principals/$logged_in_as', '$displayname', UUID(), '', 'VEVENT,VTODO' , '0')";	
	}
	if (!mysqli_query($link, $create_davitem)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Added DAV item'
	);
}
function mailbox_edit_alias($link, $postarray) {
	global $logged_in_role;
	global $logged_in_as;
	$address = mysqli_real_escape_string($link, $postarray['address']);
	$domain = substr($address, strpos($address, '@')+1);
	if (!mysqli_result(mysqli_query($link, "SELECT domain FROM domain WHERE domain='".$domain."' AND (domain NOT IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'!='".$logged_in_role."')"))) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid domain name'
		);
		return false;
	}
	if (empty($postarray['goto'])) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Destination must not be empty'
		);
		return false;
	}
	$gotos = array_map('trim', explode(',', $postarray['goto']));
	foreach ($gotos as $goto) {
		if (!filter_var($goto, FILTER_VALIDATE_EMAIL) === true) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Destination address '.htmlspecialchars($goto).' is invalid'
			);
			return false;
		}
		if ($goto == $address) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Alias address and goto address must not be identical'
			);
			return false;
		}
	}
	$goto = implode(",", $gotos);
	isset($postarray['active']) ? $active = '1' : $active = '0';
	if (!filter_var($address, FILTER_VALIDATE_EMAIL) === true) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid mail address'
		);
		return false;
	}
	$mystring = "UPDATE alias SET goto='".$goto."', active='".$active."' WHERE address='".$address."'";
	if (!mysqli_query($link, $mystring)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Saved changes to alias '.htmlspecialchars($address)
	);
}
function mailbox_edit_domain($link, $postarray) {
	$domain = mysqli_real_escape_string($link, $postarray['domain']);
	$description = mysqli_real_escape_string($link, $postarray['description']);
	$aliases = mysqli_real_escape_string($link, $postarray['aliases']);
	$mailboxes = mysqli_real_escape_string($link, $postarray['mailboxes']);
	$maxquota = mysqli_real_escape_string($link, $postarray['maxquota']);
	$quota = mysqli_real_escape_string($link, $postarray['quota']);

	$row_from_mailbox = mysqli_fetch_assoc(mysqli_query($link, "SELECT count(*) as count, max(coalesce(round(quota/1048576), 0)) as maxquota, coalesce(round(sum(quota)/1048576), 0) as quota FROM mailbox WHERE domain='".$domain."'"));
	$maxquota_in_use = $row_from_mailbox['maxquota'];
	$domain_quota_m_in_use = $row_from_mailbox['quota'];
	$mailboxes_in_use = $row_from_mailbox['count'];
	$aliases_in_use = mysqli_result(mysqli_query($link, "SELECT count(*) FROM alias WHERE domain='".$domain."' and address NOT IN (SELECT username FROM mailbox)"));

	global $logged_in_role;
	global $logged_in_as;

	if (!mysqli_result(mysqli_query($link, "SELECT domain FROM domain WHERE domain='".$domain."' AND (domain NOT IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'!='".$logged_in_role."')"))) { 
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}

	$numeric_array = array($aliases, $mailboxes, $maxquota, $quota);
	foreach ($numeric_array as $numeric) {
		if (!is_numeric($mailboxes)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Invalid form data: '.htmlspecialchars($numeric).' must be numeric'
			);
			return false;
		}
	}
	if (!is_valid_domain_name($domain) || empty ($domain)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid domain name'
		);
		return false;
	}
	if ($maxquota > $quota) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Max. size per mailbox can not be greater than domain quota'
		);
		return false;
	}
	if ($maxquota_in_use > $maxquota) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Max. quota per mailbox must be greater than or equal to '.htmlspecialchars($maxquota_in_use).'M'
		);
		return false;
	}
	if ($domain_quota_m_in_use > $quota) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Max. quota must be greater than or equal to '.htmlspecialchars($domain_quota_m_in_use).'M'
		);
		return false;
	}
	if ($mailboxes_in_use > $mailboxes) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Max. mailboxes must be greater than or equal to '.htmlspecialchars($mailboxes_in_use)
		);
		return false;
	}
	if ($aliases_in_use > $aliases) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Max. aliases must be greater than or equal to '.htmlspecialchars($aliases_in_use)
		);
		return false;
	}
	isset($postarray['active']) ? $active = '1' : $active = '0';
	isset($postarray['relay_all_recipients']) ? $relay_all_recipients = '1' : $relay_all_recipients = '0';
	isset($postarray['backupmx']) ? $backupmx = '1' : $backupmx = '0';
	$mystring = "UPDATE domain SET modified=now(), relay_all_recipients='".$relay_all_recipients."', backupmx='".$backupmx."', active='".$active."', quota='$quota', maxquota='$maxquota', mailboxes='$mailboxes', aliases='$aliases', description='$description' WHERE domain='".$domain."'";
	if (!mysqli_query($link, $mystring)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Saved changes to domain '.htmlspecialchars($domain)
	);
}
function mailbox_edit_domainadmin($link, $postarray) {
	if ($_SESSION['mailcow_cc_role'] != "admin") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	if (empty($postarray['domain'])) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Please assign a domain'
		);
		return false;
	}
	foreach ($postarray['domain'] as $domain) {
		if (!is_valid_domain_name($domain)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Invalid domain name: '.htmlspecialchars($domain)
			);
			return false;
		}
	};
	$username = mysqli_real_escape_string($link, $postarray['username']);
	$password = mysqli_real_escape_string($link, $postarray['password']);
	$password2 = mysqli_real_escape_string($link, $postarray['password2']);
	if (!ctype_alnum(str_replace(array('@', '.', '-'), '', $username))) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid username format'
		);
		return false;
	}
	isset($postarray['active']) ? $active = '1' : $active = '0';
	$mystring = "DELETE FROM domain_admins WHERE username='".$username."'";
	if (!mysqli_query($link, $mystring)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	foreach ($postarray['domain'] as $domain) {
		$mystring = "INSERT INTO domain_admins (username, domain, created, active) VALUES ('".$username."', '".$domain."', now(), '".$active."')";
		if (!mysqli_query($link, $mystring)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
	}
	if (!empty($password) && !empty($password2)) {
		if ($password != $password2) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Password mismatch'
			);
			return false;
		}
		$prep_password = escapeshellcmd($password);
		exec("/usr/bin/doveadm pw -s SHA512-CRYPT -p $prep_password", $hash, $return);
		$password_sha512c = $hash[0];
		if ($return != "0") {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Cannot create password hash'
			);
			return false;
		}
		$mystring = "UPDATE admin SET modified=now(), active='".$active."', password='".$password_sha512c."' WHERE username='".$username."';";
	}
	else {
		$mystring = "UPDATE admin SET modified=now(), active='".$active."' where username='".$username."'";
	}
	if (!mysqli_query($link, $mystring)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Saved changes to domain administrator "'.htmlspecialchars($username).'"'
	);
}
function mailbox_edit_mailbox($link, $postarray) {
	$quota_m = mysqli_real_escape_string($link, $postarray['quota']);
	$quota_b = $quota_m*1048576;
	$username = mysqli_real_escape_string($link, $postarray['username']);
	$name = mysqli_real_escape_string($link, $postarray['name']);
	$password = mysqli_real_escape_string($link, $postarray['password']);
	$password2 = mysqli_real_escape_string($link, $postarray['password2']);
	$domain = mysqli_result(mysqli_query($link, "SELECT domain FROM mailbox WHERE username='".$username."'"));
	$quota_m_now = mysqli_result(mysqli_query($link, "SELECT coalesce(round(sum(quota)/1048576), 0) as quota FROM mailbox WHERE username='".$username."'"));
	$quota_m_in_use = mysqli_result(mysqli_query($link, "SELECT coalesce(round(sum(quota)/1048576), 0) as quota FROM mailbox WHERE domain='".$domain."'"));
	$row_from_domain = mysqli_fetch_assoc(mysqli_query($link, "SELECT quota, maxquota FROM domain WHERE domain='".$domain."'"));
	$maxquota_m = $row_from_domain['maxquota'];
	$domain_quota_m = $row_from_domain['quota'];
	global $logged_in_role;
	global $logged_in_as;
	if (!mysqli_result(mysqli_query($link, "SELECT domain FROM domain WHERE domain='".$domain."' AND (domain NOT IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'!='".$logged_in_role."')"))) { 
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	if(isset($postarray['sender_acl'])) {
		foreach ($postarray['sender_acl'] as $sender_acl) {
			if (!filter_var($sender_acl, FILTER_VALIDATE_EMAIL)) {
					$_SESSION['return'] = array(
						'type' => 'danger',
						'msg' => 'Invalid sender ACL: '.htmlspecialchars($sender_acl).' must be a valid email address.'
					);
					return false;
			}
		}
	}
	if (!is_numeric($quota_m)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Quota must be numeric'
		);
		return false;
	}
	if (!ctype_alnum(str_replace(array('@', '.', '-'), '', $username))) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid username'
		);
		return false;
	}
	if ($quota_m > $maxquota_m) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Quota over max. quota limit ('.htmlspecialchars($maxquota_m).'M)'
		);
		return false;
	}
	if (($quota_m_in_use-$quota_m_now+$quota_m) > $domain_quota_m) {
		$quota_left_m = ($domain_quota_m - $quota_m_in_use + $quota_m_now);
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Quota exceeds quota left (max. '.htmlspecialchars($quota_left_m).'M)'
		);
		return false;
	}
	isset($postarray['active']) ? $active = '1' : $active = '0';
	$mystring = "DELETE FROM sender_acl WHERE logged_in_as='".$username."';";
	if (!mysqli_query($link, $mystring)) {
	$_SESSION['return'] = array(
		'type' => 'danger',
		'msg' => 'MySQL Error: '.mysqli_error($link)
	);
	return false;
	}
	foreach ($postarray['sender_acl'] as $sender_acl) {
		$mystring = "INSERT INTO sender_acl (send_as, logged_in_as) VALUES ('".$sender_acl."', '".$username."')";
		if (!mysqli_query($link, $mystring)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
		}
	}
	if (!empty($password) && !empty($password2)) {
		if ($password != $password2) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Password mismatch'
			);
			return false;
		}
		$prep_password = escapeshellcmd($password);
		exec("/usr/bin/doveadm pw -s SHA512-CRYPT -p $prep_password", $hash, $return);
		$password_sha512c = $hash[0];
		if ($return != "0") {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Cannot create password hash'
			);
			return false;
		}
		$update_user = "UPDATE alias SET modified=now(), active='".$active."' WHERE address='".$username."';";
		$update_user .= "UPDATE mailbox SET modified=now(), active='".$active."', password='".$password_sha512c."', name='".$name."', quota='".$quota_b."' WHERE username='".$username."';";
		$update_user .= "UPDATE users SET digesta1=MD5(CONCAT('".$username."', ':SabreDAV:', '".$password."')) WHERE username='".$username."';";
		if (!mysqli_multi_query($link, $update_user)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
		while ($link->next_result()) {
			if (!$link->more_results()) break;
		}
		$_SESSION['return'] = array(
			'type' => 'success',
			'msg' => 'Saved changes to mailbox '.htmlspecialchars($username)
		);
		return true;
	}
	$update_user = "UPDATE alias SET modified=now(), active='".$active."' WHERE address='".$username."';";
	$update_user .= "UPDATE mailbox SET modified=now(), active='".$active."', name='".$name."', quota='".$quota_b."' WHERE username='".$username."'";
	if (!mysqli_multi_query($link, $update_user)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	while ($link->next_result()) {
		if (!$link->more_results()) break;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Saved changes to mailbox '.htmlspecialchars($username)
	);
}
function mailbox_edit_dav($link, $postarray) {
	global $logged_in_role;
	global $logged_in_as;
	/* Handle address book input */
	foreach (array_flip($postarray['adb_displayname']) as $adb_id) {
		// Check address book access
		if (!mysqli_result(mysqli_query($link, "SELECT * FROM calendars, addressbooks
			WHERE calendars.principaluri='principals/$logged_in_as' 
			AND addressbooks.principaluri='principals/$logged_in_as'
			AND addressbooks.id='$adb_id'")) && $logged_in_role == "user") { 
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Permission denied'
			);
			return false;
		}
		// Set display name for current address book, if not empty
		$adb_displayname =  mysqli_real_escape_string($link, $postarray['adb_displayname'][$adb_id]);
		if (empty($adb_displayname)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Display name cannot be empty'
			);
			return false;
		}
		if (!mysqli_query($link, "UPDATE addressbooks SET displayname='$adb_displayname' WHERE id='$adb_id'")) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
	}
	/* Handle calendar input */
	/* Clean calendar principal_ids */
	$clean_cal = "DELETE FROM groupmembers WHERE principal_id
		IN (SELECT id FROM principals
			WHERE uri='principals/$logged_in_as/calendar-proxy-read'
			OR uri='principals/$logged_in_as/calendar-proxy-write')";
	if (!mysqli_query($link, $clean_cal)) { 
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	foreach (array_flip($postarray['cal_displayname']) as $cal_id) {
		/* Check cal access */
		if (!mysqli_result(mysqli_query($link, "SELECT * FROM calendars, addressbooks
			WHERE calendars.principaluri='principals/$logged_in_as' 
			AND addressbooks.principaluri='principals/$logged_in_as'
			AND calendars.id='$cal_id'")) && $logged_in_role == "user") { 
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Permission denied'
			);
			return false;
		}
		/* Set display name for current cal, if not empty */
		$cal_displayname =  mysqli_real_escape_string($link, $postarray['cal_displayname'][$cal_id]);
		if (empty($cal_displayname)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Display name cannot be empty'
			);
			return false;
		}
		if (!mysqli_query($link, "UPDATE calendars SET displayname='$cal_displayname' WHERE id='$cal_id'")) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
	}
	/* Setup read-only cal shares */
	if(isset($postarray['cal_ro_share'])) {
		/* No need to set read-only, when read/write is enabled */
		if(isset($postarray['cal_rw_share'])) {
			$postarray['cal_ro_share'] = array_diff($postarray['cal_ro_share'], $postarray['cal_rw_share']);
		}
		foreach ($postarray['cal_ro_share'] as $share_with) {
			$share_with = mysqli_real_escape_string($link, $share_with);
			$update_string = "INSERT INTO groupmembers (principal_id, member_id)
				VALUES (
					(SELECT id FROM principals WHERE uri='principals/".$logged_in_as."/calendar-proxy-read'),
					(SELECT id FROM principals WHERE email='".$share_with."')
				)";
			if (!mysqli_query($link, $update_string)) { 
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'MySQL Error: '.mysqli_error($link)
				);
				return false;
			}
		}
	}
	/* Setup read/write cal shares */
	if(isset($postarray['cal_rw_share'])) {
		foreach ($postarray['cal_rw_share'] as $share_with) {
			$share_with = mysqli_real_escape_string($link, $share_with);
			$update_string = "INSERT INTO groupmembers (principal_id, member_id)
				VALUES (
					(SELECT id FROM principals WHERE uri='principals/".$logged_in_as."/calendar-proxy-write'),
					(SELECT id FROM principals WHERE email='".$share_with."')
				)";
			if (!mysqli_query($link, $update_string)) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'MySQL Error: '.mysqli_error($link)
				);
				return false;
			}
		}
	}
	/* Delete marked DAV items */
	if(isset($postarray['adb_delete'])) {
		foreach ($postarray['adb_delete'] as $adb_delete_id) {
			$update_string = "DELETE FROM addressbooks WHERE ID='".$adb_delete_id."' AND uri!='default'";
			if (!mysqli_query($link, $update_string)) { 
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'MySQL Error: '.mysqli_error($link)
				);
				return false;
			}
		}
	}
	if(isset($postarray['cal_delete'])) {
		foreach ($postarray['cal_delete'] as $cal_delete_id) {
			$update_string = "DELETE FROM calendars WHERE ID='".$cal_delete_id."' AND uri!='default'";
			if (!mysqli_query($link, $update_string)) { 
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'MySQL Error: '.mysqli_error($link)
				);
				return false;
			}
		}
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Changes saved successfully'
	);
}
function mailbox_delete_domain($link, $postarray) {
	$domain = mysqli_real_escape_string($link, $postarray['domain']);
	if ($_SESSION['mailcow_cc_role'] != "admin") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	if (!is_valid_domain_name($domain) || empty ($domain)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid domain name'
		);
		return false;
	}
	$mystring = "SELECT username FROM mailbox WHERE domain='".$domain."';";
	$myresult = mysqli_result(mysqli_query($link, $mystring));
	if (!mysqli_query($link, $mystring) || !empty($myresult)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Domain is not empty, please delete all assigned mailboxes before you delete a domain.'
		);
		return false;
	}
	foreach (array("domain", "alias", "domain_admins") as $deletefrom) {
		$mystring = "DELETE FROM $deletefrom WHERE domain='".$domain."'";
		if (!mysqli_query($link, $mystring)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
	}
	$mystring = "DELETE FROM alias_domain WHERE target_domain='".$domain."'";
	if (!mysqli_query($link, $mystring)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Deleted domain '.htmlspecialchars($domain)
	);
}
function mailbox_delete_alias($link, $postarray) {
	$address = mysqli_real_escape_string($link, $postarray['address']);
	$local_part = strstr($address, '@', true);
	global $logged_in_role;
	global $logged_in_as;
	if (!mysqli_result(mysqli_query($link, "SELECT domain FROM alias WHERE address='".$address."' AND (domain NOT IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'!='".$logged_in_role."')"))) { 
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	$mystring = "DELETE FROM alias WHERE address='".$address."' AND address NOT IN (SELECT username FROM mailbox)";
	if (!mysqli_query($link, $mystring)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Deleted alias '.htmlspecialchars($address)
	);
}
function mailbox_delete_alias_domain($link, $postarray) {
	$alias_domain = mysqli_real_escape_string($link, $postarray['alias_domain']);
	global $logged_in_role;
	global $logged_in_as;
	if (!mysqli_result(mysqli_query($link, "SELECT target_domain FROM alias_domain WHERE alias_domain='".$alias_domain."' AND (target_domain NOT IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'!='".$logged_in_role."')"))) { 
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	if (!is_valid_domain_name($alias_domain)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid domain name'
		);
		return false;
	}
	$mystring = "DELETE FROM alias_domain WHERE alias_domain='".$alias_domain."'";
	if (!mysqli_query($link, $mystring)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Deleted alias domain '.htmlspecialchars($alias_domain)
	);
}
function mailbox_delete_mailbox($link, $postarray) {
	$username = mysqli_real_escape_string($link, $postarray['username']);
	global $logged_in_role;
	global $logged_in_as;
	if (!mysqli_result(mysqli_query($link, "SELECT domain FROM mailbox WHERE username='".$username."' AND (domain NOT IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'!='".$logged_in_role."')"))) { 
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	if (!filter_var($username, FILTER_VALIDATE_EMAIL)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid mailbox'
		);
		return false;
	}
	$delete_user = "DELETE FROM alias WHERE goto='".$username."';";
	$delete_user .= "UPDATE alias SET goto=REPLACE(goto, ',".$username.",', ',');";
	$delete_user .= "UPDATE alias SET goto=REPLACE(goto, ',".$username."', '');";
	$delete_user .= "UPDATE alias SET goto=REPLACE(goto, '".$username.",', '');";
	$delete_user .= "DELETE FROM quota2 WHERE username='".$username."';";
	$delete_user .= "DELETE FROM calendarobjects WHERE calendarid IN (SELECT id from calendars where principaluri='principals/".$username."');";
	$delete_user .= "DELETE FROM cards WHERE addressbookid IN (SELECT id from calendars where principaluri='principals/".$username."');";
	$delete_user .= "DELETE FROM mailbox WHERE username='".$username."';";
	$delete_user .= "DELETE FROM sender_acl WHERE logged_in_as='".$username."';";
	$delete_user .= "DELETE FROM users WHERE username='".$username."';";
	$delete_user .= "DELETE FROM principals WHERE uri='principals/".$username."';";
	$delete_user .= "DELETE FROM principals WHERE uri='principals/".$username."/calendar-proxy-read';";
	$delete_user .= "DELETE FROM principals WHERE uri='principals/".$username."/calendar-proxy-write';";
	$delete_user .= "DELETE FROM addressbooks WHERE principaluri='principals/".$username."';";
	$delete_user .= "DELETE FROM calendars WHERE principaluri='principals/".$username."';";
	if (!mysqli_multi_query($link, $delete_user)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	while ($link->next_result()) {
		if (!$link->more_results()) break;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Deleted mailbox '.htmlspecialchars($username)
	);
}
function set_admin_account($link, $postarray) {
	$name = mysqli_real_escape_string($link, $postarray['admin_user']);
	$name_now = mysqli_real_escape_string($link, $postarray['admin_user_now']);
	$password = mysqli_real_escape_string($link, $postarray['admin_pass']);
	$password2 = mysqli_real_escape_string($link, $postarray['admin_pass2']);
	if ($_SESSION['mailcow_cc_role'] != "admin") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	if (!ctype_alnum(str_replace(array('@', '.', '-'), '', $name)) || empty ($name)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid admin account'
		);
		return false;
	}
	if (!ctype_alnum(str_replace(array('@', '.', '-'), '', $name_now)) || empty ($name_now)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid new admin name'
		);
		return false;
	}
	if (!empty($password) && !empty($password2)) {
		if ($password != $password2) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Password mismatch'
			);
			return false;
		}
		$password = escapeshellcmd($password);
		exec("/usr/bin/doveadm pw -s SHA512-CRYPT -p $password", $hash, $return);
		$password = $hash[0];
		if ($return != "0") {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Cannot create password hash'
			);
			return false;
		}
		$mystring = "UPDATE admin SET modified=now(), password='".$password."', username='".$name."' WHERE username='".$name_now."'";
		if (!mysqli_query($link, $mystring)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
	}
	else {
		$mystring = "UPDATE admin SET modified=now(), username='".$name."' WHERE username='".$name_now."'";
		if (!mysqli_query($link, $mystring)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
	}
	$mystring = "UPDATE domain_admins SET username='".$name."', domain='ALL' WHERE username='".$name_now."'";
	if (!mysqli_query($link, $mystring)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Changes saved successfully'
	);
}
function set_time_limited_aliases($link, $postarray) {
	global $logged_in_as;
	$domain = substr($logged_in_as, strpos($logged_in_as, '@'));
	if ($_SESSION['mailcow_cc_role'] != "user" || empty($logged_in_as) || empty($domain)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	switch ($postarray["trigger_set_time_limited_aliases"]) {
		case "generate":
			if (!is_numeric($postarray["validity"]) || $postarray["validity"] > 672) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'Invalid form data'
				);
				return false;
			}
			$hours = $postarray["validity"];
			$mystring = "INSERT INTO spamalias (address, goto, validity) VALUES (CONCAT(SUBSTRING(MD5(RAND()) FROM 1 FOR 12), '".$domain."'), '".$logged_in_as."', DATE_ADD(NOW(), INTERVAL ".$hours." HOUR));";
			if (!mysqli_query($link, $mystring)) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'MySQL Error: '.mysqli_error($link)
				);
				return false;
			}
			$_SESSION['return'] = array(
				'type' => 'success',
				'msg' => 'Generated time-limited aliases'
			);
		break;
		case "delete":
			$mystring = "DELETE FROM spamalias WHERE goto='".$logged_in_as."'";
			if (!mysqli_query($link, $mystring)) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'MySQL Error: '.mysqli_error($link)
				);
				return false;
			}
			$_SESSION['return'] = array(
				'type' => 'success',
				'msg' => 'Deleted all time-limited aliases'
			);
		break;
		case "extend":
			$mystring = "UPDATE spamalias SET validity=DATE_ADD(validity, INTERVAL 1 HOUR) WHERE goto='".$logged_in_as."' AND validity >= NOW()";
			if (!mysqli_query($link, $mystring)) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'MySQL Error: '.mysqli_error($link)
				);
				return false;
			}
			$_SESSION['return'] = array(
				'type' => 'success',
				'msg' => 'Extended time-limited aliases (if any)'
			);
		break;
		default:
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Permission denied'
			);
			return false;
	}
}
function set_user_account($link, $postarray) {
	$name_now = mysqli_real_escape_string($link, $postarray['user_now']);
	$user_real_name = mysqli_real_escape_string($link, $postarray['user_real_name']);
	$password_old = mysqli_real_escape_string($link, $postarray['user_old_pass']);
	$password_new = mysqli_real_escape_string($link, $postarray['user_new_pass']);
	$password_new2 = mysqli_real_escape_string($link, $postarray['user_new_pass2']);
	if (!check_login($link, $name_now, $password_old) == "user") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	if ($_SESSION['mailcow_cc_role'] != "user") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	if (!empty($password_new2) && !empty($password_new)) {
		if ($password_new2 != $password_new) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Password mismatch'
			);
			return false;
		}
		$prep_password = escapeshellcmd($password_new);
		exec("/usr/bin/doveadm pw -s SHA512-CRYPT -p $prep_password", $hash, $return);
		if ($return != "0") {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Cannot create password hash'
			);
			return false;
		}
		$password_sha512c = $hash[0];
		$update_user = "UPDATE mailbox SET modified=NOW(), password='".$password_sha512c."' WHERE username='".$name_now."';";
		$update_user .= "UPDATE users SET digesta1=MD5(CONCAT('".$name_now."', ':SabreDAV:', '".$password_new."')) WHERE username='".$name_now."';";
		if (!mysqli_multi_query($link, $update_user)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
		while ($link->next_result()) {
			if (!$link->more_results()) break;
		}
	}
	if (!empty($user_real_name)) {
		$mystring = "UPDATE mailbox SET modified=NOW(), name='".$user_real_name."' WHERE username='".$name_now."'";
		if (!mysqli_query($link, $mystring)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Changes saved successfully'
	);
}
function set_fetch_mail($link, $postarray) {
	global $logged_in_as;
	$logged_in_as = escapeshellcmd($logged_in_as);
	$imap_host = explode(":", escapeshellcmd($postarray['imap_host']))[0];
	$imap_port = explode(":", escapeshellcmd($postarray['imap_host']))[1];
	$imap_username = escapeshellcmd($postarray['imap_username']);
	$imap_password = escapeshellcmd($postarray['imap_password']);
	$imap_enc = escapeshellcmd($postarray['imap_enc']);
	$imap_exclude = explode(",", str_replace(array(', ', ' , ', ' ,'), ',', escapeshellcmd($postarray['imap_exclude'])));
	if ($_SESSION['mailcow_cc_role'] != "user") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	if ($imap_enc != "/ssl" && $imap_enc != "/tls" && $imap_enc != "none") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid encryption mechanism'
		);
		return false;
	} 
	if ($imap_enc == "none") {
		$imap_enc = "";
	}
	if (!ctype_alnum(str_replace(array('.', '-'), '', $imap_host)) || empty ($imap_host)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid IMAP hostname'
		);
		return false;
	}
	if (!is_numeric($imap_port) || empty ($imap_port)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid connection port'
		);
		return false;
	}
	if (!ctype_alnum(str_replace(array('@', '.', '-', '\\', '/'), '', $imap_username)) || empty ($imap_username)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid IMAP username'
		);
		return false;
	}
	if (!ctype_alnum(str_replace(array(', ', ' , ', ' ,', ' '), '', escapeshellcmd($postarray['imap_exclude']))) && !empty($postarray['imap_exclude'])) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid exclude fields defined'
		);
		return false;
	}
	if (!$imap = imap_open("{".$imap_host.":".$imap_port."/imap/novalidate-cert".$imap_enc."}", $imap_username, $imap_password, OP_HALFOPEN, 1)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Cannot connect to IMAP server'
		);
		return false;
	}
	if ($imap_enc == "none") {
		$imap_enc = "";
	}
	elseif ($imap_enc == "/ssl") {
		$imap_enc = "imaps";
	}
	elseif ($imap_enc == "/tls") {
		$imap_enc = "starttls";
	}
	if(count($imap_exclude) > 1) {
		foreach ($imap_exclude as $each_exclude) {
			$exclude_parameter .= "-x ".$each_exclude."* ";
		}
	}
	ini_set('max_execution_time', 3600);
	exec('sudo /usr/bin/doveadm -o imapc_port='.$imap_port.' -o imapc_ssl='.$imap_enc.' \
	-o imapc_host='.$imap_host.' \
	-o imapc_user='.$imap_username.' \
	-o imapc_password='.$imap_password.' \
	-o imapc_ssl_verify=no \
	-o ssl_client_ca_dir=/etc/ssl/certs \
	-o imapc_features="rfc822.size fetch-headers" \
	-o mail_prefetch_count=20 sync -1 \
	-x "Shared*" -x "Public*" -x "Archives*" '.$exclude_parameter.' \
	-R -U -u '.$logged_in_as.' imapc:', $out, $return);
	if ($return == "2") {
		exec('sudo /usr/bin/doveadm quota recalc -A', $out, $return);
	}
	if ($return != "0") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Died with exit code '.htmlspecialchars($return)
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Successfully fetched mails'
	);
}
function add_domain_admin($link, $postarray) {
	$username = mysqli_real_escape_string($link, strtolower(trim($postarray['username'])));
	$password = mysqli_real_escape_string($link, $postarray['password']);
	$password2 = mysqli_real_escape_string($link, $postarray['password2']);
	if ($_SESSION['mailcow_cc_role'] != "admin") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	if (!ctype_alnum(str_replace(array('@', '.', '-'), '', $username)) || empty ($username)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid username: '.htmlspecialchars($username)
		);
		return false;
	}
	if (empty($postarray['domain'])) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Please assign a domain'
		);
		return false;
	}
	array_walk($postarray['domain'], function(&$string) use ($link) {
		$string = mysqli_real_escape_string($link, $string);
	});
	$qstring = "SELECT mailbox.username, admin.username FROM admin, mailbox WHERE mailbox.username='".$username."' OR admin.username='".$username."'";
	$qresult = mysqli_query($link, $qstring);
	$num_results = mysqli_num_rows($qresult);
	if ($num_results != 0) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Username '.htmlspecialchars($username).' does already exist'
		);
		return false;
	}
	if (!empty($password) && !empty($password2)) {
		if ($password != $password2) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Password mismatch'
			);
			return false;
		}
		if (!ctype_alnum(str_replace(array('@', '.', '-'), '', $username))) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Invalid username: '.htmlspecialchars($username)
			);
			return false;
		}
		$password = escapeshellcmd($password);
		exec("/usr/bin/doveadm pw -s SHA512-CRYPT -p $password", $hash, $return);
		$password = $hash[0];
		if ($return != "0") {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'Cannot create password hash'
			);
			return false;
		}
	isset($postarray['active']) ? $active = '1' : $active = '0';
	$mystring = "DELETE FROM domain_admins WHERE username='".$username."'";
		if (!mysqli_query($link, $mystring)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
		$mystring = "DELETE FROM admin WHERE username='".$username."'";
		if (!mysqli_query($link, $mystring)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
		foreach ($postarray['domain'] as $domain) {
			$mystring = "INSERT INTO domain_admins (username, domain, created, active) VALUES ('".$username."', '".$domain."', now(), '".$active."')";
			if (!mysqli_query($link, $mystring)) {
				$_SESSION['return'] = array(
					'type' => 'danger',
					'msg' => 'MySQL Error: '.mysqli_error($link)
				);
				return false;
			}
		}
		$mystring = "INSERT INTO admin (username, password, superadmin, created, modified, active) VALUES ('".$username."', '".$password."', '0', now(), now(), '".$active."')";
		if (!mysqli_query($link, $mystring)) {
			$_SESSION['return'] = array(
				'type' => 'danger',
				'msg' => 'MySQL Error: '.mysqli_error($link)
			);
			return false;
		}
	}
	else {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Password must not be empty'
		);
		return false;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Added domain admin '.htmlspecialchars($username)
	);
}
function delete_domain_admin($link, $postarray) {
	if ($_SESSION['mailcow_cc_role'] != "admin") {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Permission denied'
		);
		return false;
	}
	$username = mysqli_real_escape_string($link, $postarray['username']);
	if (!ctype_alnum(str_replace(array('@', '.', '-'), '', $username))) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Invalid username: '.htmlspecialchars($username)
		);
		return false;
	}
	$delete_domain = "DELETE FROM domain_admins WHERE username='".$username."';";
	$delete_domain .= "DELETE FROM admin WHERE username='".$username."';";
	if (!mysqli_multi_query($link, $delete_domain)) {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'MySQL Error: '.mysqli_error($link)
		);
		return false;
	}
	while ($link->next_result()) {
		if (!$link->more_results()) break;
	}
	$_SESSION['return'] = array(
		'type' => 'success',
		'msg' => 'Deleted domain admin '.htmlspecialchars($username)
	);
}
function is_valid_domain_name($domain_name) {
	$domain_name = idn_to_ascii($domain_name);
	return (preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $domain_name)
		   && preg_match("/^.{1,253}$/", $domain_name)
		   && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $domain_name));
}
?>
