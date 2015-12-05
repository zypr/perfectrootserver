<?php
if (isset($_POST["login_user"]) && isset($_POST["pass_user"])) {
	$login_user = strtolower(trim($_POST["login_user"]));
	if (check_login($link, $login_user, $_POST["pass_user"]) == "admin") {
		$_SESSION['mailcow_cc_loggedin'] = "yes";
		$_SESSION['mailcow_cc_username'] = $login_user;
		$_SESSION['mailcow_cc_role'] = "admin";
		header("Location: admin.php");
	}
	elseif (check_login($link, $login_user, $_POST["pass_user"]) == "domainadmin") {
		$_SESSION['mailcow_cc_loggedin'] = "yes";
		$_SESSION['mailcow_cc_username'] = $login_user;
		$_SESSION['mailcow_cc_role'] = "domainadmin";
		header("Location: mailbox.php");
	}
	elseif (check_login($link, $login_user, $_POST["pass_user"]) == "user") {
		$_SESSION['mailcow_cc_loggedin'] = "yes";
		$_SESSION['mailcow_cc_username'] = $login_user;
		$_SESSION['mailcow_cc_role'] = "user";
		header("Location: mailbox.php");
	}
	else {
		$_SESSION['return'] = array(
			'type' => 'danger',
			'msg' => 'Login failed'
		);
		return false;
	}
}
if (isset($_SESSION['mailcow_cc_loggedin']) && $_SESSION['mailcow_cc_loggedin'] == "yes" && $_SESSION['mailcow_cc_role'] == "admin") {
	if (isset($_POST["trigger_set_admin"])) {
		set_admin_account($link, $_POST);
	}
	if (isset($_POST["trigger_backup"])) {
		set_mailcow_config("backup", $_POST);
	}
	if (isset($_POST["trigger_public_folder"])) {
		set_mailcow_config("public_folder", $_POST);
		dovecot_reload();
	}
	if (isset($_POST["pflog_renew"])) {
		pflog_renew();
	}
	if (isset($_POST["srr"])) {
		set_mailcow_config("srr", $_POST);
		postfix_reload();
	}
	if (isset($_GET["del"])) {
		opendkim_table("delete", $_GET["del"]);
	}
	if (isset($_POST["maxmsgsize"])) {
		set_mailcow_config("maxmsgsize", $_POST["maxmsgsize"]);
	}
	if (isset($_POST["dkim_selector"])) {
		opendkim_table("add", $_POST["dkim_selector"] . "_" . $_POST["dkim_domain"]);
	}
	if (isset($_POST["trigger_anonymize"])) {
		isset($_POST['anonymize']) ? $anonymize = 'on' : $anonymize = '';
		set_mailcow_config("anonymize", $anonymize);
		postfix_reload();
	}
	if (isset($_POST["trigger_add_domain_admin"])) {
		add_domain_admin($link, $_POST);
	}
	if (isset($_POST["trigger_delete_domain_admin"])) {
		delete_domain_admin($link, $_POST);
	}
}
if (isset($_SESSION['mailcow_cc_loggedin']) && $_SESSION['mailcow_cc_loggedin'] == "yes" && $_SESSION['mailcow_cc_role'] == "user") {
	if (isset($_POST["trigger_set_user_account"])) {
		set_user_account($link, $_POST);
	}
	if (isset($_POST["trigger_set_fetch_mail"])) {
		set_fetch_mail($link, $_POST);
	}
	if (isset($_POST["trigger_set_time_limited_aliases"])) {
		set_time_limited_aliases($link, $_POST);
	}
	if (isset($_POST["trigger_mailbox_action"])) {
		switch ($_POST["trigger_mailbox_action"]) {
			case "editdav":
				mailbox_edit_dav($link, $_POST);
			break;
			case "adddav":
				mailbox_add_dav($link, $_POST);
			break;
		}
	}
}
if (isset($_SESSION['mailcow_cc_loggedin']) && $_SESSION['mailcow_cc_loggedin'] == "yes" && ($_SESSION['mailcow_cc_role'] == "domainadmin" || $_SESSION['mailcow_cc_role'] == "admin")) {
	if (isset($_POST["trigger_mailbox_action"])) {
		switch ($_POST["trigger_mailbox_action"]) {
			case "adddomain":
				mailbox_add_domain($link, $_POST);
			break;
			case "addalias":
				mailbox_add_alias($link, $_POST);
			break;
			case "editalias":
				mailbox_edit_alias($link, $_POST);
			break;
			case "addaliasdomain":
				mailbox_add_alias_domain($link, $_POST);
			break;
			case "addmailbox":
				mailbox_add_mailbox($link, $_POST);
			break;
			case "editdomain":
				mailbox_edit_domain($link, $_POST);
			break;
			case "editmailbox":
				mailbox_edit_mailbox($link, $_POST);
			break;
			case "editdomainadmin":
				mailbox_edit_domainadmin($link, $_POST);
			break;
			case "deletedomain":
				mailbox_delete_domain($link, $_POST);
			break;
			case "deletealias":
				mailbox_delete_alias($link, $_POST);
			break;
			case "deletealiasdomain":
				mailbox_delete_alias_domain($link, $_POST);
			break;
			case "deletemailbox":
				mailbox_delete_mailbox($link, $_POST);
			break;
			case "editdav":
				mailbox_edit_dav($link, $_POST);
			break;
		}
	}
}
if (isset($_POST["logout"])) {
	session_unset();
	session_destroy();
	session_write_close();
	setcookie(session_name(),'',0,'/');
	return false;
}
?>
