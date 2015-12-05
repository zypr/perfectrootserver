<?php
require_once("inc/header.inc.php");
?>
<div class="container">
<?php
if (isset($_SESSION['mailcow_cc_loggedin']) && $_SESSION['mailcow_cc_loggedin'] == "yes" && $_SESSION['mailcow_cc_role'] == "admin") {
$_SESSION['return_to'] = basename($_SERVER['PHP_SELF']);
?>
<h4><span class="glyphicon glyphicon-user" aria-hidden="true"></span> Access</h4>
<div class="panel-group" id="accordion_access">
	<div class="panel panel-default">
		<div class="panel-heading" data-toggle="collapse" data-parent="#accordion_access" data-target="#collapseAdmin">
			<a style="cursor:pointer;" class="accordion-toggle">Administrators</a>
		</div>
		<div id="collapseAdmin" class="panel-collapse collapse in">
			<div class="panel-body">
				<form class="form-horizontal" autocapitalize="none" autocorrect="off" role="form" method="post">
				<?php
				$result = mysqli_fetch_assoc(mysqli_query($link, "SELECT username from admin where superadmin='1' and active='1'"));
				?>
					<input type="hidden" name="admin_user_now" value="<?=$result['username'];?>">
					<div class="form-group">
						<label class="control-label col-sm-2" for="admin_user">Administrator:</label>
						<div class="col-sm-10">
						<input type="text" class="form-control" name="admin_user" id="admin_user" value="<?=$result['username'];?>" required>
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="admin_pass">Password:</label>
						<div class="col-sm-10">
						<input type="password" class="form-control" name="admin_pass" id="admin_pass" placeholder="Unchanged if empty">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="admin_pass2">Password (repeat):</label>
						<div class="col-sm-10">
						<input type="password" class="form-control" name="admin_pass2" id="admin_pass2">
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<button type="submit" name="trigger_set_admin" class="btn btn-default">Save changes</button>
						</div>
					</div>
				</form>
			</div>
		</div>
	</div>

	<div class="panel panel-default">
	<div class="panel-heading" data-toggle="collapse" data-parent="#accordion_access" data-target="#collapseDomAdmins">
		<a style="cursor:pointer;" class="accordion-toggle">Domain administrators</a>
	</div>
		<div id="collapseDomAdmins" class="panel-collapse collapse in">
			<div class="panel-body">
				<form method="post">
					<div class="table-responsive">
					<table class="table table-striped" id="domainadminstable">
						<thead>
						<tr>
							<th>Username</th>
							<th>Assigned domains</th>
							<th>Active</th>
							<th>Action</th>
						</tr>
						</thead>
						<tbody>
							<?php
							$result = mysqli_query($link, "SELECT username, LOWER(GROUP_CONCAT(DISTINCT domain SEPARATOR ', ')) AS domain, CASE active WHEN 1 THEN 'Yes' ELSE 'No' END AS active FROM domain_admins WHERE username NOT IN (SELECT username FROM admin WHERE superadmin='1') GROUP BY username");
							while ($row = mysqli_fetch_array($result)):
							?>
							<tr>
								<td><?=$row['username'];?></td>
								<td><?=$row['domain'];?></td>
								<td><?=$row['active'];?></td>
								<td><a href="delete.php?domain_admin=<?=$row['username'];?>">delete</a> | 
									<a href="edit.php?domain_admin=<?=$row['username'];?>">edit</a></td>
							</tr>
							<?php
							endwhile;
							?>
						</tbody>
					</table>
					</div>
				</form>
				<small>
				<h4>Add domain administrator</h4>
				<form class="form-horizontal" role="form" method="post">
					<div class="form-group">
						<label class="control-label col-sm-4" for="username">Username (<kbd>aA-zZ, @, ., -</kbd>):</label>
						<div class="col-sm-8">
							<input type="text" class="form-control" name="username" id="username" required>
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-4" for="name">Assign domains:</label>
						<div class="col-sm-8">
							<select title="Search domains..." style="width:100%" name="domain[]" size="5" multiple>
				<?php
				$resultselect = mysqli_query($link, "SELECT domain FROM domain");
				while ($row = mysqli_fetch_array($resultselect)) {
				echo "<option>".$row['domain']."</option>";
				}
				?>
							</select>
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-4" for="password">Password:</label>
						<div class="col-sm-8">
						<input type="password" class="form-control" name="password" id="password" placeholder="">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-4" for="password2">Password (repeat):</label>
						<div class="col-sm-8">
						<input type="password" class="form-control" name="password2" id="password2" placeholder="">
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-4 col-sm-8">
							<div class="checkbox">
							<label><input type="checkbox" name="active" checked> Active</label>
							</div>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-0 col-sm-8">
							<button type="submit" name="trigger_add_domain_admin" class="btn btn-default">Add domain admin</button>
						</div>
					</div>
				</form>
				</small>
			</div>
		</div>
	</div>
</div>

<h4><span class="glyphicon glyphicon-wrench" aria-hidden="true"></span> Configuration</h4>
<div class="panel-group" id="accordion_config">
<div class="panel panel-default">
<div class="panel-heading" data-toggle="collapse" data-parent="#accordion_config" data-target="#collapseBackup"><a style="cursor:pointer;" class="accordion-toggle">Backup mail</a></div>
<div id="collapseBackup" class="panel-collapse collapse in">
<div class="panel-body">
<form class="form-horizontal" role="form" method="post">
	<div class="form-group">
		<label class="control-label col-sm-4" for="location">Location (<kbd>aA-zZ, 0-9, -, _, /</kbd>)<small>, will be created if missing</small>:</label>
		<div class="col-sm-8">
			<input type="text" class="form-control" name="location" id="location" value="<?=return_mailcow_config("backup_location");?>">
		</div>
	</div>
	<div class="form-group">
		<label class="control-label col-sm-4" for="runtime">Runtime:</label>
		<div class="col-sm-8">
			<select title="Select a runtime..." style="width:50%" name="runtime">
				<option <?php if (return_mailcow_config("backup_runtime") == "hourly") { echo "selected"; } ?>>hourly</option>
				<option <?php if (return_mailcow_config("backup_runtime") == "daily") { echo "selected"; } ?>>daily</option>
				<option <?php if (return_mailcow_config("backup_runtime") == "weekly") { echo "selected"; } ?>>weekly</option>
				<option <?php if (return_mailcow_config("backup_runtime") == "monthly") { echo "selected"; } ?>>monthly</option>
			</select>
		</div>
	</div>
	<div class="form-group">
		<label class="control-label col-sm-4" for="mailboxes[]">Select mailbox(es):</label>
		<div class="col-sm-8">
			<select data-placeholder="Search users..." style="width:100%" name="mailboxes[]" multiple>
<?php
$resultselect = mysqli_query($link, "SELECT username FROM mailbox");
while ($row = mysqli_fetch_array($resultselect)) {
	if (strpos(file_get_contents($MC_MBOX_BACKUP), $row['username'])) {
		echo "<option selected>".$row['username']."</option>";
	}
	else {
		echo "<option>".$row['username']."</option>";
	}
}
?>
			</select>
		</div>
	</div>
	<div class="clearfix"></div>
	<div class="form-group">
		<div class="col-sm-offset-4 col-sm-8">
			<div class="checkbox">
			<label><input type="checkbox" name="use_backup" <?php if (return_mailcow_config("backup_active") == "on") { echo "checked"; } ?>> Use backup function</label>
			</div>
		</div>
	</div>
	<div class="clearfix"></div>
	<div class="form-group">
	<input type="hidden" name="trigger_backup">
		<div class="col-sm-8">
			<button type="submit" class="btn btn-default">Save changes</button>
		</div>
	</div>
</form>
</div>
</div>
</div>

<div class="panel panel-default">
<div class="panel-heading" data-toggle="collapse" data-parent="#accordion_config" data-target="#collapseSrr"><a style="cursor:pointer;" class="accordion-toggle">Postfix restrictions</a></div>
<div id="collapseSrr" class="panel-collapse collapse">
<div class="panel-body">
<?php
$srr_values = return_mailcow_config("srr");
?>
<form class="form-horizontal" role="form" method="post">
	<div class="form-group">
		<label class="control-label col-sm-4" for="location">Recipient restrictions</label>
		<div class="col-sm-8">
			<div class="checkbox">
			<label><input type="checkbox" name="reject_invalid_helo_hostname" <?php if (preg_match('/reject_invalid_helo_hostname/', $srr_values)) { echo "checked"; } ?>> Reject invalid HELO hostnames <b>(reject_invalid_helo_hostname)</b></label>
			</div>
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-offset-4 col-sm-8">
			<div class="checkbox">
			<label><input type="checkbox" name="reject_unknown_helo_hostname" <?php if (preg_match('/reject_unknown_helo_hostname/', $srr_values)) { echo "checked"; } ?>> Reject unknown HELO hostname (no MX- or A-Record) <b>(reject_unknown_helo_hostname)</b></label>
			</div>
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-offset-4 col-sm-8">
			<div class="checkbox">
			<label><input type="checkbox" name="reject_unknown_reverse_client_hostname" <?php if (preg_match('/reject_unknown_reverse_client_hostname/', $srr_values)) { echo "checked"; } ?>> Reject when the client IP address has no address -> name mapping (missing/invalid PTR check) <b>(reject_unknown_reverse_client_hostname)</b></label>
			</div>
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-offset-4 col-sm-8">
			<div class="checkbox">
			<label><input type="checkbox" name="reject_unknown_client_hostname" <?php if (preg_match('/reject_unknown_client_hostname/', $srr_values)) { echo "checked"; } ?>> Reject when the client IP address has no address -> name mapping and/or returned name does not match the IP (exact PTR match check) <b>(reject_unknown_client_hostname)</b></label>
			</div>
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-offset-4 col-sm-8">
			<div class="checkbox">
			<label><input type="checkbox" name="reject_non_fqdn_helo_hostname" <?php if (preg_match('/reject_non_fqdn_helo_hostname/', $srr_values)) { echo "checked"; } ?>> Reject when HELO hostname is not a FQDN <b>(reject_non_fqdn_helo_hostname)</b></label>
			</div>
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-offset-4 col-sm-8">
			<div class="checkbox">
			<label><input type="checkbox" name="z1_greylisting" <?php if (preg_match('/z1_greylisting/', $srr_values)) { echo "checked"; } ?>> Use greylisting for unauthenticated, unknown and not whitelisted senders</label>
			</div>
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-8">
			<button type="submit" name="srr" class="btn btn-default">Save changes</button>
		</div>
	</div>
</form>
</div>
</div>
</div>


<div class="panel panel-default">
<div class="panel-heading" data-toggle="collapse" data-parent="#accordion_config" data-target="#collapsePubFolders"><a style="cursor:pointer;" class="accordion-toggle">Public folders</a></div>
<div id="collapsePubFolders" class="panel-collapse collapse">
<div class="panel-body">
<p>A namespace "Public" is created. Belows public folder name indicates the name of the first auto-created mailbox within this namespace.</p>
<form class="form-horizontal" role="form" method="post">
	<div class="form-group">
		<label class="control-label col-sm-4" for="location">Folder name <small>(alphanumeric)</small>:</label>
		<div class="col-sm-8">
		<input type="text" class="form-control" name="public_folder_name" id="public_folder_name" value="<?=return_mailcow_config("public_folder_name");?>">
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-offset-4 col-sm-8">
			<div class="checkbox">
			<label><input type="checkbox" name="use_public_folder" <?=return_mailcow_config("public_folder_status");?>> Enable public folder</label>
			</div>
			<small>Toggling this option does not delete mail in any public folder.</small>
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-offset-4 col-sm-8">
			<div class="checkbox">
			<label><input type="checkbox" name="public_folder_pvt" <?=return_mailcow_config("public_folder_pvt");?>> Enable per-user seen flag</label>
			</div>
			<small>A "per-user seen flag"-enabled system will not mark a mail as read for User B, when User A has seen it, but User B did not.</small>
		</div>
	</div>
	<div class="form-group">
	<input type="hidden" name="trigger_public_folder">
		<div class="col-sm-8">
			<button type="submit" class="btn btn-default">Save changes</button>
		</div>
	</div>
</form>
</div>
</div>
</div>

<div class="panel panel-default">
<div class="panel-heading" data-toggle="collapse" data-parent="#accordion_config" data-target="#collapsePrivacy"><a style="cursor:pointer;" class="accordion-toggle">Privacy</a></div>
<div id="collapsePrivacy" class="panel-collapse collapse">
<div class="panel-body">
<p>This option enables a PCRE table to remove "User-Agent", "X-Enigmail", "X-Mailer", "X-Originating-IP" and replaces "Received: from" headers with localhost/127.0.0.1.</p>
<form class="form-horizontal" role="form" method="post">
	<div class="form-group">
		<div class="col-sm-8">
			<div class="checkbox">
				<label><input name="anonymize" type="checkbox" <?=return_mailcow_config("anonymize");?>> Anonymize outgoing mail</label>
			</div>
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-8">
			<button type="submit" name="trigger_anonymize" class="btn btn-default">Apply</button>
		</div>
	</div>
</form>
</div>
</div>
</div>

<div class="panel panel-default">
<div class="panel-heading" data-toggle="collapse" data-parent="#accordion_config" data-target="#collapseDKIM"><a style="cursor:pointer;" class="accordion-toggle">DKIM signing</a></div>
<div id="collapseDKIM" class="panel-collapse collapse">
<div class="panel-body">
<p>Default behaviour is to sign with relaxed header and body canonicalization algorithm.</p>
<h4>Active keys</h4>
<?php
opendkim_table();
?>
<h4>Add new key</h4>
<form class="form-inline" role="form" method="post">
	<div class="form-group">
		<label for="dkim_domain">Domain</label>
		<input class="form-control" id="dkim_domain" name="dkim_domain" placeholder="example.org">
	</div>
	<div class="form-group">
		<label for="dkim_selector">Selector</label>
		<input class="form-control" id="dkim_selector" name="dkim_selector" placeholder="default">
	</div>
	<button type="submit" class="btn btn-default"><span class="glyphicon glyphicon-plus"></span> Add</button>
</form>
</div>
</div>
</div>

<div class="panel panel-default">
<div class="panel-heading" data-toggle="collapse" data-parent="#accordion_config" data-target="#collapseMsgSize"><a style="cursor:pointer;" class="accordion-toggle">Message size</a></div>
<div id="collapseMsgSize" class="panel-collapse collapse">
<div class="panel-body">
<form class="form-inline" method="post">
	<p>Current message size limitation: <strong><?=return_mailcow_config("maxmsgsize");?>MB</strong></p>
	<p>This changes your webservers and Postfix configuration. Services will be reloaded.</p>
	<div class="form-group">
		<input type="number" class="form-control" id="maxmsgsize" name="maxmsgsize" placeholder="in MB" min="1" max="250">
	</div>
	<button type="submit" class="btn btn-default">Set</button>
</form>
</div>
</div>
</div>

</div>

<h4><span class="glyphicon glyphicon-dashboard" aria-hidden="true"></span> Maintenance</h4>
<div class="panel-group" id="accordion_maint">
<div class="panel panel-default">
<div class="panel-heading" data-toggle="collapse" data-parent="#accordion_maint" data-target="#collapseSysinfo"><a style="cursor:pointer;" class="accordion-toggle">System Information</a></div>
<div id="collapseSysinfo" class="panel-collapse collapse in">
<div class="panel-body">
<p>This is a very simple system information function. Please be aware that a high RAM usage is what you want on a server.</p>
<div class="row">
	<div class="col-md-6">
		<h4>Disk usage (/var/vmail) - <?=formatBytes(disk_free_space('/var/vmail'))?> free (<?=formatBytes(disk_total_space('/var/vmail'))?> total)</h4>
		<div class="progress">
		  <div class="progress-bar progress-bar-info progress-bar-striped" role="progressbar" aria-valuenow="<?php echo_sys_info("maildisk");?>"
		  aria-valuemin="0" aria-valuemax="100" style="width:<?php echo_sys_info("maildisk");?>%">
		  </div>
		</div>
	</div>
	<div class="col-md-6">
		<h4>RAM usage - <?php echo_sys_info("ram");?>%</h4>
		<div class="progress">
		  <div class="progress-bar progress-bar-info progress-bar-striped" role="progressbar" aria-valuenow="<?php echo_sys_info("ram");?>"
		  aria-valuemin="0" aria-valuemax="100" style="width:<?php echo_sys_info("ram");?>%">
		  </div>
		</div>
	</div>
</div>
<h4>Mail queue</h4>
<pre>
<?php echo_sys_info("mailq");?>
</pre>
<h4>Pflogsumm</h4>
<textarea rows="20" style="font-family:monospace;font-size:9pt;width:100%;">
<?php echo_sys_info("pflog");?>
</textarea>
<p>Last refresh: <?=round(abs(date('U') - filemtime($PFLOG)) / 60,0). " minutes ago";?></p>

<form method="post">
	<div class="form-group">
		<input type="hidden" name="pflog_renew" value="1">
		<button type="submit" class="btn btn-default">Refresh Pflogsumm log</button>
	</div>
</form>
<h4>Mailgraph</h4>
<?php echo_sys_info("mailgraph");?>
</div>
</div>
</div>

<?php
}
elseif (isset($_SESSION['mailcow_cc_loggedin']) && $_SESSION['mailcow_cc_loggedin'] == "yes" && $_SESSION['mailcow_cc_role'] == "domainadmin") {
	header('Location: mailbox.php');
	die("Permission denied");
}
elseif (isset($_SESSION['mailcow_cc_loggedin']) && $_SESSION['mailcow_cc_loggedin'] == "yes" && $_SESSION['mailcow_cc_role'] == "user") {
	header('Location: user.php');
	die("Permission denied");
} else {
	if (!function_exists('exec') || !function_exists('shell_exec')):
?>
		<div class="alert alert-danger">Please enable "exec" and "shell_exec" PHP functions.</div>
<?php
	endif;
?>
<div class="panel panel-default">
<div class="panel-heading">Login</div>
<div class="panel-body">
<form method="post">
	<div class="form-group">
		<label for="login_user">Username / Email address:</label>
		<input name="login_user" autocorrect="off" autocapitalize="none" type="name" id="login_user" class="form-control" required autofocus>
	</div>
	<div class="form-group">
		<label for="login_user">Password:</label>
		<input name="pass_user" type="password" id="pass_user" class="form-control" required>
	</div>
	<button type="submit" class="btn btn-sm btn-success" value="Login">Login</button>
	<a class="btn btn-sm btn-primary" href="/rc">Webmail</a>
	<hr>
	<p><strong>Hint:</strong> Run "mc_resetadmin" from a shell to reset the password.</p>
</form>
</div>
</div>

<?php
}
?>
<br />
<p><b><a href="/admin">&#8592; go back</a></b></p>
</div> <!-- /container -->
<?php
require_once("inc/footer.inc.php");
?>
