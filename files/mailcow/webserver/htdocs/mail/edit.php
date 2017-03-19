<?php
require_once("inc/header.inc.php");
?>
<div class="container">
	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-default">
				<div class="panel-heading">
					<h3 class="panel-title">Edit</h3>
				</div>
				<div class="panel-body">
<?php
require_once "inc/triggers.inc.php";
if (isset($_SESSION['mailcow_cc_loggedin']) &&
		isset($_SESSION['mailcow_cc_role']) &&
		$_SESSION['mailcow_cc_loggedin'] == "yes" &&
		$_SESSION['mailcow_cc_role'] != "user") {
	if (isset($_GET['alias'])) {
		if (!filter_var($_GET["alias"], FILTER_VALIDATE_EMAIL) || empty($_GET["alias"])) {
			echo 'Incorrect form data';
		}
		else {
			$alias = mysqli_real_escape_string($link, $_GET["alias"]);
			if (mysqli_num_rows(mysqli_query($link, "SELECT address, domain FROM alias WHERE address='$alias' AND (domain IN (SELECT domain from domain_admins WHERE username='$logged_in_as') OR 'admin'='$logged_in_role');")) > 0) {
			$result = mysqli_fetch_assoc(mysqli_query($link, "SELECT active, goto FROM alias WHERE address='$alias'"));
?>
				<h4>Change alias attributes for <strong><?=$alias;?></strong></h4>
				<br />
				<form class="form-horizontal" role="form" method="post">
				<input type="hidden" name="address" value="<?=$alias;?>">
					<div class="form-group">
						<label class="control-label col-sm-2" for="name">Destination address(es) <small>(comma-separated values)</small>:</label>
						<div class="col-sm-10">
							<textarea class="form-control" autocapitalize="none" autocorrect="off" rows="10" name="goto"><?=$result['goto'] ?></textarea>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<div class="checkbox">
							<label><input type="checkbox" name="active" <?php if (isset($result['active']) && $result['active']=="1") { echo "checked"; }; ?>> Active</label>
							</div>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="editalias" class="btn btn-success btn-sm">Submit</button>
						</div>
					</div>
				</form>
<?php
			}
			else {
				echo 'Item not found or no permission.';
			}
		}
	}
	elseif (isset($_GET['domain_admin'])) {
		if (!ctype_alnum(str_replace(array('@', '.', '-'), '', $_GET["domain_admin"])) || empty($_GET["domain_admin"])) {
			echo 'Incorrect form data';
		}
		else {
			$domain_admin = mysqli_real_escape_string($link, $_GET["domain_admin"]);
			if (mysqli_num_rows(mysqli_query($link, "SELECT username FROM domain_admins WHERE username='$domain_admin'")) > 0 && $logged_in_role == "admin") {
			$result = mysqli_fetch_assoc(mysqli_query($link, "SELECT * FROM domain_admins WHERE username='$domain_admin'"));
	?>
				<h4>Change assigned domains for domain administrator <strong><?=$domain_admin;?></strong></h4>
				<br />
				<form class="form-horizontal" role="form" method="post">
				<input type="hidden" name="username" value="<?=$domain_admin;?>">
					<div class="form-group">
						<label class="control-label col-sm-2" for="name">Target domain <small>(hold CTRL to select multiple domains)</small>:</label>
						<div class="col-sm-10">
							<select name="domain[]" multiple>
<?php
$result_selected = mysqli_query($link, "SELECT domain FROM domain WHERE domain IN (SELECT domain FROM domain_admins WHERE username='".$domain_admin."')");
while ($row_selected = mysqli_fetch_array($result_selected)):
?>
	<option selected><?=$row_selected['domain'];?></option>
<?php
endwhile;
$result_unselected = mysqli_query($link, "SELECT domain FROM domain WHERE domain NOT IN (SELECT domain FROM domain_admins WHERE username='".$domain_admin."')");
while ($row_unselected = mysqli_fetch_array($result_unselected)):
?>
	<option><?=$row_unselected['domain'];?></option>
<?php
endwhile;
?>
							</select>
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="password">Password:</label>
						<div class="col-sm-10">
						<input type="password" class="form-control" name="password" id="password" placeholder="Unchanged if empty">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="password2">Password (repeat):</label>
						<div class="col-sm-10">
						<input type="password" class="form-control" name="password2" id="password2">
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<div class="checkbox">
							<label><input type="checkbox" name="active" <?php if (isset($result['active']) && $result['active']=="1") { echo "checked"; }; ?>> Active</label>
							</div>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="editdomainadmin" class="btn btn-success btn-sm">Submit</button>
						</div>
					</div>
				</form>
	<?php
			}
			else {
				echo 'Item not found or no permission.';
			}
		}
	}
	elseif (isset($_GET['domain'])) {
		if (!is_valid_domain_name($_GET["domain"]) || empty($_GET["domain"])) {
			echo 'Incorrect form data';
		}
		else {
			$domain = mysqli_real_escape_string($link, $_GET["domain"]);
			if (mysqli_fetch_array(mysqli_query($link, "SELECT domain FROM domain WHERE domain='$domain' AND ((domain IN (SELECT domain from domain_admins WHERE username='$logged_in_as') OR 'admin'='$logged_in_role'))"))) {
			$result = mysqli_fetch_assoc(mysqli_query($link, "SELECT * FROM domain WHERE domain='$domain'"));
	?>
				<h4>Change settings for domain <strong><?=$domain;?></strong></h4>
				<form class="form-horizontal" role="form" method="post">
				<input type="hidden" name="domain" value="<?=$domain;?>">
					<div class="form-group">
						<label class="control-label col-sm-2" for="description">Description:</label>
						<div class="col-sm-10">
						<input type="text" class="form-control" name="description" id="description" value="<?=htmlspecialchars($result['description']);?>">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="aliases">Max. aliases:</label>
						<div class="col-sm-10">
						<input type="number" class="form-control" name="aliases" id="aliases" value="<?=$result['aliases'];?>">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="mailboxes">Max. mailboxes:</label>
						<div class="col-sm-10">
						<input type="number" class="form-control" name="mailboxes" id="mailboxes" value="<?=$result['mailboxes'];?>">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="maxquota">Max. size per mailbox (MB):</label>
						<div class="col-sm-10">
						<input type="number" class="form-control" name="maxquota" id="maxquota" value="<?=$result['maxquota'];?>">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="quota">Domain quota:</label>
						<div class="col-sm-10">
						<input type="number" class="form-control" name="quota" id="quota" value="<?=$result['quota'];?>">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2">Backup MX options:</label>
						<div class="col-sm-10">
							<div class="checkbox">
							<label><input type="checkbox" name="backupmx" <?php if (isset($result['backupmx']) && $result['backupmx']=="1") { echo "checked"; }; ?>> Relay domain</label>
							<br />
							<label><input type="checkbox" name="relay_all_recipients" <?php if (isset($result['relay_all_recipients']) && $result['relay_all_recipients']=="1") { echo "checked"; }; ?>> Relay all recipient addresses</label>
							<p><small>If you choose not to relay all recipient addresses, a mailbox must be created for each recipient on this server.</small></p>
							</div>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<div class="checkbox">
							<label><input type="checkbox" name="active" <?php if (isset($result['active']) && $result['active']=="1") { echo "checked"; }; ?>> Active</label>
							</div>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="editdomain" class="btn btn-success btn-sm">Submit</button>
						</div>
					</div>
				</form>
	<?php
			}
			else {
				echo 'Item not found or no permission.';
			}
		}
	}
	elseif (isset($_GET['mailbox'])) {
		if (!filter_var($_GET["mailbox"], FILTER_VALIDATE_EMAIL) || empty($_GET["mailbox"])) {
			echo 'Incorrect form data';
		}
		else {
			$mailbox = mysqli_real_escape_string($link, $_GET["mailbox"]);
			if (mysqli_num_rows(mysqli_query($link, "SELECT username, domain FROM mailbox WHERE username='".$mailbox."' AND ((domain IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'='".$logged_in_role."'))")) > 0) {
			$result = mysqli_fetch_assoc(mysqli_query($link, "SELECT username, domain, name, round(sum(quota / 1048576)) as quota, active FROM mailbox WHERE username='".$mailbox."'"));
	?>
				<h4>Change settings for mailbox <strong><?=$mailbox;?></strong></h4>
				<form class="form-horizontal" role="form" method="post">
				<input type="hidden" name="username" value="<?=$result['username'];?>">
					<div class="form-group">
						<label class="control-label col-sm-2" for="name">Name:</label>
						<div class="col-sm-10">
						<input type="text" class="form-control" name="name" id="name" value="<?=$result['name'];?>">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="quota">Quota (MB), 0 = unlimited:</label>
						<div class="col-sm-10">
						<input type="number" class="form-control" name="quota" id="quota" value="<?=$result['quota'];?>">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="quota">Sender ACL:</label>
						<div class="col-sm-10">
							<select title="Search users..." style="width:100%" name="sender_acl[]" size="10" multiple>
							<?php
							$result_goto_from_alias = mysqli_query($link, "SELECT address FROM alias
								WHERE goto='".$mailbox."'");
							while ($row_goto_from_alias = mysqli_fetch_array($result_goto_from_alias)):
							?>
								<option selected disabled="disabled"><?=$row_goto_from_alias['address'];?></option>
							<?php
							endwhile;

							$result_selected_sender_acl = mysqli_query($link, "SELECT send_as FROM sender_acl
								WHERE logged_in_as='".$mailbox."'");
							while ($row_selected_sender_acl = mysqli_fetch_array($result_selected_sender_acl)):
								?>
									<option selected><?=$row_selected_sender_acl['send_as'];?></option>
								<?php
							endwhile;

							$result_unselected_sender_acl = mysqli_query($link, "SELECT address FROM alias
								WHERE goto!='".$mailbox."' AND
								domain='".$result['domain']."' AND
								address NOT IN (SELECT send_as FROM sender_acl WHERE logged_in_as='".$mailbox."')");
							while ($row_unselected_sender_acl = mysqli_fetch_array($result_unselected_sender_acl)):
							?>
								<option><?=$row_unselected_sender_acl['address'];?></option>
							<?php
							endwhile;
							?>
							</select>
							<p><small>Usernames and aliases cannot be removed from sender list.</small></p>
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="password">Password:</label>
						<div class="col-sm-10">
						<input type="password" class="form-control" name="password" id="password" placeholder="Unchanged if empty">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="password2">Password (repeat):</label>
						<div class="col-sm-10">
						<input type="password" class="form-control" name="password2" id="password2">
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<div class="checkbox">
							<label><input type="checkbox" name="active" <?php if (isset($result['active']) && $result['active']=="1") { echo "checked"; }; ?>> Active</label>
							</div>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="editmailbox" class="btn btn-success btn-sm">Submit</button>
						</div>
					</div>
				</form>
	<?php
			}
			else {
				echo 'Item not found or no permission.';
			}
		}
	}
	else {
		echo '<div class="alert alert-danger" role="alert"><strong>Error:</strong>  No action specified.</div>';
	}
}
elseif (isset($_SESSION['mailcow_cc_loggedin']) &&
		isset($_SESSION['mailcow_cc_role']) &&
		$_SESSION['mailcow_cc_loggedin'] == "yes" &&
		$_SESSION['mailcow_cc_role'] == "user") {
	if (isset($_GET['dav'])) {
		if (!filter_var($_GET["dav"], FILTER_VALIDATE_EMAIL) || empty($_GET["dav"])) {
			echo 'Incorrect form data';
		}
		else {
			$dav = mysqli_real_escape_string($link, $_GET["dav"]);
			if ($dav == $logged_in_as) {
?>
				<h4>Change DAV folder properties</h4>
				<p>Share your calendars with other users.</p>
				<form class="form-horizontal" role="form" method="post">
				<div class="row">
					<div class="col-sm-6">
						<p><b>Read-only</b></p>
						<select title="Search users..." style="width:100%" name="cal_ro_share[]" size="5" multiple>
						<?php
						$result_rcrs = mysqli_query($link, "SELECT email FROM principals
							WHERE id IN (SELECT member_id FROM groupmembers
								WHERE principal_id IN (SELECT id FROM principals
									WHERE uri='principals/$logged_in_as/calendar-proxy-read'))");
						while ($row_cal_ro_selected = mysqli_fetch_array($result_rcrs)):
						?>
							<option selected><?=$row_cal_ro_selected['email'];?></option>
						<?php
						endwhile;

						$result_rcru = mysqli_query($link, "SELECT email FROM principals
							WHERE id NOT IN (SELECT member_id FROM groupmembers
								WHERE principal_id IN (SELECT id FROM principals
									WHERE uri='principals/$logged_in_as/calendar-proxy-read'))
							AND email IS NOT NULL
							AND email!='$logged_in_as'");
						while ($row_cal_ro_unselected = mysqli_fetch_array($result_rcru)):
						?>
							<option><?=$row_cal_ro_unselected['email'];?></option>
						<?php
						endwhile;
						?>
						</select>
					</div>
					<div class="col-sm-6">
						<p><b>Read-write</b></p>
						<select title="Search users..." style="width:100%" name="cal_rw_share[]" size="5" multiple>
						<?php
						$result_rcrws = mysqli_query($link, "SELECT email FROM principals
							WHERE id IN (SELECT member_id FROM groupmembers
								WHERE principal_id IN (SELECT id FROM principals
									WHERE uri='principals/$logged_in_as/calendar-proxy-write'))");
						while ($row_cal_rw_selected = mysqli_fetch_array($result_rcrws)):
						?>
							<option selected><?=$row_cal_rw_selected['email'];?></option>
						<?php
						endwhile;
						$result_rcrwu = mysqli_query($link, "SELECT email FROM principals
							WHERE id NOT IN (SELECT member_id FROM groupmembers
								WHERE principal_id IN (SELECT id FROM principals
									WHERE uri='principals/$logged_in_as/calendar-proxy-write'))
							AND email IS NOT NULL
							AND email!='$logged_in_as'");
						while ($row_cal_rw_unselected = mysqli_fetch_array($result_rcrwu)):
						?>
							<option><?=$row_cal_rw_unselected['email'];?></option>
						<?php
						endwhile;
						?>
						</select>
					</div>
				</div>
				<br />
				<p>Edit or delete address books and calendars below.
				<br /><b>Note:</b> Default address books and calendars cannot be deleted.</p>
				<div class="table-responsive">
				<table class="table table-striped">
					<thead>
					<tr>
						<th>Type</th>
						<th>Display name</th>
						<th style="text-align:center;width:65px">Delete</th>
					</tr>
					</thead>
					<tbody>
					<?php
					$result_row_cal = mysqli_query($link, "SELECT id, uri, displayname FROM calendars WHERE principaluri='principals/$logged_in_as'");
					while ($row_cal = mysqli_fetch_array($result_row_cal)):
					?>
					<tr>
						<td>Calendar, Tasks</td>
						<td><input type="text" style="width:100%" name="cal_displayname[<?=$row_cal['id'];?>]" value="<?=$row_cal['displayname'];?>"></td>
						<?php
						if ($row_cal['uri'] != "default"):
						?>
						<td style="text-align:center"><input type="checkbox" name="cal_delete[]" value="<?=$row_cal['id'];?>"></td>
						<?php
						else:
						?>
						<td style="text-align:center"><input type="checkbox" disabled></td>
						<?php
						endif;
						?>
					</tr>
					<?php
					endwhile;
					$result_row_adb = mysqli_query($link, "SELECT id, uri, displayname FROM addressbooks WHERE principaluri='principals/$logged_in_as'");
					while ($row_adb = mysqli_fetch_array($result_row_adb)):
					?>
					<tr>
						<td>Address book</td>
						<td><input type="text" style="width:100%" name="adb_displayname[<?=$row_adb['id'];?>]" value="<?=$row_adb['displayname'];?>"></td>
						<?php
						if ($row_adb['uri'] != "default"):
						?>
						<td style="text-align:center"><input type="checkbox" name="adb_delete[]" value="<?=$row_adb['id'];?>"></td>
						<?php
						else:
						?>
						<td style="text-align:center"><input type="checkbox" disabled></td>
						<?php
						endif;
						?>
					</tr>
					<?php
					endwhile;
					?>
					</tbody>
				</table>
				</div>
				<div class="form-group">
					<div class="col-sm-offset-2 col-sm-10">
						<button type="submit" name="trigger_mailbox_action" value="editdav" class="btn btn-success btn-sm">Apply</button>
					</div>
				</div>
				</form>
	<?php
			}
			else {
				echo 'Item not found or no permission.';
			}
		}
	}
	else {
		echo '<div class="alert alert-danger" role="alert"><strong>Error:</strong>  No valid action specified.</div>';
	}
}
else {
	echo '<div class="alert alert-danger" role="alert">Permission denied';
}
?>
				</div>
			</div>
		</div>
	</div>
<a href="<?=$_SESSION['return_to'];?>">&#8592; go back</a>
</div> <!-- /container -->
<?php
require_once("inc/footer.inc.php");
?>
