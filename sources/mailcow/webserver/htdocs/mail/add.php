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
	if (isset($_GET['domain'])) {
?>
				<h4>Add domain</h4>
				<form class="form-horizontal" role="form" method="post">
					<div class="form-group">
						<label class="control-label col-sm-2" for="domain">Domain name:</label>
						<div class="col-sm-10">
						<input type="text" autocorrect="off" autocapitalize="none" class="form-control" name="domain" id="domain" placeholder="Domain to receive mail for">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="description">Description:</label>
						<div class="col-sm-10">
						<input type="text" class="form-control" name="description" id="description" placeholder="Description">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="aliases">Max. aliases:</label>
						<div class="col-sm-10">
						<input type="number" class="form-control" name="aliases" id="aliases" value="200">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="mailboxes">Max. mailboxes:</label>
						<div class="col-sm-10">
						<input type="number" class="form-control" name="mailboxes" id="mailboxes" value="50">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="maxquota">Max. size per mailbox (MB):</label>
						<div class="col-sm-10">
						<input type="number" class="form-control" name="maxquota" id="maxquota" value="4096">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="quota">Domain quota:</label>
						<div class="col-sm-10">
						<input type="number" class="form-control" name="quota" id="quota" value="10240">
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
							<label><input type="checkbox" name="active" checked> Active</label>
							</div>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="adddomain" class="btn btn-success">Submit</button>
						</div>
					</div>
				</form>
<?php
	}
	elseif (isset($_GET['alias'])) {
?>
				<h4>Add alias</h4>
				<form class="form-horizontal" role="form" method="post">
					<div class="form-group">
						<label class="control-label col-sm-2" for="address">Alias address(es) <small>(full email address OR @example.com for <span style='color:#ec466a'>catch-all</span>)</small> - comma separated:</label>
						<div class="col-sm-10">
							<textarea autocorrect="off" autocapitalize="none" class="form-control" rows="5" name="address"></textarea>
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="goto" placeholder="first@example.net, second@example.net">Destination address(es) - comma separated:</label>
						<div class="col-sm-10">
							<textarea autocorrect="off" autocapitalize="none" class="form-control" rows="5" name="goto"></textarea>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<div class="checkbox">
							<label><input type="checkbox" name="active" checked> Active</label>
							</div>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="addalias" class="btn btn-success ">Submit</button>
						</div>
					</div>
				</form>
<?php
	}
	elseif (isset($_GET['alias_domain'])) {
?>
				<h4>Add domain alias</h4>
				<form class="form-horizontal" role="form" method="post">
					<div class="form-group">
						<label class="control-label col-sm-2" for="alias_domain">Alias domain:</label>
						<div class="col-sm-10">
							<select name="alias_domain" size="1">
<?php
$result = mysqli_query($link, "SELECT domain FROM domain WHERE domain IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'='".$logged_in_role."'");
while ($row = mysqli_fetch_array($result)) {
	echo "<option>".$row['domain']."</option>";
}
?>
							</select>
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="name">Target domain:</label>
						<div class="col-sm-10">
							<select name="target_domain" size="1">
<?php
$result = mysqli_query($link, "SELECT domain FROM domain WHERE domain IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'='".$logged_in_role."'");
while ($row = mysqli_fetch_array($result)) {
	echo "<option>".$row['domain']."</option>";
}
?>
							</select>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<div class="checkbox">
							<label><input type="checkbox" name="active" checked> Active</label>
							</div>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="addaliasdomain" class="btn btn-success ">Submit</button>
						</div>
					</div>
				</form>
<?php
	}
	elseif (isset($_GET['mailbox'])) {
	?>
				<h4>Add a mailbox</h4>
				<form class="form-horizontal" role="form" method="post">
					<div class="form-group">
						<label class="control-label col-sm-2" for="local_part">Mailbox Alias (left part of mail address) <small>(alphanumeric)</small>:</label>
						<div class="col-sm-10">
							<input type="text" autocorrect="off" autocapitalize="none" pattern="[a-zA-Z0-9.- ]+" class="form-control" name="local_part" id="local_part" required>
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="name">Select domain:</label>
						<div class="col-sm-10">
							<select name="domain" size="1">
<?php
$result = mysqli_query($link, "SELECT domain FROM domain WHERE domain IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'='".$logged_in_role."'");
while ($row = mysqli_fetch_array($result)) {
	echo "<option>".$row['domain']."</option>";
}
?>
							</select>
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="name">Name:</label>
						<div class="col-sm-10">
						<input type="text" class="form-control" name="name" id="name">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="quota">Quota (MB), 0 = unlimited:</label>
						<div class="col-sm-10">
						<input type="number" class="form-control" name="quota" id="quota" value="1024">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="password">Password:</label>
						<div class="col-sm-10">
						<input type="password" class="form-control" name="password" id="password" placeholder="">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="password2">Password (repeat):</label>
						<div class="col-sm-10">
						<input type="password" class="form-control" name="password2" id="password2" placeholder="">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="default_cal">Default calendar name:</label>
						<div class="col-sm-10">
						<input type="text" class="form-control" name="default_cal" id="default_cal" value="Calendar">
						</div>
					</div>
					<div class="form-group">
						<label class="control-label col-sm-2" for="default_card">Default address book name:</label>
						<div class="col-sm-10">
						<input type="text" class="form-control" name="default_card" id="default_card" value="Address book">
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<div class="checkbox">
							<label><input type="checkbox" name="active" checked> Active</label>
							</div>
						</div>
					</div>
					<div class="form-group">
						<div class="col-sm-offset-2 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="addmailbox" class="btn btn-success ">Submit</button>
						</div>
					</div>
				</form>
<?php
	}
	else {
		echo '<div class="alert alert-danger" role="alert"><strong>Error:</strong> No valid action specified.</div>';
	}
}
elseif (isset($_SESSION['mailcow_cc_loggedin']) &&
		isset($_SESSION['mailcow_cc_role']) &&
		$_SESSION['mailcow_cc_loggedin'] == "yes" &&
		$_SESSION['mailcow_cc_role'] == "user") {
	if (isset($_GET['dav'])) {
?>
			<h4>Add DAV item</h4>
			<form class="form-horizontal" role="form" method="post">
				<div class="form-group">
					<label class="control-label col-sm-2" for="displayname">Display name:</label>
					<div class="col-sm-10">
					<input type="text" class="form-control" name="displayname" id="displayname" required>
					</div>
				</div>
				<div class="form-group">
					<label class="col-sm-2 control-label">DAV type:</label>
					<div class="col-sm-10">
						<div class="radio radio-default">
							<label>
								<input type="radio" name="davtype" id="davtype_calendar" value="calendar" checked>
								Calendar and tasks
							</label>
						</div>
						<div class="radio radio-default">
							<label>
								<input type="radio" name="davtype" id="davtype_addressbook" value="addressbook">
								Address book
							</label>
						</div>
					</div>
				</div>
				<div class="form-group">
					<div class="col-sm-offset-2 col-sm-10">
						<button type="submit" name="trigger_mailbox_action" value="adddav" class="btn btn-success ">Submit</button>
					</div>
				</div>
			</form>
<?php
	}
	else {
		echo '<div class="alert alert-danger" role="alert"><strong>Error:</strong> No valid action specified.</div>';
	}
}
else {
	echo '<div class="alert alert-danger" role="alert">Permission denied</div>';
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
