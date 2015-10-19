<?php
require_once("inc/header.inc.php");
if (isset($_SESSION['mailcow_cc_loggedin']) && $_SESSION['mailcow_cc_loggedin'] == "yes" && $_SESSION['mailcow_cc_role'] == "user") {
$_SESSION['return_to'] = basename($_SERVER['PHP_SELF']);
$user_details = mysqli_query($link, "SELECT name, username FROM mailbox WHERE username='".$logged_in_as."'");
?>


<div class="container">
<div class="panel panel-default">
<div class="panel-heading">Change user details</div>
<div class="panel-body">
<form class="form-horizontal" role="form" method="post">
	<input type="hidden" name="user_now" value="<?=$logged_in_as;?>">
	<div class="form-group">
		<label class="control-label col-sm-3" for="user_old_pass">Display name:</label>
		<div class="col-sm-5">
		<input type="text" class="form-control" name="user_real_name" id="user_real_name" value="<?=htmlspecialchars(mysqli_fetch_assoc($user_details)['name']);?>" required>
		</div>
	</div>
	<hr>
	<div class="form-group">
		<label class="control-label col-sm-3" for="user_old_pass">Current password:</label>
		<div class="col-sm-5">
		<input type="password" class="form-control" name="user_old_pass" id="user_old_pass" required>
		</div>
	</div>
	<div class="form-group">
		<label class="control-label col-sm-3" for="user_new_pass"><small>New password:</small></label>
		<div class="col-sm-5">
		<input type="password" class="form-control" name="user_new_pass" id="user_new_pass" placeholder="Unchanged if empty">
		</div>
	</div>
	<div class="form-group">
		<label class="control-label col-sm-3" for="user_new_pass2"><small>Repeat new password:</small></label>
		<div class="col-sm-5">
		<input type="password" class="form-control" name="user_new_pass2" id="user_new_pass2">
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-offset-3 col-sm-9">
			<button type="submit" name="trigger_set_user_account" class="btn btn-default">Change user details</button>
		</div>
	</div>
</form>
</div>
</div>

<ul><b>Did you know?</b> You can tag your mail address like "<?=explode('@', $logged_in_as)[0];?><b>+Private</b>@<?=explode('@', $logged_in_as)[1];?>" to automatically create a subfolder named "Private" in your inbox.</ul>
<br />

<div class="panel panel-default">
<div class="panel-heading">Generate time-limited aliases</div>
<div class="panel-body">
<form class="form-horizontal" role="form" method="post">
<div class="table-responsive">
<table class="table table-striped" id="timelimitedaliases">
	<thead>
	<tr>
		<th>Alias</th>
		<th>Valid until</th>
		<th>Time left (HH:MM:SS)</th>
	</tr>
	</thead>
	<tbody>
<?php
$result = mysqli_query($link, "SELECT address, goto, TIMEDIFF(validity, NOW()) as timeleft, validity FROM spamalias WHERE goto='".$logged_in_as."' AND validity >= NOW() ORDER BY timeleft ASC");
while ($row = mysqli_fetch_array($result)):
?>
		<tr>
		<td><?=$row['address'];?></td>
		<td><?=$row['validity'];?></td>
		<td><?=$row['timeleft'];?></td>
		</tr>
<?php
endwhile;
?>
	</tbody>
</table>
</div>
<div class="form-group">
	<div class="col-sm-9">
		<label for="validity">Validity</label>
		<select name="validity" size="1">
			<option value="1">1 hour</option>
			<option value="6">6 hours</option>
			<option value="24">1 day</option>
			<option value="168">1 week</option>
			<option value="672">4 weeks</option>
		</select>
	</div>
</div>
<div class="form-group">
	<div class="col-sm-12">
		<button type="submit" name="trigger_set_time_limited_aliases" value="generate" class="btn btn-success">Generate random alias</button>
		<button type="submit" name="trigger_set_time_limited_aliases" value="delete" class="btn btn-danger">Delete all aliases</button>
		<button type="submit" name="trigger_set_time_limited_aliases" value="extend" class="btn btn-default">Add 1 hour to all aliases</button>
	</div>
</div>
</form>
</div>
</div>

<div class="panel panel-default">
<div class="panel-heading">Calendars and Contacts</div>
<div class="panel-body">
<h4>My CalDAV and CardDAV items</h4>
<div class="table-responsive">
<table class="table table-striped" id="domainadminstable">
	<thead>
	<tr>
		<th colspan="2">Components</th>
		<th>URI</th>
		<th>Display name</th>
		<th>Export</th>
		<th>Link</th>
	</tr>
	</thead>
	<tbody>
<?php
$result = mysqli_query($link, "SELECT substring_index(principaluri,'/',-1) AS owner, components, uri, displayname FROM calendars WHERE principaluri='principals/".$logged_in_as."'");
while ($row = mysqli_fetch_array($result)):
?>
		<tr>
		<td><span class="glyphicon glyphicon-calendar"></span></td>
		<td><?=str_replace(array('VEVENT', 'VTODO', ','), array('Calendar', 'Tasks', ', '), $row['components']);?></td>
		<td><?=$row['uri'];?></td>
		<td><?=htmlspecialchars($row['displayname']);?></td>
		<td><a href="https://<?=$DAV_SUBDOMAIN.".".$MYHOSTNAME_1.".".$MYHOSTNAME_2."/calendars/".$row['owner']."/".$row['uri'];?>?export">Download (ICS format)</a></td>
		<td><a href="https://<?=$DAV_SUBDOMAIN.".".$MYHOSTNAME_1.".".$MYHOSTNAME_2."/calendars/".$row['owner']."/".$row['uri'];?>">Open</a></td>
		</tr>
<?php
endwhile;
$result = mysqli_query($link, "SELECT substring_index(principaluri,'/',-1) AS owner, uri, displayname FROM addressbooks WHERE principaluri='principals/".$logged_in_as."'");
while ($row = mysqli_fetch_array($result)):
?>
		<tr>
		<td><span class="glyphicon glyphicon-earphone"></span></td>
		<td>Address Book</td>
		<td><?=$row['uri'];?></td>
		<td><?=$row['displayname'];?></td>
		<td><a href="https://<?=$DAV_SUBDOMAIN.".".$MYHOSTNAME_1.".".$MYHOSTNAME_2."/addressbooks/".$row['owner']."/".$row['uri'];?>?export">Download (ICS format)</a></td>
		<td><a href="https://<?=$DAV_SUBDOMAIN.".".$MYHOSTNAME_1.".".$MYHOSTNAME_2."/addressbooks/".$row['owner']."/".$row['uri'];?>">Open</a></td>
		</tr>
<?php
endwhile;
?>
	</tbody>
</table>
</div>
<div class="col-sm-12">
	<p><a href="add.php?dav" class="btn btn-success btn-default">Add item</a>
	<a href="edit.php?dav=<?=$logged_in_as?>" class="btn btn-default">Edit details and permissions</a></p>
</div>
<h4>Shared with me</h4>
<div class="table-responsive">
<table class="table table-striped table-hover" id="domainadminstable">
	<thead>
	<tr>
		<th colspan="2">Components</th>
		<th>Owner</th>
		<th>Permission</th>
		<th>Display name</th>
		<th>Export</th>
		<th>Link</th>
	</tr>
	</thead>
	<tbody>
<?php
$result = mysqli_query($link, "SELECT components, substring_index(principaluri,'/',-1) AS owner, uri, displayname FROM calendars
	WHERE CONCAT(principaluri, '/calendar-proxy-read') IN (
		SELECT uri FROM principals WHERE id IN (
			SELECT principal_id FROM groupmembers WHERE member_id=(
				SELECT id FROM principals WHERE email='".$logged_in_as."')));");
while ($row = mysqli_fetch_array($result)):
?>
		<tr class="warning">
		<td><span class="glyphicon glyphicon-calendar"></span></td>
		<td><?=str_replace(array('VEVENT', 'VTODO', ','), array('Calendar', 'Tasks', ', '), $row['components']);?></td>
		<td><?=$row['owner'];?></td>
		<td>Read-only</td>
		<td><?=htmlspecialchars($row['displayname']);?></td>
		<td><a href="https://<?=$DAV_SUBDOMAIN.".".$MYHOSTNAME_1.".".$MYHOSTNAME_2."/calendars/".$row['owner']."/".$row['uri'];?>?export">Download (ICS format)</a></td>
		<td><a href="https://<?=$DAV_SUBDOMAIN.".".$MYHOSTNAME_1.".".$MYHOSTNAME_2."/calendars/".$row['owner']."/".$row['uri'];?>">Open</a></td>
		</tr>
<?php
endwhile;
$result = mysqli_query($link, "SELECT components, substring_index(principaluri,'/',-1) AS owner, uri, displayname FROM calendars
	WHERE CONCAT(principaluri, '/calendar-proxy-write') IN (
		SELECT uri FROM principals WHERE id IN (
			SELECT principal_id FROM groupmembers WHERE member_id=(
				SELECT id FROM principals WHERE email='".$logged_in_as."')));");
while ($row = mysqli_fetch_array($result)):
?>
		<tr class="success">
		<td><span class="glyphicon glyphicon-calendar"></span></td>
		<td><?=str_replace(array('VEVENT', 'VTODO', ','), array('Calendar', 'Tasks', ', '), $row['components']);?></td>
		<td><?=$row['owner'];?></td>
		<td>Read-write</td>
		<td><?=htmlspecialchars($row['displayname']);?></td>
		<td><a href="https://<?=$DAV_SUBDOMAIN.".".$MYHOSTNAME_1.".".$MYHOSTNAME_2."/calendars/".$row['owner']."/".$row['uri'];?>?export">Download (ICS format)</a></td>
		<td><a href="https://<?=$DAV_SUBDOMAIN.".".$MYHOSTNAME_1.".".$MYHOSTNAME_2."/calendars/".$row['owner']."/".$row['uri'];?>">Open</a></td>
		</tr>
<?php
endwhile;
?>
	</tbody>
</table>
</div>
</div>
</div>

<div class="panel panel-default">
<div class="panel-heading">Fetch mails</div>
<div class="panel-body">
<p>This is <b>not a recurring task</b>. This feature will perform a one-way synchronisation and leave the remote server as it is, no mails will be deleted on either sides.</p>
<p>The first synchronisation may take a while.</p>
<form class="form-horizontal" role="form" method="post">
	<div class="form-group">
		<label class="control-label col-sm-2" for="imap_host">IMAP host with port:</label>
		<div class="col-sm-10">
		<input type="text" class="form-control" name="imap_host" id="imap_host" placeholder="remote.example.com:993" required>
		</div>
	</div>
	<div class="form-group">
		<label class="control-label col-sm-2" for="imap_username">IMAP username:</label>
		<div class="col-sm-10">
		<input type="text" class="form-control" name="imap_username" id="imap_username" required>
		</div>
	</div>
	<div class="form-group">
		<label class="control-label col-sm-2" for="imap_password">IMAP password:</label>
		<div class="col-sm-10">
		<input type="password" class="form-control" name="imap_password" id="imap_password" required>
		</div>
	</div>
	<div class="form-group">
		<label class="control-label col-sm-2" for="imap_exclude">Exclude folders:</label>
		<div class="col-sm-10">
		<input type="text" class="form-control" name="imap_exclude" id="imap_exclude" placeholder="Folder1, Folder2, Folder3">
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-offset-2 col-sm-10">
			<div class="radio">
				<label><input type="radio" name="imap_enc" value="/ssl" checked>SSL</label>
			</div>
			<div class="radio">
				<label><input type="radio" name="imap_enc" value="/tls" >STARTTLS</label>
			</div>
			<div class="radio">
				<label><input type="radio" name="imap_enc" value="none">None (this will try STARTTLS)</label>
			</div>
		</div>
	</div>
	<div class="form-group">
		<div class="col-sm-offset-2 col-sm-10">
			<button type="submit" id="trigger_set_fetch_mail" name="trigger_set_fetch_mail" class="btn btn-success" disabled>Sync now</button>
		</div>
	</div>
</form>
</div>
</div>

</div> <!-- /container -->
<?php
}
else {
	header('Location: admin.php');
}
require_once("inc/footer.inc.php");
?>
