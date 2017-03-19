<?php
require_once("inc/header.inc.php");
if (isset($_SESSION['mailcow_cc_loggedin']) && $_SESSION['mailcow_cc_loggedin'] == "yes" && ($_SESSION['mailcow_cc_role'] == "admin" || $_SESSION['mailcow_cc_role'] == "domainadmin")) {
$_SESSION['return_to'] = basename($_SERVER['PHP_SELF']);
?>
<div class="container">
	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-default">
				<div class="panel-heading">
				<h3 class="panel-title">Domains</h3>
				<div class="pull-right">
					<span class="clickable filter" data-toggle="tooltip" title="Toggle table filter" data-container="body">
						<i class="glyphicon glyphicon-filter"></i>
					</span>
					<a href="add.php?domain"><span class="glyphicon glyphicon-plus"></span></a>
				</div>
				</div>
				<div class="panel-body">
					<input type="text" class="form-control" id="domaintable-filter" data-action="filter" data-filters="#domaintable" placeholder="Filter" />
				</div>
				<div class="table-responsive">
				<table class="table table-striped" id="domaintable">
					<thead>
						<tr>
							<th>Domain</th>
							<th>Aliases</th>
							<th>Mailboxes</th>
							<th>Max. quota per mailbox</th>
							<th>Domain Quota</th>
							<th>Backup MX</th>
							<th>Active</th>
							<th>Action</th>
						</tr>
					</thead>
					<tbody>
<?php
$result = mysqli_query($link, "SELECT domain, aliases, mailboxes, maxquota, quota, CASE backupmx WHEN 1 THEN 'Yes' ELSE 'No' END AS backupmx, CASE active WHEN 1 THEN 'Yes' ELSE 'No' END AS active FROM 
domain WHERE 
domain IN (SELECT domain from domain_admins WHERE username='$logged_in_as') OR 'admin'='$logged_in_role'");
while ($row = mysqli_fetch_array($result)):
?>
						<tr>
							<td>
<?php
$getpostmaster = mysqli_query($link, "SELECT alias.active as aactive, mailbox.active as mactive, username, address FROM alias, mailbox WHERE 
(username='postmaster@".$row['domain']."' OR address='postmaster@".$row['domain']."' OR address='@".$row['domain']."')");
$postmasterstatus = mysqli_fetch_assoc($getpostmaster);
if ($row['backupmx'] == "No" && !isset($postmasterstatus['address']) || ($postmasterstatus['aactive'] == "0" || $postmasterstatus['mactive'] == "0")):
?>
							<span data-toggle="tooltip" title="Postmaster missing/invalid - Please create an alias or a mailbox for the postmaster user."><i class="glyphicon glyphicon-exclamation-sign"></i> <?=$row['domain'];?></span>
<?php
else:
?>

							<?=$row['domain'];?>
<?php
endif;
?>
							</td>
							<td><?= mysqli_result(mysqli_query($link, "SELECT count(*) FROM alias WHERE domain='".$row['domain']."' and address NOT IN (SELECT username FROM mailbox)"));?> of <?=$row['aliases'];?></td>
							<td><?= mysqli_result(mysqli_query($link, "SELECT count(*) FROM mailbox WHERE domain='".$row['domain']."'"));?> of <?=$row['mailboxes'];?></td>
							<td><?=$row['maxquota'];?>M</td>
							<td><?= mysqli_result(mysqli_query($link, "SELECT coalesce(round(sum(quota)/1048576), 0) FROM mailbox WHERE domain='".$row['domain']."'"));?>M of <?=$row['quota'];?>M</td>
							<td><?=$row['backupmx'];?></td>
							<td><?=$row['active'];?></td>
							<td><a href="delete.php?domain=<?=urlencode($row['domain']);?>">delete</a> | 
							<a href="edit.php?domain=<?=urlencode($row['domain']);?>">edit</a></td>
<?php
endwhile;
?>
	</tr>
					</tbody>
				</table>
				</div>
			</div>
		</div>
	</div>
	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-default">
				<div class="panel-heading">
					<h3 class="panel-title">Domain Aliases</h3>
					<div class="pull-right">
						<span class="clickable filter" data-toggle="tooltip" title="Toggle table filter" data-container="body">
							<i class="glyphicon glyphicon-filter"></i>
						</span>
						<a href="add.php?alias_domain"><span class="glyphicon glyphicon-plus"></span></a>
					</div>
				</div>
				<div class="panel-body">
					<input type="text" class="form-control" id="domainaliastable-filter" data-action="filter" data-filters="#domainaliastable" placeholder="Filter" />
				</div>
				<div class="table-responsive">
				<table class="table table-striped" id="domainaliastable">
					<thead>
						<tr>
							<th>Alias domain</th>
							<th>Target domain</th>
							<th>Active</th>
							<th>Action</th>
						</tr>
					</thead>
					<tbody>
<?php
$result = mysqli_query($link, "SELECT alias_domain, target_domain, CASE active WHEN 1 THEN 'Yes' ELSE 'No' END AS active FROM 
alias_domain WHERE 
target_domain IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'='".$logged_in_role."'");
while ($row = mysqli_fetch_array($result)):
?>
	<tr><td><?=$row['alias_domain'];?>
	</td><td><?=$row['target_domain'];?>
	</td><td><?=$row['active'];?>
	</td><td><a href="delete.php?alias_domain=<?=urlencode($row['alias_domain']);?>">delete</a>
	</td></tr>
<?php
endwhile;
?>
					</tbody>
				</table>
				</div>
			</div>
		</div>
	</div>
	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-default">
				<div class="panel-heading">
					<h3 class="panel-title">Mailboxes</h3>
					<div class="pull-right">
						<span class="clickable filter" data-toggle="tooltip" title="Toggle table filter" data-container="body">
							<i class="glyphicon glyphicon-filter"></i>
						</span>
						<a href="add.php?mailbox"><span class="glyphicon glyphicon-plus"></span></a>
					</div>
				</div>
				<div class="panel-body">
					<input type="text" class="form-control" id="mailboxtable-filter" data-action="filter" data-filters="#mailboxtable" placeholder="Filter" />
				</div>
				<div class="table-responsive">
				<table class="table table-striped" id="mailboxtable">
					<thead>
						<tr>
							<th>Username</th>
							<th>Name</th>
							<th>Domain</th>
							<th>Quota</th>
							<th>In use</th>
							<th>Msg #</th>
							<th>Active</th>
							<th>Action</th>
						</tr>
					</thead>
					<tbody>
<?php
$result = mysqli_query($link, "SELECT domain.backupmx, mailbox.username, mailbox.name, CASE mailbox.active WHEN 1 THEN 'Yes' ELSE 'No' END AS active, mailbox.domain, mailbox.quota, quota2.bytes, quota2.messages 
FROM mailbox, quota2, domain WHERE (mailbox.username = quota2.username) AND (domain.domain = mailbox.domain) AND 
(mailbox.domain IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 'admin'='".$logged_in_role."')");
while ($row = mysqli_fetch_array($result)):
?>
	<tr>
<?php
if ($row['backupmx'] == "0"):
?>
		<td><?=$row['username'];?></td>
<?php
else:
?>
		<td><span data-toggle="tooltip" title="Relayed address on backup mx domain"><i class="glyphicon glyphicon-forward"></i> <?=$row['username'];?></span></td>
<?php
endif;
?>

		<td><?=$row['name'];?></td>
		<td><?=$row['domain'];?></td>
		<td>
<?php
if ((formatBytes($row['quota'], 2)) == "0" ) {
	echo "&#8734;";
}
else {
	echo formatBytes($row['quota'], 2);
}
?>
		</td>
			<td><?= formatBytes($row['bytes'], 2);?></td>
			<td><?=$row['messages'];?></td>
			<td><?=$row['active'];?></td>
			<td><a href="delete.php?mailbox=<?=urlencode($row['username']);?>">delete</a> | 
			<a href="edit.php?mailbox=<?=urlencode($row['username']);?>">edit</a></td>
		</tr>
<?php
endwhile;
?>
					</tbody>
				</table>
				</div>
			</div>
		</div>
	</div>
	<div class="row">
		<div class="col-md-12">
			<div class="panel panel-default">
				<div class="panel-heading">
					<h3 class="panel-title">Aliases</h3>
					<div class="pull-right">
						<span class="clickable filter" data-toggle="tooltip" title="Toggle table filter" data-container="body">
							<i class="glyphicon glyphicon-filter"></i>
						</span>
						<a href="add.php?alias"><span class="glyphicon glyphicon-plus"></span></a>
					</div>
				</div>
				<div class="panel-body">
					<input type="text" class="form-control" id="aliastable-filter" data-action="filter" data-filters="#aliastable" placeholder="Filter" />
				</div>
				<div class="table-responsive">
				<table class="table table-striped" id="aliastable">
					<thead>
						<tr>
							<th>Alias address</th>
							<th>Destination</th>
							<th>Domain</th>
							<th>Active</th>
							<th>Action</th>
						</tr>
					</thead>
					<tbody>
<?php
$result = mysqli_query($link, "SELECT address, goto, domain, CASE active WHEN 1 THEN 'Yes' ELSE 'No' END AS active FROM alias WHERE 
(address NOT IN (SELECT username FROM mailbox) AND address!=goto) AND 
(domain IN (SELECT domain from domain_admins WHERE username='".$logged_in_as."') OR 
'admin'='".$logged_in_role."')");
while ($row = mysqli_fetch_array($result)):
?>
					<tr>
						<td>
<?php		
if(!filter_var($row['address'], FILTER_VALIDATE_EMAIL)) {
	echo "<b style='color:#ec466a'>Catch-all</b> for ".$row['address'];
}
else {
	echo $row['address'];
}
?>
						</td>
						<td>
<?php
foreach(explode(",", $row['goto']) as $goto):
?>
			<?=$goto;?><br />
<?php
endforeach;
?>
						</td>
						<td><?=$row['domain'];?></td>
						<td><?=$row['active'];?></td>
						<td><a href="delete.php?alias=<?=urlencode($row['address']);?>">delete</a> 
<?php
if(filter_var($row['address'], FILTER_VALIDATE_EMAIL)):
?>
	| <a href="edit.php?alias=<?=urlencode($row['address']);?>">edit</a>
<?php
endif;
?>
						</td>
					</tr>
<?php
endwhile;
?>
					</tbody>
				</table>
				</div>
			</div>
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
