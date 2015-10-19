<?php
require_once("inc/header.inc.php");
$_SESSION['return_to'] = basename($_SERVER['PHP_SELF']);
?>
<div class="container">
	<h2>Welcome @ <?php echo $MYHOSTNAME; ?></h2>
	<p style="font-weight:300;font-size:24px;margin-right:151px;line-height:30px;margin-top:-2px"><i>Get cownnected...</i></h4>
	<p>Please login using your <strong>full@email.address</strong></p>
	<div class="table-responsive">
	<table class="table table-striped">
		<thead>
		<tr>
			<th>Service</th>
			<th>Encryption</th>
			<th>Hostname</th>
			<th>Port</th>
		</tr>
		</thead>
		<tbody>
			<tr>
				<td>IMAP</td>
				<td>STARTTLS</td>
				<td><?php echo $MYHOSTNAME; ?></td>
				<td>143</td>
			</tr>
			<tr>
				<td>IMAPS</td>
				<td>SSL</td>
				<td><?php echo $MYHOSTNAME; ?></td>
				<td>993</td>
			</tr>
			<tr>
				<td>POP3</td>
				<td>STARTTLS</td>
				<td><?php echo $MYHOSTNAME; ?></td>
				<td>110</td>
			</tr>
			<tr>
				<td>POP3S</td>
				<td>SSL</td>
				<td><?php echo $MYHOSTNAME; ?></td>
				<td>995</td>
			</tr>
			<tr>
				<td>SMTP</td>
				<td>STARTTLS</td>
				<td><?php echo $MYHOSTNAME; ?></td>
				<td>587</td>
			</tr>
			<tr>
				<td>SMTPS</td>
				<td>SSL</td>
				<td><?php echo $MYHOSTNAME; ?></td>
				<td>465</td>
			</tr>
		</tbody>
	</table>
	</div>
	<p>Please use the PLAIN authentication method.
	<br />Your credentials will not be transfered until a secure session was initiated.
	</p>
	<h4>Microsoft ActiveSync</h4>
	<p>ActiveSync support is enabled.</p>
	<h4>Cal- and CardDAV</h4>
	<p><a href="user.php" style="text-decoration:underline">Navigate to your personal settings</a> and copy the full path of your desired calendar or address book.</p>
	<h4>Health check (© MXToolBox)</h4>
	<p>"The Domain Health Check will execute hundreds of domain/email/network performance tests to make sure all of your systems are online and performing optimally. The report will then return results for your domain and highlight critical problem areas for your domain that need to be resolved."</p>
	<a class="btn btn-default" href="http://mxtoolbox.com/SuperTool.aspx?action=smtp:<?php echo $MYHOSTNAME ?>" target="_blank">Run &raquo;</a>
</div> <!-- /container -->
<?php
require_once("inc/footer.inc.php");
?>
