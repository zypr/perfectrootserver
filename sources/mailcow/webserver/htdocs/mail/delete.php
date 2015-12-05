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
	if (isset($_GET["domain"])) {
		if (!is_valid_domain_name($_GET["domain"]) || empty($_GET["domain"])) {
			echo 'Your provided domain name is invalid.';
		}
		else {
			$domain = mysqli_real_escape_string($link, $_GET["domain"]);
			if (mysqli_result(mysqli_query($link, "SELECT domain FROM domain WHERE domain='$domain' AND ((domain IN (SELECT domain from domain_admins WHERE username='$logged_in_as') OR 'admin'='$logged_in_role'))"))) {
				echo '<div class="alert alert-danger" role="alert"><strong>Warning:</strong> You are about to delete a domain!</div>';
				echo "<p>This will also delete domain alises assigned to the domain</p>";
				echo "<p><strong>Domain must be empty to be deleted!</b></p>";
				?>
				<form class="form-horizontal" role="form" method="post" action="mailbox.php">
				<input type="hidden" name="domain" value="<?php echo $domain ?>">
					<div class="form-group">
						<div class="col-sm-offset-1 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="deletedomain" class="btn btn-default btn-sm">Delete</button>
						</div>
					</div>
				</form>
				<?php
			}
			else {
				echo 'Your provided domain name does not exist or cannot be removed.';
			}
		}
	}
	elseif (isset($_GET["alias"])) {
                $local_part = strstr($_GET["alias"], '@', true);
                if (empty($_GET["alias"]) || ((!filter_var($_GET["alias"], FILTER_VALIDATE_EMAIL) === true) && !empty($local_part))) {
			echo 'Your provided alias name is invalid';
		}
		else {
			$alias = mysqli_real_escape_string($link, $_GET["alias"]);
			if (mysqli_result(mysqli_query($link, "SELECT goto domain FROM alias WHERE (address='$alias' AND goto!='$alias') AND (domain IN (SELECT domain from domain_admins WHERE username='$logged_in_as') OR 'admin'='$logged_in_role')"))) {
				echo '<div class="alert alert-danger" role="alert"><strong>Warning:</strong> You are about to delete an alias!</div>';
				echo "<p>The following users will no longer receive mail for/send mail from alias address <strong>$alias:</strong></p>";
				$query = "SELECT goto, domain FROM alias WHERE (address='$alias' AND goto!='$alias) AND ((domain IN (SELECT domain from domain_admins WHERE username='$logged_in_as') OR 'admin'='$logged_in_role'))";
				$result = mysqli_query($link, $query);
				echo "<ul>";
				while ($row = mysqli_fetch_array($result)) {
					echo "<li>", $row['goto'], "</li>";
				}
				echo "</ul>";
				?>
				<form class="form-horizontal" role="form" method="post" action="mailbox.php">
				<input type="hidden" name="address" value="<?php echo $alias ?>">
					<div class="form-group">
						<div class="col-sm-offset-1 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="deletealias" class="btn btn-default btn-sm">Delete</button>
						</div>
					</div>
				</form>
				<?php
			}
			else {
				echo 'Your provided alias name does not exist or cannot be removed.';
			}
		}
	}
	elseif (isset($_GET["alias_domain"])) {
		if (!is_valid_domain_name($_GET["alias_domain"]) || empty($_GET["alias_domain"])) {
			echo 'Alias domain name invalid';
		}
		else {
			$alias_domain = mysqli_real_escape_string($link, $_GET["alias_domain"]);
			if (mysqli_result(mysqli_query($link, "SELECT alias_domain, target_domain FROM alias_domain WHERE alias_domain='$alias_domain' AND (target_domain IN (SELECT domain from domain_admins WHERE username='$logged_in_as') OR 'admin'='$logged_in_role')"))) {
				echo '<div class="alert alert-danger" role="alert"><strong>Warning:</strong> You are about to delete an alias domain!</div>';
				echo "<p>The server will stop accepting mails for the domain name <strong>$alias_domain</strong>.</p>";
				?>
				<form class="form-horizontal" role="form" method="post" action="mailbox.php">
				<input type="hidden" name="alias_domain" value="<?php echo $alias_domain ?>">
					<div class="form-group">
						<div class="col-sm-offset-1 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="deletealiasdomain" class="btn btn-default btn-sm">Delete</button>
						</div>
					</div>
				</form>
				<?php
			}
			else {
				echo 'Your provided alias domain name does not exist or cannot be removed.';
			}
		}
	}
	elseif (isset($_GET["domain_admin"])) {
		if (!ctype_alnum(str_replace(array('@', '.', '-'), '', $_GET["domain_admin"])) || empty($_GET["domain_admin"])) {
			echo 'Domain administrator name invalid';
		}
		else {
			$domain_admin = mysqli_real_escape_string($link, $_GET["domain_admin"]);
			if (mysqli_result(mysqli_query($link, "SELECT username FROM domain_admins WHERE username='$domain_admin'")) && $logged_in_role == "admin") {
				echo '<div class="alert alert-danger" role="alert"><strong>Warning:</strong> You are about to delete a domain administrator!</div>';
				echo "<p>The domain administrator <strong>$domain_admin</strong> will not be able to login after deletion.</p>";
				?>
				<form class="form-horizontal" role="form" method="post" action="admin.php">
				<input type="hidden" name="username" value="<?php echo $domain_admin ?>">
					<div class="form-group">
						<div class="col-sm-offset-1 col-sm-10">
							<button type="submit" name="trigger_delete_domain_admin" class="btn btn-default btn-sm">Delete</button>
						</div>
					</div>
				</form>
				<?php
			}
			else {
				echo 'Action not supported.';
			}
		}
	}
	elseif (isset($_GET["mailbox"])) {
		if (!filter_var($_GET["mailbox"], FILTER_VALIDATE_EMAIL)) {
			echo 'Your provided mailbox name is invalid';
		}
		else {
			$mailbox = mysqli_real_escape_string($link, $_GET["mailbox"]);
			if (mysqli_result(mysqli_query($link, "SELECT address, domain FROM alias WHERE address='$mailbox' AND (domain IN (SELECT domain from domain_admins WHERE username='$logged_in_as') OR 'admin'='$logged_in_role')"))) {
				echo '<div class="alert alert-danger" role="alert"><strong>Warning:</strong> You are about to delete a mailbox!</div>';
				echo "<p>The mailbox user <strong>$mailbox</strong> + its address books and calendars will be deleted.</p>";
				echo "<p>The user will also be removed from the alias addresses listed below (if any).</p>";
				echo "<ul>";
				$result = mysqli_query($link, "SELECT address FROM alias WHERE goto='$mailbox' and address!='$mailbox'");
				while ($row = mysqli_fetch_array($result)) {
					echo "<li>", $row['address'], "</li>";
				}
				echo "</ul>";
				?>
				<form class="form-horizontal" role="form" method="post" action="mailbox.php">
				<input type="hidden" name="username" value="<?php echo $mailbox ?>">
					<div class="form-group">
						<div class="col-sm-offset-1 col-sm-10">
							<button type="submit" name="trigger_mailbox_action" value="deletemailbox" class="btn btn-default btn-sm">Delete</button>
						</div>
					</div>
				</form>
				<?php
			}
			else {
				echo 'Your provided mailbox name does not exist.';
			}
		}
	}
	else {
		echo '<div class="alert alert-danger" role="alert"><strong>Error:</strong>  No valid action specified.</div>';
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
