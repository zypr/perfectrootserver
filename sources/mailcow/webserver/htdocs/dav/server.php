<?php
date_default_timezone_set('Europe/Berlin');

$baseUri = '/';

$pdo = new PDO('mysql:dbname=my_mailcowdb;host=my_dbhost', 'my_mailcowuser', 'my_mailcowpass');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

function exception_error_handler($errno, $errstr, $errfile, $errline) {
    throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
}
set_error_handler("exception_error_handler");
require_once 'vendor/autoload.php';

/**
 * The backends. Yes we do really need all of them.
 *
 * This allows any developer to subclass just any of them and hook into their
 * own backend systems.
 */
$authBackend      = new \Sabre\DAV\Auth\Backend\PDO($pdo);
$principalBackend = new \Sabre\DAVACL\PrincipalBackend\PDO($pdo);
$carddavBackend   = new \Sabre\CardDAV\Backend\PDO($pdo);
$caldavBackend    = new \Sabre\CalDAV\Backend\PDO($pdo);

$nodes = [
    new \Sabre\CalDAV\Principal\Collection($principalBackend),
    new \Sabre\CalDAV\CalendarRoot($principalBackend, $caldavBackend),
    new \Sabre\CardDAV\AddressBookRoot($principalBackend, $carddavBackend),
];

$server = new \Sabre\DAV\Server($nodes);
if (isset($baseUri)) $server->setBaseUri($baseUri);

$server->addPlugin(new \Sabre\DAV\Auth\Plugin($authBackend, 'SabreDAV'));
$server->addPlugin(new \Sabre\CalDAV\Plugin());
$server->addPlugin(new \Sabre\CardDAV\Plugin());
$server->addPlugin(new \Sabre\DAVACL\Plugin());
$server->addPlugin(new \Sabre\DAV\Sync\Plugin());
$server->addPlugin(new \Sabre\CardDAV\VCFExportPlugin());
$server->addPlugin(new \Sabre\CalDAV\ICSExportPlugin());

$server->exec();
