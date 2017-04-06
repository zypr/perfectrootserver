#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

postfix() {
echo "${info} Installing Postfix..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
DEBIAN_FRONTEND=noninteractive aptitude -y install postfix-mysql postfix-pcre postfix >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

mkdir -p /etc/postfix/mysql/
cat > /etc/postfix/mysql/postfix-mysql-virtual_alias_maps.cf <<END
user = vimbadmin
password = $VIMB_MYSQL_PASS
hosts = 127.0.0.1
dbname = vimbadmin
query = SELECT goto FROM alias WHERE address = '%s' AND active = '1'
END


cat > /etc/postfix/mysql/postfix-mysql-virtual_domains_maps.cf <<END
user = vimbadmin
password = $VIMB_MYSQL_PASS
hosts = 127.0.0.1
dbname = vimbadmin
query = SELECT domain FROM domain WHERE domain = '%s' AND backupmx = '0' AND active = '1'
END


cat > /etc/postfix/mysql/postfix-mysql-virtual_mailbox_maps.cf <<END
user = vimbadmin
password = $VIMB_MYSQL_PASS
hosts = 127.0.0.1
dbname = vimbadmin
table = mailbox
select_field = maildir
where_field = username
END


cat > /etc/postfix/mysql/postfix-mysql-virtual_transport_maps.cf <<END
user = vimbadmin
password = $VIMB_MYSQL_PASS
hosts = 127.0.0.1
dbname = vimbadmin
table = domain
select_field = transport
where_field = domain
additional_conditions = and backupmx = '0' and active = '1'
END

chown -R root:postfix /etc/postfix/mysql
chmod 750 /etc/postfix/mysql/
chmod 640 /etc/postfix/mysql/*

sleep 2

mkdir -p /etc/postfix/

rm -rf /etc/postfix/main.cf
cat >> /etc/postfix/main.cf << 'EOF1'
# SMTPd greeting banner: You MUST specify $myhostname at the start of the text. This is required by the SMTP protocol.
smtpd_banner = $myhostname

# Disable local biff service
biff = no

# Do not append the string $mydomain to -locally- submitted email.
append_dot_mydomain = no

# Readme directory
readme_directory = /usr/share/doc/postfix

# HTML directory
html_directory = /usr/share/doc/postfix/html

# Certificates
smtpd_tls_cert_file = /etc/ssl/mail.domain.tld.cer
smtpd_tls_key_file = /etc/ssl/mail.domain.tld.key

# Opportunistic TLS. TLS auth only.
smtpd_tls_security_level=may
smtpd_tls_auth_only=yes

# TLS session cache for SMTPd
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache

# Disallow SSLv2 and SSLv3, only accept secure ciphers
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3
smtpd_tls_mandatory_ciphers=high

# Log TLS handling
smtpd_tls_loglevel = 1
smtp_tls_loglevel = 1

# Delay reject until RCPT TO
smtpd_delay_reject = yes

# Enable elliptic curve cryptography, "ultra" needs more cpu time
smtpd_tls_eecdh_grade = strong

# Sender, recipient, client and data restrictions
# !! non-FQDN HELOs are rejected on Port 25 only, see master.cf

# Auth. Benutzer dürfen auch innerhalb der "mynetworks" nur von den Adressen senden, die ihnen zugehörig sind.
smtpd_sender_restrictions = reject_authenticated_sender_login_mismatch,
# Erst jetzt werden "mynetworks" zugelassen
# Unauth. Benutzer wie der Cron-Dienst können so weiterhin Mails versenden, etwa
# als cron@fqdn
   permit_mynetworks,
# Anderen unauth. Benutzern das Benutzen jeder Adresse verbieten.
   reject_sender_login_mismatch,
# Alle auth. jetzt zulassen.
   permit_sasl_authenticated,
# Nicht im System vorhandene Absender jetzt ablehnen
   reject_unlisted_sender,
# Ablehnen, wenn die Sender-Domäne nicht existiert
   reject_unknown_sender_domain

# Akzeptiere alle Empfänger, die ein authentifizierter Absender oder ein Absender aus "mynetworks" angibt
smtpd_recipient_restrictions = permit_sasl_authenticated,
   permit_mynetworks,
# Schnittstelle zu Dovecot, um die Quota live zu überprüfen (verhindert Bounces)
   check_policy_service unix:private/quota-status,
# Ablehnen, wenn der HELO FQDN nicht aufzulösen ist
   reject_unknown_helo_hostname,
# Ablehnen, wenn KEIN PTR zu dieser IP existiert
# Verhindert nicht, dass ein FALSCHER PTR abgelehnt wird!
# Hierfür würde "reject_unknown_client_hostname" verwendet.
   reject_unknown_reverse_client_hostname,
# Kein offenes Relay
   reject_unauth_destination

# Unauth. Benutzer dürfen ihre Befehle nicht "pipen"
smtpd_data_restrictions =
   reject_unauth_pipelining,
   permit

# Eine Art Tabelle mit vorhanden Identitäten und ihren Zugehörigkeiten
smtpd_sender_login_maps = proxy:mysql:/etc/postfix/mysql/postfix-mysql-virtual_alias_maps.cf

# Certificates
smtp_tls_cert_file = /etc/ssl/mail.domain.tld.cer
smtp_tls_key_file = /etc/ssl/mail.domain.tld.key

# Opportunistic TLS. Use TLS if this is supported by the remote SMTP server, otherwise use plaintext.
smtp_tls_security_level=may

# TLS session cache for SMTP
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache

# A custom list with secure ciphers.
tls_high_cipherlist=EDH+CAMELLIA:EDH+aRSA:EECDH+aRSA+AESGCM:EECDH+aRSA+SHA384:EECDH+aRSA+SHA256:EECDH:+CAMELLIA256:+AES256:+CAMELLIA128:+AES128:+SSLv3:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!DSS:!RC4:!SEED:!ECDSA:CAMELLIA256-SHA:AES256-SHA:CAMELLIA128-SHA:AES128-SHA

# Use the FQDN for the local hostname!
myhostname = mail.domain.tld

# Alias maps and database for -local- delivery only
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases

# The domain name that locally-posted mail appears to come from, and that locally posted mail is delivered to.
myorigin = mail.domain.tld

# The list of domains that are delivered via the -local- mail delivery transport. No external domains like "domain.tld" belong here! "mail.domain.tld" is fine.
mydestination = mail.domain.tld, localhost

# We lookup MX records to send non-local mail, so this stays empty
relayhost =

# Trusted SMTP clients with more privileges. Trusted clients can relay mail.
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128

# The maximal size of any -local- individual mailbox
mailbox_size_limit = 0

# The maximal size of any -virtual- individual mailbox
virtual_mailbox_limit = 0

# Handle Postfix-style extensions
recipient_delimiter = +

# The network interface addresses that this mail system receives mail on.
inet_interfaces = all

# Specifies what protocols Postfix will use when it makes or accepts network connections, and also controls what DNS lookups Postfix will use when it makes network connections.
inet_protocols = ipv4

# VRFY command is not really needed anymore
disable_vrfy_command = yes

# Please say hello first...
smtpd_helo_required = yes

# The SASL plug-in type that the Postfix SMTP server should use for authentication.
smtpd_sasl_type=dovecot

# Where to passthrough our authentication information for the above plug-in
smtpd_sasl_path=private/auth_dovecot

# Enable SASL authentication in the Postfix SMTP server.
smtpd_sasl_auth_enable = yes

# Report the SASL authenticated user name in the smtpd Received message header.
smtpd_sasl_authenticated_header = yes

# Have Postfix advertise AUTH support in a non-standard way.
broken_sasl_auth_clients = yes

# The lookup tables that the proxymap server is allowed to access for the read-only service.
proxy_read_maps = $local_recipient_maps $mydestination $virtual_alias_maps $virtual_alias_domains $virtual_mailbox_maps $virtual_mailbox_domains $relay_recipient_maps $relay_domains $canonical_maps $sender_canonical_maps $recipient_canonical_maps $relocated_maps $transport_maps $mynetworks $smtpd_sender_login_maps

## Virtual transport configuration
# A prefix that the virtual delivery agent prepends to all pathname results from $virtual_mailbox_maps
virtual_mailbox_base = /

# THIS contains a list of domains we are the final destination for (unlike "mydestination").
virtual_mailbox_domains = proxy:mysql:/etc/postfix/mysql/postfix-mysql-virtual_domains_maps.cf

# Alias specific mail addresses or domains to other local or remote address.
virtual_alias_maps = proxy:mysql:/etc/postfix/mysql/postfix-mysql-virtual_alias_maps.cf

# Specify a left-hand side of "@domain.tld" to match any user in the specified domain
virtual_mailbox_maps = proxy:mysql:/etc/postfix/mysql/postfix-mysql-virtual_mailbox_maps.cf

# The minimum user ID value that the virtual delivery agent accepts
virtual_minimum_uid = 5000

# We use "vmail" user with UID/GID 5000 to lookup tables
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

# The default mail delivery transport and next-hop destination for final delivery to domains listed with "virtual_mailbox_domains"
virtual_transport = lmtps:unix:private/dovecot-lmtp

transport_maps = mysql:/etc/postfix/mysql/postfix-mysql-virtual_transport_maps.cf

## Queue configuration
# Consider a message as undeliverable, when delivery fails with a temporary error, and the time in the queue has reached this limit.
maximal_queue_lifetime = 1d

# Consider a bounce message as undeliverable, when delivery fails with a temporary error, and the time in the queue has reached this limit.
bounce_queue_lifetime = 1d

# The time between deferred queue scans by the queue manager.
queue_run_delay = 300s

# The maximal/minimal time between attempts to deliver a deferred message.
maximal_backoff_time = 1800s
minimal_backoff_time = 300s

# Maximum mail size (500 MiB)
message_size_limit = 524288000

# This tarpits a client after 3 erroneous commands for 10s
smtpd_soft_error_limit = 3
smtpd_error_sleep_time = 10s
smtpd_hard_error_limit = ${stress?1}${stress:5}

postscreen_access_list = permit_mynetworks

# Drop connections from blacklisted servers with a 521 reply
postscreen_blacklist_action = drop

# Clean Postscreen cache after 24h
postscreen_cache_cleanup_interval = 24h

postscreen_dnsbl_ttl = 5m
postscreen_dnsbl_threshold = 8
postscreen_dnsbl_action = enforce
postscreen_dnsbl_sites =
  b.barracudacentral.org=127.0.0.2*7
  dnsbl.inps.de=127.0.0.2*7
  bl.mailspike.net=127.0.0.2*5
  bl.mailspike.net=127.0.0.[10;11;12]*4
  dnsbl.sorbs.net=127.0.0.10*8
  dnsbl.sorbs.net=127.0.0.5*6
  dnsbl.sorbs.net=127.0.0.7*3
  dnsbl.sorbs.net=127.0.0.8*2
  dnsbl.sorbs.net=127.0.0.6*2
  dnsbl.sorbs.net=127.0.0.9*2
  zen.spamhaus.org=127.0.0.[10;11]*8
  zen.spamhaus.org=127.0.0.[4..7]*6
  zen.spamhaus.org=127.0.0.3*4
  zen.spamhaus.org=127.0.0.2*3
  hostkarma.junkemailfilter.com=127.0.0.2*3
  hostkarma.junkemailfilter.com=127.0.0.4*1
  hostkarma.junkemailfilter.com=127.0.1.2*1
  wl.mailspike.net=127.0.0.[18;19;20]*-2
  hostkarma.junkemailfilter.com=127.0.0.1*-2
postscreen_greet_banner = $smtpd_banner
postscreen_greet_action = enforce
postscreen_greet_wait = 3s
postscreen_greet_ttl = 2d
postscreen_bare_newline_enable = no
postscreen_non_smtp_command_enable = no
postscreen_pipelining_enable = no
postscreen_cache_map = proxy:btree:$data_directory/postscreen_cache
EOF1
sed -i "s/domain.tld/${MYDOMAIN}/g" /etc/postfix/main.cf

rm /etc/postfix/master.cf
cat >> /etc/postfix/master.cf << 'EOF1'
# Postscreen on Port 25/tcp, filters zombies (spam machines) on first level with lowest costs.
smtp      inet  n       -       n       -       1       postscreen

# Postscreen passes sane clients to the real SMTP daemon here.
smtpd      pass  -       -       n       -       -       smtpd
# Reject non-FQDN HELOs on Port 25 (after passing postscreen process)
  -o smtpd_helo_restrictions=permit_mynetworks,reject_non_fqdn_helo_hostname
  -o smtpd_proxy_filter=127.0.0.1:10024
  -o smtpd_client_connection_count_limit=10
  -o smtpd_proxy_options=speed_adjust

# For mail submitting users. Authenticated clients and known networks only.
submission inet n       -       -       -       -       smtpd
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_proxy_filter=127.0.0.1:10025
  -o smtpd_client_connection_count_limit=10
  -o smtpd_proxy_options=speed_adjust

# Handles TLS connections for postscreen to make them readable
tlsproxy  unix  -       -       n       -       0       tlsproxy
# This implements an ad-hoc DNS white/blacklist lookup service
dnsblog   unix  -       -       n       -       0       dnsblog

pickup    fifo  n       -       -       60      1       pickup
cleanup   unix  n       -       -       -       0       cleanup
qmgr      fifo  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       -       1000?   1       tlsmgr
rewrite   unix  -       -       -       -       -       trivial-rewrite
bounce    unix  -       -       -       -       0       bounce
defer     unix  -       -       -       -       0       bounce
trace     unix  -       -       -       -       0       bounce
verify    unix  -       -       -       -       1       verify
flush     unix  n       -       -       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       -       -       -       smtp
relay     unix  -       -       -       -       -       smtp
showq     unix  n       -       -       -       -       showq
error     unix  -       -       -       -       -       error
retry     unix  -       -       -       -       -       error
discard   unix  -       -       -       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       -       -       -       lmtp
anvil     unix  -       -       -       -       1       anvil
scache    unix  -       -       -       -       1       scache

# LMTP with STARTTLS support, needs newer Dovecot versions
lmtps     unix  -       -       -       -       -       lmtp
  -o lmtp_use_tls=yes
  -o lmtp_tls_loglevel=1
  -o lmtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt
  -o lmtp_enforce_tls=yes
  -o lmtp_tls_mandatory_protocols=!SSLv2,!SSLv3
  -o lmtp_tls_protocols=!SSLv2,!SSLv3
  -o lmtp_tls_mandatory_ciphers=high
  -o lmtp_tls_ciphers=high
  -o lmtp_send_xforward_command=yes
  -o lmtp_tls_security_level=encrypt
  -o lmtp_tls_note_starttls_offer=yes

# Amavis reinjection, maximal 5 smtpd Prozesse, muss den Amavis Prozessen entsprechen!
127.0.0.1:10035 inet    n       -       -       -       5       smtpd
  -o smtpd_authorized_xforward_hosts=127.0.0.0/8
  -o smtpd_client_restrictions=
  -o smtpd_helo_restrictions=
  -o smtpd_sender_restrictions=
  -o smtpd_recipient_restrictions=permit_mynetworks,reject
  -o smtpd_data_restrictions=
  -o mynetworks=127.0.0.0/8
  -o receive_override_options=no_unknown_recipient_checks
EOF1
}
source ~/configs/userconfig.cfg