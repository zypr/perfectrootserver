#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

mailfilter() {
echo "${info} Installing Mailfilter..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
apt-get -q -y --force-yes install zip rar unrar unzip p7zip-full amavisd-new clamav-daemon spamassassin >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

cat >> /etc/amavis/conf.d/50-user << 'EOF1'
use strict;

# Maximale Anzahl an Prozessen, die Amavis vorhält.
# Siehe auch Anmerkung in master.cf im Listener für Reinjection
$max_servers = 5;

# Amavis wird mitgeteilt, wie auf die MySQL-Datenbank zugegriffen werden kann.
@lookup_sql_dsn = (
    ['DBI:mysql:database=vimbadmin;host=127.0.0.1;port=3306',
     'vimbadmin',
     'changeme']);

# Hierdurch ermittelt Amavis die lokalen Domänen
$sql_select_policy = 'SELECT domain FROM domain WHERE CONCAT("@",domain) IN (%k)';

# Ein Listener für die Herkunft "external" sowie "submission"
$inet_socket_port = [10024,10025];

# Mails werden auf Port 10035 zurückgeführt
$forward_method = 'smtp:[127.0.0.1]:10035';
$notify_method  = 'smtp:[127.0.0.1]:10035';

# Listener :10025 bekommt eine eigene Policy
$interface_policy{'10025'} = 'SUBMISSION';

$policy_bank{'SUBMISSION'} = {
        # Diese Mails kommen von einem vertrauten System
        originating => 1,
        # 7-bit Kodierung erzwingen, damit ein späteres Kodieren die DKIM-Signatur nicht zerstört
        smtpd_discard_ehlo_keywords => ['8BITMIME'],
        # Viren auch von auth. Sendern ablehnen
        final_virus_destiny => D_REJECT,
        final_bad_header_destiny => D_PASS,
        final_spam_destiny => D_PASS,
        terminate_dsn_on_notify_success => 0,
        warnbadhsender => 1,
};

# "mail.domain.tld" bitte anpassen
$myhostname = "mail.domain.tld";

# Wer wird über Viren, Spam und "bad header mails" informiert?
# Den Benutzer "postmaster" bitte nachträglich in ViMbAdmin erstellen (Alias möglich)
$virus_admin = "postmaster\@$mydomain";
$spam_admin = "postmaster\@$mydomain";
$banned_quarantine_to = "postmaster\@$mydomain";
$bad_header_quarantine_to = "postmaster\@$mydomain";

# DKIM kann verifiziert werden.
$enable_dkim_verification = 1;

# AR-Header darf gesetzt werden
$allowed_added_header_fields{lc('Authentication-Results')} = 1;

# DKIM-Signatur
# Gilt nur, wenn "originating = 1", ergo für die SUBMISSION policy bank
# "default" ist hierbei der Selector
# "domain.tld" als Domäne bitte anpassen
# "enable_dkim_signing" nur "1" setzen, wenn Mails wirklich signiert werden sollen.
# "/var/lib/amavis/db/dkim_domain.tld.key" sollte ebenso dem Namen der Domäne angepasst werden.
# Die TTL beträgt im Beispiel 7 Tage
# relaxed/relaxed beschreibt die Header/Body canonicalization, relaxed ist weniger restriktiv

$enable_dkim_signing = 1;
dkim_key('domain.tld', 'default', '/var/lib/amavis/db/dkim_domain.tld.key');
@dkim_signature_options_bysender_maps = (
    { '.' =>
        {
                ttl => 7*24*3600,
                c => 'relaxed/relaxed'
        }
    }
);

# Viren- und Spamfilter ACL; werden automatisch ermittelt
@bypass_virus_checks_maps = (
   \%bypass_virus_checks, \@bypass_virus_checks_acl, \$bypass_virus_checks_re);

@bypass_spam_checks_maps = (
   \%bypass_spam_checks, \@bypass_spam_checks_acl, \$bypass_spam_checks_re);

#------------ Do not modify anything below this line -------------
1;  # ensure a defined return
EOF1
sed -i "s/mail.domain.tld/mail.${MYDOMAIN}/g" /etc/amavis/conf.d/50-user
sed -i "s/changeme/${VIMB_MYSQL_PASS}/g" /etc/amavis/conf.d/50-user
sed -i "s/domain.tld/${MYDOMAIN}/g" /etc/amavis/conf.d/50-user

amavisd-new genrsa /var/lib/amavis/db/dkim_${MYDOMAIN}.key 2048 >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
amavisd-new showkey ${MYDOMAIN} >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

adduser clamav amavis >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
# ACHTUNG, Ab 0.99.2 startet ClamAV mit diesem Parameter nicht mehr, da er entfernt wurde. Vielen Dank für den Hinweis!
#sed -i 's/AllowSupplementaryGroups false/AllowSupplementaryGroups true/g' /etc/clamav/clamd.conf
}
source ~/configs/userconfig.cfg