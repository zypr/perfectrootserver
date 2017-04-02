#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

dovecot() {
echo "${info} Installing Dovecot..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

echo 'deb http://xi.dovecot.fi/debian/ stable-auto/dovecot-2.3 main' > /etc/apt/sources.list.d/dovecot.list
wget -q http://xi.dovecot.fi/debian/archive.key -O- | apt-key add - >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
apt-get -qq update >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
apt-get -q -y --force-yes install dovecot-common dovecot-core dovecot-imapd dovecot-lmtpd dovecot-managesieved dovecot-sieve dovecot-mysql >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

groupadd -g 5000 vmail >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
useradd -g vmail -u 5000 vmail -d /var/vmail >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
mkdir /var/vmail 
chown -R vmail: /var/vmail/

rm /etc/dovecot/dovecot.conf
cat > /etc/dovecot/dovecot.conf <<END
auth_mechanisms = plain login
disable_plaintext_auth = yes
login_log_format_elements = "user=<%u> method=%m rip=%r lip=%l mpid=%e %c %k"
mail_home = /var/vmail/%d/%n
mail_location = maildir:~/Maildir:LAYOUT=fs
mail_uid = vmail
mail_gid = vmail
# notify wird von mail_log benötigt. mail_log informiert in diesem Fall über DELETE und EXPUNGE (weiter unten)
mail_plugins = quota acl mail_log notify
auth_username_chars = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@
ssl_protocols = !SSLv3 !SSLv2
ssl_cipher_list = EDH+CAMELLIA:EDH+aRSA:EECDH+aRSA+AESGCM:EECDH+aRSA+SHA384:EECDH+aRSA+SHA256:EECDH:+CAMELLIA256:+AES256:+CAMELLIA128:+AES128:+SSLv3:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!DSS:!RC4:!SEED:!ECDSA:CAMELLIA256-SHA:AES256-SHA:CAMELLIA128-SHA:AES128-SHA
log_timestamp = "%Y-%m-%d %H:%M:%S "
passdb {
  args = /etc/dovecot/dovecot-mysql.conf
  driver = sql
}
# Der "namespace separator" sollte "/" lauten, da es zusammen mit der ACL zu Konflikten käme, wenn der Benutzername das Zeichen "." enthält.
namespace inbox {
  inbox = yes
  location =
  separator = /
  mailbox Trash {
    auto = subscribe
    special_use = \Trash
  }
    mailbox "Deleted Messages" {
      special_use = \Trash
    }
    mailbox "Gelöschte Objekte" {
      special_use = \Trash
    }
    mailbox "Papierkorb" {
      special_use = \Trash
    }
  mailbox Archive {
    auto = subscribe
    special_use = \Archive
  }
    mailbox Archiv {
      special_use = \Archive
    }
  mailbox Sent {
    auto = subscribe
    special_use = \Sent
  }
    mailbox "Sent Messages" {
      special_use = \Sent
    }
    mailbox "Gesendet" {
      special_use = \Sent
    }
  mailbox Drafts {
    auto = subscribe
    special_use = \Drafts
  }
    mailbox Entwürfe {
      special_use = \Drafts
    }
  mailbox Junk {
    auto = subscribe
    special_use = \Junk
  }
  prefix =
}
# Dieser Namespace wird für die ACL Erweiterung benötigt.
# Freigegebene Ordner erscheinen automatisch in der Ordnerliste.
namespace {
    type = shared
    separator = /
    prefix = Shared/%%u/
    location = maildir:%%h/Maildir:LAYOUT=fs:INDEXPVT=~/Maildir/Shared/%%u
    subscriptions = yes
    list = yes
}
protocols = imap sieve lmtp
service dict {
  unix_listener dict {
    mode = 0660
    user = vmail
    group = vmail
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth_dovecot {
    group = postfix
    mode = 0660
    user = postfix
  }
  unix_listener auth-master {
    mode = 0600
    user = vmail
  }
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
  }
  user = root
}
service managesieve-login {
  inet_listener sieve {
    port = 4190
  }
  service_count = 1
  process_min_avail = 2
  vsz_limit = 128M
}
service managesieve {
  process_limit = 256
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    group = postfix
    mode = 0600
    user = postfix
  }
  user = vmail
}
listen = *
ssl_cert = </etc/nginx/ssl/$MYDOMAIN.pem
ssl_key = </etc/nginx/ssl/$MYDOMAIN.key.pem
userdb {
  args = /etc/dovecot/dovecot-mysql.conf
  driver = sql
}
protocol imap {
  mail_plugins = quota imap_quota imap_acl acl mail_log notify
}
protocol lmtp {
  mail_plugins = quota sieve acl notify
  auth_socket_path = /var/run/dovecot/auth-master
  postmaster_address = postmaster@$MYDOMAIN
}
protocol sieve {
  managesieve_logout_format = bytes=%i/%o
}
protocol lda {
  mail_plugins = sieve quota acl notify
  postmaster_address = postmaster@$MYDOMAIN
}
plugin {
  mail_log_events = delete undelete expunge
# Um quasi-öffentliche Ordner für authentifizierte Benutzer via ACL zu erstellen
  acl_anyone = allow
# Wird automatisch verwaltet und beinhaltet eine Übersicht der Freigaben
  acl_shared_dict = file:/var/vmail/shared-mailboxes.db
# In jeder Mailbox wird von Dovecot eine Datei gepflegt, die die Freigaben regelt
  acl = vfile
  quota = maildir:User quota
# Die Ordner Trash und Sent erhalten +10% auf die Quota
  quota_rule = Trash:storage=+10%%
  quota_rule = Sent:storage=+10%%
# Eigene Sieve Filter liegen im Heimverzeichnis
  sieve = ~/sieve/dovecot.sieve
  sieve_dir = ~/sieve
# Der globale Filter außerhalb
  sieve_before = /var/vmail/before.sieve
  sieve_max_script_size = 1M
  sieve_quota_max_scripts = 0
  sieve_quota_max_storage = 0
# Auch dann weitermachen, wenn die Quota nicht ermittelt werden kann
# Gilt für den von Dovecot bereitgestellten Postfix policy service
  quota_status_success = DUNNO
  quota_status_nouser = DUNNO
  quota_status_overquota = "552 5.2.2 Mailbox is over quota"
}
service quota-status {
  executable = quota-status -p postfix
  unix_listener /var/spool/postfix/private/quota-status {
   group = postfix
   mode = 0660
   user = postfix
  }
  client_limit = 1
}
END

cat > /etc/dovecot/dovecot-mysql.conf <<END
driver = mysql
connect = "host=localhost dbname=vimbadmin user=vimbadmin password=$VIMB_MYSQL_PASS"
default_pass_scheme = SHA512-CRYPT
password_query = SELECT username as user, password as password, \
        homedir AS home, \
        maildir AS mail, uid, gid, \
        concat('*:bytes=', quota) as quota_rule \
        FROM mailbox WHERE username = '%Lu' AND active = '1' \
        AND ( access_restriction = 'ALL' OR LOCATE( '%Us', access_restriction ) > 0 )
user_query = SELECT homedir AS home, \
        maildir AS mail, uid, gid, \
        concat('*:bytes=', quota) as quota_rule \
        FROM mailbox WHERE username = '%u'
iterate_query = SELECT username FROM mailbox;
END

chown root:vmail /etc/dovecot/dovecot-mysql.conf
chmod 640 /etc/dovecot/dovecot-mysql.conf

cat > /var/vmail/before.sieve <<END
require "fileinto";
if header :contains "X-Spam-Flag" "YES" {
  fileinto "Junk";
}
END

sievec /var/vmail/before.sieve
chown vmail: /var/vmail/before.*
}
source ~/configs/userconfig.cfg