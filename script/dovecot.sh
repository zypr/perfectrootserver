#!/bin/bash
# The perfect rootserver - Your Webserverinstallation Script!
# by shoujii | BoBBer446 > 2017
#####
# https://github.com/shoujii/perfectrootserver
# Compatible with Debian 8.x (jessie)
# Special thanks to Zypr!
#
	# This program is free software; you can redistribute it and/or modify
    # it under the terms of the GNU General Public License as published by
    # the Free Software Foundation; either version 2 of the License, or
    # (at your option) any later version.

    # This program is distributed in the hope that it will be useful,
    # but WITHOUT ANY WARRANTY; without even the implied warranty of
    # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    # GNU General Public License for more details.

    # You should have received a copy of the GNU General Public License along
    # with this program; if not, write to the Free Software Foundation, Inc.,
    # 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#-------------------------------------------------------------------------------------------------------------

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

dovecot() {
echo "${info} Installing Dovecot..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'

openssl req -new -newkey rsa:4096 -sha256 -days 1095 -nodes -x509 -subj "/C=DE/ST=STATE/L=CITY/O=MAIL/CN=`hostname -f`" -keyout /etc/ssl/`hostname -f`.key  -out /etc/ssl/`hostname -f`.cer >>"$main_log" 2>>"$err_log"
chmod 600 /etc/ssl/`hostname -f`.key >>"$main_log" 2>>"$err_log"
cp /etc/ssl/`hostname -f`.cer /usr/local/share/ca-certificates/ >>"$main_log" 2>>"$err_log"
update-ca-certificates >>"$main_log" 2>>"$err_log"

touch /etc/apt/sources.list.d/jessie-backports.list
echo "deb http://ftp.debian.org/debian jessie-backports main" >> /etc/apt/sources.list.d/jessie-backports.list
apt-get update -qq >>"$main_log" 2>>"$err_log"
apt-get -y -t jessie-backports install dovecot-common dovecot-core dovecot-imapd dovecot-lmtpd dovecot-managesieved dovecot-sieve dovecot-mysql >>"$main_log" 2>>"$err_log"

groupadd -g 5000 vmail >>"$main_log" 2>>"$err_log"
useradd -g vmail -u 5000 vmail -d /var/vmail >>"$main_log" 2>>"$err_log"
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
mail_plugins = quota acl mail_log notify
auth_username_chars = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@
ssl_protocols = !SSLv3 !SSLv2
ssl_cipher_list = EECDH+ECDSA+CHACHA20 EECDH+CHACHA20 EECDH+ECDSA+AESGCM EECDH+AESGCM EECDH+ECDSA+AES256 EECDH+AES256 EECDH+ECDSA+AES128 EECDH+AES128 EECDH+ECDSA+3DES EECDH+3DES EDH+CHACHA20 EDH+AESGCM EDH+AES256 EDH+AES128 EDH+3DES !CAMELLIA !SEED !IDEA !RC2 !RC4 !aDSS !kECDHe !kECDHr !kDHd !kDHr !eNULL !aNULL !MEDIUM !LOW !EXPORT
log_timestamp = "%Y-%m-%d %H:%M:%S "
passdb {
  args = /etc/dovecot/dovecot-mysql.conf
  driver = sql
}
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
ssl_cert = </etc/nginx/ssl/domain.tld.pem
ssl_key = </etc/nginx/ssl/domain.tld.key.pem
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
  postmaster_address = postmaster@domain.tld
}
protocol sieve {
  managesieve_logout_format = bytes=%i/%o
}
protocol lda {
  mail_plugins = sieve quota acl notify
  postmaster_address = postmaster@domain.tld
}
plugin {
  mail_log_events = delete undelete expunge
  acl_anyone = allow
  acl_shared_dict = file:/var/vmail/shared-mailboxes.db
  acl = vfile
  quota = maildir:User quota
  quota_rule = Trash:storage=+10%%
  quota_rule = Sent:storage=+10%%
  sieve = ~/sieve/dovecot.sieve
  sieve_dir = ~/sieve
  sieve_before = /var/vmail/before.sieve
  sieve_max_script_size = 1M
  sieve_quota_max_scripts = 0
  sieve_quota_max_storage = 0
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
sed -i "s/domain.tld/${MYDOMAIN}/g" /etc/dovecot/dovecot.conf

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