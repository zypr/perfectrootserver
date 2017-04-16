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

ssh() {

echo "${info} Downloading OpenSSH..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
wget http://ftp.hostserver.de/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz >>"$main_log" 2>>"$err_log"
tar -xzf openssh-${OPENSSH_VERSION}.tar.gz >>"$main_log" 2>>"$err_log"
cd openssh-${OPENSSH_VERSION}
echo "${info} Compiling OpenSSH..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
./configure --prefix=/usr --with-pam --with-zlib --with-ssl-engine --with-ssl-dir=/etc/ssl --sysconfdir=/etc/ssh >>"$main_log" 2>>"$err_log"
make >>"$make_log" 2>>"$make_err_log" && mv /etc/ssh{,.bak} && make install >>"$make_log" 2>>"$make_err_log"

sed -i 's/^#Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i 's/^#AddressFamily any/AddressFamily inet/g' /etc/ssh/sshd_config
sed -i 's/^#Protocol 2/Protocol 2/g' /etc/ssh/sshd_config
sed -i 's/^#HostKey \/etc\/ssh\/ssh_host_rsa_key/HostKey \/etc\/ssh\/ssh_host_rsa_key/g' /etc/ssh/sshd_config
sed -i 's/^#HostKey \/etc\/ssh\/ssh_host_ecdsa_key/HostKey \/etc\/ssh\/ssh_host_ecdsa_key/g' /etc/ssh/sshd_config
sed -i 's/^#HostKey \/etc\/ssh\/ssh_host_ed25519_key/HostKey \/etc\/ssh\/ssh_host_ed25519_key/g' /etc/ssh/sshd_config
sed -i 's/^#ServerKeyBits 1024/ServerKeyBits 2048/' /etc/ssh/sshd_config
sed -i 's/^#RekeyLimit default none/RekeyLimit 256M/' /etc/ssh/sshd_config
sed -i 's/^#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
sed -i 's/^#KeyRegenerationInterval 1h/KeyRegenerationInterval 1800/g' /etc/ssh/sshd_config
sed -i 's/^#SyslogFacility AUTH/SyslogFacility AUTH/g' /etc/ssh/sshd_config
sed -i 's/^#LoginGraceTime 2m/LoginGraceTime 30/g' /etc/ssh/sshd_config
sed -i 's/^#MaxAuthTries 6/MaxAuthTries 20/g' /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin yes/PermitRootLogin yes/g' /etc/ssh/sshd_config
sed -i 's/^#StrictModes yes/StrictModes yes/g' /etc/ssh/sshd_config
sed -i 's/^#RSAAuthentication yes/RSAAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
sed -i 's/^AuthorizedKeysFile	.ssh\/authorized_keys/#AuthorizedKeysFile	.ssh\/authorized_keys/g' /etc/ssh/sshd_config
sed -i 's/^#RhostsRSAAuthentication no/RhostsRSAAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/^#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/^#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/^#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/^#AllowTcpForwarding yes/AllowTcpForwarding yes/g' /etc/ssh/sshd_config
sed -i 's/^#X11Forwarding no/X11Forwarding yes/g' /etc/ssh/sshd_config
sed -i 's/^#X11DisplayOffset 10/X11DisplayOffset 10/g' /etc/ssh/sshd_config
sed -i 's/^#PrintMotd yes/PrintMotd no/g' /etc/ssh/sshd_config
sed -i 's/^#PrintLastLog yes/PrintLastLog yes/g' /etc/ssh/sshd_config
# sed -i 's/^#TCPKeepAlive yes/TCPKeepAlive yes/g' /etc/ssh/sshd_config
# sed -i 's/^#ClientAliveInterval 0/ClientAliveInterval 30/g' /etc/ssh/sshd_config
# sed -i 's/^#ClientAliveCountMax 3/ClientAliveCountMax 3000/g' /etc/ssh/sshd_config
sed -i 's/^#UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config
sed -i 's/^#Banner none/Banner \/etc\/issue/g' /etc/ssh/sshd_config
sed -i 's/^#MaxStartups 10:30:100/MaxStartups 2/g' /etc/ssh/sshd_config
sed -i 's/^#MaxSessions 10/MaxSessions 3/g' /etc/ssh/sshd_config
sed -i 's/^Subsystem	sftp	\/usr\/libexec\/sftp-server/Subsystem sftp \/usr\/lib\/openssh\/sftp-server/g' /etc/ssh/sshd_config
echo -e "" >> /etc/ssh/sshd_config
echo -e "# Allow client to pass locale environment variables" >> /etc/ssh/sshd_config
echo -e "AcceptEnv LANG LC_* TZ" >> /etc/ssh/sshd_config
echo -e "" >> /etc/ssh/sshd_config
echo -e "# KEX algorithms">> /etc/ssh/sshd_config
echo -e "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256">> /etc/ssh/sshd_config
echo -e "" >> /etc/ssh/sshd_config
echo -e "# Ciphers">> /etc/ssh/sshd_config
echo -e "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr">> /etc/ssh/sshd_config
echo -e "" >> /etc/ssh/sshd_config
echo -e "# MAC algorithms">> /etc/ssh/sshd_config
echo -e "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com">> /etc/ssh/sshd_config


rm -rf /etc/nginx/nginx.conf
cat > /etc/issue <<END
####################################################################
# Unauthorized access to this system is forbidden and will be      #
# prosecuted by law. By accessing this system, you agree that your #
# actions may be monitored if unauthorized usage is suspected.     #
#     --------------------------------------------------------     #
#      For more information please visit perfectrootserver.de      #
#     --------------------------------------------------------     #
####################################################################
END
systemctl -q restart ssh.service
}
source ~/configs/versions.cfg