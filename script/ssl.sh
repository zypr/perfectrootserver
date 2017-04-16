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

ssl() {

# OpenSSL

echo "${info} Installing OpenSSL libs & headers..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
apt-get -q -y --force-yes install libssl-dev >>"$main_log" 2>>"$err_log"
cd ~/sources
wget http://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz >>"$main_log" 2>>"$err_log"
tar -xzf openssl-${OPENSSL_VERSION}.tar.gz >>"$main_log" 2>>"$err_log"
}
source ~/configs/userconfig.cfg
source ~/configs/versions.cfg
