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

policydweight() {

# http://kefk.org/free_software/postfix#policyd-weight
# http://www.holl.co.at/home/howto-email/#a2.3

mkdir -p /usr/local/bin/policyd-weight/
mkdir -p ~/sources/policydweight/ >>"$main_log" 2>>"$err_log"
cd ~/sources/policydweight/
wget http://www.policyd-weight.org/policyd-weight

mv ~/sources/policydweight/* /usr/local/bin/policyd-weight
mv policyd-weight /usr/local/bin/policyd-weight
chmod 0555 /usr/local/bin/policyd-weight


# If these settings seem appropriate you don't need a configuration file at all.
# In case you like to change some settings, create a file (i.e. /usr/local/etc/policyd-weight.conf)
# and add only the variables that differ from the defaults.
# For example if you want only DNSBL checks and a different port use:
cat > /usr/local/etc/policyd-weight.conf <<END
$MAXDNSBLHITS = 3;
$MAXDNSBLSCORE = 16;

END

# Activate policydweight in postfix
echo -e "check_policy_service inet:127.0.0.1:12525" >> /etc/postfix/main.cf
}
