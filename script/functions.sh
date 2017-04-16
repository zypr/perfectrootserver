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

# Some nice colors
red() { echo "$(tput setaf 1)$*$(tput setaf 9)"; }
green() { echo "$(tput setaf 2)$*$(tput setaf 9)"; }
yellow() { echo "$(tput setaf 3)$*$(tput setaf 9)"; }
magenta() { echo "$(tput setaf 5)$*$(tput setaf 9)"; }
cyan() { echo "$(tput setaf 6)$*$(tput setaf 9)"; }
textb() { echo $(tput bold)${1}$(tput sgr0); }
greenb() { echo $(tput bold)$(tput setaf 2)${1}$(tput sgr0); }
redb() { echo $(tput bold)$(tput setaf 1)${1}$(tput sgr0); }
yellowb() { echo $(tput bold)$(tput setaf 3)${1}$(tput sgr0); }
pinkb() { echo $(tput bold)$(tput setaf 5)${1}$(tput sgr0); }

# Some nice variables
info="$(textb [INFO] -)"
warn="$(yellowb [WARN] -)"
error="$(redb [ERROR] -)"
fyi="$(pinkb [INFO] -)"
ok="$(greenb [OKAY] -)"

IPADR=$(ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)
INTERFACE=$(ip route get 8.8.8.8 | head -1 | cut -d' ' -f5)
FQDNIP=$(source ~/configs/userconfig.cfg; dig @8.8.8.8 +short ${MYDOMAIN})
WWWIP=$(source ~/configs/userconfig.cfg; dig @8.8.8.8 +short www.${MYDOMAIN})
CHECKRDNS=$(dig @8.8.8.8 -x ${IPADR} +short)

main_log="/root/logs/main.log"
err_log="/root/logs/error.log"
make_log="/root/logs/make.log"
make_err_log="/root/logs/make_error.log"