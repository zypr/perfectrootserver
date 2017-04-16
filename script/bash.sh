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

bashinstall() {

echo "${info} Downloading GNU bash & latest security patches..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
cd ~/sources
mkdir bash && cd $_
wget https://ftp.gnu.org/gnu/bash/bash-${BASH_VERSION}.tar.gz >>"$main_log" 2>>"$err_log"

wget -r -np -nd --reject="index.html*,.sig" https://ftp.gnu.org/gnu/bash/bash-${BASH_VERSION}-patches/ >>"$main_log" 2>>"$err_log"
nfiles=$(ls | wc -l)

tar zxf bash-${BASH_VERSION}.tar.gz && cd bash-${BASH_VERSION} >>"$main_log" 2>>"$err_log"

##################### Fix me!!! #######
echo "${info} Patching sourcefiles..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
for i in ../bash${BASH}-[0-9][0-9][0-9]; do patch -p0 -s < $i; done

echo "${info} Compiling GNU bash..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
./configure --prefix=/usr/local >>"$make_log" 2>>"$make_err_log"
make >>"$make_log" 2>>"$make_err_log"
make install >>"$make_log" 2>>"$make_err_log"
cp -f /usr/local/bin/bash /bin/bash
sleep 2

}
source ~/configs/versions.cfg
