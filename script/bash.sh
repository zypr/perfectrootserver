#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

bashinstall() {

echo "${info} Downloading GNU bash & latest security patches..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
cd ~/sources
mkdir bash && cd $_
wget https://ftp.gnu.org/gnu/bash/bash-${BASH_VERSION}.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

wget -r -np -nd --reject="index.html*,.sig" https://ftp.gnu.org/gnu/bash/bash-${BASH_VERSION}-patches/ >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
nfiles=$(ls | wc -l)
echo $nfiles

tar zxf bash-${BASH_VERSION}.tar.gz && cd bash-${BASH_VERSION} >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log

##################### Fix me!!! #######
echo "${info} Patching sourcefiles..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
for i in ../bash${BASH}-[0-9][0-9][0-9]; do patch -p0 -s < $nfiles; done

echo "${info} Compiling GNU bash..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
./configure --prefix=/usr/local >>/root/logs/make.log 2>&1
make >>/root/logs/make.log 2>&1
make install >>/root/logs/make.log 2>&1
cp -f /usr/local/bin/bash /bin/bash
sleep 2

}
source ~/configs/versions.cfg