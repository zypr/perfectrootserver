#!/bin/bash
# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)

#################################
##  DO NOT MODIFY, JUST DON'T! ##
#################################

ssl() {

# OpenSSL

echo "${info} Installing OpenSSL libs & headers..." | awk '{ print strftime("[%H:%M:%S] |"), $0 }'
apt-get -qq update && apt-get -q -y --force-yes install libssl-dev >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
cd ~/sources
wget http://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
tar -xzf openssl-${OPENSSL_VERSION}.tar.gz >>/root/logs/stderror.log 2>&1 >>/root/logs/stdout.log
}
source ~/configs/userconfig.cfg
source ~/configs/versions.cfg
