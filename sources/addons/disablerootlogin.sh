# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow and https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)


#DisableRootLogin
disablerootlogin() {
source ~/addonconfig.cfg
	
if [ ${DISABLE_ROOT_LOGIN} == '1' ]; then

echo
echo
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo "$(date +"[%T]") |  $(textb Disable Root Login in Perfect RootServer Script) "
echo "$(date +"[%T]") | $(textb +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+)"
echo
echo "$(date +"[%T]") | ${info} Welcome to the Perfect Rootserver Addon installation!"
echo "$(date +"[%T]") | ${info} Please wait while the installer is preparing for the first use..."

#creating a strong password!
USERPASS=$(openssl rand -base64 30  |  sed 's|/|_|')
	
sed 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config >>/root/stderror.log 2>&1  >> /root/stdout.log
sed -i "/LoginGraceTime 30/ s//\n AllowGroups $SSHUSER \n/" /etc/ssh/sshd_config >>/root/stderror.log 2>&1  >> /root/stdout.log

groupadd --system sshusers >>/root/stderror.log 2>&1  >> /root/stdout.log

#  --disabled-password yes or no for ssh login
adduser $SSHUSER --gecos "" --no-create-home --home /root/ --ingroup sshusers >>/root/stderror.log 2>&1  >> /root/stdout.log
echo $SSHUSER:$USERPASS | chpasswd >>/root/stderror.log 2>&1  >> /root/stdout.log
	
#restart
service ssh restart

echo "--------------------------------------------" >> ~/addoninformation.txt
	echo "DisableRootLogin" >> ~/addoninformation.txt
	echo "--------------------------------------------" >> ~/addoninformation.txt
	echo Your SSH USER: $SSHUSER >> ~/addoninformation.txt
	echo Your SSH USER Password: $USERPASS >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt >> ~/addoninformation.txt
	echo "" >> ~/addoninformation.txt >> ~/addoninformation.txt
fi
}
