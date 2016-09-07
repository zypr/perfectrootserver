# The perfect rootserver
# by shoujii | BoBBer446
# https://github.com/shoujii/perfectrootserver
# Big thanks to https://github.com/andryyy/mailcow and https://github.com/zypr/perfectrootserver
# Compatible with Debian 8.x (jessie)


#DisableRootLogin
DisableRootLogin() {
source ~/userconfig.cfg
	
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

cd /etc/ssh/sshd_config
sed 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config >/dev/null 2>&1
sed -i "/LoginGraceTime 30/ s//\n AllowGroups $SSHUSER \n/" /etc/ssh/sshd_config >/dev/null 2>&1

	groupadd --system sshusers >/dev/null 2>&1
	#  --disabled-password yes or no for ssh login
	adduser $SSHUSER --gecos "" --no-create-home --home /root/ --ingroup sshusers >/dev/null 2>&1
	echo $SSHUSER:$USERPASS | chpasswd >/dev/null 2>&1
#restart
systemctl -q start ssh

fi #if [ ${DISABLE_ROOT_LOGIN} == '1' ]; then
}
