if [ ${SSH_PASS} == 'generatepw' ]; then
	   SSH_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
  	 sed -i "s/SSH_PASS=\`generatepw\`/SSH_PASS=\`$SSH_PASS\`/g"  
fi

if [ ${USE_MAILSERVER} == '1' ]; then
  if [ ${MAILCOW_ADMIN_PASS} == 'generatepw' ]; then
	   SSH_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
  	 sed -i "s/MAILCOW_ADMIN_PASS=\`generatepw\`/MAILCOW_ADMIN_PASS=\`$MAILCOW_ADMIN_PASS\`/g"  
  fi
fi


if [ ${USE_PMA="1"} == '1' ]; then
  if [ ${PMA_HTTPAUTH_PASS} == 'generatepw' ]; then
	   PMA_HTTPAUTH_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
  	 sed -i "s/PMA_HTTPAUTH_PASS=\`generatepw\`/PMA_HTTPAUTH_PASS=\`$PMA_HTTPAUTH_PASS\`/g"  
  fi
  
  if [ ${PMA_BFSECURE_PASS} == 'generatepw' ]; then
	   PMA_BFSECURE_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
  	 sed -i "s/PMA_BFSECURE_PASS=\`generatepw\`/PMA_BFSECURE_PASS=\`$PMA_BFSECURE_PASS\`/g"  
  fi
fi

if [ ${MYSQL_ROOT_PASS} == 'generatepw' ]; then
	   MYSQL_ROOT_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
  	 sed -i "s/MYSQL_ROOT_PASS=\`generatepw\`/MYSQL_ROOT_PASS=\`$MYSQL_ROOT_PASS\`/g"  
fi

if [ ${MYSQL_MCDB_PASS} == 'generatepw' ]; then
	   MYSQL_MCDB_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
  	 sed -i "s/MYSQL_MCDB_PASS=\`generatepw\`/MYSQL_MCDB_PASS=\`$MYSQL_MCDB_PASS\`/g"  
fi

if [ ${MYSQL_RCDB_PASS} == 'generatepw' ]; then
	   MYSQL_RCDB_PASSS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
  	 sed -i "s/MYSQL_RCDB_PASS=\`generatepw\`/MYSQL_RCDB_PASS=\`$MYSQL_RCDB_PASS\`/g"  
fi

if [ ${MYSQL_PMADB_PASS} == 'generatepw' ]; then
	   MYSQL_PMADB_PASS=$(openssl rand -base64 30 | tr -d / | cut -c -24 | grep -P '(?=^.{8,255}$)(?=^[^\s]*$)(?=.*\d)(?=.*[A-Z])(?=.*[a-z])')
  	 sed -i "s/MYSQL_PMADB_PASS=\`generatepw\`/MYSQL_PMADB_PASS=\`$MYSQL_PMADB_PASS\`/g"  
fi

source ~/userconfig.cfg
