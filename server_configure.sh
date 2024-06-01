#!/bin/ksh
# need SERVER_NAME (dns server name)
# JITSI_DNS
# _MY_EMAIL
# TURN_SERVER_NAME
# ELEMENT_SERVER_NAME
# ADMIN_SERVER_NAME
set -e # stop if it is an error

# ADD pwgen
pkg_add pwgen
export CURRENT_DIRECTORY=$(pwd)

# DOAS permissions
cat $CURRENT_DIRECTORY/doas_config > /etc/doas.conf

# POSTGRESQL
pkg_add postgresql-server py3-psycopg2
doas -n -u _postgresql mkdir /var/postgresql/data
cd "/var/postgresql"
export DB_SUPERUSER_PASSWORD=$(pwgen -s 641)
echo $DB_SUPERUSER_PASSWORD > db_superuser_password
doas -n -u _postgresql initdb -D /var/postgresql/data -A scram-sha-256 -E UTF8 --pwfile db_superuser_password
rm db_superuser_password
rcctl enable postgresql
rcctl start postgresql
export DB_SYNAPSE_USER_PASSWORD=$(pwgen -s 641)
su - _postgresql <<EOF
export PGPASSWORD="$DB_SUPERUSER_PASSWORD"
createdb  --encoding=UTF8 --locale=C --template=template0 synapse
psql -c "CREATE USER synapse_user WITH PASSWORD '$DB_SYNAPSE_USER_PASSWORD';" -d synapse
psql -c "grant all privileges on database synapse to synapse_user;" -d synapse
psql -c "ALTER DATABASE synapse OWNER TO synapse_user;" -d synapse
export PGPASSWORD=""
EOF

# SYNAPSE
pkg_add synapse
cd "/var/synapse"; doas -n -u _synapse python3 -m synapse.app.homeserver --server-name $SERVER_NAME --config-path homeserver.yaml --generate-config --report-stats=no
export REGISTRATION_SHARED=$(cat /var/synapse/homeserver.yaml | grep registration_shared_secret)
export MACARON_SECRET=$(cat /var/synapse/homeserver.yaml | grep macaroon_secret_key)
export FORM_SECRET=$(cat /var/synapse/homeserver.yaml | grep form_secret)
export TURN_SECRET_KEY=$(pwgen -s 641)
cat $CURRENT_DIRECTORY/homeserver | envsubst '${SERVER_NAME} ${DB_SYNAPSE_USER_PASSWORD} ${REGISTRATION_SHARED} ${MACARON_SECRET} ${FORM_SECRET} ${TURN_SERVER_NAME} ${TURN_SECRET_KEY}' > /var/synapse/homeserver.yaml
rcctl enable synapse

# CERTBOT
pkg_add certbot
certbot certonly --standalone -d $SERVER_NAME --key-type rsa --quiet --agree-tos --email $_MY_EMAIL
certbot certonly --standalone -d $TURN_SERVER_NAME --key-type rsa --quiet --agree-tos --email $_MY_EMAIL
certbot certonly --standalone -d $ELEMENT_SERVER_NAME --key-type rsa --quiet --agree-tos --email $_MY_EMAIL
certbot certonly --standalone -d $ADMIN_SERVER_NAME --key-type rsa --quiet --agree-tos --email $_MY_EMAIL
certbot certonly --key-type rsa --standalone -w /var/www/jitsi-meet -d $JITSI_DNS --quiet --agree-tos --email $_MY_EMAIL
echo "0 0,12 * * * certbot renew --pre-hook 'rcctl stop nginx' --post-hook 'rcctl start nginx'" | tee -a /etc/crontab

# COTURN
cd /tmp
ftp https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/{ports.tar.gz,SHA256.sig}
signify -Cp /etc/signify/openbsd-$(uname -r | cut -c 1,3)-base.pub -x SHA256.sig ports.tar.gz
cd /usr
tar -xzf /tmp/ports.tar.gz
cd /usr/ports/telephony/coturn
make install
# this file is not creating automatically
cat $CURRENT_DIRECTORY/turnserver | envsubst '${TURN_SECRET_KEY} ${TURN_SERVER_NAME}' > /etc/turnserver.conf
rcctl start turnserver synapse

# ELEMENT
pkg_add wget
mkdir /var/www/element
cd /var/www/element
wget "https://github.com/element-hq/element-web/releases/download/v1.11.66/element-v1.11.66.tar.gz"
tar -xzvf element-v1.11.66.tar.gz
cd element-v1.11.66
cat $CURRENT_DIRECTORY/element_config | envsubst '${SERVER_NAME} ${JITSI_DNS}' > config.json

# SYNAPSE_ADMIN
mkdir /var/www/synapse_admin
cd /var/www/synapse_admin
wget "https://github.com/Awesome-Technologies/synapse-admin/releases/download/0.10.1/synapse-admin-0.10.1.tar.gz"
tar -xzvf synapse-admin-0.10.1.tar.gz
cat $CURRENT_DIRECTORY/synapse_admin_config | envsubst '${SERVER_NAME}' > /var/www/synapse_admin/synapse-admin-0.10.1/config.json

# PF
cat $CURRENT_DIRECTORY/pf > /etc/pf.conf
pfctl -f /etc/pf.conf

# JITSI
# -PROSODY
pkg_add prosody jitsi-meet jicofo jitsi-videobridge
export _YOU_JVB_SECRET=$(pwgen -s 641)
cat $CURRENT_DIRECTORY/prosody_config | envsubst '${JITSI_DNS} ${_YOU_JVB_SECRET}' > /etc/prosody/prosody.cfg.lua
echo "\n\n\n\n\n\n\n" | prosodyctl cert generate localhost --quiet
export _JITSI_STORE_PASSWORD=$(pwgen -s 641)
echo "yes\n" | $(javaPathHelper -h jicofo)/bin/keytool -import -alias prosody -file /var/prosody/localhost.crt -keystore /etc/ssl/jitsi.store -storepass $_JITSI_STORE_PASSWORD
cp /etc/ssl/jitsi.store /etc/ssl/jvb.store
prosodyctl install --server=https://modules.prosody.im/rocks/ mod_client_proxy
prosodyctl install --server=https://modules.prosody.im/rocks/ mod_roster_command
export _FOCUS_PASSWORD=$(pwgen -s 641)
prosodyctl register focus localhost $_FOCUS_PASSWORD
prosodyctl register jvb localhost $_YOU_JVB_SECRET
prosodyctl mod_roster_command subscribe focus.$JITSI_DNS focus@localhost
rcctl set jicofo flags "--host=$JITSI_DNS"
# -JICOFO
cat $CURRENT_DIRECTORY/jicofo_config_shell | envsubst '${_JITSI_STORE_PASSWORD}' > /etc/jicofo/jicofo.in.sh
cat $CURRENT_DIRECTORY/jicofo_config | envsubst '${_FOCUS_PASSWORD}' > /etc/jicofo/jicofo.conf
# -JVB
cat $CURRENT_DIRECTORY/jvb_config_shell | envsubst '${_JITSI_STORE_PASSWORD}' > /etc/jvb/jvb.in.sh
cat $CURRENT_DIRECTORY/jvb_config | envsubst '${_YOU_JVB_SECRET}' > /etc/jvb/jvb.conf
# -JITSI-MEET
cat $CURRENT_DIRECTORY/jitsi_config | envsubst '${JITSI_DNS}' > /var/www/jitsi-meet/config.js

# NGINX
pkg_add nginx
rcctl enable nginx prosody jicofo jvb
rcctl order nginx prosody jicofo jvb
cat $CURRENT_DIRECTORY/nginx_config | envsubst '${JITSI_DNS} ${SERVER_NAME} ${ELEMENT_SERVER_NAME} ${ADMIN_SERVER_NAME}' > /etc/nginx/nginx.conf
rcctl start nginx
rcctl start prosody jicofo jvb
