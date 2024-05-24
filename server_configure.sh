#!/bin/ksh
# need SERVER_NAME (dns server name)
# JITSI_DNS
# POSTGRES_USER_PASSWORD
# DB_SUPERUSER_PASSWORD
# DB_SYNAPSE_USER_PASSWORD
# _MY_EMAIL
# TURN_SERVER_NAME

cat > /etc/doas.conf <<- EOM
permit keepenv :wheel
permit nopass root as _synapse cmd python3
permit nopass root as _postgresql cmd mkdir
permit nopass root as _postgresql cmd initdb
permit nopass root as _postgresql cmd createuser
permit nopass root as _postgresql cmd createdb
permit nopass root as _postgresql cmd psql
permit nopass root as _postgresql cmd export
permit nopass _postgresql as root cmd rcctl
EOM
pkg_add synapse postgresql-server py3-psycopg2
cd "/var/synapse"; doas -n -u _synapse python3 -m synapse.app.homeserver --server-name $SERVER_NAME --config-path homeserver.yaml --generate-config --report-stats=no
doas -n -u _postgresql mkdir /var/postgresql/data
cd "/var/postgresql"
echo $DB_SUPERUSER_PASSWORD > db_superuser_password
doas -n -u _postgresql initdb -D /var/postgresql/data -A scram-sha-256 -E UTF8 --pwfile db_superuser_password
rm db_superuser_password
rcctl enable postgresql
rcctl start postgresql
su - _postgresql <<EOF
export PGPASSWORD="$DB_SUPERUSER_PASSWORD"
createdb  --encoding=UTF8 --locale=C --template=template0 synapse
psql -c "CREATE USER synapse_user WITH PASSWORD '$DB_SYNAPSE_USER_PASSWORD';" -d synapse
psql -c "grant all privileges on database synapse to synapse_user;" -d synapse
psql -c "ALTER DATABASE synapse OWNER TO synapse_user;" -d synapse
export PGPASSWORD=""
EOF
REGISTRATION_SHARED=$(cat /var/synapse/homeserver.yaml | grep registration_shared_secret)
MACARON_SECRET=$(cat /var/synapse/homeserver.yaml | grep macaroon_secret_key)
FORM_SECRET=$(cat /var/synapse/homeserver.yaml | grep form_secret)
cat > /var/synapse/homeserver.yaml <<- EOM
# Configuration file for Synapse.
#
# This is a YAML file: see [1] for a quick introduction. Note in particular
# that *indentation is important*: all the elements of a list or dictionary
# should have the same indentation.
#
# [1] https://docs.ansible.com/ansible/latest/reference_appendices/YAMLSyntax.html
#
# For more information on how to configure Synapse, including a complete accounting of
# each option, go to docs/usage/configuration/config_documentation.md or
# https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html
server_name: "$SERVER_NAME"
pid_file: /var/synapse/homeserver.pid
listeners:
  - port: 8008
    tls: false
    type: http
    x_forwarded: true
    bind_addresses: ['::1', '127.0.0.1']
    resources:
      - names: [client, federation]
        compress: false
database:
  name: psycopg2
  args:
    user: synapse_user
    password: $DB_SYNAPSE_USER_PASSWORD
    dbname: synapse
    host: localhost
    cp_min: 5
    cp_max: 10
log_config: "/var/synapse/$SERVER_NAME.log.config"
media_store_path: /var/synapse/media_store
$REGISTRATION_SHARED
report_stats: false
$MACARON_SECRET
$FORM_SECRET
signing_key_path: "/var/synapse/$SERVER_NAME.signing.key"
trusted_key_servers:
  - server_name: "matrix.org"
enable_registration: true
registration_requires_token: true

# vim:ft=yaml

EOM
rcctl enable synapse
rcctl start synapse
pkg_add certbot
certbot certonly --standalone -d $SERVER_NAME --key-type rsa --quiet --agree-tos --email $_MY_EMAIL
ln -s /etc/letsencrypt/live/$SERVER_NAME/fullchain.pem /etc/ssl/$SERVER_NAME.cert
ln -s /etc/letsencrypt/live/$SERVER_NAME/private/privkey.pem /etc/ssl/private/$SERVER_NAME.key
echo "0 0,12 * * * root python3 -c 'import random; import time; time.sleep(random.random() * 3600)' && sudo certbot renew -p" | tee -a /etc/crontab
cd /tmp
ftp "https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/{ports.tar.gz, SHA.256.sig}"
signify -Cp /etc/signify/openbsd-$(uname -r | cut -c 1,3)-base.pub -x SHA256.sig ports.tar.gz
cd /usr
tar -xzf /tmp/ports.tar.gz
cd /usr/ports/telephony/coturn
make install
SECRET_KEY=$(pwgen -s 641)
cat > /etc/turnserver.conf <<- EOM
use-auth-secret
static-auth-secret=$SECRET_KEY
realm=$TURN_SERVER_NAME

# VoIP traffic is all UDP. There is no reason to let users connect to arbitrary TCP endpoints via the relay.
no-tcp-relay

# don't let the relay ever try to connect to private IP address ranges within your network (if any)
# given the turn server is likely behind your firewall, remember to include any privileged public IPs too.
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=172.16.0.0-172.31.255.255

# recommended additional local peers to block, to mitigate external access to internal services.
# https://www.rtcsec.com/article/slack-webrtc-turn-compromise-and-bug-bounty/#how-to-fix-an-open-turn-relay-to-address-this-vulnerability
no-multicast-peers
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=192.0.0.0-192.0.0.255
denied-peer-ip=192.0.2.0-192.0.2.255
denied-peer-ip=192.88.99.0-192.88.99.255
denied-peer-ip=198.18.0.0-198.19.255.255
denied-peer-ip=198.51.100.0-198.51.100.255
denied-peer-ip=203.0.113.0-203.0.113.255
denied-peer-ip=240.0.0.0-255.255.255.255

# special case the turn server itself so that client->TURN->TURN->client flows work
# this should be one of the turn server's listening IPs
allowed-peer-ip=10.0.0.1

# consider whether you want to limit the quota of relayed streams per user (or total) to avoid risk of DoS.
user-quota=12 # 4 streams per video call, so 12 streams = 3 simultaneous relayed calls per user.
total-quota=1200

# TLS certificates, including intermediate certs.
# For Let's Encrypt certificates, use \`fullchain.pem\` here.
cert=/etc/letsencrypt/live/$SERVER_NAME/fullchain.pem

# TLS private key file
pkey=/etc/letsencrypt/live/$SERVER_NAME/privkey.pem

# Ensure the configuration lines that disable TLS/DTLS are commented-out or removed
#no-tls
#no-dtls
EOM
rcctl restart turnserver synapse
pkg_add wget
mkdir /var/www/element
cd /var/www/element
wget "https://github.com/element-hq/element-web/releases/download/v1.11.66/element-v1.11.66.tar.gz"
tar -xzvf element-v1.11.66.tar.gz
cd element-v1.11.66
cat > config.json <<- EOM
{
    "default_server_config": {
        "m.homeserver": {
            "base_url": "https://$SERVER_NAME:8448",
            "server_name": "$SERVER_NAME"
        },
        "m.identity_server": {
            "base_url": "https://vector.im"
        }
    },
    "disable_custom_urls": false,
    "disable_guests": false,
    "disable_login_language_selector": false,
    "disable_3pid_login": false,
    "brand": "Element",
    "integrations_ui_url": "https://scalar.vector.im/",
    "integrations_rest_url": "https://scalar.vector.im/api",
    "integrations_widgets_urls": [
        "https://scalar.vector.im/_matrix/integrations/v1",
        "https://scalar.vector.im/api",
        "https://scalar-staging.vector.im/_matrix/integrations/v1",
        "https://scalar-staging.vector.im/api",
        "https://scalar-staging.riot.im/scalar/api"
    ],
    "default_country_code": "GB",
    "show_labs_settings": false,
    "features": {},
    "default_federate": true,
    "default_theme": "light",
    "room_directory": {
        "servers": ["matrix.org"]
    },
    "enable_presence_by_hs_url": {
        "https://matrix.org": false,
        "https://matrix-client.matrix.org": false
    },
    "setting_defaults": {
        "breadcrumbs": true
    },
    "jitsi": {
        "preferred_domain": "$JITSI_DNS"
    },
    "element_call": {
        "url": "https://call.element.io",
        "participant_limit": 8,
        "brand": "Element Call"
    },
    "map_style_url": "https://api.maptiler.com/maps/streets/style.json?key=fU3vlMsMn4Jb6dnEIFsx"
}
EOM
