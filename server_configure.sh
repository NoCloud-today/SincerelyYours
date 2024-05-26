#!/bin/ksh
# need SERVER_NAME (dns server name)
# JITSI_DNS
# POSTGRES_USER_PASSWORD
# DB_SUPERUSER_PASSWORD
# DB_SYNAPSE_USER_PASSWORD
# _MY_EMAIL
# TURN_SERVER_NAME
# ELEMENT_SERVER_NAME
# ADMIN_SERVER_NAME
# _YOU_JVB_SECRET (password for jvb)
# _JITSI_STORE_PASSWORD (password for jitsi store and jvb store),
# _FOCUS_PASSWORD (password for focus prosody user)

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
pkg_add synapse postgresql-server py3-psycopg2 prosody jitsi-meet jicofo jitsi-videobridge
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
pkg_add pwgen
TURN_SECRET_KEY=$(pwgen -s 641)
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

# vim:ft=yaml
turn_uris: [ "turn:$TURN_SERVER_NAME?transport=udp", "turn:$TURN_SERVER_NAME?transport=tcp" ]
turn_shared_secret: "$TURN_SECRET_KEY"
turn_user_lifetime: 86400000
turn_allow_guests: true

EOM
rcctl enable synapse
pkg_add certbot
certbot certonly --standalone -d $SERVER_NAME --key-type rsa --quiet --agree-tos --email $_MY_EMAIL
ln -s /etc/letsencrypt/live/$SERVER_NAME/fullchain.pem /etc/ssl/$SERVER_NAME.cert
ln -s /etc/letsencrypt/live/$SERVER_NAME/privkey.pem /etc/ssl/private/$SERVER_NAME.key
certbot certonly --standalone -d $TURN_SERVER_NAME --key-type rsa --quiet --agree-tos --email $_MY_EMAIL
ln -s /etc/letsencrypt/live/$TURN_SERVER_NAME/fullchain.pem /etc/ssl/$TURN_SERVER_NAME.cert
ln -s /etc/letsencrypt/live/$TURN_SERVER_NAME/privkey.pem /etc/ssl/private/$TURN_SERVER_NAME.key
echo "0 0,12 * * * root python3 -c 'import random; import time; time.sleep(random.random() * 3600)' && sudo certbot renew -p" | tee -a /etc/crontab
cd /tmp
ftp https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/{ports.tar.gz,SHA256.sig}
signify -Cp /etc/signify/openbsd-$(uname -r | cut -c 1,3)-base.pub -x SHA256.sig ports.tar.gz
cd /usr
tar -xzf /tmp/ports.tar.gz
cd /usr/ports/telephony/coturn
make install
cat > /etc/turnserver.conf <<- EOM
use-auth-secret
static-auth-secret=$TURN_SECRET_KEY
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
cert=/etc/letsencrypt/live/$TURN_SERVER_NAME/fullchain.pem

# TLS private key file
pkey=/etc/letsencrypt/live/$TURN_SERVER_NAME/privkey.pem

# Ensure the configuration lines that disable TLS/DTLS are commented-out or removed
# no-tls
# no-dtls
EOM
rcctl start turnserver synapse
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
certbot certonly --standalone -d $ELEMENT_SERVER_NAME --key-type rsa --quiet --agree-tos --email $_MY_EMAIL
ln -s /etc/letsencrypt/live/$ELEMENT_SERVER_NAME/fullchain.pem /etc/ssl/$ELEMENT_SERVER_NAME.cert
ln -s /etc/letsencrypt/live/$ELEMENT_SERVER_NAME/privkey.pem /etc/ssl/private/$ELEMENT_SERVER_NAME.key
mkdir /var/www/synapse_admin
cd /var/www/synapse_admin
wget "https://github.com/Awesome-Technologies/synapse-admin/releases/download/0.10.1/synapse-admin-0.10.1.tar.gz"
tar -xzvf synapse-admin-0.10.1.tar.gz
certbot certonly --standalone -d $ADMIN_SERVER_NAME --key-type rsa --quiet --agree-tos --email $_MY_EMAIL
ln -s /etc/letsencrypt/live/$ADMIN_SERVER_NAME/fullchain.pem /etc/ssl/$ADMIN_SERVER_NAME.cert
ln -s /etc/letsencrypt/live/$ADMIN_SERVER_NAME/privkey.pem /etc/ssl/private/$ADMIN_SERVER_NAME.key

cat > /etc/pf.conf <<- EOM
#  \$OpenBSD: pf.conf,v 1.55 2017/12/03 20:40:04 sthen Exp \$
#
# See pf.conf(5) and /etc/examples/pf.conf

set skip on lo
block in all
pass out all
pass in proto { tcp udp } to port ssh
pass out proto { tcp udp } to port { 53 80 443 }
block return    # block stateless traffic
pass            # establish keep-state

# By default, do not permit remote connections to X11
block return in on ! lo0 proto tcp to port 6000:6010

# Port build user does not need network
block return out log proto {tcp udp} user _pbuild

pass in on egress proto tcp to port { 80 443 }
pass in on egress proto udp to port 10000

EOM

pfctl -f /etc/pf.conf
cat > /etc/prosody/prosody.cfg.lua <<- EOM
-- Prosody Example Configuration File
--
-- Information on configuring Prosody can be found on our
-- website at https://prosody.im/doc/configure
--
-- Tip: You can check that the syntax of this file is correct
-- when you have finished by running this command:
--     prosodyctl check config
-- If there are any errors, it will let you know what and where
-- they are, otherwise it will keep quiet.
--
-- The only thing left to do is rename this file to remove the .dist ending, and fill in the
-- blanks. Good luck, and happy Jabbering!


---------- Server-wide settings ----------
-- Settings in this section apply to the whole server and are the default settings
-- for any virtual hosts

-- This is a (by default, empty) list of accounts that are admins
-- for the server. Note that you must create the accounts separately
-- (see https://prosody.im/doc/creating_accounts for info)
-- Example: admins = { "user1@example.com", "user2@example.net" }
admins = { "focus@auth.$JITSI_DNS" }

-- Drop privileges
prosody_user = "_prosody"
prosody_group = "_prosody"

-- Enable POSIX-only options
pidfile = "/var/prosody/prosody.pid"

-- This option allows you to specify additional locations where Prosody
-- will search first for modules. For additional modules you can install, see
-- the community module repository at https://modules.prosody.im/
--plugin_paths = {}

-- This is the list of modules Prosody will load on startup.
-- Documentation for bundled modules can be found at: https://prosody.im/doc/modules
modules_enabled = {

  -- Generally required
    "disco"; -- Service discovery
    "roster"; -- Allow users to have a roster. Recommended ;)
    "saslauth"; -- Authentication for clients and servers. Recommended if you want to log in.
    "tls"; -- Add support for secure TLS on c2s/s2s connections

  -- Not essential, but recommended
    "blocklist"; -- Allow users to block communications with other users
    "bookmarks"; -- Synchronise the list of open rooms between clients
    "carbons"; -- Keep multiple online clients in sync
    "dialback"; -- Support for verifying remote servers using DNS
    "limits"; -- Enable bandwidth limiting for XMPP connections
    "pep"; -- Allow users to store public and private data in their account
    "private"; -- Legacy account storage mechanism (XEP-0049)
    "smacks"; -- Stream management and resumption (XEP-0198)
    "vcard4"; -- User profiles (stored in PEP)
    "vcard_legacy"; -- Conversion between legacy vCard and PEP Avatar, vcard

  -- Nice to have
    "csi_simple"; -- Simple but effective traffic optimizations for mobile devices
    "invites"; -- Create and manage invites
    "invites_adhoc"; -- Allow admins/users to create invitations via their client
    "invites_register"; -- Allows invited users to create accounts
    "ping"; -- Replies to XMPP pings with pongs
    "register"; -- Allow users to register on this server using a client and change passwords
    "time"; -- Let others know the time here on this server
    "uptime"; -- Report how long server has been running
    "version"; -- Replies to server version requests
    --"mam"; -- Store recent messages to allow multi-device synchronization
    --"turn_external"; -- Provide external STUN/TURN service for e.g. audio/video calls

  -- Admin interfaces
    "admin_adhoc"; -- Allows administration via an XMPP client that supports ad-hoc commands
    "admin_shell"; -- Allow secure administration via 'prosodyctl shell'

  -- HTTP modules
    --"bosh"; -- Enable BOSH clients, aka "Jabber over HTTP"
    --"http_openmetrics"; -- for exposing metrics to stats collectors
    --"websocket"; -- XMPP over WebSockets

  -- Other specific functionality
    --"announce"; -- Send announcement to all online users
    --"groups"; -- Shared roster support
    --"legacyauth"; -- Legacy authentication. Only used by some old clients and bots.
    --"mimicking"; -- Prevent address spoofing
    --"motd"; -- Send a message to users when they log in
    --"proxy65"; -- Enables a file transfer proxy service which clients behind NAT can use
    --"s2s_bidi"; -- Bi-directional server-to-server (XEP-0288)
    --"server_contact_info"; -- Publish contact information for this service
    --"tombstones"; -- Prevent registration of deleted accounts
    --"watchregistrations"; -- Alert admins of registrations
    --"welcome"; -- Welcome users who register accounts
}

-- These modules are auto-loaded, but should you want
-- to disable them then uncomment them here:
modules_disabled = {
  -- "offline"; -- Store offline messages
  -- "c2s"; -- Handle client connections
  -- "s2s"; -- Handle server-to-server connections
  -- "posix"; -- POSIX functionality, sends server to background, etc.
}


-- Server-to-server authentication
-- Require valid certificates for server-to-server connections?
-- If false, other methods such as dialback (DNS) may be used instead.

s2s_secure_auth = true

-- Some servers have invalid or self-signed certificates. You can list
-- remote domains here that will not be required to authenticate using
-- certificates. They will be authenticated using other methods instead,
-- even when s2s_secure_auth is enabled.

--s2s_insecure_domains = { "insecure.example" }

-- Even if you disable s2s_secure_auth, you can still require valid
-- certificates for some domains by specifying a list here.

--s2s_secure_domains = { "jabber.org" }


-- Rate limits
-- Enable rate limits for incoming client and server connections. These help
-- protect from excessive resource consumption and denial-of-service attacks.

limits = {
  c2s = {
    rate = "10kb/s";
  };
  s2sin = {
    rate = "30kb/s";
  };
}

-- Authentication
-- Select the authentication backend to use. The 'internal' providers
-- use Prosody's configured data storage to store the authentication data.
-- For more information see https://prosody.im/doc/authentication

authentication = "internal_hashed"

-- Many authentication providers, including the default one, allow you to
-- create user accounts via Prosody's admin interfaces. For details, see the
-- documentation at https://prosody.im/doc/creating_accounts


-- Storage
-- Select the storage backend to use. By default Prosody uses flat files
-- in its configured data directory, but it also supports more backends
-- through modules. An "sql" backend is included by default, but requires
-- additional dependencies. See https://prosody.im/doc/storage for more info.

--storage = "sql" -- Default is "internal"

-- For the "sql" backend, you can uncomment *one* of the below to configure:
--sql = { driver = "SQLite3", database = "prosody.sqlite" } -- Default. 'database' is the filename.
--sql = { driver = "MySQL", database = "prosody", username = "prosody", password = "secret", host = "localhost" }
--sql = { driver = "PostgreSQL", database = "prosody", username = "prosody", password = "secret", host = "localhost" }


-- Archiving configuration
-- If mod_mam is enabled, Prosody will store a copy of every message. This
-- is used to synchronize conversations between multiple clients, even if
-- they are offline. This setting controls how long Prosody will keep
-- messages in the archive before removing them.

archive_expires_after = "1w" -- Remove archived messages after 1 week

-- You can also configure messages to be stored in-memory only. For more
-- archiving options, see https://prosody.im/doc/modules/mod_mam


-- Audio/video call relay (STUN/TURN)
-- To ensure clients connected to the server can establish connections for
-- low-latency media streaming (such as audio and video calls), it is
-- recommended to run a STUN/TURN server for clients to use. If you do this,
-- specify the details here so clients can discover it.
-- Find more information at https://prosody.im/doc/turn

-- Specify the address of the TURN service (you may use the same domain as XMPP)
--turn_external_host = "turn.example.com"

-- This secret must be set to the same value in both Prosody and the TURN server
--turn_external_secret = "your-secret-turn-access-token"


-- Logging configuration
-- For advanced logging see https://prosody.im/doc/logging
log = {
  info = "/var/prosody/prosody.log"; -- Change 'info' to 'debug' for verbose logging
  error = "/var/prosody/prosody.err";
  -- "*syslog"; -- Uncomment this for logging to syslog
  -- "*console"; -- Log to the console, useful for debugging when running in the foreground
}


-- Uncomment to enable statistics
-- For more info see https://prosody.im/doc/statistics
-- statistics = "internal"


-- Certificates
-- Every virtual host and component needs a certificate so that clients and
-- servers can securely verify its identity. Prosody will automatically load
-- certificates/keys from the directory specified here.
-- For more information, including how to use 'prosodyctl' to auto-import certificates
-- (from e.g. Let's Encrypt) see https://prosody.im/doc/certificates

-- Location of directory to find certificates in (relative to main config file):
certificates = "certs"

----------- Virtual hosts -----------
-- You need to add a VirtualHost entry for each domain you wish Prosody to serve.
-- Settings under each VirtualHost entry apply *only* to that host.

http_interfaces = { "*", "::" }
VirtualHost "$JITSI_DNS"
    authentication = "anonymous";
    modules_enabled = { "bosh";
        "pubsub"; }
    c2s_require_encryption = false
VirtualHost "localhost"
VirtualHost "auth.$JITSI_DNS"
  admins = { "focus@auth.$JITSI_DNS",
  "jvb@auth.$JITSI_DNS" }
  ssl = {
    certificate = "/var/prosody/auth.$JITSI_DNS.crt";
    key = "/var/prosody/auth.$JITSI_DNS.key";
  }
  authentication = "internal_hashed"
Component "conference.$JITSI_DNS" "muc"
Component "jvb.$JITSI_DNS"
   component_secret = "$_YOU_JVB_SECRET"
Component "focus.$JITSI_DNS" "client_proxy"
   target_address = "focus@auth.$JITSI_DNS"
Component "internal.auth.$JITSI_DNS" "muc"
   muc_room_locking = false
   muc_room_default_public_jids = true
-- Prosody requires at least one enabled VirtualHost to function. You can
-- safely remove or disable 'localhost' once you have added another.


--VirtualHost "example.com"

------ Components ------
-- You can specify components to add hosts that provide special services,
-- like multi-user conferences, and transports.
-- For more information on components, see https://prosody.im/doc/components

---Set up a MUC (multi-user chat) room server on conference.example.com:
--Component "conference.example.com" "muc"
--- Store MUC messages in an archive and allow users to access it
--modules_enabled = { "muc_mam" }

---Set up a file sharing component
--Component "share.example.com" "http_file_share"

---Set up an external component (default component port is 5347)
--
-- External components allow adding various services, such as gateways/
-- bridges to non-XMPP networks and services. For more info
-- see: https://prosody.im/doc/components#adding_an_external_component
--
--Component "gateway.example.com"
--  component_secret = "password"


---------- End of the Prosody Configuration file ----------
-- You usually **DO NOT** want to add settings here at the end, as they would
-- only apply to the last defined VirtualHost or Component.
--
-- Settings for the global section should go higher up, before the first
-- VirtualHost or Component line, while settings intended for specific hosts
-- should go under the corresponding VirtualHost or Component line.
--
-- For more information see https://prosody.im/doc/configure
EOM
echo "\n\n\n\n\n\n\n" | prosodyctl cert generate auth.$JITSI_DNS --quiet
echo "yes\n" | $(javaPathHelper -h jicofo)/bin/keytool -import -alias prosody -file /var/prosody/auth.$JITSI_DNS.crt -keystore /etc/ssl/jitsi.store -storepass $_JITSI_STORE_PASSWORD
cp /etc/ssl/jitsi.store /etc/ssl/jvb.store
prosodyctl install --server=https://modules.prosody.im/rocks/ mod_client_proxy
prosodyctl install --server=https://modules.prosody.im/rocks/ mod_roster_command
prosodyctl register focus auth.$JITSI_DNS $_FOCUS_PASSWORD
prosodyctl register jvb auth.$JITSI_DNS $_YOU_JVB_SECRET
prosodyctl mod_roster_command subscribe focus.$JITSI_DNS focus@auth.$JITSI_DNS
rcctl set jicofo flags "--host=$JITSI_DNS"
certbot certonly --key-type rsa --standalone -w /var/www/jitsi-meet -d $JITSI_DNS --quiet --agree-tos --email $_MY_EMAIL
ln -s /etc/letsencrypt/live/$JITSI_DNS/fullchain.pem /etc/ssl/$JITSI_DNS.cert
ln -s /etc/letsencrypt/live/$JITSI_DNS/privkey.pem /etc/ssl/private/$JITSI_DNS.key
cat > /etc/jicofo/jicofo.in.sh <<- EOM
JICOFO_CONF=/etc/jicofo/jicofo.conf
JICOFO_LOG_CONFIG=/etc/jicofo/logging.properties
JICOFO_TRUSTSTORE=/etc/ssl/jitsi.store
JICOFO_TRUSTSTORE_PASSWORD='$_JITSI_STORE_PASSWORD'
JICOFO_MAXMEM=3G
JICOFO_DHKEYSIZE=2048
EOM
cat > /etc/jicofo/jicofo.conf <<- EOM
jicofo {
  authentication {
    enabled = false
    type = SHIBBOLETH
    # login-url =
    # logout-url =
    authentication-lifetime = 24 hours
    enable-auto-login = true
  }
  // Configuration related to jitsi-videobridge
  bridge {
    health-checks {
      // Whether jicofo should perform periodic health checks to the connected bridges.
      enabled = true
      // The interval at which to perform health checks.
      interval = 10 seconds
      // Use the lack of presence to infer unhealthy status instead of sending explicit health check requests.
      use-presence = false
      // A bridge will be consider unhealthy unless we've received its presence in that period.
      presence-timeout = 45 seconds
    }
    // The JID of the MUC to be used as a brewery for bridge instances.
    brewery-jid = "JvbBrewery@internal.auth.$JITSI_DNS"
    # brewery-jid = jvbbrewery@example.com
    xmpp-connection-name = Client
  }
  conference {
    // Whether to automatically grant the 'owner' role to the first participant in the conference (and subsequently to
    enable-auto-owner = true
  }

  rest {
    port = 8888
    tls-port = 8843
    prometheus {
      enabled = true
    }
  }

  sctp {
    enabled = false
  }
  xmpp {
    // The separate XMPP connection used for communication with clients (endpoints).
    client {
      enabled = true
      hostname = "localhost"
      port = 5222
      domain = "auth.$JITSI_DNS"
      username = "focus"
      password = "$_FOCUS_PASSWORD"
      // A flag to suppress the TLS certificate verification. XXX really?
      disable-certificate-verification = true

      // Use TLS between Jicofo and the XMPP server
      use-tls = true
    }
    // The separate XMPP connection used for internal services (currently only jitsi-videobridge).
    service {
      enabled = false
      # further params as \`client\`
    }

    // The list of domains with trusted services. Only members logged in to these domains can declare themselves to be
    // Jibri instances.
    trusted-domains = [ "auth.$JITSI_DNS" ]
  }
}
EOM
cat > /etc/jvb/jvb.conf <<- EOM
ice4j {
  harvest {
    use-link-local-addresses = false
  }
}

videobridge {
  apis {
    xmpp-client {
      presence-interval = 120s
      configs {
        ourprosody {
          hostname = "localhost"
          domain = "auth.$JITSI_DNS"
          username = "jvb"
          password = "$_YOU_JVB_SECRET"
          muc_jids = "JvbBrewery@internal.auth.$JITSI_DNS"
          muc_nickname = "jvb"
          disable_certificate_verification = true
        }
      }
    }
  }
  sctp {
    enabled = false
  }
  ice {
    tcp {
      enabled = false
      port = 443
    }
    udp {
      port = 10000
    }
  }
}
EOM
cat > /etc/jvb/jvb.in.sh <<- EOM
JVB_CONF=/etc/jvb/jvb.conf
JVB_LOG_CONFIG=/etc/jvb/logging.properties
JVB_TRUSTSTORE=/etc/ssl/jvb.store
JVB_TRUSTSTORE_PASSWORD='$_JITSI_STORE_PASSWORD'
JVB_MAXMEM=3G
JVB_DHKEYSIZE=2048
JVB_GC_TYPE=G1GC
JVB_SC_HOME_LOCATION='/etc'
JVB_SC_HOME_NAME='jvb'
EOM
cat > /var/www/jitsi-meet/config.js <<- EOM
/* eslint-disable comma-dangle, no-unused-vars, no-var, prefer-template, vars-on-top */

/*
 * NOTE: If you add a new option please remember to document it here:
 * https://jitsi.github.io/handbook/docs/dev-guide/dev-guide-configuration
 */

var subdir = '<!--# echo var="subdir" default="" -->';
var subdomain = '<!--# echo var="subdomain" default="" -->';

if (subdomain) {
    subdomain = subdomain.substr(0, subdomain.length - 1).split('.')
        .join('_')
        .toLowerCase() + '.';
}

// In case of no ssi provided by the webserver, use empty strings
if (subdir.startsWith('<!--')) {
    subdir = '';
}
if (subdomain.startsWith('<!--')) {
    subdomain = '';
}

var enableJaaS = false;

var config = {
    // Connection
    //

    hosts: {
        // XMPP domain.
        domain: '$JITSI_DNS',

        // When using authentication, domain for guest users.
        // anonymousdomain: 'guest.example.com',

        // Domain for authenticated users. Defaults to <domain>.
        // authdomain: 'jitsi-meet.example.com',

        // Focus component domain. Defaults to focus.<domain>.
        // focus: 'focus.jitsi-meet.example.com',

        // XMPP MUC domain. FIXME: use XEP-0030 to discover it.
        muc: 'conference.$JITSI_DNS',
    },

    // BOSH URL. FIXME: use XEP-0156 to discover it.
    bosh: '//$JITSI_DNS/http-bind',

    // Websocket URL
    // websocket: 'wss://jitsi-meet.example.com/' + subdir + 'xmpp-websocket',

    // The real JID of focus participant - can be overridden here
    // Do not change username - FIXME: Make focus username configurable
    // https://github.com/jitsi/jitsi-meet/issues/7376
    // focusUserJid: 'focus@auth.jitsi-meet.example.com',


    // Testing / experimental features.
    //

    testing: {
        // Disables the End to End Encryption feature. Useful for debugging
        // issues related to insertable streams.
        // disableE2EE: false,

        // Enables XMPP WebSocket (as opposed to BOSH) for the given amount of users.
        // mobileXmppWsThreshold: 10, // enable XMPP WebSockets on mobile for 10% of the users

        // P2P test mode disables automatic switching to P2P when there are 2
        // participants in the conference.
        // p2pTestMode: false,

        // Enables the test specific features consumed by jitsi-meet-torture
        // testMode: false,

        // Disables the auto-play behavior of *all* newly created video element.
        // This is useful when the client runs on a host with limited resources.
        // noAutoPlayVideo: false,

        // Enable callstats only for a percentage of users.
        // This takes a value between 0 and 100 which determines the probability for
        // the callstats to be enabled.
        // callStatsThreshold: 5, // enable callstats for 5% of the users.
    },

    // Disables moderator indicators.
    // disableModeratorIndicator: false,

    // Disables the reactions feature.
    // disableReactions: true,

    // Disables the reactions moderation feature.
    // disableReactionsModeration: false,

    // Disables polls feature.
    // disablePolls: false,

    // Disables self-view tile. (hides it from tile view and from filmstrip)
    // disableSelfView: false,

    // Disables self-view settings in UI
    // disableSelfViewSettings: false,

    // screenshotCapture : {
    //      Enables the screensharing capture feature.
    //      enabled: false,
    //
    //      The mode for the screenshot capture feature.
    //      Can be either 'recording' - screensharing screenshots are taken
    //      only when the recording is also on,
    //      or 'always' - screensharing screenshots are always taken.
    //      mode: 'recording',
    // }

    // Disables ICE/UDP by filtering out local and remote UDP candidates in
    // signalling.
    // webrtcIceUdpDisable: false,

    // Disables ICE/TCP by filtering out local and remote TCP candidates in
    // signalling.
    // webrtcIceTcpDisable: false,


    // Media
    //

    // Enable unified plan implementation support on Chromium based browsers.
    // enableUnifiedOnChrome: false,

    // Audio

    // Disable measuring of audio levels.
    // disableAudioLevels: false,

    // audioLevelsInterval: 200,

    // Enabling this will run the lib-jitsi-meet no audio detection module which
    // will notify the user if the current selected microphone has no audio
    // input and will suggest another valid device if one is present.
    enableNoAudioDetection: true,

    // Enabling this will show a "Save Logs" link in the GSM popover that can be
    // used to collect debug information (XMPP IQs, SDP offer/answer cycles)
    // about the call.
    // enableSaveLogs: false,

    // Enabling this will hide the "Show More" link in the GSM popover that can be
    // used to display more statistics about the connection (IP, Port, protocol, etc).
    // disableShowMoreStats: true,

    // Enabling this will run the lib-jitsi-meet noise detection module which will
    // notify the user if there is noise, other than voice, coming from the current
    // selected microphone. The purpose it to let the user know that the input could
    // be potentially unpleasant for other meeting participants.
    enableNoisyMicDetection: true,

    // Start the conference in audio only mode (no video is being received nor
    // sent).
    // startAudioOnly: false,

    // Every participant after the Nth will start audio muted.
    // startAudioMuted: 10,

    // Start calls with audio muted. Unlike the option above, this one is only
    // applied locally. FIXME: having these 2 options is confusing.
    // startWithAudioMuted: false,

    // Enabling it (with #params) will disable local audio output of remote
    // participants and to enable it back a reload is needed.
    // startSilent: false,

    // Enables support for opus-red (redundancy for Opus).
    // enableOpusRed: false,

    // Specify audio quality stereo and opusMaxAverageBitrate values in order to enable HD audio.
    // Beware, by doing so, you are disabling echo cancellation, noise suppression and AGC.
    // Specify enableOpusDtx to enable support for opus-dtx where
    // audio packets won’t be transmitted while participant is silent or muted.
    // audioQuality: {
    //     stereo: false,
    //     opusMaxAverageBitrate: null, // Value to fit the 6000 to 510000 range.
    //     enableOpusDtx: false,
    // },

    // Video

    // Sets the preferred resolution (height) for local video. Defaults to 720.
    // resolution: 720,

    // Specifies whether the raised hand will hide when someone becomes a dominant speaker or not
    // disableRemoveRaisedHandOnFocus: false,

    // speakerStats: {
    //     // Specifies whether the speaker stats is enable or not.
    //     disabled: false,

    //     // Specifies whether there will be a search field in speaker stats or not.
    //     disableSearch: false,

    //     // Specifies whether participants in speaker stats should be ordered or not, and with what priority.
    //     // 'role', <- Moderators on top.
    //     // 'name', <- Alphabetically by name.
    //     // 'hasLeft', <- The ones that have left in the bottom.
    //     order: [
    //         'role',
    //         'name',
    //         'hasLeft',
    //     ],
    // },

    // DEPRECATED. Please use speakerStats.disableSearch instead.
    // Specifies whether there will be a search field in speaker stats or not
    // disableSpeakerStatsSearch: false,

    // DEPRECATED. Please use speakerStats.order .
    // Specifies whether participants in speaker stats should be ordered or not, and with what priority
    // speakerStatsOrder: [
    //  'role', <- Moderators on top
    //  'name', <- Alphabetically by name
    //  'hasLeft', <- The ones that have left in the bottom
    // ], <- the order of the array elements determines priority

    // How many participants while in the tile view mode, before the receiving video quality is reduced from HD to SD.
    // Use -1 to disable.
    // maxFullResolutionParticipants: 2,

    // w3c spec-compliant video constraints to use for video capture. Currently
    // used by browsers that return true from lib-jitsi-meet's
    // util#browser#usesNewGumFlow. The constraints are independent from
    // this config's resolution value. Defaults to requesting an ideal
    // resolution of 720p.
    // constraints: {
    //     video: {
    //         height: {
    //             ideal: 720,
    //             max: 720,
    //             min: 240,
    //         },
    //     },
    // },

    // Enable / disable simulcast support.
    // disableSimulcast: false,

    // Enable / disable layer suspension.  If enabled, endpoints whose HD layers are not in use will be suspended
    // (no longer sent) until they are requested again. This is enabled by default. This must be enabled for screen
    // sharing to work as expected on Chrome. Disabling this might result in low resolution screenshare being sent
    // by the client.
    // enableLayerSuspension: false,

    // Every participant after the Nth will start video muted.
    // startVideoMuted: 10,

    // Start calls with video muted. Unlike the option above, this one is only
    // applied locally. FIXME: having these 2 options is confusing.
    // startWithVideoMuted: false,

    // Desktop sharing

    // Optional desktop sharing frame rate options. Default value: min:5, max:5.
    // desktopSharingFrameRate: {
    //     min: 5,
    //     max: 5,
    // },

    // This option has been deprecated since it is no longer supported as per the w3c spec.
    // https://w3c.github.io/mediacapture-screen-share/#dom-mediadevices-getdisplaymedia. If the user has not
    // interacted with the webpage before the getDisplayMedia call, the promise will be rejected by the browser. This
    // has already been implemented in Firefox and Safari and will be implemented in Chrome soon.
    // https://bugs.chromium.org/p/chromium/issues/detail?id=1198918
    // startScreenSharing: false,

    // Recording

    // DEPRECATED. Use recordingService.enabled instead.
    // fileRecordingsEnabled: false,

    // Enable the dropbox integration.
    // dropbox: {
    //     appKey: '<APP_KEY>', // Specify your app key here.
    //     // A URL to redirect the user to, after authenticating
    //     // by default uses:
    //     // 'https://jitsi-meet.example.com/static/oauth.html'
    //     redirectURI:
    //          'https://jitsi-meet.example.com/subfolder/static/oauth.html',
    // },

    // recordingService: {
    //     // When integrations like dropbox are enabled only that will be shown,
    //     // by enabling fileRecordingsServiceEnabled, we show both the integrations
    //     // and the generic recording service (its configuration and storage type
    //     // depends on jibri configuration)
    //     enabled: false,

    //     // Whether to show the possibility to share file recording with other people
    //     // (e.g. meeting participants), based on the actual implementation
    //     // on the backend.
    //     sharingEnabled: false,

    //     // Hide the warning that says we only store the recording for 24 hours.
    //     hideStorageWarning: false,
    // },

    // DEPRECATED. Use recordingService.enabled instead.
    // fileRecordingsServiceEnabled: false,

    // DEPRECATED. Use recordingService.sharingEnabled instead.
    // fileRecordingsServiceSharingEnabled: false,

    // Local recording configuration.
    // localRecording: {
    //     // Whether to disable local recording or not.
    //     disable: false,

    //     // Whether to notify all participants when a participant is recording locally.
    //     notifyAllParticipants: false,

    //     // Whether to disable the self recording feature (only local participant streams).
    //     disableSelfRecording: false,
    // },

    // Customize the Live Streaming dialog. Can be modified for a non-YouTube provider.
    // liveStreaming: {
    //    // Whether to enable live streaming or not.
    //    enabled: false,
    //    // Terms link
    //    termsLink: 'https://www.youtube.com/t/terms',
    //    // Data privacy link
    //    dataPrivacyLink: 'https://policies.google.com/privacy',
    //    // RegExp string that validates the stream key input field
    //    validatorRegExpString: '^(?:[a-zA-Z0-9]{4}(?:-(?!$)|$)){4}',
    //    // Documentation reference for the live streaming feature.
    //    helpLink: 'https://jitsi.org/live'
    // },

    // DEPRECATED. Use liveStreaming.enabled instead.
    // liveStreamingEnabled: false,

    // DEPRECATED. Use transcription.enabled instead.
    // transcribingEnabled: false,

    // DEPRECATED. Use transcription.useAppLanguage instead.
    // transcribeWithAppLanguage: true,

    // DEPRECATED. Use transcription.preferredLanguage instead.
    // preferredTranscribeLanguage: 'en-US',

    // DEPRECATED. Use transcription.autoCaptionOnRecord instead.
    // autoCaptionOnRecord: false,

    // Transcription options.
    // transcription: {
    //     // Whether the feature should be enabled or not.
    //     enabled: false,

    //     // Translation languages.
    //     // Available languages can be found in
    //     // ./src/react/features/transcribing/translation-languages.json.
    //     translationLanguages: ['en', 'es', 'fr', 'ro'],

    //     // Important languages to show on the top of the language list.
    //     translationLanguagesHead: ['en'],

    //     // If true transcriber will use the application language.
    //     // The application language is either explicitly set by participants in their settings or automatically
    //     // detected based on the environment, e.g. if the app is opened in a chrome instance which
    //     // is using french as its default language then transcriptions for that participant will be in french.
    //     // Defaults to true.
    //     useAppLanguage: true,

    //     // Transcriber language. This settings will only work if "useAppLanguage"
    //     // is explicitly set to false.
    //     // Available languages can be found in
    //     // ./src/react/features/transcribing/transcriber-langs.json.
    //     preferredLanguage: 'en-US',

    //     // Disable start transcription for all participants.
    //     disableStartForAll: false,

    //     // Enables automatic turning on captions when recording is started
    //     autoCaptionOnRecord: false,
    // },

    // Misc

    // Default value for the channel "last N" attribute. -1 for unlimited.
    channelLastN: -1,

    // Connection indicators
    // connectionIndicators: {
    //     autoHide: true,
    //     autoHideTimeout: 5000,
    //     disabled: false,
    //     disableDetails: false,
    //     inactiveDisabled: false
    // },

    // Provides a way for the lastN value to be controlled through the UI.
    // When startLastN is present, conference starts with a last-n value of startLastN and channelLastN
    // value will be used when the quality level is selected using "Manage Video Quality" slider.
    // startLastN: 1,

    // Provides a way to use different "last N" values based on the number of participants in the conference.
    // The keys in an Object represent number of participants and the values are "last N" to be used when number of
    // participants gets to or above the number.
    //
    // For the given example mapping, "last N" will be set to 20 as long as there are at least 5, but less than
    // 29 participants in the call and it will be lowered to 15 when the 30th participant joins. The 'channelLastN'
    // will be used as default until the first threshold is reached.
    //
    // lastNLimits: {
    //     5: 20,
    //     30: 15,
    //     50: 10,
    //     70: 5,
    //     90: 2,
    // },

    // Specify the settings for video quality optimizations on the client.
    // videoQuality: {
    //    // Provides a way to prevent a video codec from being negotiated on the JVB connection. The codec specified
    //    // here will be removed from the list of codecs present in the SDP answer generated by the client. If the
    //    // same codec is specified for both the disabled and preferred option, the disable settings will prevail.
    //    // Note that 'VP8' cannot be disabled since it's a mandatory codec, the setting will be ignored in this case.
    //    disabledCodec: 'H264',
    //
    //    // Provides a way to set a preferred video codec for the JVB connection. If 'H264' is specified here,
    //    // simulcast will be automatically disabled since JVB doesn't support H264 simulcast yet. This will only
    //    // rearrange the the preference order of the codecs in the SDP answer generated by the browser only if the
    //    // preferred codec specified here is present. Please ensure that the JVB offers the specified codec for this
    //    // to take effect.
    //    preferredCodec: 'VP8',
    //
    //    // Provides a way to enforce the preferred codec for the conference even when the conference has endpoints
    //    // that do not support the preferred codec. For example, older versions of Safari do not support VP9 yet.
    //    // This will result in Safari not being able to decode video from endpoints sending VP9 video.
    //    // When set to false, the conference falls back to VP8 whenever there is an endpoint that doesn't support the
    //    // preferred codec and goes back to the preferred codec when that endpoint leaves.
    //    enforcePreferredCodec: false,
    //
    //    // Provides a way to configure the maximum bitrates that will be enforced on the simulcast streams for
    //    // video tracks. The keys in the object represent the type of the stream (LD, SD or HD) and the values
    //    // are the max.bitrates to be set on that particular type of stream. The actual send may vary based on
    //    // the available bandwidth calculated by the browser, but it will be capped by the values specified here.
    //    // This is currently not implemented on app based clients on mobile.
    //    maxBitratesVideo: {
    //          H264: {
    //              low: 200000,
    //              standard: 500000,
    //              high: 1500000,
    //          },
    //          VP8 : {
    //              low: 200000,
    //              standard: 500000,
    //              high: 1500000,
    //          },
    //          VP9: {
    //              low: 100000,
    //              standard: 300000,
    //              high: 1200000,
    //          },
    //    },
    //
    //    // The options can be used to override default thresholds of video thumbnail heights corresponding to
    //    // the video quality levels used in the application. At the time of this writing the allowed levels are:
    //    //     'low' - for the low quality level (180p at the time of this writing)
    //    //     'standard' - for the medium quality level (360p)
    //    //     'high' - for the high quality level (720p)
    //    // The keys should be positive numbers which represent the minimal thumbnail height for the quality level.
    //    //
    //    // With the default config value below the application will use 'low' quality until the thumbnails are
    //    // at least 360 pixels tall. If the thumbnail height reaches 720 pixels then the application will switch to
    //    // the high quality.
    //    minHeightForQualityLvl: {
    //        360: 'standard',
    //        720: 'high',
    //    },
    //
    // },

    // Notification timeouts
    // notificationTimeouts: {
    //     short: 2500,
    //     medium: 5000,
    //     long: 10000,
    // },

    // // Options for the recording limit notification.
    // recordingLimit: {
    //
    //    // The recording limit in minutes. Note: This number appears in the notification text
    //    // but doesn't enforce the actual recording time limit. This should be configured in
    //    // jibri!
    //    limit: 60,
    //
    //    // The name of the app with unlimited recordings.
    //    appName: 'Unlimited recordings APP',
    //
    //    // The URL of the app with unlimited recordings.
    //    appURL: 'https://unlimited.recordings.app.com/',
    // },

    // Disables or enables RTX (RFC 4588) (defaults to false).
    // disableRtx: false,

    // Moves all Jitsi Meet 'beforeunload' logic (cleanup, leaving, disconnecting, etc) to the 'unload' event.
    // disableBeforeUnloadHandlers: true,

    // Disables or enables TCC support in this client (default: enabled).
    // enableTcc: true,

    // Disables or enables REMB support in this client (default: enabled).
    // enableRemb: true,

    // Enables ICE restart logic in LJM and displays the page reload overlay on
    // ICE failure. Current disabled by default because it's causing issues with
    // signaling when Octo is enabled. Also when we do an "ICE restart"(which is
    // not a real ICE restart), the client maintains the TCC sequence number
    // counter, but the bridge resets it. The bridge sends media packets with
    // TCC sequence numbers starting from 0.
    // enableIceRestart: false,

    // Enables forced reload of the client when the call is migrated as a result of
    // the bridge going down.
    // enableForcedReload: true,

    // Use TURN/UDP servers for the jitsi-videobridge connection (by default
    // we filter out TURN/UDP because it is usually not needed since the
    // bridge itself is reachable via UDP)
    // useTurnUdp: false

    // Enable support for encoded transform in supported browsers. This allows
    // E2EE to work in Safari if the corresponding flag is enabled in the browser.
    // Experimental.
    // enableEncodedTransformSupport: false,

    // UI
    //

    // Disables responsive tiles.
    // disableResponsiveTiles: false,

    // DEPRECATED. Please use \`securityUi?.hideLobbyButton\` instead.
    // Hides lobby button.
    // hideLobbyButton: false,

    // DEPRECATED. Please use \`lobby?.autoKnock\` instead.
    // If Lobby is enabled starts knocking automatically.
    // autoKnockLobby: false,

    // DEPRECATED. Please use \`lobby?.enableChat\` instead.
    // Enable lobby chat.
    // enableLobbyChat: true,

    // DEPRECATED! Use \`breakoutRooms.hideAddRoomButton\` instead.
    // Hides add breakout room button
    // hideAddRoomButton: false,

    // Require users to always specify a display name.
    // requireDisplayName: true,

    // DEPRECATED! Use 'welcomePage.disabled' instead.
    // Whether to use a welcome page or not. In case it's false a random room
    // will be joined when no room is specified.
    // enableWelcomePage: true,

    // Configs for welcome page.
    // welcomePage: {
    //     // Whether to disable welcome page. In case it's disabled a random room
    //     // will be joined when no room is specified.
    //     disabled: false,
    //     // If set,landing page will redirect to this URL.
    //     customUrl: ''
    // },

    // Configs for the lobby screen.
    // lobby {
    //     // If Lobby is enabled, it starts knocking automatically. Replaces \`autoKnockLobby\`.
    //     autoKnock: false,
    //     // Enables the lobby chat. Replaces \`enableLobbyChat\`.
    //     enableChat: true,
    // },

    // Configs for the security related UI elements.
    // securityUi: {
    //     // Hides the lobby button. Replaces \`hideLobbyButton\`.
    //     hideLobbyButton: false,
    //     // Hides the possibility to set and enter a lobby password.
    //     disableLobbyPassword: false,
    // },

    // Disable app shortcuts that are registered upon joining a conference
    // disableShortcuts: false,

    // Disable initial browser getUserMedia requests.
    // This is useful for scenarios where users might want to start a conference for screensharing only
    // disableInitialGUM: false,

    // Enabling the close page will ignore the welcome page redirection when
    // a call is hangup.
    // enableClosePage: false,

    // Disable hiding of remote thumbnails when in a 1-on-1 conference call.
    // Setting this to null, will also disable showing the remote videos
    // when the toolbar is shown on mouse movements
    // disable1On1Mode: null | false | true,

    // Default local name to be displayed
    // defaultLocalDisplayName: 'me',

    // Default remote name to be displayed
    // defaultRemoteDisplayName: 'Fellow Jitster',

    // Hides the display name from the participant thumbnail
    // hideDisplayName: false,

    // Hides the dominant speaker name badge that hovers above the toolbox
    // hideDominantSpeakerBadge: false,

    // Default language for the user interface. Cannot be overwritten.
    // defaultLanguage: 'en',

    // Disables profile and the edit of all fields from the profile settings (display name and email)
    // disableProfile: false,

    // Hides the email section under profile settings.
    // hideEmailInSettings: false,

    // When enabled the password used for locking a room is restricted to up to the number of digits specified
    // default: roomPasswordNumberOfDigits: false,
    // roomPasswordNumberOfDigits: 10,

    // Message to show the users. Example: 'The service will be down for
    // maintenance at 01:00 AM GMT,
    // noticeMessage: '',

    // Enables calendar integration, depends on googleApiApplicationClientID
    // and microsoftApiApplicationClientID
    // enableCalendarIntegration: false,

    // Configs for prejoin page.
    prejoinConfig: {
    //     // When 'true', it shows an intermediate page before joining, where the user can configure their devices.
    //     // This replaces \`prejoinPageEnabled\`.
         enabled: true,
    //     // Hides the participant name editing field in the prejoin screen.
    //     // If requireDisplayName is also set as true, a name should still be provided through
    //     // either the jwt or the userInfo from the iframe api init object in order for this to have an effect.
    //     hideDisplayName: false,
    //     // List of buttons to hide from the extra join options dropdown.
         hideExtraJoinButtons: ['no-audio', 'by-phone'],
     },

    // When 'true', the user cannot edit the display name.
    // (Mainly useful when used in conjunction with the JWT so the JWT name becomes read only.)
    // readOnlyName: false,

    // If etherpad integration is enabled, setting this to true will
    // automatically open the etherpad when a participant joins.  This
    // does not affect the mobile app since opening an etherpad
    // obscures the conference controls -- it's better to let users
    // choose to open the pad on their own in that case.
    // openSharedDocumentOnJoin: false,

    // If true, shows the unsafe room name warning label when a room name is
    // deemed unsafe (due to the simplicity in the name) and a password is not
    // set or the lobby is not enabled.
    // enableInsecureRoomNameWarning: false,

    // Whether to automatically copy invitation URL after creating a room.
    // Document should be focused for this option to work
    // enableAutomaticUrlCopy: false,

    // Array with avatar URL prefixes that need to use CORS.
    // corsAvatarURLs: [ 'https://www.gravatar.com/avatar/' ],

    // Base URL for a Gravatar-compatible service. Defaults to Gravatar.
    // DEPRECATED! Use \`gravatar.baseUrl\` instead.
    // gravatarBaseURL: 'https://www.gravatar.com/avatar/',

    // Setup for Gravatar-compatible services.
    // gravatar: {
    //     // Defaults to Gravatar.
    //     baseUrl: 'https://www.gravatar.com/avatar/',
    //     // True if Gravatar should be disabled.
    //     disabled: false,
    // },

    // App name to be displayed in the invitation email subject, as an alternative to
    // interfaceConfig.APP_NAME.
    // inviteAppName: null,

    // Moved from interfaceConfig(TOOLBAR_BUTTONS).
    // The name of the toolbar buttons to display in the toolbar, including the
    // "More actions" menu. If present, the button will display. Exceptions are
    // "livestreaming" and "recording" which also require being a moderator and
    // some other values in config.js to be enabled. Also, the "profile" button will
    // not display for users with a JWT.
    // Notes:
    // - it's impossible to choose which buttons go in the "More actions" menu
    // - it's impossible to control the placement of buttons
    // - 'desktop' controls the "Share your screen" button
    // - if \`toolbarButtons\` is undefined, we fallback to enabling all buttons on the UI
    // toolbarButtons: [
    //    'camera',
    //    'chat',
    //    'closedcaptions',
    //    'desktop',
    //    'download',
    //    'embedmeeting',
    //    'etherpad',
    //    'feedback',
    //    'filmstrip',
    //    'fullscreen',
    //    'hangup',
    //    'help',
    //    'highlight',
    //    'invite',
    //    'linktosalesforce',
    //    'livestreaming',
    //    'microphone',
    //    'noisesuppression',
    //    'participants-pane',
    //    'profile',
    //    'raisehand',
    //    'recording',
    //    'security',
    //    'select-background',
    //    'settings',
    //    'shareaudio',
    //    'sharedvideo',
    //    'shortcuts',
    //    'stats',
    //    'tileview',
    //    'toggle-camera',
    //    'videoquality',
    //    'whiteboard',
    // ],

    // Holds values related to toolbar visibility control.
    // toolbarConfig: {
    //     // Moved from interfaceConfig.INITIAL_TOOLBAR_TIMEOUT
    //     // The initial number of milliseconds for the toolbar buttons to be visible on screen.
    //     initialTimeout: 20000,
    //     // Moved from interfaceConfig.TOOLBAR_TIMEOUT
    //     // Number of milliseconds for the toolbar buttons to be visible on screen.
    //     timeout: 4000,
    //     // Moved from interfaceConfig.TOOLBAR_ALWAYS_VISIBLE
    //     // Whether toolbar should be always visible or should hide after x milliseconds.
    //     alwaysVisible: false,
    //     // Indicates whether the toolbar should still autohide when chat is open
    //     autoHideWhileChatIsOpen: false,
    // },

    // Toolbar buttons which have their click/tap event exposed through the API on
    // \`toolbarButtonClicked\`. Passing a string for the button key will
    // prevent execution of the click/tap routine; passing an object with \`key\` and
    // \`preventExecution\` flag on false will not prevent execution of the click/tap
    // routine. Below array with mixed mode for passing the buttons.
    // buttonsWithNotifyClick: [
    //     'camera',
    //     {
    //         key: 'chat',
    //         preventExecution: false
    //     },
    //     {
    //         key: 'closedcaptions',
    //         preventExecution: true
    //     },
    //     'desktop',
    //     'download',
    //     'embedmeeting',
    //     'end-meeting',
    //     'etherpad',
    //     'feedback',
    //     'filmstrip',
    //     'fullscreen',
    //     'hangup',
    //     'hangup-menu',
    //     'help',
    //     {
    //         key: 'invite',
    //         preventExecution: false
    //     },
    //     'livestreaming',
    //     'microphone',
    //     'mute-everyone',
    //     'mute-video-everyone',
    //     'noisesuppression',
    //     'participants-pane',
    //     'profile',
    //     {
    //         key: 'raisehand',
    //         preventExecution: true
    //     },
    //     'recording',
    //     'security',
    //     'select-background',
    //     'settings',
    //     'shareaudio',
    //     'sharedvideo',
    //     'shortcuts',
    //     'stats',
    //     'tileview',
    //     'toggle-camera',
    //     'videoquality',
    //     // The add passcode button from the security dialog.
    //     {
    //         key: 'add-passcode',
    //         preventExecution: false
    //     },
    //     'whiteboard',
    // ],

    // List of pre meeting screens buttons to hide. The values must be one or more of the 5 allowed buttons:
    // 'microphone', 'camera', 'select-background', 'invite', 'settings'
    // hiddenPremeetingButtons: [],

    // An array with custom option buttons for the participant context menu
    // type:  Array<{ icon: string; id: string; text: string; }>
    // customParticipantMenuButtons: [],

    // An array with custom option buttons for the toolbar
    // type:  Array<{ icon: string; id: string; text: string; }>
    // customToolbarButtons: [],

    // Stats
    //

    // Whether to enable stats collection or not in the TraceablePeerConnection.
    // This can be useful for debugging purposes (post-processing/analysis of
    // the webrtc stats) as it is done in the jitsi-meet-torture bandwidth
    // estimation tests.
    // gatherStats: false,

    // The interval at which PeerConnection.getStats() is called. Defaults to 10000
    // pcStatsInterval: 10000,

    // To enable sending statistics to callstats.io you must provide the
    // Application ID and Secret.
    // callStatsID: '',
    // callStatsSecret: '',
    // callStatsApplicationLogsDisabled: false,

    // The callstats initialize config params as described in the API:
    // https://docs.callstats.io/docs/javascript#callstatsinitialize-with-app-secret
    // callStatsConfigParams: {
    //     disableBeforeUnloadHandler: true, // disables callstats.js's window.onbeforeunload parameter.
    //     applicationVersion: "app_version", // Application version specified by the developer.
    //     disablePrecalltest: true, // disables the pre-call test, it is enabled by default.
    //     siteID: "siteID", // The name/ID of the site/campus from where the call/pre-call test is made.
    //     additionalIDs: { // additionalIDs object, contains application related IDs.
    //         customerID: "Customer Identifier. Example, walmart.",
    //         tenantID: "Tenant Identifier. Example, monster.",
    //         productName: "Product Name. Example, Jitsi.",
    //         meetingsName: "Meeting Name. Example, Jitsi loves callstats.",
    //         serverName: "Server/MiddleBox Name. Example, jvb-prod-us-east-mlkncws12.",
    //         pbxID: "PBX Identifier. Example, walmart.",
    //         pbxExtensionID: "PBX Extension Identifier. Example, 5625.",
    //         fqExtensionID: "Fully qualified Extension Identifier. Example, +71 (US) +5625.",
    //         sessionID: "Session Identifier. Example, session-12-34",
    //     },
    //     collectLegacyStats: true, //enables the collection of legacy stats in chrome browser
    //     collectIP: true, //enables the collection localIP address
    // },

    // Enables sending participants' display names to callstats
    // enableDisplayNameInStats: false,

    // Enables sending participants' emails (if available) to callstats and other analytics
    // enableEmailInStats: false,

    // faceLandmarks: {
    //     // Enables sharing your face coordinates. Used for centering faces within a video.
    //     enableFaceCentering: false,

    //     // Enables detecting face expressions and sharing data with other participants
    //     enableFaceExpressionsDetection: false,

    //     // Enables displaying face expressions in speaker stats
    //     enableDisplayFaceExpressions: false,

    //     // Enable rtc stats for face landmarks
    //     enableRTCStats: false,

    //     // Minimum required face movement percentage threshold for sending new face centering coordinates data.
    //     faceCenteringThreshold: 10,

    //     // Milliseconds for processing a new image capture in order to detect face coordinates if they exist.
    //     captureInterval: 1000,
    // },

    // Controls the percentage of automatic feedback shown to participants when callstats is enabled.
    // The default value is 100%. If set to 0, no automatic feedback will be requested
    // feedbackPercentage: 100,

    // Privacy
    //

    // If third party requests are disabled, no other server will be contacted.
    // This means avatars will be locally generated and callstats integration
    // will not function.
    // disableThirdPartyRequests: false,


    // Peer-To-Peer mode: used (if enabled) when there are just 2 participants.
    //

    p2p: {
        // Enables peer to peer mode. When enabled the system will try to
        // establish a direct connection when there are exactly 2 participants
        // in the room. If that succeeds the conference will stop sending data
        // through the JVB and use the peer to peer connection instead. When a
        // 3rd participant joins the conference will be moved back to the JVB
        // connection.
        enabled: true,

        // Enable unified plan implementation support on Chromium for p2p connection.
        // enableUnifiedOnChrome: false,

        // Sets the ICE transport policy for the p2p connection. At the time
        // of this writing the list of possible values are 'all' and 'relay',
        // but that is subject to change in the future. The enum is defined in
        // the WebRTC standard:
        // https://www.w3.org/TR/webrtc/#rtcicetransportpolicy-enum.
        // If not set, the effective value is 'all'.
        // iceTransportPolicy: 'all',

        // Provides a way to set the video codec preference on the p2p connection. Acceptable
        // codec values are 'VP8', 'VP9' and 'H264'.
        // preferredCodec: 'H264',

        // Provides a way to prevent a video codec from being negotiated on the p2p connection.
        // disabledCodec: '',

        // How long we're going to wait, before going back to P2P after the 3rd
        // participant has left the conference (to filter out page reload).
        // backToP2PDelay: 5,

        // The STUN servers that will be used in the peer to peer connections
        stunServers: [

            // { urls: 'stun:jitsi-meet.example.com:3478' },
            { urls: 'stun:meet-jit-si-turnrelay.jitsi.net:443' },
        ],
    },

    analytics: {
        // True if the analytics should be disabled
        // disabled: false,

        // The Google Analytics Tracking ID:
        // googleAnalyticsTrackingId: 'your-tracking-id-UA-123456-1',

        // Matomo configuration:
        // matomoEndpoint: 'https://your-matomo-endpoint/',
        // matomoSiteID: '42',

        // The Amplitude APP Key:
        // amplitudeAPPKey: '<APP_KEY>',

        // Obfuscates room name sent to analytics (amplitude, rtcstats)
        // Default value is false.
        // obfuscateRoomName: false,

        // Configuration for the rtcstats server:
        // By enabling rtcstats server every time a conference is joined the rtcstats
        // module connects to the provided rtcstatsEndpoint and sends statistics regarding
        // PeerConnection states along with getStats metrics polled at the specified
        // interval.
        // rtcstatsEnabled: false,
        // rtcstatsStoreLogs: false,

        // In order to enable rtcstats one needs to provide a endpoint url.
        // rtcstatsEndpoint: wss://rtcstats-server-pilot.jitsi.net/,

        // The interval at which rtcstats will poll getStats, defaults to 10000ms.
        // If the value is set to 0 getStats won't be polled and the rtcstats client
        // will only send data related to RTCPeerConnection events.
        // rtcstatsPollInterval: 10000,

        // This determines if rtcstats sends the SDP to the rtcstats server or replaces
        // all SDPs with an empty string instead.
        // rtcstatsSendSdp: false,

        // Array of script URLs to load as lib-jitsi-meet "analytics handlers".
        // scriptURLs: [
        //      "libs/analytics-ga.min.js", // google-analytics
        //      "https://example.com/my-custom-analytics.js",
        // ],
    },

    // Logs that should go be passed through the 'log' event if a handler is defined for it
    // apiLogLevels: ['warn', 'log', 'error', 'info', 'debug'],

    // Information about the jitsi-meet instance we are connecting to, including
    // the user region as seen by the server.
    // deploymentInfo: {
    //     shard: "shard1",
    //     region: "europe",
    //     userRegion: "asia",
    // },

    // Array<string> of disabled sounds.
    // Possible values:
    // - 'ASKED_TO_UNMUTE_SOUND'
    // - 'E2EE_OFF_SOUND'
    // - 'E2EE_ON_SOUND'
    // - 'INCOMING_MSG_SOUND'
    // - 'KNOCKING_PARTICIPANT_SOUND'
    // - 'LIVE_STREAMING_OFF_SOUND'
    // - 'LIVE_STREAMING_ON_SOUND'
    // - 'NO_AUDIO_SIGNAL_SOUND'
    // - 'NOISY_AUDIO_INPUT_SOUND'
    // - 'OUTGOING_CALL_EXPIRED_SOUND'
    // - 'OUTGOING_CALL_REJECTED_SOUND'
    // - 'OUTGOING_CALL_RINGING_SOUND'
    // - 'OUTGOING_CALL_START_SOUND'
    // - 'PARTICIPANT_JOINED_SOUND'
    // - 'PARTICIPANT_LEFT_SOUND'
    // - 'RAISE_HAND_SOUND'
    // - 'REACTION_SOUND'
    // - 'RECORDING_OFF_SOUND'
    // - 'RECORDING_ON_SOUND'
    // - 'TALK_WHILE_MUTED_SOUND'
    // disabledSounds: [],

    // DEPRECATED! Use \`disabledSounds\` instead.
    // Decides whether the start/stop recording audio notifications should play on record.
    // disableRecordAudioNotification: false,

    // DEPRECATED! Use \`disabledSounds\` instead.
    // Disables the sounds that play when other participants join or leave the
    // conference (if set to true, these sounds will not be played).
    // disableJoinLeaveSounds: false,

    // DEPRECATED! Use \`disabledSounds\` instead.
    // Disables the sounds that play when a chat message is received.
    // disableIncomingMessageSound: false,

    // Information for the chrome extension banner
    // chromeExtensionBanner: {
    //     // The chrome extension to be installed address
    //     url: 'https://chrome.google.com/webstore/detail/jitsi-meetings/kglhbbefdnlheedjiejgomgmfplipfeb',
    //     edgeUrl: 'https://microsoftedge.microsoft.com/addons/detail/jitsi-meetings/eeecajlpbgjppibfledfihobcabccihn',

    //     // Extensions info which allows checking if they are installed or not
    //     chromeExtensionsInfo: [
    //         {
    //             id: 'kglhbbefdnlheedjiejgomgmfplipfeb',
    //             path: 'jitsi-logo-48x48.png',
    //         },
    //         // Edge extension info
    //         {
    //             id: 'eeecajlpbgjppibfledfihobcabccihn',
    //             path: 'jitsi-logo-48x48.png',
    //         },
    //     ]
    // },

    // e2ee: {
    //   labels,
    //   externallyManagedKey: false,
    // },

    // Options related to end-to-end (participant to participant) ping.
    // e2eping: {
    //   // Whether ene-to-end pings should be enabled.
    //   enabled: false,
    //
    //   // The number of responses to wait for.
    //   numRequests: 5,
    //
    //   // The max conference size in which e2e pings will be sent.
    //   maxConferenceSize: 200,
    //
    //   // The maximum number of e2e ping messages per second for the whole conference to aim for.
    //   // This is used to control the pacing of messages in order to reduce the load on the backend.
    //   maxMessagesPerSecond: 250,
    // },

    // If set, will attempt to use the provided video input device label when
    // triggering a screenshare, instead of proceeding through the normal flow
    // for obtaining a desktop stream.
    // NOTE: This option is experimental and is currently intended for internal
    // use only.
    // _desktopSharingSourceDevice: 'sample-id-or-label',

    // DEPRECATED! Use deeplinking.disabled instead.
    // If true, any checks to handoff to another application will be prevented
    // and instead the app will continue to display in the current browser.
    // disableDeepLinking: false,

    // The deeplinking config.
    // For information about the properties of
    // deeplinking.[ios/android].dynamicLink check:
    // https://firebase.google.com/docs/dynamic-links/create-manually
    // deeplinking: {
    //
    //     // The desktop deeplinking config.
    //     desktop: {
    //         appName: 'Jitsi Meet'
    //     },
    //     // If true, any checks to handoff to another application will be prevented
    //     // and instead the app will continue to display in the current browser.
    //     disabled: false,

    //     // whether to hide the logo on the deep linking pages.
    //     hideLogo: false,

    //     // The ios deeplinking config.
    //     ios: {
    //         appName: 'Jitsi Meet',
    //         // Specify mobile app scheme for opening the app from the mobile browser.
    //         appScheme: 'org.jitsi.meet',
    //         // Custom URL for downloading ios mobile app.
    //         downloadLink: 'https://itunes.apple.com/us/app/jitsi-meet/id1165103905',
    //         dynamicLink: {
    //             apn: 'org.jitsi.meet',
    //             appCode: 'w2atb',
    //             customDomain: undefined,
    //             ibi: 'com.atlassian.JitsiMeet.ios',
    //             isi: '1165103905'
    //         }
    //     },

    //     // The android deeplinking config.
    //     android: {
    //         appName: 'Jitsi Meet',
    //         // Specify mobile app scheme for opening the app from the mobile browser.
    //         appScheme: 'org.jitsi.meet',
    //         // Custom URL for downloading android mobile app.
    //         downloadLink: 'https://play.google.com/store/apps/details?id=org.jitsi.meet',
    //         // Android app package name.
    //         appPackage: 'org.jitsi.meet',
    //         fDroidUrl: 'https://f-droid.org/en/packages/org.jitsi.meet/',
    //         dynamicLink: {
    //             apn: 'org.jitsi.meet',
    //             appCode: 'w2atb',
    //             customDomain: undefined,
    //             ibi: 'com.atlassian.JitsiMeet.ios',
    //             isi: '1165103905'
    //         }
    //     }
    // },

    // // The terms, privacy and help centre URL's.
    // legalUrls: {
    //     helpCentre: 'https://web-cdn.jitsi.net/faq/meet-faq.html',
    //     privacy: 'https://jitsi.org/meet/privacy',
    //     terms: 'https://jitsi.org/meet/terms'
    // },

    // A property to disable the right click context menu for localVideo
    // the menu has option to flip the locally seen video for local presentations
    // disableLocalVideoFlip: false,

    // A property used to unset the default flip state of the local video.
    // When it is set to 'true', the local(self) video will not be mirrored anymore.
    // doNotFlipLocalVideo: false,

    // Mainly privacy related settings

    // Disables all invite functions from the app (share, invite, dial out...etc)
    // disableInviteFunctions: true,

    // Disables storing the room name to the recents list. When in an iframe this is ignored and
    // the room is never stored in the recents list.
    // doNotStoreRoom: true,

    // Deployment specific URLs.
    // deploymentUrls: {
    //    // If specified a 'Help' button will be displayed in the overflow menu with a link to the specified URL for
    //    // user documentation.
    //    userDocumentationURL: 'https://docs.example.com/video-meetings.html',
    //    // If specified a 'Download our apps' button will be displayed in the overflow menu with a link
    //    // to the specified URL for an app download page.
    //    downloadAppsUrl: 'https://docs.example.com/our-apps.html',
    // },

    // Options related to the remote participant menu.
    // remoteVideoMenu: {
    //     // Whether the remote video context menu to be rendered or not.
    //     disabled: true,
    //     // If set to true the 'Kick out' button will be disabled.
    //     disableKick: true,
    //     // If set to true the 'Grant moderator' button will be disabled.
    //     disableGrantModerator: true,
    //     // If set to true the 'Send private message' button will be disabled.
    //     disablePrivateChat: true,
    // },

    // Endpoint that enables support for salesforce integration with in-meeting resource linking
    // This is required for:
    // listing the most recent records - salesforceUrl/records/recents
    // searching records - salesforceUrl/records?text=\${text}
    // retrieving record details - salesforceUrl/records/\${id}?type=\${type}
    // and linking the meeting - salesforceUrl/sessions/\${sessionId}/records/\${id}
    //
    // salesforceUrl: 'https://api.example.com/',

    // If set to true all muting operations of remote participants will be disabled.
    // disableRemoteMute: true,

    // Enables support for lip-sync for this client (if the browser supports it).
    // enableLipSync: false,

    /**
     External API url used to receive branding specific information.
     If there is no url set or there are missing fields, the defaults are applied.
     The config file should be in JSON.
     None of the fields are mandatory and the response must have the shape:
    {
        // The domain url to apply (will replace the domain in the sharing conference link/embed section)
        inviteDomain: 'example-company.org,
        // The hex value for the colour used as background
        backgroundColor: '#fff',
        // The url for the image used as background
        backgroundImageUrl: 'https://example.com/background-img.png',
        // The anchor url used when clicking the logo image
        logoClickUrl: 'https://example-company.org',
        // The url used for the image used as logo
        logoImageUrl: 'https://example.com/logo-img.png',
        // Overwrite for pool of background images for avatars
        avatarBackgrounds: ['url(https://example.com/avatar-background-1.png)', '#FFF'],
        // The lobby/prejoin screen background
        premeetingBackground: 'url(https://example.com/premeeting-background.png)',
        // A list of images that can be used as video backgrounds.
        // When this field is present, the default images will be replaced with those provided.
        virtualBackgrounds: ['https://example.com/img.jpg'],
        // Object containing a theme's properties. It also supports partial overwrites of the main theme.
        // For a list of all possible theme tokens and their current defaults, please check:
        // https://github.com/jitsi/jitsi-meet/tree/master/resources/custom-theme/custom-theme.json
        // For a short explanations on each of the tokens, please check:
        // https://github.com/jitsi/jitsi-meet/blob/master/react/features/base/ui/Tokens.ts
        // IMPORTANT!: This is work in progress so many of the various tokens are not yet applied in code
        // or they are partially applied.
        customTheme: {
            palette: {
                ui01: "orange !important",
                ui02: "maroon",
                surface02: 'darkgreen',
                ui03: "violet",
                ui04: "magenta",
                ui05: "blueviolet",
                field02Hover: 'red',
                action01: 'green',
                action01Hover: 'lightgreen',
                disabled01: 'beige',
                success02: 'cadetblue',
                action02Hover: 'aliceblue',
            },
            typography: {
                labelRegular: {
                    fontSize: 25,
                    lineHeight: 30,
                    fontWeight: 500,
                }
            }
        }
    }
    */
    // dynamicBrandingUrl: '',

    // Options related to the participants pane.
    // participantsPane: {
    //     // Hides the moderator settings tab.
    //     hideModeratorSettingsTab: false,
    //     // Hides the more actions button.
    //     hideMoreActionsButton: false,
    //     // Hides the mute all button.
    //     hideMuteAllButton: false,
    // },

    // Options related to the breakout rooms feature.
    // breakoutRooms: {
    //     // Hides the add breakout room button. This replaces \`hideAddRoomButton\`.
    //     hideAddRoomButton: false,
    //     // Hides the auto assign participants button.
    //     hideAutoAssignButton: false,
    //     // Hides the join breakout room button.
    //     hideJoinRoomButton: false,
    // },

    // When true the user cannot add more images to be used as virtual background.
    // Only the default ones from will be available.
    // disableAddingBackgroundImages: false,

    // Disables using screensharing as virtual background.
    // disableScreensharingVirtualBackground: false,

    // Sets the background transparency level. '0' is fully transparent, '1' is opaque.
    // backgroundAlpha: 1,

    // The URL of the moderated rooms microservice, if available. If it
    // is present, a link to the service will be rendered on the welcome page,
    // otherwise the app doesn't render it.
    // moderatedRoomServiceUrl: 'https://moderated.jitsi-meet.example.com',

    // If true, tile view will not be enabled automatically when the participants count threshold is reached.
    // disableTileView: true,

    // If true, the tiles will be displayed contained within the available space rather than enlarged to cover it,
    // with a 16:9 aspect ratio (old behaviour).
    // disableTileEnlargement: true,

    // Controls the visibility and behavior of the top header conference info labels.
    // If a label's id is not in any of the 2 arrays, it will not be visible at all on the header.
    // conferenceInfo: {
    //     // those labels will not be hidden in tandem with the toolbox.
    //     alwaysVisible: ['recording', 'raised-hands-count'],
    //     // those labels will be auto-hidden in tandem with the toolbox buttons.
    //     autoHide: [
    //         'subject',
    //         'conference-timer',
    //         'participants-count',
    //         'e2ee',
    //         'transcribing',
    //         'video-quality',
    //         'insecure-room',
    //         'highlight-moment',
    //         'top-panel-toggle',
    //     ]
    // },

    // Hides the conference subject
    // hideConferenceSubject: false,

    // Hides the conference timer.
    // hideConferenceTimer: false,

    // Hides the recording label
    // hideRecordingLabel: false,

    // Hides the participants stats
    // hideParticipantsStats: true,

    // Sets the conference subject
    // subject: 'Conference Subject',

    // Sets the conference local subject
    // localSubject: 'Conference Local Subject',

    // This property is related to the use case when jitsi-meet is used via the IFrame API. When the property is true
    // jitsi-meet will use the local storage of the host page instead of its own. This option is useful if the browser
    // is not persisting the local storage inside the iframe.
    // useHostPageLocalStorage: true,

    // Etherpad ("shared document") integration.
    //
    // If set, add a "Open shared document" link to the bottom right menu that
    // will open an etherpad document.
    // etherpad_base: 'https://your-etherpad-installati.on/p/',

    // To enable information about dial-in access to meetings you need to provide
    // dialInNumbersUrl and dialInConfCodeUrl.
    // dialInNumbersUrl returns a json array of numbers that can be used for dial-in.
    // {"countryCode":"US","tollFree":false,"formattedNumber":"+1 123-456-7890"}
    // dialInConfCodeUrl is the conference mapper converting a meeting id to a PIN used for dial-in
    // or the other way around (more info in resources/cloud-api.swagger)

    // List of undocumented settings used in jitsi-meet
    /**
     _immediateReloadThreshold
     debug
     debugAudioLevels
     deploymentInfo
     dialOutAuthUrl
     dialOutCodesUrl
     dialOutRegionUrl
     disableRemoteControl
     displayJids
     externalConnectUrl
     e2eeLabels
     firefox_fake_device
     googleApiApplicationClientID
     iAmRecorder
     iAmSipGateway
     microsoftApiApplicationClientID
     peopleSearchQueryTypes
     peopleSearchUrl
     requireDisplayName
     tokenAuthUrl
     */

    /**
     * This property can be used to alter the generated meeting invite links (in combination with a branding domain
     * which is retrieved internally by jitsi meet) (e.g. https://meet.jit.si/someMeeting
     * can become https://brandedDomain/roomAlias)
     */
    // brandingRoomAlias: null,

    // List of undocumented settings used in lib-jitsi-meet
    /**
     _peerConnStatusOutOfLastNTimeout
     _peerConnStatusRtcMuteTimeout
     abTesting
     avgRtpStatsN
     callStatsConfIDNamespace
     callStatsCustomScriptUrl
     desktopSharingSources
     disableAEC
     disableAGC
     disableAP
     disableHPF
     disableNS
     enableTalkWhileMuted
     forceJVB121Ratio
     forceTurnRelay
     hiddenDomain
     hiddenFromRecorderFeatureEnabled
     ignoreStartMuted
     websocketKeepAlive
     websocketKeepAliveUrl
     */

    /**
     * Default interval (milliseconds) for triggering mouseMoved iframe API event
     */
    mouseMoveCallbackInterval: 1000,

    /**
        Use this array to configure which notifications will be shown to the user
        The items correspond to the title or description key of that notification
        Some of these notifications also depend on some other internal logic to be displayed or not,
        so adding them here will not ensure they will always be displayed

        A falsy value for this prop will result in having all notifications enabled (e.g null, undefined, false)
    */
    // notifications: [
    //     'connection.CONNFAIL', // shown when the connection fails,
    //     'dialog.cameraNotSendingData', // shown when there's no feed from user's camera
    //     'dialog.kickTitle', // shown when user has been kicked
    //     'dialog.liveStreaming', // livestreaming notifications (pending, on, off, limits)
    //     'dialog.lockTitle', // shown when setting conference password fails
    //     'dialog.maxUsersLimitReached', // shown when maximmum users limit has been reached
    //     'dialog.micNotSendingData', // shown when user's mic is not sending any audio
    //     'dialog.passwordNotSupportedTitle', // shown when setting conference password fails due to password format
    //     'dialog.recording', // recording notifications (pending, on, off, limits)
    //     'dialog.remoteControlTitle', // remote control notifications (allowed, denied, start, stop, error)
    //     'dialog.reservationError',
    //     'dialog.serviceUnavailable', // shown when server is not reachable
    //     'dialog.sessTerminated', // shown when there is a failed conference session
    //     'dialog.sessionRestarted', // show when a client reload is initiated because of bridge migration
    //     'dialog.tokenAuthFailed', // show when an invalid jwt is used
    //     'dialog.transcribing', // transcribing notifications (pending, off)
    //     'dialOut.statusMessage', // shown when dial out status is updated.
    //     'liveStreaming.busy', // shown when livestreaming service is busy
    //     'liveStreaming.failedToStart', // shown when livestreaming fails to start
    //     'liveStreaming.unavailableTitle', // shown when livestreaming service is not reachable
    //     'lobby.joinRejectedMessage', // shown when while in a lobby, user's request to join is rejected
    //     'lobby.notificationTitle', // shown when lobby is toggled and when join requests are allowed / denied
    //     'notify.chatMessages', // shown when receiving chat messages while the chat window is closed
    //     'notify.disconnected', // shown when a participant has left
    //     'notify.connectedOneMember', // show when a participant joined
    //     'notify.connectedTwoMembers', // show when two participants joined simultaneously
    //     'notify.connectedThreePlusMembers', // show when more than 2 participants joined simultaneously
    //     'notify.leftOneMember', // show when a participant left
    //     'notify.leftTwoMembers', // show when two participants left simultaneously
    //     'notify.leftThreePlusMembers', // show when more than 2 participants left simultaneously
    //     'notify.grantedTo', // shown when moderator rights were granted to a participant
    //     'notify.hostAskedUnmute', // shown to participant when host asks them to unmute
    //     'notify.invitedOneMember', // shown when 1 participant has been invited
    //     'notify.invitedThreePlusMembers', // shown when 3+ participants have been invited
    //     'notify.invitedTwoMembers', // shown when 2 participants have been invited
    //     'notify.kickParticipant', // shown when a participant is kicked
    //     'notify.linkToSalesforce', // shown when joining a meeting with salesforce integration
    //     'notify.moderationStartedTitle', // shown when AV moderation is activated
    //     'notify.moderationStoppedTitle', // shown when AV moderation is deactivated
    //     'notify.moderationInEffectTitle', // shown when user attempts to unmute audio during AV moderation
    //     'notify.moderationInEffectVideoTitle', // shown when user attempts to enable video during AV moderation
    //     'notify.moderationInEffectCSTitle', // shown when user attempts to share content during AV moderation
    //     'notify.mutedRemotelyTitle', // shown when user is muted by a remote party
    //     'notify.mutedTitle', // shown when user has been muted upon joining,
    //     'notify.newDeviceAudioTitle', // prompts the user to use a newly detected audio device
    //     'notify.newDeviceCameraTitle', // prompts the user to use a newly detected camera
    //     'notify.participantWantsToJoin', // shown when lobby is enabled and participant requests to join meeting
    //     'notify.passwordRemovedRemotely', // shown when a password has been removed remotely
    //     'notify.passwordSetRemotely', // shown when a password has been set remotely
    //     'notify.raisedHand', // shown when a partcipant used raise hand,
    //     'notify.startSilentTitle', // shown when user joined with no audio
    //     'notify.unmute', // shown to moderator when user raises hand during AV moderation
    //     'notify.videoMutedRemotelyTitle', // shown when user's video is muted by a remote party,
    //     'prejoin.errorDialOut',
    //     'prejoin.errorDialOutDisconnected',
    //     'prejoin.errorDialOutFailed',
    //     'prejoin.errorDialOutStatus',
    //     'prejoin.errorStatusCode',
    //     'prejoin.errorValidation',
    //     'recording.busy', // shown when recording service is busy
    //     'recording.failedToStart', // shown when recording fails to start
    //     'recording.unavailableTitle', // shown when recording service is not reachable
    //     'toolbar.noAudioSignalTitle', // shown when a broken mic is detected
    //     'toolbar.noisyAudioInputTitle', // shown when noise is detected for the current microphone
    //     'toolbar.talkWhileMutedPopup', // shown when user tries to speak while muted
    //     'transcribing.failedToStart', // shown when transcribing fails to start
    // ],

    // List of notifications to be disabled. Works in tandem with the above setting.
    // disabledNotifications: [],

    // Prevent the filmstrip from autohiding when screen width is under a certain threshold
    // disableFilmstripAutohiding: false,

    // filmstrip: {
    //     // Disables user resizable filmstrip. Also, allows configuration of the filmstrip
    //     // (width, tiles aspect ratios) through the interfaceConfig options.
    //     disableResizable: false,

    //     // Disables the stage filmstrip
    //     // (displaying multiple participants on stage besides the vertical filmstrip)
    //     disableStageFilmstrip: false,

    //     // Default number of participants that can be displayed on stage.
    //     // The user can change this in settings. Number must be between 1 and 6.
    //     stageFilmstripParticipants: 1,

    //     // Disables the top panel (only shown when a user is sharing their screen).
    //     disableTopPanel: false,

    //     // The minimum number of participants that must be in the call for
    //     // the top panel layout to be used.
    //     minParticipantCountForTopPanel: 50,
    // },

    // Tile view related config options.
    // tileView: {
    //     // The optimal number of tiles that are going to be shown in tile view. Depending on the screen size it may
    //     // not be possible to show the exact number of participants specified here.
    //     numberOfVisibleTiles: 25,
    // },

    // Specifies whether the chat emoticons are disabled or not
    // disableChatSmileys: false,

    // Settings for the GIPHY integration.
    // giphy: {
    //     // Whether the feature is enabled or not.
    //     enabled: false,
    //     // SDK API Key from Giphy.
    //     sdkKey: '',
    //     // Display mode can be one of:
    //     // - tile: show the GIF on the tile of the participant that sent it.
    //     // - chat: show the GIF as a message in chat
    //     // - all: all of the above. This is the default option
    //     displayMode: 'all',
    //     // How long the GIF should be displayed on the tile (in milliseconds).
    //     tileTime: 5000,
    //     // Limit results by rating: g, pg, pg-13, r. Default value: g.
    //     rating: 'pg',
    //     // The proxy server url for giphy requests in the web app.
    //     proxyUrl: 'https://giphy-proxy.example.com',
    // },

    // Logging
    // logging: {
    //      // Default log level for the app and lib-jitsi-meet.
    //      defaultLogLevel: 'trace',
    //      // Option to disable LogCollector (which stores the logs on CallStats).
    //      //disableLogCollector: true,
    //      // Individual loggers are customizable.
    //      loggers: {
    //      // The following are too verbose in their logging with the default level.
    //      'modules/RTC/TraceablePeerConnection.js': 'info',
    //      'modules/statistics/CallStats.js': 'info',
    //      'modules/xmpp/strophe.util.js': 'log',
    // },

    // Application logo url
    // defaultLogoUrl: 'images/watermark.svg',

    // Settings for the Excalidraw whiteboard integration.
    // whiteboard: {
    //     // Whether the feature is enabled or not.
    //     enabled: true,
    //     // The server used to support whiteboard collaboration.
    //     // https://github.com/jitsi/excalidraw-backend
    //     collabServerBaseUrl: 'https://excalidraw-backend.example.com',
    // },
};

// Temporary backwards compatibility with old mobile clients.
config.flags = config.flags || {};
config.flags.sourceNameSignaling = true;
config.flags.sendMultipleVideoStreams = true;
config.flags.receiveMultipleVideoStreams = true;

// Set the default values for JaaS customers
if (enableJaaS) {
    config.dialInNumbersUrl = 'https://conference-mapper.jitsi.net/v1/access/dids';
    config.dialInConfCodeUrl = 'https://conference-mapper.jitsi.net/v1/access';
    config.roomPasswordNumberOfDigits = 10; // skip re-adding it (do not remove comment)
}

EOM
pkg_add nginx
rcctl enable nginx prosody jicofo jvb
rcctl order nginx prosody jicofo jvb
cat > /etc/nginx/nginx.conf <<- EOM
# Take note of http://wiki.nginx.org/Pitfalls

#user  www;
worker_processes  1;

#load_module "modules/ngx_stream_module.so";

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;
#error_log  syslog:server=unix:/dev/log,severity=notice;

#pid        logs/nginx.pid;

worker_rlimit_nofile 1024;
events {
    worker_connections  800;
}


http {
    include       mime.types;
    default_type  application/octet-stream;
    index         index.html index.htm;

    #log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
    #                  '\$status \$body_bytes_sent "\$http_referer" '
    #                  '"\$http_user_agent" "\$http_x_forwarded_for"';

    #access_log  logs/access.log  main;
    #access_log  syslog:server=unix:/dev/log,severity=notice main;

    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    server_tokens off;

    server {
        listen       80;
        listen       [::]:80;
        server_name  localhost;
        root         /var/www/htdocs;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root  /var/www/htdocs;
        }

        # FastCGI to CGI wrapper server
        #
        #location /cgi-bin/ {
        #    fastcgi_pass   unix:run/slowcgi.sock;
        #    fastcgi_split_path_info ^(/cgi-bin/[^/]+)(.*);
        #    fastcgi_param  PATH_INFO \$fastcgi_path_info;
        #    include        fastcgi_params;
        #}

        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \.php$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on unix socket
        #
        #location ~ \.php$ {
        #    try_files      \$uri \$uri/ =404;
        #    fastcgi_pass   unix:run/php-fpm.sock;
        #    fastcgi_index  index.php;
        #    fastcgi_param  SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        #    include        fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #    deny  all;
        #}
    }

    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;

        server_name $JITSI_DNS;

        ssl_certificate /etc/ssl/$JITSI_DNS.cert;
        ssl_certificate_key /etc/ssl/private/$JITSI_DNS.key;

        root /jitsi-meet;

        # BOSH
        location = /http-bind {
            proxy_pass      http://127.0.0.1:5280/http-bind;
            proxy_set_header X-Forwarded-For \$remote_addr;
            proxy_set_header Host \$http_host;
        }

        ssi on;
        ssi_types application/x-javascript application/javascript;

        location ~ ^/(libs|css|static|images|fonts|lang|sounds|connection_optimization)/(.*)$ {
            add_header 'Access-Control-Allow-Origin' '*';
            alias /jitsi-meet/\$1/\$2;
        }

        # rooms
        location ~ ^/([a-zA-Z0-9=\?]+)$ {
            rewrite ^/(.*)$ / break;
        }

        # external_api.js must be accessible from the root of the
        # installation for the electron version of Jitsi Meet to work
        location /external_api.js {
            alias /jitsi-meet/libs/external_api.min.js;
        }
    }
    
    server {
        listen 443 ssl;
        listen [::]:443 ssl;

        # For the federation port
        listen 8448 ssl default_server;
        listen [::]:8448 ssl default_server;

        server_name $SERVER_NAME;
        ssl_certificate /etc/ssl/$SERVER_NAME.cert;
        ssl_certificate_key /etc/ssl/private/$SERVER_NAME.key;

        location ~ ^(/_matrix|/_synapse/client|_synapse/admin) {
            # note: do not add a path (even a single /) after the port in \`proxy_pass\`,
            # otherwise nginx will canonicalise the URI and cause signature verification
            # errors.
            proxy_pass http://localhost:8008;
            proxy_set_header X-Forwarded-For \$remote_addr;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_set_header Host \$host;

            # Nginx by default only allows file uploads up to 1M in size
            # Increase client_max_body_size to match max_upload_size defined in homeserver.yaml
            client_max_body_size 50M;
    
           # Synapse responses may be chunked, which is an HTTP/1.1 feature.
           proxy_http_version 1.1;
        }
    }

    server {
  listen 443 ssl;
  listen [::]:443 ssl;
  root /element/element-v1.11.66;
        ssl_certificate /etc/letsencrypt/live/$ELEMENT_SERVER_NAME/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/$ELEMENT_SERVER_NAME/privkey.pem;
  # Add index.php to the list if you are using PHP
  index index.html index.htm index.nginx-debian.html;

  server_name $ELEMENT_SERVER_NAME;

  location / {
    # First attempt to serve request as file, then
    # as directory, then fall back to displaying a 404.
    try_files \$uri \$uri/ =404;
  }
    }

    server {
        listen 443 ssl;
        listen [::]:443 ssl;
        root /synapse_admin/synapse-admin-0.10.1;
        ssl_certificate /etc/letsencrypt/live/$ADMIN_SERVER_NAME/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/$ADMIN_SERVER_NAME/privkey.pem;
        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        server_name $ADMIN_SERVER_NAME;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files \$uri \$uri/ =404;
        }
    }

    # another virtual host using mix of IP-, name-, and port-based configuration
    #
    #server {
    #    listen       8000;
    #    listen       somename:8080;
    #    server_name  somename  alias  another.alias;
    #    root         /var/www/htdocs;
    #}


    # HTTPS server
    #
    #server {
    #    listen       443;
    #    server_name  localhost;
    #    root         /var/www/htdocs;

    #    ssl                  on;
    #    ssl_certificate      /etc/ssl/server.cert;
    #    ssl_certificate_key  /etc/ssl/private/server.key;

    #    ssl_session_timeout  5m;
    #    ssl_session_cache    shared:SSL:1m;

    #    ssl_ciphers  HIGH:!aNULL:!MD5:!RC4;
    #    ssl_prefer_server_ciphers   on;
    #}

}
EOM
rcctl start nginx
rcctl start prosody jicofo jvb
