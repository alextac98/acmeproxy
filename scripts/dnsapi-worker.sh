#!/bin/bash
# Fixed script: all untrusted inputs arrive as arguments/environment, never shell source.
umask 077
readonly proxy_source="$1" proxy_driver="$2" proxy_action="$3" proxy_fqdn="$4" proxy_value="$5" proxy_work="$6"
set --
. "$proxy_source/acme.sh" >/dev/null 2>&1 || exit 1
export LE_WORKING_DIR="$proxy_source"
export LE_CONFIG_HOME="$proxy_work"
export CERT_HOME="$proxy_work"
export ACCOUNT_CONF_PATH="$proxy_work/account.conf"
export DOMAIN_CONF="$proxy_work/domain.conf"
export HTTP_HEADER="$proxy_work/http.header"
export _ACME_INSECURE=""
export DEBUG=0
export LOG_FILE=""
export SYS_LOG=0
export ACME_OPENSSL_BIN=openssl
export USER_AGENT="acmeproxy/0.1 acme.sh/3.1.4"
touch "$ACCOUNT_CONF_PATH" "$DOMAIN_CONF" || exit 1
. "$proxy_source/dnsapi/$proxy_driver.sh" || exit 1
"${proxy_driver}_${proxy_action}" "$proxy_fqdn" "$proxy_value"
