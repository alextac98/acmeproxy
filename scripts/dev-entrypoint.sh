#!/bin/sh
set -eu
umask 077

if [ ! -w /config ]; then
  echo 'Cannot write /config. Run Compose with DEV_UID=$(id -u) DEV_GID=$(id -g) and ensure dev-data is owned by that user.' >&2
  exit 1
fi

# Seed only a new directory. Never replace configuration edited by an admin.
if [ ! -e /config/config.toml ]; then
  cp /etc/acmeproxy/default.toml /config/config.toml
fi
acmeproxy init --config-dir /config
exec acmeproxy serve --config-dir /config
