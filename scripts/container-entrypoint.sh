#!/bin/sh
set -eu
umask 077
# Explicit CLI commands (including init and --version) retain their normal behavior.
if [ "$#" -gt 0 ]; then
  exec acmeproxy "$@"
fi
if [ ! -w /config ]; then
  echo 'Cannot write /config. Use a named volume, or give the container UID/GID ownership of the bind mount.' >&2
  exit 1
fi
# Never repair a partially lost installation by silently generating replacement keys.
if [ -e /config/acmeproxy.sqlite ] || [ -e /config/master.key ] || [ -e /config/admin.token ]; then
  if [ ! -s /config/master.key ] || [ ! -s /config/admin.token ] || [ ! -s /config/config.toml ]; then
    echo 'Incomplete existing configuration. Restore the complete /config backup before starting.' >&2
    exit 1
  fi
else
  if [ ! -e /config/config.toml ]; then
    cp /etc/acmeproxy/default.toml /config/config.toml
  fi
  acmeproxy init --config-dir /config
fi
exec acmeproxy serve --config-dir /config
