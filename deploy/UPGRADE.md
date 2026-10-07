# Upgrade ACME Proxy

Keep your previous Compose file before upgrading. Updates happen only when you change the pinned image.

## 1. Back up

Stop the app and save the whole configuration volume, including its encryption key and database:

```sh
umask 077
mkdir -p backups
docker compose stop acmeproxy
docker compose run --rm --no-deps -T --entrypoint tar acmeproxy \
  --exclude=./scratch -C /config -czf - . > backups/config-before-upgrade.tar.gz
tar -tzf backups/config-before-upgrade.tar.gz
```

Keep this backup private and save a copy off the host.

## 2. Update

Download and verify the new deployment kit. Copy its `image` reference into your existing `compose.yaml`, keeping your volume and network settings. Compare the Compose files for any other deployment changes.

```sh
docker compose pull
docker compose up -d --wait
docker compose logs --tail=100 acmeproxy
```

Sign in and check your providers, clients, and pending challenges.

## If you need to restore

An older image may not understand an upgraded database. Restore the backup with the previous image.

1. Stop the failed app with `docker compose down` (without `-v`).
2. Restore your previous Compose file. Under `volumes.config.name`, choose a **new, unused** volume name to preserve the failed installation.
3. Restore and start:

   ```sh
   docker compose run --rm --no-deps -T --entrypoint tar acmeproxy \
     -C /config -xzf - < backups/config-before-upgrade.tar.gz
   docker compose up -d --wait
   ```

Sign in with the backed-up token. Restoring loses changes made since the backup; check any DNS records changed during that time before resuming client traffic.

## HTTP-01 ACME endpoint migration

The ACME endpoint now requires HTTP-01 verification for every requested hostname.
Legacy `trusted_network` and `approved_accounts` settings become `http01`; account
approval no longer grants issuance permission. Existing issued chains remain available,
but unissued legacy orders are invalidated. Clients must create fresh orders and answer
HTTP-01 on port 80. Configure `acme.validation_networks` for private challenge responders.
Wildcard orders are rejected on this endpoint. The authenticated DNS gateway and managed
certificate UI/API continue to use DNS-01 and support wildcards.
