# Install ACME Proxy

You need Docker and Docker Compose v2 with `up --wait` support. Images support Linux AMD64 and ARM64.

## Start the app

1. Download the deployment archive and `SHA256SUMS` from the same GitHub Release.
2. Verify the download:

   ```sh
   sha256sum --ignore-missing --check SHA256SUMS
   ```

3. Unpack the archive, open its directory, and run:

   ```sh
   docker compose up -d --wait
   docker compose exec acmeproxy cat /config/admin.token
   ```

Open http://127.0.0.1:8080 and sign in with the token. Add your DNS providers and clients in the UI. No registry login or source checkout is needed.

Configuration is created on first startup and kept in the `acmeproxy-config` Docker volume. `config.example.toml` is a reference; it does not replace your settings.

## Everyday use

```sh
docker compose logs --tail=100 acmeproxy  # View logs
docker compose restart acmeproxy        # Restart
docker compose down                    # Stop, keeping your data
```

Do not use `down -v`: it deletes your data. Use one instance per volume, on local storage. See [UPGRADE.md](UPGRADE.md) before updating.

The default port is accessible only from the Docker host. For remote access, put the app behind an HTTPS reverse proxy. A containerized proxy should share a Docker network and connect to `acmeproxy:8080`.

## Docker without Compose

Replace `IMAGE_REFERENCE` below with the exact image reference in `compose.yaml`:

```sh
docker volume create acmeproxy-config
docker run -d --name acmeproxy --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v acmeproxy-config:/config \
  --tmpfs /config/scratch:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700 \
  --security-opt no-new-privileges:true --cap-drop ALL \
  --stop-timeout 45 \
  --health-cmd 'curl --fail --silent http://127.0.0.1:8080/healthz' \
  --health-interval 10s --health-start-period 20s \
  IMAGE_REFERENCE
docker exec acmeproxy cat /config/admin.token
```
