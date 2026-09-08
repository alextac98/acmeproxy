# ACME Proxy

<img src="web/brand/logo.png" alt="ACME Proxy logo" width="360" />

A self-hosted DNS-01 challenge gateway with a small admin UI. Keep DNS API credentials
in one place and issue revocable, domain-scoped credentials to services on your network.
Services continue to manage their own certificates and private keys.

**Development preview.** The gateway and worker lifecycle are tested with a local fake
DNS provider. The catalog contains 184 available acme.sh adapters; those providers have
not been live-verified here. Read the [architecture and rollout plan](docs/PLAN.md) for
the remaining reliability and security gates before a production release.

## Run locally

Requires Linux, a current stable Rust toolchain, Bash, curl, openssl, tar, and standard Unix tools.
Some DNS providers require additional tools. Node is not needed to run the application.

```sh
sh scripts/install-dnsapi.sh
cargo run -- init --config-dir ./data
cargo run -- serve --config-dir ./data
```

Open <http://127.0.0.1:8080> and sign in using the contents of `data/admin.token`.
The token is never printed automatically. The default adapter path assumes `data/`
is beside `.local/`; adjust `dnsapi_home` for another layout.

The server defaults to loopback HTTP. For access from other machines, terminate HTTPS
at a reverse proxy and restrict administration to trusted operators. The proxy itself
does not obtain its own TLS certificate in this version.

## One configuration directory

```text
data/
  config.toml         # Source of truth: server, DNS providers, clients
  master.key          # Encrypts credentials and persisted worker state
  admin.token         # Bootstrap admin credential
  acmeproxy.sqlite    # Runtime journal, audit history, config projection
  acmeproxy.sqlite-*  # SQLite WAL/shared-memory files while running
  server.lock         # Prevents multiple processes using this directory
  scratch/            # Temporary worker files; mount on tmpfs when deployed
```

Mount or move this directory as a unit. **Secure backups must include `master.key`;**
encrypted configuration and runtime state cannot be recovered without it. Stop the
server before copying the directory, or use a consistent SQLite backup procedure.
The provider bundle is an application dependency, not instance configuration.

All application settings are in `config.toml`; no `.env` file is required:

```toml
[server]
listen = "127.0.0.1:8080"
dnsapi_home = "../.local/acme.sh" # Relative to the configuration directory, or absolute
challenge_ttl_seconds = 3600
worker_timeout_seconds = 30
audit_retention = 1000 # Keep the newest N activity events (50–100000)
```

The UI writes the same file using atomic replacement. Manual edits take effect on
restart. If the file changes externally while the server is running, UI saves are
blocked until restart. Saves normalize formatting and replace comments.

For file-only provisioning, append providers and clients:

```toml
[[providers]]
name = "Cloudflare production"
driver = "dns_cf"
zone = "example.com"
# An omitted id is generated and persisted on startup.
[providers.credentials]
CF_Token = "replace-with-a-zone-scoped-dns-api-token"
CF_Zone_ID = "replace-with-zone-id"

[[clients]]
name = "Home Assistant"
scopes = ["home.example.com"]
token = "replace-with-a-cryptographically-random-token-of-at-least-32-characters"
```

On successful startup, plaintext provider credentials become `encrypted_credentials`
and client tokens become `token_hash`. Avoid retaining plaintext imports in version
control or backups. When replacing credentials through the file, remove the previous
`encrypted_credentials` entry before adding a new credentials table. Provider rotation
is allowed: existing challenges retain encrypted snapshots of their original credentials.
Use Retry on a failed challenge to adopt the current credentials. Provider removal or
zone/driver changes are blocked until its challenges are cleaned.

Client IDs are Basic-auth usernames. Removing a client from the file or setting
`revoked = true` disables it and queues cleanup. Token changes keep the existing client
ID. An exact scope permits only that challenge name; `*.apps.example.com` permits
descendants of any depth, excluding `apps.example.com` itself. DNS-01 cannot distinguish
hostname validation from wildcard validation at the same challenge name.

## Activity log

The Activity page at `/activity` shows persisted audit events with time, action,
actor, target, and outcome. Search by action, actor, target, or outcome and browse 50 events per
page. Older pages stay in place while new events arrive; use Latest to return
to the newest events.

Set **Keep last N events** in the viewer or `server.audit_retention` in
`config.toml` (default 1000, range 50–100000). UI changes are saved immediately;
file edits apply on restart. Older events are automatically deleted as new ones
arrive, and reducing the limit prunes existing history. The UI asks for confirmation
before reducing it. This is the application audit log, not raw server stdout.

## Client API

For acme.sh, use the existing `dns_acmeproxy` adapter:

```sh
export ACMEPROXY_ENDPOINT='https://acmeproxy.example.com'
export ACMEPROXY_USERNAME='client-uuid-from-the-ui-or-config'
export ACMEPROXY_PASSWORD='client-token'
acme.sh --issue --dns dns_acmeproxy -d home.example.com
```

The UI shows these environment settings when it creates a client. Client tokens are
shown once; create a replacement client or provision a new token if one is lost.

Both `POST /present` and `POST /cleanup` accept Basic auth, or a client bearer token:

```json
{
  "fqdn": "_acme-challenge.home.example.com.",
  "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
```

The value must be the ACME client's base64url-encoded SHA-256 challenge digest.
Success returns the supplied `fqdn` and `value`, plus a challenge ID when available.
HTTP 200 means the DNS adapter completed successfully, not that DNS has propagated.
The ACME client remains responsible for propagation checking and certificate issuance.
HTTP 503 means the durable operation is still pending; retry the identical request.
Unknown cleanup is a successful no-op and never deletes an untracked record.

Matching requests are idempotent in the local journal. DNS mutations use at-least-once
delivery: provider-specific reconciliation is still needed to resolve a crash after a
remote write but before the result is committed. Workers retry failures up to five
times. Failed cleanup remains visible for an administrator to retry. Leases expire
after the configured TTL; expiration queues cleanup rather than declaring it complete.

Only `account.conf` and `domain.conf` adapter state is preserved. Adapters needing other
files, custom tools, or nonstandard environment settings may need more integration.
No CNAME delegation is implemented. The client protocol matches acme.sh; actual ACME
issuance and Caddy/Traefik compatibility have not yet been tested.

## Nginx Proxy Manager

Nginx Proxy Manager v2.15.1 includes the **DnsMulti** provider, backed by
[`certbot-dns-multi`](https://github.com/alexzorin/certbot-dns-multi). Its lego
[`httpreq`](https://go-acme.github.io/lego/dns/httpreq/) backend sends the same
`/present` and `/cleanup` requests as this gateway in its default mode.
This configuration is verified against upstream definitions, but has not yet been
tested end to end with Nginx Proxy Manager.

Create a gateway client scoped to the certificate's domain(s). In Nginx Proxy Manager,
add a Let's Encrypt certificate, enable DNS Challenge, select **DnsMulti**, and enter:

```ini
dns_multi_provider = httpreq
HTTPREQ_ENDPOINT = http://YOUR-PROXY-HOST:8080
HTTPREQ_USERNAME = YOUR-PROXY-CLIENT-ID
HTTPREQ_PASSWORD = YOUR-PROXY-CLIENT-TOKEN
HTTPREQ_HTTP_TIMEOUT = 90
```

Use port 8081 for the development Compose host mapping. The endpoint must be reachable
from the Nginx Proxy Manager container; `localhost` would refer to that container.
Leave `HTTPREQ_MODE` unset. RAW mode sends `domain`, `token`, and `keyAuth`, which this
gateway does not accept. Start with 60 seconds in NPM's Propagation Seconds field.
After issuance, select the certificate in the proxy host's SSL settings. NPM remains
responsible for certificate issuance and renewals; it holds only a scoped gateway
token, while Cloudflare credentials stay in ACME Proxy.

The ACME-DNS dropdown option uses a different protocol and is not compatible with this
gateway. Selecting Cloudflare would connect NPM directly to Cloudflare instead.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The integration tests use a fake adapter and do not call external DNS APIs. They cover
scope boundaries, Basic-auth compatibility, exact-value cleanup, duplicate presents,
revocation, encrypted state, restart recovery, TTL cleanup, timeout process termination,
and authoritative file configuration.

The UI is embedded from `web/` at compile time; rebuild the Rust binary after edits.
The pinned adapter install is checksum-verified and does not auto-update at runtime.
To review/update the provider catalog, run `python3 scripts/generate-catalog.py` against
the pinned source and inspect the resulting `docs/providers.json` diff.

Run the real pinned Cloudflare adapter against a mocked HTTP transport, and check the UI:

```sh
cargo test --test dnsapi -- --ignored
cargo build
npm ci
npx playwright install chromium
npm run test:ui
```

The browser test uses its own temporary configuration directory and fake credentials.

## Development with Docker Compose

From the repository root, run:

```sh
docker compose up --build --watch
```

Open <http://localhost:8081>, or `http://<server-lan-ip>:8081` from your laptop.
Read `dev-data/admin.token` to sign in. The first startup creates keys and seeds
`dev-data/config.toml` with the container's DNS adapter path. Existing configuration
and credentials are preserved. This directory is separate from the standalone
server's `data/` directory; copy no files between them while either server is running.

The development build uses Rust's debug profile and cached dependencies. Changes to
Rust source, UI assets, migrations, or build inputs trigger a rebuild and restart via
[Compose Watch](https://docs.docker.com/compose/how-tos/file-watch/) (Compose 2.22+).
No host Rust or Node installation is required. Database migration files already
applied to a persistent database must not be edited; add a new migration instead.

The container defaults to UID/GID 1000. If your Linux user has different IDs, run:

```sh
DEV_UID="$(id -u)" DEV_GID="$(id -g)" docker compose up --build --watch
```

`DEV_PORT=8082` overrides the host port. These optional variables configure Docker;
application settings remain in `dev-data/config.toml`. The internal listener should
remain `0.0.0.0:8080` for this Compose file's port mapping and health check.

```sh
docker compose logs -f acmeproxy
docker compose restart acmeproxy  # Apply manual config.toml edits
docker compose down              # Stop; dev-data remains intact
```

For background operation without watching files, use `docker compose up --build -d`.
Configuration is deliberately not watched: saves from the UI must not restart the
server. Worker scratch files use tmpfs; the rest of the instance lives in `dev-data/`.

## Container

The image runs as a non-root user and includes the pinned adapter bundle. For a Docker
bind mount, initialize using your host UID so the directory stays editable:

```sh
docker build -t acmeproxy:dev .
mkdir -p data
# For a NEW configuration directory only; retain any existing config.toml.
cp examples/container.toml data/config.toml
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/data:/config" acmeproxy:dev init --config-dir /config
docker run --rm --name acmeproxy --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8080:8080 -v "$PWD/data:/config" \
  --tmpfs "/config/scratch:rw,noexec,nosuid,nodev,uid=$(id -u),gid=$(id -g),mode=0700" \
  acmeproxy:dev
```

The config's listener is `0.0.0.0` inside the container; this example publishes only to
host loopback. Provider adapters needing extra executables require an extended image.

Container initialization and restart are tested with Podman using
`python3 scripts/smoke-container.py`. Docker users can select `--engine docker` and
`--image acmeproxy:dev`; the Docker commands above have not been run against a Docker
daemon in this workspace.

## License

This project is licensed under the [MIT License](LICENSE).
