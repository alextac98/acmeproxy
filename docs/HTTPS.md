# Native HTTPS

ACME Proxy can serve its admin UI and ACME directory over TLS itself, using a Let's
Encrypt certificate it obtains and renews with the DNS provider you already configured.
You need this when a client refuses a plain-HTTP directory. Caddy, for example, rejects
one on any hostname it does not consider internal.

A TLS-terminating reverse proxy still works and needs none of this. Native HTTPS has one
advantage over it: the app sees each client's real address, so `acme.allowed_networks`
keeps working.

## How the certificate is obtained

The server requests its certificate through the same worker as **Managed certificates**.
That path only needs outbound access to Let's Encrypt and your DNS provider, so it does
not depend on the proxy's own listeners or ACME endpoint.

- **First boot:** both ports open immediately. TLS handshakes fail until DNS-01 completes,
  which can take up to about 10 minutes, then HTTPS starts working without a restart. The
  plain HTTP listener works throughout. There is deliberately no self-signed fallback.
- **Renewal:** happens two-thirds of the way through the certificate's validity. New
  connections use the renewed certificate immediately; nothing restarts.
- **Failures:** the current certificate keeps being served, even after it expires, and
  issuance keeps retrying with backoff and then daily. Overview shows the error. `/healthz`
  stays healthy, because restarting would not help. Restarting does trigger an immediate
  retry.
- **Storage:** the private key is encrypted under `master.key` in SQLite. It is never written
  out and cannot be downloaded through the UI or API. The UI also cannot delete this
  certificate, pause its renewal, or remove the last DNS provider covering it.

## Configuration

`[server.tls]` lives in `config.toml` and is read at startup. Stop the server before editing
the file.

```toml
[server.tls]
listen = "0.0.0.0:8443"
domain = "certs.example.com"
terms_agreed = true                 # Let's Encrypt subscriber agreement
# staging = true                    # untrusted test certificates; default false
# plain_http = "full"               # or "acme_only"
# plain_http_origin = "http://certs.example.com:8080"

[acme]
base_url = "https://certs.example.com"
```

- `domain` is one exact hostname and must be covered by a configured DNS provider.
- `acme.base_url`, when set, must be the `https://` origin of `domain`. Include a port if
  you publish one other than 443.
- `staging` is separate from `acme.staging`. Clients will not trust a staging certificate.
  After switching from staging to production, the old staging certificate becomes an
  ordinary managed certificate; remove it in the UI.
- Publish the port in Compose, for example `"443:8443"`. The container does not need to
  bind a privileged port.

### What plain HTTP still serves

| `plain_http` | Admin pages | Admin API, `/present`, `/cleanup` | `/acme/*` | `/healthz` |
| --- | --- | --- | --- | --- |
| `full` (default) | Served | Served | Served | Served |
| `acme_only` | 308 to HTTPS | 403 | Served | Served |

`/acme/*` on the plain listener also requires `plain_http_origin`. Without it, those
requests are refused and clients must use HTTPS.

Each listener advertises URLs on its own origin. A client that connected over HTTP gets
HTTP URLs built from `plain_http_origin`, and a client that connected over HTTPS gets URLs
built from `acme.base_url`. Signed requests must name the origin of the listener that
received them. Account URLs are accepted from either origin, so existing accounts remain
valid.

Keeping `/acme/*` on HTTP during a migration is low risk: requests are signed, carry no
bearer tokens, and HTTP-01 is still enforced. Someone on the network path could disrupt
issuance, but could not obtain a certificate. Admin and DNS gateway tokens are bearer
credentials, which is why `acme_only` removes them from plain HTTP.

HSTS is not sent. It applies to every port on a host, so it would break the plain listener
during a migration.

## Migrating existing HTTP clients

1. Upgrade the image with no configuration change. Behaviour is identical.
2. Stop the server. Add `[server.tls]` with `plain_http_origin` set to the **current**
   `acme.base_url`, change `acme.base_url` to HTTPS, publish the HTTPS port, and start. HTTP
   clients see no change.
3. Wait for `HTTPS certificate loaded` in the logs, then check both directories. HTTPS must
   return `https://` URLs and HTTP must still return `http://` URLs:

   ```sh
   curl -s https://certs.example.com/acme/directory
   curl -s http://certs.example.com:8080/acme/directory
   ```

4. Point each client at the HTTPS directory, by hostname. The certificate cannot cover an IP
   address. Expect each client to register a new account and request one new certificate
   per name, because clients store accounts by directory URL.
5. Set `plain_http = "acme_only"` and restart.
6. When the logs stop showing `ACME client is using plain HTTP`, remove the plain port from
   Compose. Leave `server.listen` alone: the container healthcheck still uses it. Remove
   `plain_http_origin` to close the endpoint entirely.

## Rolling back

Stop the server, remove `[server.tls]`, restore the previous `acme.base_url`, and unpublish
the HTTPS port. Do this before going back to an older image, because older versions reject
the unknown setting. Point any client you already moved back at the HTTP directory. No
database migration is involved.
