# Internal ACME endpoint

ACME Proxy can expose an ACME directory to Certbot and other ACME clients. The client
creates its account key and certificate private key locally, sends a signed order and
CSR, and receives a Let's Encrypt certificate. The operator configures DNS access once;
clients do not need provider credentials, gateway client IDs/tokens, a DNS plugin, or
manual TXT records. Client renewal timers request replacement certificates the same way.

This is separate from **Certificates**, where this server generates and stores private
keys, and **Clients**, which grants external ACME clients access to the DNS gateway only.
For ordinary ACME clients, use the directory URL from **Settings**.

## Operator setup

1. Configure DNS provider connections for the zones you want to issue certificates for.
2. Open **Settings → ACME endpoint** and select an access mode:
   - **Disabled**: no downstream ACME service (the default).
   - **Trusted network**: clients from allowed network CIDRs may request allowed domains.
     Accounts are created automatically, with no individual operator approval.
   - **Approved ACME accounts**: the same network restrictions apply, but each automatically
     registered ACME account must also be approved in Settings before ordering certificates.
     Register using `certbot register --server <directory URL> --agree-tos --email <email>`,
     approve the account, then issue. A first issuance attempt also registers an account
     before reporting that approval is required; rerun it after approval.
3. Set the server URL as clients will see it, for example `http://10.13.1.240:8080` or
   `https://acme.internal.example.com`. Use an origin without a path or query.
4. Set the allowed client CIDRs, for example `10.13.1.0/24`. Defaults cover loopback and
   private LAN ranges. These checks use the TCP peer; forwarded headers cannot bypass them.
   Behind a reverse proxy, restrict ingress at the proxy too, because the app sees its IP.
5. Optionally limit allowed certificate domains. Empty means all names covered by configured
   DNS providers. `ha.example.com` allows that exact certificate, not `*.ha.example.com`.
   `*.example.com` permits descendants and descendant wildcard certificates, but not
   `example.com` itself. Include both the apex and wildcard scope when both are wanted.
6. Select Let's Encrypt **staging** first, accept the subscriber agreement, and save.
   Settings take effect immediately. Staging certificates are not browser trusted.
   Once tested, select production. Each existing order retains its original environment.

Trusted-network mode is deliberately an issuance permission: a client in those networks
can obtain certificates for any domain allowed by that policy. It does not separately
prove that the client controls the domain. Our server performs real DNS-01 validation
with Let's Encrypt using the operator's credentials. Downstream authorizations are
already valid under the local policy, so no challenge is presented to the client.

ACME clients still use standard account keys, JWS signatures, and single-use nonces.
These are automatically managed by the client; there is no separately issued password.
The admin UI and DNS gateway retain their existing authentication.

## Certbot

Copy the directory URL from Settings. For the current development listener:

```sh
certbot certonly --standalone --non-interactive --agree-tos \
  --server http://10.13.1.240:8080/acme/directory \
  --email you@example.com -d ha.example.com \
  --issuance-timeout 1200
```

Replace the domain and email. Wildcards work too: add `-d '*.example.com'` with shell
quoting. The standalone plugin is selected, but it does not bind a challenge listener
when the server returns valid authorizations. No inbound challenge ports are needed.

Certbot saves its certificate/private key and renewal configuration locally. Keep its
normal renewal timer enabled:

```sh
certbot renew
```

Use the client's installation/deploy hook to reload the consuming service after renewal.
The gateway does not store the client's certificate private key and does not schedule
renewals for downstream clients. Choose staging or production in the gateway settings;
changing settings affects new orders. Do not request duplicate certificates through the
managed Certificates page for the same client workflow.

Certbot 5.8.0 has been tested over HTTP against a local instance. Many other ACME clients
require HTTPS; terminate TLS at a reverse proxy and configure the matching HTTPS origin
for those clients. Changing the advertised origin changes account/resource URLs; point
clients at the new directory and let them register against that endpoint again.

## Home Assistant OS

The official Let's Encrypt app supports a custom `acme_server`. A configuration matching
this endpoint's preauthorized order flow is:

```yaml
email: you@example.com
domains:
  - ha.example.com
certfile: fullchain.pem
keyfile: privkey.pem
challenge: http
dns: {}
acme_server: http://10.13.1.240:8080/acme/directory
```

Here `challenge: http` selects the app's ordinary standalone Certbot flow; the gateway
returns valid downstream authorizations and handles upstream DNS-01, so the client does
not perform an HTTP challenge. Do not configure `dns-httpreq`, a provider token, or a
client ID for this flow. Configure allowed networks for the address the HA host uses.

Start the app to issue, and schedule its periodic starts for renewal. Configure HA or
its TLS proxy to load the resulting `/ssl/fullchain.pem` and `/ssl/privkey.pem`, and
reload/restart that TLS consumer after renewal. See the [official app documentation](https://github.com/home-assistant/addons/blob/master/letsencrypt/DOCS.md).
The equivalent Certbot flow is tested locally; the HA app itself has not been tested.

## Protocol and operational scope

- Directory, nonces, account registration/lookup/update/deactivation, account order lists,
  new orders, authorizations, finalization, certificate download, account key rollover,
  and upstream certificate revocation are implemented.
- Account signatures support ES256 (P-256) and RS256 (RSA 2048–8192). CSRs must have valid
  signatures and DNS SANs matching the order exactly. The issued certificate must match
  both the CSR public key and the requested names before it is returned.
- Certificate revocation accepts the issuing downstream account or the certificate's
  matching supported JWK. The upstream request uses our account that issued the certificate.
- ACME accounts and certificates are isolated by account ownership. Removed approval,
  disabled issuance, deactivated accounts, domain-policy changes and missing provider
  coverage block subsequent processing/finalization. Account key rollover preserves the
  approved account identity. Settings saves do not overwrite concurrent approvals.
- Orders expire after 24 hours before issuance. At most 100 outstanding orders, 20 new
  orders per account/hour, 100 new orders globally/hour and 1000 registered accounts are
  allowed. Nonces expire after five minutes and their store is capped at 10000 entries.
- Issuance uses the existing durable DNS journal, credential snapshots and exact-value
  cleanup. An attempt is bounded to 20 minutes; failed orders retry up to three times
  before becoming invalid. The client's issuance timeout should allow time for DNS
  propagation and a queue of other requests. Failed cleanup remains visible for operators.
- CSRs, upstream order URLs and certificate chains are persisted in SQLite so interrupted
  issuance can resume without changing the client's key. Only our upstream ACME account
  key is held by the server, encrypted using `master.key`. No client private key is sent.
- Account/order history is retained in SQLite; there is currently no automatic history
  pruning. ARI, EAB, IP identifiers, custom validity periods and public client challenge
  validation are not implemented. This endpoint is intended for operator-authorized
  internal issuance, not a publicly accessible CA or a general transparent ACME proxy.
- Live Let's Encrypt and real-provider verification remain deployment/release checks.
  The existing provider at-least-once mutation limitations also apply here.

## Verification

The Rust suite covers account isolation, signature/nonce/URL checks, network and domain
policy, approval changes, CSR identity/signature checks, key rollover, upstream DNS-01,
cleanup, and resuming after upstream finalization. Browser tests exercise saving settings,
account approval, persisted values, preserving unsaved changes, and the mobile layout.

An optional test runs the actual Certbot CLI through registration, wildcard/apex issuance
and renewal, against the HTTP endpoint, with a simulated upstream CA and local DNS server:

```sh
ACMEPROXY_CERTBOT=/path/to/certbot cargo test real_certbot_issues_and_renews -- --ignored
```

The fixture uses temporary directories and never contacts Let's Encrypt or a real DNS API.
