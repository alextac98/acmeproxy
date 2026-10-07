# HTTP-01 ACME endpoint

Acme Proxy exposes a standard ACME directory to Certbot and other clients that support
custom ACME servers and HTTP-01. The client creates its account key and certificate
private key locally, proves control of each hostname through HTTP-01, sends a signed CSR,
and receives a Let's Encrypt certificate. Acme Proxy handles upstream DNS-01 using the
operator's configured DNS credentials. Clients need no gateway token, DNS plugin, or
operator account approval. Their normal renewal timers repeat the same verified flow.

This is one of three certificate workflows. The authenticated **DNS gateway** lets an
external client obtain certificates directly from its CA, using `/present` and `/cleanup`
to publish DNS-01 records. **Managed Certificates** lets an administrator request a
certificate through the UI/API; this server generates/stores its private key and renews
it automatically. Those two workflows also support wildcards. This endpoint supports
individual DNS hostnames only and never receives a client's certificate private key.

## Operator setup

1. Configure DNS provider connections for the zones you want to issue certificates for.
2. Open **Settings → ACME endpoint** and select **HTTP-01 verification**. The endpoint
   starts **Disabled**; disabling it does not disable the DNS gateway or managed certificates.
3. Set the server URL as clients will see it, for example `https://acme.internal.example.com`.
   Use an origin without a path/query. Terminate HTTPS at your reverse proxy. HTTP origins
   are accepted for local testing, but many clients require HTTPS.
4. Set allowed client network CIDRs. Defaults cover loopback/private LAN ranges. Checks
   use the TCP peer, so forwarded headers cannot bypass them. Behind a reverse proxy,
   also restrict ingress there because the app sees the proxy's IP. These restrictions
   allow clients to attempt validation; they never bypass HTTP-01.
5. For private HTTP responders, add their network CIDRs to **Private HTTP-01 destination
   networks**, for example `10.13.1.0/24`. Empty permits public destinations only. Client
   networks and validation destination networks are separate policies. Loopback may be
   explicitly granted for local deployments; link-local, metadata, multicast, unspecified,
   and IPv4 transition/tunnel destinations are blocked even with broad network grants.
6. Optionally limit allowed certificate domains. Empty permits names covered by configured
   DNS providers. `ha.example.com` permits only that hostname; `*.example.com` permits
   individual descendant hostnames, excluding `example.com`. A wildcard **scope** does not
   enable wildcard **certificates**.
7. Select Let's Encrypt **staging** first, accept the subscriber agreement, and save.
   Once tested, select production. Existing orders keep their original environment.

A hostname must resolve, from Acme Proxy, to the client's HTTP-01 responder on port 80.
Split DNS can point it at a private service; inbound access from the public Internet is
unnecessary because Let's Encrypt validates upstream through DNS-01. Protect the proxy's
DNS resolver and routing: someone who can redirect its validation requests can attack
local hostname verification, while our upstream DNS credentials still satisfy the CA.

## Certbot

Copy the directory URL from Settings:

```sh
certbot certonly --standalone --non-interactive --agree-tos \
  --server https://acme.internal.example.com/acme/directory \
  --email you@example.com -d ha.example.com \
  --issuance-timeout 1200
```

The standalone plugin now actually binds port 80 and serves the challenge. That port
must be free and reachable from Acme Proxy. If a web server already owns port 80, use
Certbot's webroot/web-server integration and route `/.well-known/acme-challenge/` to it.
The certificate hostname should resolve to the challenge responder, not automatically
to the Acme Proxy directory server.

Certbot saves the certificate/private key and renewal settings locally. Keep its usual
renewal timer enabled:

```sh
certbot renew
```

Use deployment hooks to reload the consuming service. Acme Proxy stores the resulting
certificate chain for authenticated ACME download and recovery; it does not receive
client private keys or schedule client renewals. Avoid duplicate managed requests for
the same workflow.

Only `http-01` is offered. Clients configured exclusively for `dns-01` or `tls-alpn-01`
will report that no compatible challenge is available. Wildcard orders return the ACME
`rejectedIdentifier` error with an explanation; unsupported identifier types such as
IP addresses return `unsupportedIdentifier`. There is no trusted-issuance fallback.

## Home Assistant OS

The official Let's Encrypt app supports a custom `acme_server`:

```yaml
email: you@example.com
domains:
  - ha.example.com
certfile: fullchain.pem
keyfile: privkey.pem
challenge: http
dns: {}
acme_server: https://acme.internal.example.com/acme/directory
```

Here `challenge: http` performs real HTTP-01. The app's port 80 responder must be reachable
from Acme Proxy, with the hostname resolving to it and its private network explicitly
allowed for validation. No DNS provider token, `dns-httpreq`, or gateway client ID is needed.
Schedule the app's renewal runs and reload HA or its TLS proxy after renewal. See the
[official app documentation](https://github.com/home-assistant/addons/blob/master/letsencrypt/DOCS.md).
The actual Certbot flow is tested locally; the HA app itself has not been tested.

## Verification and operational scope

- Orders start `pending`. Each hostname has its own random HTTP-01 token and durable
  authorization. A signed acknowledgement binds the expected response to the requesting
  account key. Only after **every** authorization succeeds does an order become `ready`.
  Finalization and each upstream worker phase enforce verified authorization again.
- The validator requests the standard challenge path on port 80, using the requested
  hostname as Host. DNS answers are checked and pinned for the entire request/redirect
  chain, including IPv4-mapped IPv6 handling. System HTTP proxy settings are ignored.
- Redirects are limited to ten and must preserve the hostname and challenge path, using
  HTTP port 80 or HTTPS port 443 without credentials, query, or fragment. Cross-host/path
  redirects are unsupported. Like Let's Encrypt, HTTPS challenge redirects can bootstrap
  through an expired/self-signed certificate. Responses must be HTTP 200 and match the
  full token/account-thumbprint, ignoring trailing whitespace. Bodies are limited to
  4096 bytes and never reflected in error messages.
- Each validation attempt is bounded to 30 seconds and retries up to three times with
  ten seconds between attempts. Duplicate acknowledgements do not reset attempts or
  generate more requests. The separate validation worker resumes persisted jobs after
  restart and does not wait for slow upstream certificate issuance.
- Disabled issuance, deactivated accounts, expired orders, domain-policy changes, and
  lost provider coverage prevent validation/finalization/issuance. Validation destination
  changes during a request invalidate its result. Account key rollover preserves identity;
  an acknowledged challenge retains its original account-bound response.
- Accounts use standard ES256 or RS256 JWS signatures and single-use nonces. CSRs must
  have valid signatures and DNS SANs exactly matching the order; returned certificates
  must match the CSR public key and names. Account/order/challenge/download access is
  isolated by account ownership. Revocation accepts the issuing downstream account or
  the certificate's supported matching key and uses our issuing upstream account.
- Directory, account management/order lists, key rollover, authorizations/challenges,
  finalization, download, and upstream revocation are implemented. ARI, EAB, IP identifiers,
  custom validity dates, and other downstream challenge types are not implemented.
- Orders expire after 24 hours. Limits remain 100 outstanding orders (including unverified
  orders), 20 new orders per account/hour, 100 globally/hour, and 1000 registered accounts.
  Nonces expire after five minutes and their store is capped at 10000 entries.
- Upstream issuance uses the existing durable DNS journal and exact-value cleanup.
  Attempts are bounded to 20 minutes and retry up to three times. CSRs, upstream order
  URLs, and issued chains are persisted in SQLite for recovery. Our upstream account
  key is encrypted with `master.key`; no downstream certificate private key is sent.
- Account/order/authorization history currently has no automatic pruning. Live Let's
  Encrypt/provider verification remains a deployment check. This is a self-hosted
  service for configured DNS zones, not issuance for arbitrary domains.

## Upgrading from trusted issuance

Legacy `trusted_network` and `approved_accounts` configuration values become `http01`.
Approvals no longer grant issuance permission. Issued certificates remain downloadable;
unissued legacy orders become invalid and their DNS cleanup is queued. Create fresh
orders and configure reachable HTTP-01 responders, including explicit private destination
networks. Existing DNS gateway clients and managed certificates keep their behavior.

## Tests

The Rust suite exercises actual HTTP validation, per-hostname/account binding, early
finalization and worker bypass rejection, wildcard/identifier rejection, address/redirect
restrictions, failure/retry/expiry/restart behavior, migration, JWS/nonce/CSR checks,
upstream DNS-01, cleanup, private-key separation, and certificate download recovery.
Browser tests cover HTTP-01 settings, private destination policy, registered accounts,
persistence, unsaved edits, and mobile layout. Existing suites cover authenticated DNS
gateway operations and managed issuance/renewal/downloads.

An optional real Certbot test issues and renews through HTTP-01 against a simulated
upstream CA and local challenge responder:

```sh
ACMEPROXY_CERTBOT=/path/to/certbot cargo test real_certbot_issues_and_renews -- --ignored
```

The fixture maps the HTTP challenge hostname to an isolated unprivileged test listener;
production validation always starts on port 80. Tests never contact Let's Encrypt or a
real DNS provider.

The shipping server's independent validation worker can also be tested with real Docker
DNS and a port 80 HTTP responder. This requires Docker and Python's `cryptography` package
(included with Certbot):

```sh
python scripts/smoke-http01.py --image acmeproxy:your-test-image
```

This uses disposable containers/networks/volumes and never finalizes a CSR, so it makes no
upstream CA or DNS provider request. It checks successful proof and private-network denial.
