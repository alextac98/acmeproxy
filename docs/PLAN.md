# ACME Proxy implementation plan

## Product boundary

A self-hosted DNS-01 gateway and internal ACME endpoint, with optional managed certificates.
External gateway clients keep their ACME accounts, keys, renewals, and certificates.
Managed requests instead let the server own that lifecycle: an administrator requests
domains, and the issuer uses existing operator-configured DNS providers automatically.
The gateway creates/removes only `_acme-challenge` TXT values. The internal ACME endpoint forwards client CSRs to Let's Encrypt after operator-policy
authorization and upstream DNS-01 validation. It does not sign certificates itself.

**Configuration is the source of truth.** A single directory contains `config.toml`,
keys, and durable runtime state. An administrator can configure the service entirely
through TOML, or use the embedded UI, which edits the same file. No external database,
message broker, Node runtime, or cloud service is required. DNS APIs and the clients'
chosen certificate authorities remain external dependencies.

## Stack and tradeoffs

| Component | Choice | Reason |
| --- | --- | --- |
| Server | Rust, Tokio, Axum | Memory safety, typed state transitions, bounded asynchronous operations |
| Configuration | TOML with atomic file replacement | Easy to mount, inspect, back up, and manage with configuration tools |
| Runtime state | SQLite, WAL, full synchronization | Durable challenge journal without a separate database service |
| DNS integration | Pinned acme.sh `dnsapi` worker processes | Broad provider reach without reimplementing DNS APIs |
| Secret encryption | XChaCha20-Poly1305, random nonce, provider/job ID as associated data | Authenticated encryption of credentials and worker state |
| Client credentials | Random 256-bit tokens, persisted SHA-256 hashes | Revocable service identities; suitable hashing for high-entropy tokens |
| Admin UI | Embedded HTML/CSS/JavaScript | A single server binary plus the adapter bundle; no frontend build needed |

Rust alone does not make an application stable. Recovery semantics, ownership checks,
DNS adapter behavior, monitoring, and tested upgrades matter more than language choice.

`dnsapi` is the collection of shell adapters in acme.sh, not a Rust library. The current
catalog includes 184 adapters with extractable documented credential fields from
acme.sh 3.1.4. This count is **available integration surface, not verified support**.
Providers needing other binaries, files, unusual state, or undocumented variables may
need explicit packaging work. acmeproxy itself is excluded to avoid recursive routing.

An all-Go implementation using lego is a credible alternative with less integration
overhead. A Rust server plus a Go lego worker is also possible, but adds a second
compiled toolchain. Keep the worker boundary so we can add native adapters or replace
the shell backend after conformance results identify specific gaps.

## Request path

```mermaid
sequenceDiagram
    participant Client as ACME client
    participant Proxy as Rust gateway
    participant State as SQLite journal
    participant Worker as DNS adapter process
    participant DNS as DNS provider
    Client->>Proxy: POST /present (client ID + token, fqdn, value)
    Proxy->>Proxy: Authenticate, authorize domain, select zone
    Proxy->>State: Persist owned present_pending challenge
    Proxy->>Worker: Run adapter with this provider's credentials
    Worker->>DNS: Create exact TXT value
    Worker-->>Proxy: Result and cleanup state
    Proxy->>State: Persist result and encrypted worker state
    Proxy-->>Client: Success only after adapter succeeds
    Note over Client,DNS: Client checks DNS propagation and completes ACME validation
    Client->>Proxy: POST /cleanup (same fqdn and value)
    Proxy->>State: Persist cleanup_pending
    Proxy->>Worker: Remove owned TXT value
    Worker->>DNS: Delete matching value
    Proxy->>State: Mark cleaned
```

## Internal ACME endpoint

See [ACME endpoint design, setup and verification](ACME.md). This is the primary flow
for clients such as Certbot: the client owns its account key, certificate key, installation
and renewal timer. The gateway presents an ACME directory and automatically authorizes
covered names according to a trusted-network or approved-account policy, then submits
the client's verified CSR to Let's Encrypt using the same durable DNS worker.

The endpoint is disabled by default. Settings and account approvals are persisted in
TOML; registered account public keys, single-use nonces, orders, CSRs and issued chains
are runtime state in SQLite. There is no client certificate private key on this path.
An order pins its upstream staging/production choice. The existing serial issuance
worker processes both managed certificates and downstream ACME jobs, so upstream account
creation and provider mutations preserve the single-process recovery assumptions.

## Managed certificate lifecycle

- `instant-acme` handles ACME with Let's Encrypt production/staging over verified HTTPS;
  `rcgen` generates ECDSA P-256 keys and CSRs. No CA URL is accepted from requesters.
- A separate, serial issuer queues DNS mutations into the existing worker journal. It
  releases the mutation lock while awaiting DNS and CA responses, so cleanup can proceed.
- Internal challenge owners are excluded from external authentication, client listings,
  and file-config client revocation. No gateway token setup is required for issuance.
- ACME account credentials and pending/current certificate keys are encrypted at rest.
  The order URL, CSR, and encrypted key are persisted before finalization; a restarted
  issuer resumes the order. A crash between remote order creation and persistence can
  still leave an unused CA order, but no DNS has been changed for that order yet.
- Downloaded certificates must match both the saved key and requested SANs before the
  current key/chain pair is replaced atomically. Failed renewals retain the previous pair.
- Renewal uses two thirds of actual certificate validity. ARI scheduling is not implemented.
  Initial requests stop after five failures; existing certificates retry daily thereafter.
- Cleanup is queued on success, failure, or timeout. A process crash also retains the DNS
  journal and expiration lease. Existing at-least-once provider mutation limitations apply.
- Authenticated admin downloads provide PEM chain, key, and atomic bundle retrieval.
  Deployment to consuming services and scoped certificate retrieval credentials are not
  implemented. Existing external gateway clients can still own their full lifecycle.
- Local simulated-CA/DNS tests cover automated wildcard/apex issuance, cleanup, saved-order
  recovery after finalization, renewal scheduling, key rotation, failed renewal retention,
  request authorization and downloads. Live staging verification remains a release gate.

## Configuration contract

- `config.toml` defines server settings, provider instances, and client policies.
- Provider credentials are encrypted in the file. A plaintext `[providers.credentials]`
  block is accepted for initial provisioning and replaced with ciphertext at startup.
- Client plaintext `token` can be imported similarly; it becomes `token_hash`.
- IDs are stable UUIDs. Omit an ID on initial file provisioning and the server creates it.
- The UI never returns stored provider secrets or token hashes; new client tokens are
  returned once. For Basic auth the username is the client ID, password is its token.
- UI saves replace the configuration atomically and then commit its database projection.
  A commit failure after the file save makes the process refuse further work; restart
  reconstructs the projection from the authoritative file.
- File edits require restart. An external configuration change blocks UI saves until
  restart so the UI cannot silently overwrite new file-defined policy.
- Each challenge pins an encrypted credential snapshot so credential rotation does not
  change in-flight cleanup. Manual retry explicitly adopts the current credentials.
  Provider removal and zone/driver changes are blocked while challenges are unresolved.
  Client removal/revocation queues cleanup and retains ownership history.
- UI saves normalize TOML and do not preserve comments or formatting. A future
  `read_only_config` mode should make GitOps ownership explicit and disable UI mutations.

## Security and correctness contract

- Only canonical ASCII DNS names and base64url-encoded SHA-256 DNS-01 values are accepted.
  Use punycode for IDNs. Requests cannot choose record types, commands, or provider IDs.
- Exact domain scopes match exactly. `*.example.com` authorizes descendants of any depth,
  but not the apex. All suffix checks enforce DNS label boundaries.
- DNS-01 for `example.com` and `*.example.com` uses the same TXT name. This protocol
  cannot distinguish those certificate intents. Domain authorization grants the ability
  to validate wildcard certificates at that name as well.
- The longest matching configured zone routes a **new** challenge. Existing challenges
  retain their original provider, even if a more specific zone is added later.
- A challenge is owned by one client and one exact `(fqdn, value)` pair. Unknown cleanup
  is a no-op. Another client cannot clean up the pair. Different values at one name are
  tracked separately; actual coexistence depends on the adapter/provider contract.
- The worker gets a cleared environment with only catalog-listed provider options.
  Its command is fixed; arguments never become generated shell code. Output is discarded
  to prevent adapter diagnostics from leaking credentials.
- Workers have bounded execution times and their process groups are terminated on
  timeout. This is **process separation, not an OS security sandbox**. Reviewed adapters
  execute as the service user. Before general availability, separate worker OS identity,
  mount/network restrictions, resource quotas, and credential delivery over a pipe are
  required. Same-UID processes may inspect worker environment variables.
- Worker `account.conf` and `domain.conf` state is encrypted between operations. The
  scratch directory briefly holds plaintext: mount it on tmpfs in deployed environments.
  It is cleared on normal completion and stale job directories are removed at startup.
- The admin UI uses a bearer token held only in page memory, never browser storage.
  All APIs require credentials; no ambient cookie authentication or permissive CORS.
  The default listener is loopback. Use HTTPS at a reverse proxy for remote clients.

## Delivery milestones

### 1. Runnable foundation — implemented

- TOML-driven setup and a self-contained configuration directory.
- Embedded UI: provider configuration and credential replacement, client creation and
  revocation, challenge state, manual retry/cleanup, and recent audit events.
- `/present` and `/cleanup` protocol, matching acme.sh's `dns_acmeproxy` payload/response.
- Encrypted credentials and adapter state, hashed tokens, domain scopes, record ownership.
- Durable pending operations, bounded retries with backoff, expiration cleanup, single
  process lock, quota on outstanding challenges, graceful server shutdown.
- Mock-provider lifecycle, authorization, timeout, encryption, and restart tests.

### 2. DNS correctness and compatibility gate — next

- Real create/read/delete tests on dedicated zones: start with Cloudflare, Route 53,
  DigitalOcean, and RFC2136. No provider is certified by the current mocked tests.
- Provider capabilities: multi-value TXT preservation, idempotent add/remove, minimum
  TTL, state requirements, timeout ambiguity, retry classification, and rate limits.
- Test acme.sh end to end against Let's Encrypt staging or Pebble. Test lego HTTPREQ
  default mode, Nginx Proxy Manager's DnsMulti integration, Traefik, and Caddy separately
  before claiming client compatibility. HTTPREQ_MODE=RAW sends a different payload and
  is not supported by this gateway.
- Add authoritative DNS propagation diagnostics and explicit, authorized CNAME delegation.
  The first version does not follow CNAMEs or verify delegation targets.
- Recover crashes between remote mutation and local result commit. Operations are
  currently **at least once**: an ambiguous retry can duplicate DNS values for adapters
  that do not implement idempotence. Exact-once remote mutation is not available merely
  by using SQLite; use provider reads and reconciliation.
- Preserve additional adapter artifacts when necessary. Today only account/domain
  configuration is persisted. Drivers needing certificates or other files need an
  explicit adapter-specific contract.

### 3. Operational hardening and beta

- Isolated worker user/container, restricted mounts, process/memory/file limits.
- Per-client and authentication rate limiting; fair scheduling and per-zone queues.
- OIDC/passkeys or password-based admin sessions with CSRF protection and roles.
  Bootstrap token auth is sufficient for the local development preview.
- Metrics for queue age, cleanup failures, retries, provider latency; alerting and
  structured error categories with carefully redacted diagnostics.
- Master-key rotation, richer credential-version management,
  encrypted backup export and tested restore/upgrade/downgrade procedures.
- Runtime-state/audit retention and pagination; current history grows without pruning.
- Configuration validation CLI, read-only GitOps mode, hot reload with transactional
  policy checks, and comment-preserving edits if desired.
- Signed reproducible releases, SBOM, dependency/adaptor update tests, non-root images,
  ARM64 builds, CI across supported Linux distributions, external security review.

### 4. Scale only when needed

Stay single-node for the first release. SQLite plus a single worker deliberately
serializes mutations and has limited throughput. For HA, introduce PostgreSQL job
claims, fencing, distributed per-zone locks, and shared secret-management semantics;
do not run multiple replicas against a SQLite volume or claim NFS is supported.

## Research sources

- [acmeproxy.pl](https://github.com/MadCamel/acmeproxy.pl)
- [acme.sh dns_acmeproxy wire protocol](https://github.com/acmesh-official/acme.sh/blob/3661fd86b6304115e42f43910e6dd452ab9866d6/dnsapi/dns_acmeproxy.sh)
- [Pinned acme.sh DNS adapters](https://github.com/acmesh-official/acme.sh/tree/3661fd86b6304115e42f43910e6dd452ab9866d6/dnsapi)
- [lego](https://go-acme.github.io/lego/)
- [libdns interfaces](https://github.com/libdns/libdns)
- [Axum](https://docs.rs/axum/latest/axum/)
- [SQLx](https://docs.rs/sqlx/latest/sqlx/)
- [RustCrypto XChaCha20-Poly1305](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/)
