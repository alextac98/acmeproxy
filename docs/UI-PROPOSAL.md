# ACME Proxy UI proposal

The interface should answer three questions quickly: how do I get a certificate,
is it working, and what do I need to fix? Use a workflow workspace with a stable
sidebar, focused lists, and detail pages that bring status, configuration links,
and the next action together.

The workflow workspace is the approved design and is implemented in `web/`.
The interactive mockup remains a reference with illustrative domains, dates,
and states, and local-only interactions. It is stored in
`.ui-proposal/acme-ui-layout.html`. The domain workspace is an alternative proposal.

## Problems addressed by the refactor

- Administration opens on DNS providers, even after setup is complete.
- Provider, client, and challenge counts appear above unrelated operational pages.
- “Clients” describes DNS gateway credentials, while HTTP-01 ACME client accounts
  and connection instructions are inside Settings. Those two client types are
  materially different, but the navigation does not explain the distinction.
- Settings mixes endpoint configuration, connection instructions, account lists,
  and recent orders into one long page.
- Errors and issuance information are spread across Certificates, DNS validations,
  Activity, and Settings. A user has to discover the relationship themselves.
- Certificate rows expose downloads, renewal controls, and removal together,
  creating a dense set of actions without a clear hierarchy.
- Activity retention is presented beside event search, mixing an instance setting
  with a task for investigating events.

## Recommended navigation

| Location | Purpose | Primary action |
| --- | --- | --- |
| Overview | Actionable failures, managed certificate status, connection summary, recent activity | Get a certificate |
| Certificate methods → Managed certificates | Certificates and private keys managed by this server | Request certificate |
| Certificate methods → ACME endpoint | Directory URL, HTTP-01 client instructions, accounts, endpoint configuration | Connect ACME client |
| Certificate methods → DNS gateway | Domain-scoped client access, credentials, DNS-01 connection instructions | Create gateway client |
| Activity → Events | Search administrative and worker events | Search or inspect |
| Activity → DNS validations | Inspect publishing, propagation context, and cleanup outcomes | Inspect or retry |
| Activity → ACME orders | Inspect orders from the HTTP-01 endpoint | Inspect order |
| DNS providers | Shared DNS credentials and zone coverage | Connect provider |
| Settings | Instance preferences, log retention, service configuration guidance | Save preferences |

Show the three certificate methods as peer destinations beneath the visible
Certificate methods label. Keep Overview and Activity as day-to-day work.
Group DNS providers and Settings under Configuration. Keep help, version details,
and sign-out in the utility area with visible or accessible labels.

Preserve existing bookmarked routes through redirects or aliases. In particular,
`/clients` should open gateway clients and `/validations` should open the DNS
validations tab. Settings should provide a direct link to the relocated endpoint.
Tabs and detail pages should have addressable routes, support the browser back
button, and preserve unsaved input during background refresh.

## Main entry point: Get a certificate

Offer three methods using their actual ownership model:

| Method | Private key | Renewal | What the user sets up |
| --- | --- | --- | --- |
| Managed certificates | ACME Proxy | ACME Proxy | Domains and certificate authority environment |
| ACME endpoint | Client | Client | HTTP-01 ACME directory URL and reachable hostname |
| DNS gateway | Client | Client | Client ID/token and allowed domain scopes |

Use these exact names in navigation, the method chooser, page headings, and
breadcrumbs. Every method page and its child forms/details describes the method
directly beneath the page heading in one concise paragraph: who obtains the
certificate, who stores the key, who renews it, which validation method is used,
and whether wildcard certificates are supported. Keep this explanation in the
heading's text flow, with one consistent text style and no separate facts line,
tinted box, or repeated method label.
The methods can be used concurrently; selecting one opens a workspace and does
not switch the whole instance into an exclusive mode.

For the ACME endpoint, the client requests from ACME Proxy; ACME Proxy obtains
the upstream certificate after HTTP-01 verification. For the DNS gateway, the
client requests directly from its certificate authority, and ACME Proxy only
publishes and cleans up DNS records. Both keep keys and renewal on the client,
so key ownership alone does not distinguish these two methods.

All three require DNS provider coverage. Explain HTTP-01 reachability and its lack
of wildcard certificate support at method selection. Both DNS gateway and managed
certificate methods support wildcard certificates. Network allowlists never
replace hostname verification. ACME accounts register automatically; they do not
require gateway tokens or an approval workflow.

For a fresh instance, replace operational summaries with an ordered setup path:
connect DNS, choose a method, then inspect issuance. Gate dependent actions until
the relevant prerequisite is satisfied, and show missing DNS coverage beside
domain input. Returning users land on Overview or their bookmarked screen.

## Detail pages and action hierarchy

A certificate list needs domains, status, expiry, and one obvious detail action.
Its detail page needs current certificate validity, renewal status and schedule,
DNS provider links, available downloads, and the latest failure or phase.
Distinguish a failed renewal from an expired certificate: a current download can
remain valid while the next renewal is failing. Keep production and staging
certificates visibly distinct.

Use one Download files entry point for chain, key, and bundle. Keep Retry renewal
beside a recoverable failure. Put removal in an advanced section with its existing
confirmation semantics. Renewal produces updated files; it does not automatically
install them on downstream services.

A gateway client detail page contains allowed domains, client ID, connection
instructions, related validation activity, and revocation. Show a new token only
once. Keep revocation separate from permanent deletion of a revoked client.
Different clients must open their own details and instructions.

Provider details describe saved credentials as Configured rather than Healthy.
Saving a token does not establish live provider health. Changes should retain
the existing handling of outstanding challenges and credential snapshots.

Endpoint configuration belongs beside the endpoint connection guide. Keep
network and domain restrictions discoverable through an expandable section,
with field-level errors and independent save state. Do not hide a failed save or
silently change security-sensitive values. Wildcard domain scopes and wildcard
certificate support need separate wording.

## Troubleshooting and observability

Bring administrative events, DNS gateway validations, and HTTP-01 orders into
Activity without merging their distinct lifecycles. Preserve search, pagination,
refresh behavior, and available retry/cleanup actions. Retention belongs in
Settings, including confirmation before reducing the limit.

Show actionable failures on Overview with a route to the relevant detail. Surface
domain/client/provider context wherever the existing data supports it. Exact
certificate-to-validation timelines may require additional correlation data;
matching domain names alone is insufficient to claim that an event belongs to a
particular certificate attempt. Where correlation is unavailable, link to a
clearly labeled filtered activity view rather than implying a causal timeline.

The DNS gateway cannot inventory the certificates or private keys held by its
clients. Label managed certificate counts explicitly, and describe client-owned
certificates through access and validation activity only. Do not invent expiry
dates, deployment status, or renewal health for certificates the server cannot see.

## Alternative: Domain workspace

The second mockup uses top navigation and a domain list beside a selected-domain
workspace. Certificate status, DNS coverage, authorized clients, and validation
activity appear together. It is attractive if hostname troubleshooting dominates
daily use.

The workflow workspace is the initial recommendation. It fits the current resource
model and handles multi-domain certificates and clients with broad wildcard scopes
more naturally. A domain workspace requires a derived inventory, explicit rules
for overlapping scopes and certificate subject alternative names, and careful
handling of client-owned certificates that are not visible to this server. It
could become a later domain detail view without replacing the main navigation.

## Implementation and validation

The implementation uses the current admin APIs with new addressable pages for
Overview, method selection, provider and client details, certificate details,
request forms, endpoint configuration, and ACME order details. `/clients` and
`/validations` are aliases for the new destinations. The mobile menu exposes the
same navigation. Form input survives background refresh, and client tokens are
cleared when their one-time dialog closes. Certificate downloads share one entry
point; removal remains behind Advanced and its existing confirmation.

Browser tests cover the three methods, setup, legacy bookmarks, detail routes,
browser history, provider drafts, tokens, downloads, renewals, cleanup, retention,
endpoint settings, and layouts down to 320 pixels.

Measure success through task completion: a new user can select the right method,
connect a client without hunting through Settings, and find and resolve a renewal
failure while understanding whether the current certificate is still valid.
Verify both certificate environments, all three methods, revoked clients, cleanup
failures, one-time tokens, unsaved edits during refresh, direct routes, browser
back, and mobile use.
