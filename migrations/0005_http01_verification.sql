-- Previously, downstream orders were preauthorized by network/account policy.
-- Preserve issued certificates, but require a fresh HTTP-01 order for unissued work.
ALTER TABLE acme_orders RENAME TO acme_orders_legacy;
CREATE TABLE acme_orders (
 id TEXT PRIMARY KEY REFERENCES clients(id),
 account_id TEXT NOT NULL REFERENCES downstream_accounts(id),
 domains TEXT NOT NULL,
 staging INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','ready','processing','valid','invalid')),
 phase TEXT NOT NULL DEFAULT 'Awaiting HTTP-01 verification',
 csr BLOB,
 upstream_url TEXT,
 fullchain TEXT,
 certificate_der BLOB,
 revoked INTEGER NOT NULL DEFAULT 0,
 error TEXT,
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
);
INSERT INTO acme_orders
SELECT id,account_id,domains,staging,
 CASE WHEN state IN ('ready','processing') THEN 'invalid' ELSE state END,
 CASE WHEN state IN ('ready','processing') THEN 'HTTP-01 verification required' ELSE phase END,
 csr,upstream_url,fullchain,certificate_der,revoked,
 CASE WHEN state IN ('ready','processing') THEN 'Create a new order to complete HTTP-01 verification' ELSE error END,
 attempts,next_attempt,expires_at,created_at,updated_at
FROM acme_orders_legacy;
DROP TABLE acme_orders_legacy;
CREATE INDEX acme_orders_pending ON acme_orders(state,next_attempt);
CREATE INDEX acme_orders_account ON acme_orders(account_id,created_at);

CREATE TABLE acme_authorizations (
 order_id TEXT NOT NULL REFERENCES acme_orders(id),
 identifier_index INTEGER NOT NULL,
 domain TEXT NOT NULL,
 token TEXT NOT NULL UNIQUE,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','processing','valid','invalid')),
 key_authorization TEXT,
 validated_at INTEGER,
 error TEXT,
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt INTEGER NOT NULL,
 PRIMARY KEY(order_id,identifier_index)
);
CREATE INDEX acme_authorizations_pending ON acme_authorizations(state,next_attempt);

UPDATE challenges SET state='cleanup_pending',operation='cleanup',attempts=0,next_attempt=0
WHERE client_id IN (SELECT id FROM acme_orders WHERE state='invalid')
 AND state IN ('active','present_pending');
