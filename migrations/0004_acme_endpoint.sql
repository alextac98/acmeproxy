CREATE TABLE downstream_accounts (
 id TEXT PRIMARY KEY,
 thumbprint TEXT NOT NULL UNIQUE,
 jwk TEXT NOT NULL,
 contact TEXT NOT NULL DEFAULT '[]',
 status TEXT NOT NULL DEFAULT 'valid' CHECK(status IN ('valid','deactivated')),
 created_at INTEGER NOT NULL
);
CREATE TABLE acme_nonces (
 hash BLOB PRIMARY KEY,
 expires_at INTEGER NOT NULL
);
CREATE INDEX acme_nonces_expiry ON acme_nonces(expires_at);
CREATE TABLE acme_orders (
 id TEXT PRIMARY KEY REFERENCES clients(id),
 account_id TEXT NOT NULL REFERENCES downstream_accounts(id),
 domains TEXT NOT NULL,
 staging INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'ready' CHECK(state IN ('ready','processing','valid','invalid')),
 phase TEXT NOT NULL DEFAULT 'Awaiting client CSR',
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
CREATE INDEX acme_orders_pending ON acme_orders(state,next_attempt);
CREATE INDEX acme_orders_account ON acme_orders(account_id,created_at);
