-- Internal challenge owners cannot authenticate and are not file-configured clients.
ALTER TABLE clients ADD COLUMN managed INTEGER NOT NULL DEFAULT 0;
CREATE TABLE acme_accounts (
 staging INTEGER PRIMARY KEY CHECK(staging IN (0,1)),
 credentials BLOB NOT NULL
);
CREATE TABLE certificates (
 id TEXT PRIMARY KEY REFERENCES clients(id),
 domains TEXT NOT NULL,
 staging INTEGER NOT NULL CHECK(staging IN (0,1)),
 auto_renew INTEGER NOT NULL DEFAULT 1,
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','issuing','issued','failed')),
 phase TEXT NOT NULL DEFAULT 'Queued',
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 expires_at INTEGER,
 renew_at INTEGER,
 last_error TEXT,
 order_url TEXT,
 pending_key BLOB,
 pending_csr BLOB,
 fullchain TEXT,
 private_key BLOB,
 UNIQUE(domains, staging)
);
CREATE INDEX certificates_due ON certificates(state,next_attempt);
