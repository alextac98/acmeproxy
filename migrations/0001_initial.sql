CREATE TABLE metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE providers (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, driver TEXT NOT NULL,
 zone TEXT NOT NULL UNIQUE, credentials BLOB NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE clients (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash BLOB NOT NULL UNIQUE,
 scopes TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL
);
CREATE TABLE challenges (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES clients(id),
 provider_id TEXT NOT NULL REFERENCES providers(id), credentials_snapshot BLOB NOT NULL,
 fqdn TEXT NOT NULL, value TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('present_pending','active','cleanup_pending','cleaned','failed')),
 operation TEXT NOT NULL CHECK(operation IN ('present','cleanup')),
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 last_error TEXT, worker_state BLOB,
 UNIQUE(fqdn, value)
);
CREATE INDEX challenges_pending ON challenges(state, next_attempt);
CREATE TABLE audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
 actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL
);
