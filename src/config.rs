use crate::{
    App, now,
    provider::{Driver, validate_credentials},
    security::{self, Vault},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sqlx::{Row, Sqlite, Transaction};
use std::{
    collections::{BTreeMap, HashSet},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Server,
    #[serde(default)]
    pub acme: crate::acme::Settings,
    #[serde(default)]
    pub providers: Vec<Provider>,
    #[serde(default)]
    pub clients: Vec<Client>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub listen: String,
    pub dnsapi_home: String,
    pub challenge_ttl_seconds: i64,
    pub worker_timeout_seconds: u64,
    pub audit_retention: i64,
}
impl Default for Server {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".into(),
            dnsapi_home: "../.local/acme.sh".into(),
            challenge_ttl_seconds: 3600,
            worker_timeout_seconds: 30,
            audit_retention: 1000,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    #[serde(default = "new_id")]
    pub id: String,
    pub name: String,
    pub driver: String,
    pub zone: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub encrypted_credentials: String,
    /// Optional plaintext import, replaced by encrypted_credentials on successful startup.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    #[serde(default = "new_id")]
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub token_hash: String,
    /// Optional plaintext import, replaced by token_hash on successful startup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}
fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub struct ConfigFile {
    pub path: PathBuf,
    pub value: Config,
}
impl ConfigFile {
    pub fn load(path: PathBuf) -> anyhow::Result<Self> {
        Ok(Self {
            value: toml::from_str(&std::fs::read_to_string(&path)?)?,
            path,
        })
    }
}

pub fn write(path: &Path, config: &Config) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    writeln!(
        temp,
        "# ACME Proxy configuration. UI saves rewrite this file; manual edits require a restart.\n# Keep this directory private and back up master.key with the encrypted configuration.\n{}",
        toml::to_string_pretty(config)?
    )?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn normalize(config: &mut Config, vault: &Vault, drivers: &[Driver]) -> anyhow::Result<()> {
    config.acme.normalize()?;
    anyhow::ensure!(
        (50..=100_000).contains(&config.server.audit_retention),
        "audit retention must be 50..100000 events"
    );
    anyhow::ensure!(
        (60..=86400).contains(&config.server.challenge_ttl_seconds),
        "challenge TTL must be 60..86400 seconds"
    );
    anyhow::ensure!(
        (1..=120).contains(&config.server.worker_timeout_seconds),
        "worker timeout must be 1..120 seconds"
    );
    let mut ids = HashSet::new();
    let mut zones = HashSet::new();
    for provider in &mut config.providers {
        anyhow::ensure!(
            uuid::Uuid::parse_str(&provider.id).is_ok() && ids.insert(provider.id.clone()),
            "provider IDs must be unique UUIDs"
        );
        anyhow::ensure!(
            !provider.name.trim().is_empty() && provider.name.len() <= 100,
            "provider name must be 1..100 characters"
        );
        provider.zone = security::domain(&provider.zone).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            zones.insert(provider.zone.clone()),
            "only one provider per zone is allowed"
        );
        let driver = drivers
            .iter()
            .find(|d| d.id == provider.driver)
            .ok_or_else(|| {
                anyhow::anyhow!("provider adapter is not installed: {}", provider.driver)
            })?;
        if !provider.credentials.is_empty() {
            anyhow::ensure!(
                provider.encrypted_credentials.is_empty(),
                "specify credentials OR encrypted_credentials, not both"
            );
            validate_credentials(driver, &provider.credentials).map_err(anyhow::Error::msg)?;
            provider.encrypted_credentials = URL_SAFE_NO_PAD
                .encode(vault.seal(&provider.id, &serde_json::to_vec(&provider.credentials)?)?);
            provider.credentials.clear();
        }
        let credentials = serde_json::from_slice(&vault.open(
            &provider.id,
            &URL_SAFE_NO_PAD.decode(&provider.encrypted_credentials)?,
        )?)?;
        validate_credentials(driver, &credentials).map_err(anyhow::Error::msg)?;
    }
    let mut hashes = HashSet::new();
    for client in &mut config.clients {
        anyhow::ensure!(
            uuid::Uuid::parse_str(&client.id).is_ok() && ids.insert(client.id.clone()),
            "client IDs must be unique UUIDs"
        );
        anyhow::ensure!(
            !client.name.trim().is_empty() && client.name.len() <= 100,
            "client name must be 1..100 characters"
        );
        anyhow::ensure!(
            !client.scopes.is_empty() && client.scopes.len() <= 100,
            "clients require 1..100 scopes"
        );
        client.scopes = client
            .scopes
            .iter()
            .map(|s| security::scope(s).map_err(anyhow::Error::msg))
            .collect::<anyhow::Result<_>>()?;
        if let Some(token) = client.token.take() {
            anyhow::ensure!(
                token.len() >= 32 && token.len() <= 256,
                "client tokens must contain 32..256 characters"
            );
            client.token_hash = URL_SAFE_NO_PAD.encode(security::hash(&token));
        }
        anyhow::ensure!(
            URL_SAFE_NO_PAD.decode(&client.token_hash)?.len() == 32
                && hashes.insert(client.token_hash.clone()),
            "client token hashes must be unique SHA-256 hashes"
        );
    }
    Ok(())
}

pub async fn sync(tx: &mut Transaction<'_, Sqlite>, config: &Config) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO metadata(key,value) VALUES('audit_retention',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(config.server.audit_retention).execute(&mut **tx).await?;
    sqlx::query(
        "DELETE FROM audit WHERE id <= (SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET ?)",
    )
    .bind(config.server.audit_retention)
    .execute(&mut **tx)
    .await?;
    for old in sqlx::query("SELECT * FROM providers")
        .fetch_all(&mut **tx)
        .await?
    {
        let id: String = old.get("id");
        let new = config.providers.iter().find(|p| p.id == id);
        let changed = match new {
            None => true,
            Some(p) => {
                p.driver != old.get::<String, _>("driver") || p.zone != old.get::<String, _>("zone")
            }
        };
        if changed {
            let active: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM challenges WHERE provider_id=? AND state!='cleaned'",
            )
            .bind(&id)
            .fetch_one(&mut **tx)
            .await?;
            anyhow::ensure!(
                active == 0,
                "clean up outstanding challenges before changing or removing provider {id}"
            );
        }
        if new.is_none() {
            sqlx::query("DELETE FROM challenges WHERE provider_id=?")
                .bind(&id)
                .execute(&mut **tx)
                .await?;
            sqlx::query("DELETE FROM providers WHERE id=?")
                .bind(&id)
                .execute(&mut **tx)
                .await?;
        }
    }
    for p in &config.providers {
        sqlx::query("INSERT INTO providers(id,name,driver,zone,credentials,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,driver=excluded.driver,zone=excluded.zone,credentials=excluded.credentials")
            .bind(&p.id).bind(&p.name).bind(&p.driver).bind(&p.zone).bind(URL_SAFE_NO_PAD.decode(&p.encrypted_credentials)?).bind(now()).execute(&mut **tx).await?;
    }
    // Removed clients remain as revoked history for challenge ownership and audit references.
    sqlx::query("UPDATE clients SET revoked=1 WHERE managed=0")
        .execute(&mut **tx)
        .await?;
    for c in &config.clients {
        let managed: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM clients WHERE id=? AND managed=1)")
                .bind(&c.id)
                .fetch_one(&mut **tx)
                .await?;
        anyhow::ensure!(!managed, "client ID is reserved for certificate management");
        sqlx::query("INSERT INTO clients(id,name,token_hash,scopes,revoked,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,token_hash=excluded.token_hash,scopes=excluded.scopes,revoked=excluded.revoked")
            .bind(&c.id).bind(&c.name).bind(URL_SAFE_NO_PAD.decode(&c.token_hash)?).bind(serde_json::to_string(&c.scopes)?).bind(c.revoked).bind(now()).execute(&mut **tx).await?;
    }
    sqlx::query("UPDATE challenges SET state='cleanup_pending', operation='cleanup', attempts=0, next_attempt=? WHERE client_id IN (SELECT id FROM clients WHERE revoked=1) AND state NOT IN ('cleaned','cleanup_pending')")
        .bind(now()).execute(&mut **tx).await?;
    Ok(())
}

// Caller holds app.mutation. Persist the authoritative file before committing its DB projection.
pub async fn apply(app: &App, next: Config, action: &str, target: &str) -> anyhow::Result<()> {
    apply_inner(app, next, action, target, None).await
}

// Caller holds app.mutation, as with apply.
pub async fn delete_client(app: &App, id: &str) -> anyhow::Result<()> {
    let mut next = app.config.lock().await.value.clone();
    next.clients.retain(|client| client.id != id);
    apply_inner(app, next, "client.deleted", id, Some(id)).await
}

async fn apply_inner(
    app: &App,
    mut next: Config,
    action: &str,
    target: &str,
    deleted_client: Option<&str>,
) -> anyhow::Result<()> {
    normalize(&mut next, &app.vault, &app.drivers)?;
    let mut file = app.config.lock().await;
    anyhow::ensure!(
        toml::to_string(&ConfigFile::load(file.path.clone())?.value)?
            == toml::to_string(&file.value)?,
        "configuration changed on disk; restart before making UI changes"
    );
    let mut tx = app.db.begin().await?;
    if let Some(id) = deleted_client {
        let deletable: bool = sqlx::query_scalar(
            "SELECT revoked AND NOT EXISTS(SELECT 1 FROM challenges WHERE client_id=? AND state!='cleaned') FROM clients WHERE id=?",
        )
        .bind(id).bind(id).fetch_one(&mut *tx).await?;
        anyhow::ensure!(
            deletable,
            "client must be revoked and all DNS records cleaned up"
        );
    }
    sync(&mut tx, &next).await?;
    if let Some(id) = deleted_client {
        sqlx::query("DELETE FROM challenges WHERE client_id=?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM clients WHERE id=?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "INSERT INTO audit(at,actor,action,target,outcome) VALUES(?,'admin',?,?,'success')",
    )
    .bind(now())
    .bind(action)
    .bind(target)
    .execute(&mut *tx)
    .await?;
    write(&file.path, &next)?;
    if let Err(error) = tx.commit().await {
        // The durable config is authoritative; restart reconstructs the projection.
        app.healthy
            .store(false, std::sync::atomic::Ordering::SeqCst);
        return Err(error.into());
    }
    file.value = next;
    app.wake.notify_one();
    Ok(())
}
