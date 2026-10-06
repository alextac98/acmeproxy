//! Downstream ACME interface. Clients own certificate private keys; this service
//! authorizes domains by operator policy and performs upstream DNS-01 validation.
mod protocol;
mod worker;
pub(crate) use worker::process_one;

use crate::{App, api, config, security};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Disabled,
    TrustedNetwork,
    ApprovedAccounts,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub mode: Mode,
    pub base_url: String,
    pub allowed_networks: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub approved_accounts: Vec<String>,
    pub staging: bool,
    pub terms_agreed: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Disabled,
            base_url: String::new(),
            allowed_networks: [
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "::1/128",
                "fc00::/7",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            allowed_domains: vec![],
            approved_accounts: vec![],
            staging: true,
            terms_agreed: false,
        }
    }
}
impl Settings {
    pub fn normalize(&mut self) -> anyhow::Result<()> {
        self.base_url = self.base_url.trim().trim_end_matches('/').to_string();
        if self.mode != Mode::Disabled || !self.base_url.is_empty() {
            let url = url::Url::parse(&self.base_url)?;
            anyhow::ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.path() == "/",
                "ACME URL must be an HTTP(S) origin without a path, credentials or query"
            );
            self.base_url = url.as_str().trim_end_matches('/').to_string();
        }
        if self.mode != Mode::Disabled {
            anyhow::ensure!(
                self.terms_agreed,
                "accept the Let's Encrypt subscriber agreement before enabling ACME"
            );
            anyhow::ensure!(
                !self.allowed_networks.is_empty(),
                "configure allowed client networks"
            );
        }
        anyhow::ensure!(
            self.allowed_networks.len() <= 100
                && self.allowed_domains.len() <= 100
                && self.approved_accounts.len() <= 1000,
            "ACME policy is too large"
        );
        for network in &mut self.allowed_networks {
            *network = network.trim().parse::<ipnet::IpNet>()?.trunc().to_string();
        }
        for domain in &mut self.allowed_domains {
            *domain = security::scope(domain.trim()).map_err(anyhow::Error::msg)?;
        }
        for id in &self.approved_accounts {
            uuid::Uuid::parse_str(id)?;
        }
        Ok(())
    }
    fn url(&self, suffix: &str) -> String {
        format!("{}/acme/{suffix}", self.base_url)
    }
    fn accepts_ip(&self, ip: std::net::IpAddr) -> bool {
        self.allowed_networks.iter().any(|n| {
            n.parse::<ipnet::IpNet>()
                .is_ok_and(|n| n.contains(&ip.to_canonical()))
        })
    }
    fn accepts_account(&self, id: &str) -> bool {
        self.mode == Mode::TrustedNetwork
            || (self.mode == Mode::ApprovedAccounts
                && self.approved_accounts.iter().any(|v| v == id))
    }
}

pub fn router() -> Router<App> {
    Router::new()
        .route("/directory", get(protocol::handle))
        .route("/new-nonce", get(protocol::handle).head(protocol::handle))
        .route("/new-account", post(protocol::handle))
        .route("/new-order", post(protocol::handle))
        .route("/account/{id}", post(protocol::handle))
        .route("/account/{id}/orders", post(protocol::handle))
        .route("/order/{id}", post(protocol::handle))
        .route("/authz/{id}/{index}", post(protocol::handle))
        .route("/finalize/{id}", post(protocol::handle))
        .route("/certificate/{id}", post(protocol::handle))
        .route("/revoke-cert", post(protocol::handle))
        .route("/key-change", post(protocol::handle))
}

pub async fn get_settings(State(app): State<App>) -> api::Result<Json<Value>> {
    let settings = app.config.lock().await.value.acme.clone();
    let accounts = sqlx::query("SELECT id,thumbprint,contact,status,created_at FROM downstream_accounts ORDER BY created_at DESC").fetch_all(&app.db).await?;
    let orders = sqlx::query("SELECT id,account_id,domains,staging,state,phase,error,created_at FROM acme_orders ORDER BY created_at DESC LIMIT 100").fetch_all(&app.db).await?;
    Ok(Json(json!({ "settings":settings,
        "accounts": accounts.iter().map(|r|json!({"id":r.get::<String,_>("id"),"thumbprint":r.get::<String,_>("thumbprint"),"contact":serde_json::from_str::<Value>(r.get("contact")).unwrap_or(json!([])),"status":r.get::<String,_>("status"),"created_at":r.get::<i64,_>("created_at")})).collect::<Vec<_>>(),
        "orders": orders.iter().map(|r|json!({"id":r.get::<String,_>("id"),"account_id":r.get::<String,_>("account_id"),"domains":serde_json::from_str::<Value>(r.get("domains")).unwrap_or(json!([])),"staging":r.get::<bool,_>("staging"),"state":r.get::<String,_>("state"),"phase":r.get::<String,_>("phase"),"error":r.get::<Option<String>,_>("error"),"created_at":r.get::<i64,_>("created_at")})).collect::<Vec<_>>()
    })))
}

pub async fn put_settings(
    State(app): State<App>,
    Json(mut settings): Json<Settings>,
) -> api::Result<Json<Value>> {
    settings.normalize().map_err(|_| {
        api::bad(
            "check ACME mode, public URL, network CIDRs, domain scopes, and subscriber agreement",
        )
    })?;
    let _guard = app.mutation.lock().await;
    let mut next = app.config.lock().await.value.clone();
    // Account approval has a separate endpoint; a form save must not overwrite concurrent approvals.
    settings.approved_accounts = next.acme.approved_accounts.clone();
    next.acme = settings;
    config::apply(&app, next, "acme.settings_changed", "acme").await?;
    Ok(Json(json!({"status":"saved"})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    approved: bool,
}
pub async fn approve_account(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<Approval>,
) -> api::Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM downstream_accounts WHERE id=? AND status='valid')",
    )
    .bind(&id)
    .fetch_one(&app.db)
    .await?;
    if !exists {
        return Err(api::bad("active ACME account not found"));
    }
    let mut next = app.config.lock().await.value.clone();
    next.acme.approved_accounts.retain(|v| v != &id);
    if input.approved {
        next.acme.approved_accounts.push(id.clone());
    }
    config::apply(&app, next, "acme.account_approval_changed", &id).await?;
    Ok(Json(json!({"approved":input.approved})))
}

/// Exact policies do not implicitly authorize wildcard certificates. Wildcard
/// policies cover descendants and descendant wildcards, but not their apex.
fn permits_domain(domain: &str, scopes: &[String]) -> bool {
    if scopes.is_empty() {
        return true;
    }
    if let Some(base) = domain.strip_prefix("*.") {
        scopes.iter().any(|s| {
            s.strip_prefix("*.")
                .is_some_and(|scope| security::within(base, scope))
        })
    } else {
        security::allowed(domain, scopes)
    }
}

async fn check_domains(app: &App, settings: &Settings, domains: &[String]) -> anyhow::Result<()> {
    let zones: Vec<String> = sqlx::query_scalar("SELECT zone FROM providers")
        .fetch_all(&app.db)
        .await?;
    anyhow::ensure!(
        domains
            .iter()
            .all(|d| permits_domain(d, &settings.allowed_domains)
                && zones
                    .iter()
                    .any(|zone| security::within(d.strip_prefix("*.").unwrap_or(d), zone))),
        "domains are not authorized or have no DNS provider"
    );
    Ok(())
}

async fn check_order_policy(app: &App, id: &str) -> anyhow::Result<()> {
    let settings = app.config.lock().await.value.acme.clone();
    let row = sqlx::query("SELECT o.account_id,o.domains,o.expires_at,a.status FROM acme_orders o JOIN downstream_accounts a ON a.id=o.account_id WHERE o.id=?").bind(id).fetch_one(&app.db).await?;
    anyhow::ensure!(
        settings.accepts_account(row.get("account_id"))
            && row.get::<String, _>("status") == "valid"
            && row.get::<i64, _>("expires_at") > crate::now(),
        "ACME order is no longer authorized"
    );
    check_domains(
        app,
        &settings,
        &serde_json::from_str::<Vec<String>>(row.get("domains"))?,
    )
    .await
}

#[cfg(test)]
mod tests;
