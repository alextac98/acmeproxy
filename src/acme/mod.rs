//! Downstream ACME interface. Clients own certificate private keys; this service
//! verifies downstream HTTP-01 and performs upstream DNS-01 validation.
mod protocol;
mod validation;
mod worker;
pub use validation::run_worker as run_validation_worker;
pub(crate) use worker::process_one;

use crate::{App, api, config, security};
use axum::{
    Json, Router,
    extract::State,
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
    // Existing installations are upgraded to verification, never trusted issuance.
    #[serde(alias = "trusted_network", alias = "approved_accounts")]
    Http01,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub mode: Mode,
    pub base_url: String,
    pub allowed_networks: Vec<String>,
    pub allowed_domains: Vec<String>,
    /// Additional non-public networks reachable by the HTTP-01 verifier.
    pub validation_networks: Vec<String>,
    /// Accept old configuration files; approvals no longer bypass HTTP-01.
    #[serde(skip_serializing)]
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
            validation_networks: vec![],
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
                && self.validation_networks.len() <= 100,
            "ACME policy is too large"
        );
        for network in self
            .allowed_networks
            .iter_mut()
            .chain(&mut self.validation_networks)
        {
            *network = network.trim().parse::<ipnet::IpNet>()?.trunc().to_string();
        }
        for domain in &mut self.allowed_domains {
            *domain = security::scope(domain.trim()).map_err(anyhow::Error::msg)?;
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
        .route("/challenge/{id}/{index}", post(protocol::handle))
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
            "check ACME mode, public URL, client and validation network CIDRs, domain scopes, and subscriber agreement",
        )
    })?;
    let _guard = app.mutation.lock().await;
    let mut next = app.config.lock().await.value.clone();
    next.acme = settings;
    config::apply(&app, next, "acme.settings_changed", "acme").await?;
    Ok(Json(json!({"status":"saved"})))
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

async fn check_order_access(app: &App, id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        app.healthy.load(std::sync::atomic::Ordering::SeqCst),
        "configuration needs restart"
    );
    let settings = app.config.lock().await.value.acme.clone();
    let row = sqlx::query("SELECT o.account_id,o.domains,o.expires_at,a.status FROM acme_orders o JOIN downstream_accounts a ON a.id=o.account_id WHERE o.id=?").bind(id).fetch_one(&app.db).await?;
    anyhow::ensure!(
        settings.mode == Mode::Http01
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

async fn check_order_policy(app: &App, id: &str) -> anyhow::Result<()> {
    check_order_access(app, id).await?;
    let domains: Vec<String> = serde_json::from_str(
        &sqlx::query_scalar::<_, String>("SELECT domains FROM acme_orders WHERE id=?")
            .bind(id)
            .fetch_one(&app.db)
            .await?,
    )?;
    let authorizations = sqlx::query(
        "SELECT domain,state,key_authorization,validated_at FROM acme_authorizations WHERE order_id=? ORDER BY identifier_index",
    ).bind(id).fetch_all(&app.db).await?;
    anyhow::ensure!(
        authorizations.len() == domains.len()
            && authorizations.iter().zip(&domains).all(|(a, d)| {
                a.get::<String, _>("domain") == *d
                    && a.get::<String, _>("state") == "valid"
                    && a.get::<Option<String>, _>("key_authorization").is_some()
                    && a.get::<Option<i64>, _>("validated_at").is_some()
            }),
        "every requested name must pass HTTP-01 verification"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
