//! Managed certificates use the same durable DNS journal as external ACME clients.
//! Only this worker talks to the CA; no provider secrets or ACME state reach the UI.
use crate::{
    App,
    api::{Error, bad, conflict},
    now, security, store,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use std::time::Duration;

const MAX_CERTIFICATES: i64 = 100;
const JOB_TIMEOUT: u64 = 1200;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    domains: Vec<String>,
    #[serde(default)]
    staging: bool,
    #[serde(default)]
    terms_agreed: bool,
}

pub async fn list(State(app): State<App>) -> crate::api::Result<Json<Value>> {
    let rows = sqlx::query("SELECT id,domains,staging,auto_renew,state,phase,attempts,next_attempt,created_at,updated_at,expires_at,renew_at,last_error,fullchain IS NOT NULL AS downloadable FROM certificates ORDER BY created_at DESC")
        .fetch_all(&app.db).await?;
    Ok(Json(json!(rows.iter().map(|r| json!({
        "id": r.get::<String,_>("id"), "domains": serde_json::from_str::<Value>(r.get("domains")).unwrap_or(json!([])),
        "staging": r.get::<bool,_>("staging"), "auto_renew": r.get::<bool,_>("auto_renew"),
        "state": r.get::<String,_>("state"), "phase": r.get::<String,_>("phase"),
        "attempts": r.get::<i64,_>("attempts"), "next_attempt": r.get::<i64,_>("next_attempt"),
        "created_at": r.get::<i64,_>("created_at"), "updated_at": r.get::<i64,_>("updated_at"),
        "expires_at": r.get::<Option<i64>,_>("expires_at"), "renew_at": r.get::<Option<i64>,_>("renew_at"),
        "last_error": r.get::<Option<String>,_>("last_error"), "downloadable": r.get::<bool,_>("downloadable")
    })).collect::<Vec<_>>())))
}

pub async fn create(
    State(app): State<App>,
    Json(input): Json<Create>,
) -> crate::api::Result<(StatusCode, Json<Value>)> {
    if !input.terms_agreed {
        return Err(bad("agree to the Let's Encrypt subscriber agreement"));
    }
    if input.domains.is_empty() || input.domains.len() > 20 {
        return Err(bad("enter between 1 and 20 domains"));
    }
    let mut domains = input
        .domains
        .iter()
        .map(|s| security::scope(s.trim()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(bad)?;
    domains.sort();
    domains.dedup();
    let _guard = app.mutation.lock().await;
    let zones: Vec<String> = sqlx::query_scalar("SELECT zone FROM providers")
        .fetch_all(&app.db)
        .await?;
    for domain in &domains {
        let name = domain.strip_prefix("*.").unwrap_or(domain);
        if name.len() + "_acme-challenge.".len() > 253 {
            return Err(bad("domain is too long for a DNS challenge"));
        }
        if !zones.iter().any(|z| security::within(name, z)) {
            return Err(bad("no DNS provider is configured for one or more domains"));
        }
    }
    let domains_json = serde_json::to_string(&domains).map_err(anyhow::Error::from)?;
    let existing: Option<String> =
        sqlx::query_scalar("SELECT id FROM certificates WHERE domains=? AND staging=?")
            .bind(&domains_json)
            .bind(input.staging)
            .fetch_optional(&app.db)
            .await?;
    if let Some(id) = existing {
        return Ok((StatusCode::OK, Json(json!({"id": id}))));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM certificates")
        .fetch_one(&app.db)
        .await?;
    if count >= MAX_CERTIFICATES {
        return Err(Error(
            StatusCode::TOO_MANY_REQUESTS,
            "certificate limit reached",
        ));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let mut tx = app.db.begin().await?;
    sqlx::query("INSERT INTO clients(id,name,token_hash,scopes,revoked,created_at,managed) VALUES(?,?,?,?,0,?,1)")
        .bind(&id).bind(format!("Certificate: {}", domains.join(", "))).bind(security::hash(&security::random_secret()))
        .bind(&domains_json).bind(now()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO certificates(id,domains,staging,next_attempt,created_at,updated_at) VALUES(?,?,?,?,?,?)")
        .bind(&id).bind(domains_json).bind(input.staging).bind(now()).bind(now()).bind(now()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit(at,actor,action,target,outcome) VALUES(?,'admin','certificate.requested',?,'queued')")
        .bind(now()).bind(&id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id": id}))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    auto_renew: bool,
}
pub async fn settings(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<Settings>,
) -> crate::api::Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    let result = sqlx::query("UPDATE certificates SET auto_renew=?,state=CASE WHEN ?=0 AND state='queued' AND fullchain IS NOT NULL THEN 'failed' ELSE state END,updated_at=? WHERE id=?")
        .bind(input.auto_renew)
        .bind(input.auto_renew)
        .bind(now())
        .bind(&id)
        .execute(&app.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(Error(StatusCode::NOT_FOUND, "certificate not found"));
    }
    store::audit(
        &app.db,
        "admin",
        "certificate.renewal_changed",
        &id,
        if input.auto_renew {
            "enabled"
        } else {
            "disabled"
        },
    )
    .await?;
    Ok(Json(json!({"auto_renew":input.auto_renew})))
}

pub async fn retry(
    State(app): State<App>,
    Path(id): Path<String>,
) -> crate::api::Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    let result = sqlx::query("UPDATE certificates SET state='queued',phase='Queued',attempts=0,next_attempt=?,last_error=NULL,order_url=NULL,pending_key=NULL,pending_csr=NULL,updated_at=? WHERE id=? AND state='failed'")
        .bind(now()).bind(now()).bind(&id).execute(&app.db).await?;
    if result.rows_affected() == 0 {
        return Err(conflict("only failed certificate requests can be retried"));
    }
    store::audit(&app.db, "admin", "certificate.retried", &id, "queued").await?;
    Ok(Json(json!({"status":"queued"})))
}

pub async fn remove(
    State(app): State<App>,
    Path(id): Path<String>,
) -> crate::api::Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    let state: String = sqlx::query_scalar("SELECT state FROM certificates WHERE id=?")
        .bind(&id)
        .fetch_optional(&app.db)
        .await?
        .ok_or(Error(StatusCode::NOT_FOUND, "certificate not found"))?;
    if state == "issuing" {
        return Err(conflict("wait for the current issuance attempt to finish"));
    }
    let outstanding: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM challenges WHERE client_id=? AND state!='cleaned'",
    )
    .bind(&id)
    .fetch_one(&app.db)
    .await?;
    if outstanding != 0 {
        return Err(conflict(
            "wait for DNS cleanup; retry failed cleanup in DNS validations",
        ));
    }
    let mut tx = app.db.begin().await?;
    sqlx::query("DELETE FROM certificates WHERE id=?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM challenges WHERE client_id=?")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM clients WHERE id=? AND managed=1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO audit(at,actor,action,target,outcome) VALUES(?,'admin','certificate.removed',?,'success')")
        .bind(now()).bind(&id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"removed"})))
}

pub async fn download(
    State(app): State<App>,
    Path((id, file)): Path<(String, String)>,
) -> crate::api::Result<Response> {
    if !matches!(
        file.as_str(),
        "fullchain.pem" | "privkey.pem" | "bundle.pem"
    ) {
        return Err(Error(StatusCode::NOT_FOUND, "file not found"));
    }
    let row = sqlx::query("SELECT fullchain,private_key FROM certificates WHERE id=?")
        .bind(&id)
        .fetch_optional(&app.db)
        .await?
        .ok_or(Error(StatusCode::NOT_FOUND, "certificate not found"))?;
    let chain: String = row
        .get::<Option<String>, _>("fullchain")
        .ok_or(conflict("certificate has not been issued yet"))?;
    let content = if file == "fullchain.pem" {
        chain
    } else {
        let bytes: Vec<u8> = row
            .get::<Option<Vec<u8>>, _>("private_key")
            .ok_or(conflict("certificate key is unavailable"))?;
        let key = String::from_utf8(app.vault.open(&format!("certificate:{id}"), &bytes)?)
            .map_err(anyhow::Error::from)?;
        if file == "bundle.pem" {
            format!("{key}{chain}")
        } else {
            key
        }
    };
    store::audit(&app.db, "admin", "certificate.downloaded", &id, &file).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-pem-file".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        content,
    )
        .into_response())
}

async fn phase(app: &App, id: &str, value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        app.healthy.load(std::sync::atomic::Ordering::SeqCst),
        "configuration needs restart"
    );
    sqlx::query("UPDATE certificates SET phase=?,updated_at=? WHERE id=?")
        .bind(value)
        .bind(now())
        .bind(id)
        .execute(&app.db)
        .await?;
    Ok(())
}

pub(crate) async fn account(app: &App, staging: bool) -> anyhow::Result<Account> {
    let context = format!("acme-account:{staging}");
    let credentials: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT credentials FROM acme_accounts WHERE staging=?")
            .bind(staging)
            .fetch_optional(&app.db)
            .await?;
    if let Some(bytes) = credentials {
        return Ok(Account::builder()?
            .from_credentials(serde_json::from_slice(&app.vault.open(&context, &bytes)?)?)
            .await?);
    }
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            if staging {
                LetsEncrypt::Staging
            } else {
                LetsEncrypt::Production
            }
            .url()
            .to_owned(),
            None,
        )
        .await?;
    let sealed = app
        .vault
        .seal(&context, &serde_json::to_vec(&credentials)?)?;
    sqlx::query("INSERT INTO acme_accounts(staging,credentials) VALUES(?,?)")
        .bind(staging)
        .bind(sealed)
        .execute(&app.db)
        .await?;
    Ok(account)
}

/// Queue or resume an internal challenge under the same mutation lock used by the DNS worker.
pub(crate) async fn present(
    app: &App,
    id: &str,
    fqdn: &str,
    value: &str,
) -> anyhow::Result<String> {
    let (_, name) = security::challenge(fqdn, value).map_err(anyhow::Error::msg)?;
    let _guard = app.mutation.lock().await;
    anyhow::ensure!(
        app.healthy.load(std::sync::atomic::Ordering::SeqCst),
        "configuration needs restart"
    );
    let existing =
        sqlx::query("SELECT id,client_id,state FROM challenges WHERE fqdn=? AND value=?")
            .bind(fqdn)
            .bind(value)
            .fetch_optional(&app.db)
            .await?;
    if let Some(row) = &existing {
        anyhow::ensure!(
            row.get::<String, _>("client_id") == id,
            "challenge belongs to another client"
        );
        let state: &str = row.get("state");
        if matches!(state, "active" | "present_pending") {
            return Ok(row.get("id"));
        }
        anyhow::ensure!(
            state == "cleaned",
            "previous DNS cleanup must finish before validation resumes"
        );
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM challenges WHERE state!='cleaned'")
        .fetch_one(&app.db)
        .await?;
    anyhow::ensure!(count < 1000, "outstanding challenge limit reached");
    let providers =
        sqlx::query("SELECT id,zone,credentials FROM providers ORDER BY length(zone) DESC")
            .fetch_all(&app.db)
            .await?;
    let provider = providers
        .iter()
        .find(|p| security::within(&name, p.get("zone")))
        .ok_or_else(|| anyhow::anyhow!("no DNS provider for domain"))?;
    let challenge_id = existing
        .as_ref()
        .map(|r| r.get::<String, _>("id"))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    sqlx::query("INSERT INTO challenges(id,client_id,provider_id,credentials_snapshot,fqdn,value,state,operation,next_attempt,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,'present_pending','present',?,?,?,?) ON CONFLICT(fqdn,value) DO UPDATE SET provider_id=excluded.provider_id,credentials_snapshot=excluded.credentials_snapshot,state='present_pending',operation='present',attempts=0,next_attempt=excluded.next_attempt,expires_at=excluded.expires_at,updated_at=excluded.updated_at,worker_state=NULL,last_error=NULL")
        .bind(&challenge_id).bind(id).bind(provider.get::<String,_>("id")).bind(provider.get::<Vec<u8>,_>("credentials"))
        .bind(fqdn).bind(value).bind(now()).bind(now()+JOB_TIMEOUT as i64+600).bind(now()).bind(now()).execute(&app.db).await?;
    app.wake.notify_one();
    Ok(challenge_id)
}

pub(crate) async fn wait_present(app: &App, challenge: &str) -> anyhow::Result<()> {
    loop {
        let state: String = sqlx::query_scalar("SELECT state FROM challenges WHERE id=?")
            .bind(challenge)
            .fetch_one(&app.db)
            .await?;
        match state.as_str() {
            "active" => return Ok(()),
            "present_pending" => tokio::time::sleep(Duration::from_secs(1)).await,
            _ => anyhow::bail!("DNS presentation failed or was cancelled"),
        }
    }
}

pub(crate) async fn cleanup(app: &App, id: &str) -> anyhow::Result<()> {
    let _guard = app.mutation.lock().await;
    sqlx::query("UPDATE challenges SET state='cleanup_pending',operation='cleanup',attempts=0,next_attempt=?,updated_at=? WHERE client_id=? AND state NOT IN ('cleaned','cleanup_pending') AND NOT (state='failed' AND operation='cleanup')")
        .bind(now()).bind(now()).bind(id).execute(&app.db).await?;
    app.wake.notify_one();
    Ok(())
}

pub(crate) async fn wait_dns(
    resolver: &hickory_resolver::TokioResolver,
    fqdn: &str,
    value: &str,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(records)) = tokio::time::timeout(
            Duration::from_secs(15),
            resolver.txt_lookup(format!("{fqdn}.")),
        )
        .await
            && records
                .iter()
                .any(|txt| txt.txt_data().concat() == value.as_bytes())
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    anyhow::bail!("DNS propagation timed out")
}

async fn discard_order(app: &App, id: &str) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE certificates SET order_url=NULL,pending_key=NULL,pending_csr=NULL WHERE id=?",
    )
    .bind(id)
    .execute(&app.db)
    .await?;
    Ok(())
}

async fn issue(
    app: &App,
    id: &str,
    account: Account,
    resolver: &hickory_resolver::TokioResolver,
) -> anyhow::Result<()> {
    let row = sqlx::query(
        "SELECT domains,order_url,pending_key,pending_csr FROM certificates WHERE id=?",
    )
    .bind(id)
    .fetch_one(&app.db)
    .await?;
    let domains: Vec<String> = serde_json::from_str(row.get("domains"))?;
    phase(app, id, "Creating ACME order").await?;
    let mut order = if let Some(url) = row.get::<Option<String>, _>("order_url") {
        match account.order(url).await {
            Ok(order) => order,
            Err(error) => {
                if matches!(&error, instant_acme::Error::Api(problem) if problem.status == Some(404))
                {
                    discard_order(app, id).await?;
                }
                return Err(error.into());
            }
        }
    } else {
        let identifiers = domains
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect::<Vec<_>>();
        let order = account.new_order(&NewOrder::new(&identifiers)).await?;
        let key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(domains.clone())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&key)?.der().to_vec();
        // Persist key and CSR before finalization. Resuming an issued order must use the same key.
        sqlx::query("UPDATE certificates SET order_url=?,pending_key=?,pending_csr=?,updated_at=? WHERE id=?")
            .bind(order.url()).bind(app.vault.seal(&format!("certificate:{id}"), key.serialize_pem().as_bytes())?)
            .bind(csr).bind(now()).bind(id).execute(&app.db).await?;
        order
    };
    if order.state().status == OrderStatus::Invalid {
        discard_order(app, id).await?;
        anyhow::bail!("ACME order is invalid; next attempt will create a new order");
    }
    if order.state().status == OrderStatus::Pending {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            if authz.status != AuthorizationStatus::Pending {
                discard_order(app, id).await?;
                anyhow::bail!("ACME authorization is no longer pending");
            }
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| anyhow::anyhow!("CA did not offer DNS-01"))?;
            let identifier = challenge.identifier().to_string();
            let domain = identifier.strip_prefix("*.").unwrap_or(&identifier);
            // Never act on an unexpected CA identifier, even if a provider covers it.
            anyhow::ensure!(
                domains
                    .iter()
                    .any(|d| d.strip_prefix("*.").unwrap_or(d) == domain),
                "unexpected ACME identifier"
            );
            let fqdn = format!("_acme-challenge.{domain}");
            let value = challenge.key_authorization().dns_value();
            phase(app, id, "Publishing DNS validation").await?;
            let challenge_id = present(app, id, &fqdn, &value).await?;
            wait_present(app, &challenge_id).await?;
            phase(app, id, "Waiting for DNS propagation").await?;
            wait_dns(resolver, &fqdn, &value).await?;
            phase(app, id, "Validating domain with Let's Encrypt").await?;
            challenge.set_ready().await?;
        }
        let status = order.poll_ready(&RetryPolicy::default()).await;
        // The library can return an API error with an invalid order, not only a status.
        if order.state().status == OrderStatus::Invalid {
            discard_order(app, id).await?;
            anyhow::bail!("ACME validation failed");
        }
        anyhow::ensure!(status? == OrderStatus::Ready, "order is not ready");
    }
    phase(app, id, "Issuing certificate").await?;
    if order.state().status == OrderStatus::Ready {
        let csr: Vec<u8> = sqlx::query_scalar("SELECT pending_csr FROM certificates WHERE id=?")
            .bind(id)
            .fetch_one(&app.db)
            .await?;
        order.finalize_csr(&csr).await?;
    }
    let fullchain = order.poll_certificate(&RetryPolicy::default()).await;
    if order.state().status == OrderStatus::Invalid {
        discard_order(app, id).await?;
        anyhow::bail!("ACME finalization failed");
    }
    save_issued(app, id, &fullchain?).await
}

async fn save_issued(app: &App, id: &str, fullchain: &str) -> anyhow::Result<()> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(fullchain.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid certificate PEM"))?;
    let cert = pem
        .parse_x509()
        .map_err(|_| anyhow::anyhow!("invalid X.509 certificate"))?;
    let row = sqlx::query("SELECT domains,pending_key FROM certificates WHERE id=?")
        .bind(id)
        .fetch_one(&app.db)
        .await?;
    let domains: Vec<String> = serde_json::from_str(row.get("domains"))?;
    let sealed: Vec<u8> = row.try_get("pending_key")?;
    let key = app.vault.open(&format!("certificate:{id}"), &sealed)?;
    let key = rcgen::KeyPair::from_pem(std::str::from_utf8(&key)?)?;
    anyhow::ensure!(
        cert.public_key().subject_public_key.data.as_ref() == key.public_key_raw(),
        "certificate does not match pending key"
    );
    let san = cert
        .subject_alternative_name()?
        .ok_or_else(|| anyhow::anyhow!("missing certificate domains"))?;
    let mut names = san
        .value
        .general_names
        .iter()
        .map(|name| match name {
            x509_parser::extensions::GeneralName::DNSName(name) => Ok(name.to_ascii_lowercase()),
            _ => Err(anyhow::anyhow!("unexpected certificate identifier")),
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    names.sort();
    names.dedup();
    anyhow::ensure!(names == domains, "certificate domains do not match request");
    let expires = cert.validity().not_after.timestamp();
    let starts = cert.validity().not_before.timestamp();
    anyhow::ensure!(
        expires > now() && expires > starts,
        "CA returned an expired certificate"
    );
    // Renew two thirds through the actual validity period, including short-lived certificates.
    let renew_at =
        (starts + (expires - starts) * 2 / 3).max(now() + ((expires - now()) / 3).clamp(1, 3600));
    let mut tx = app.db.begin().await?;
    sqlx::query("UPDATE certificates SET fullchain=?,private_key=pending_key,expires_at=?,renew_at=?,state='issued',phase='Issued',attempts=0,next_attempt=?,last_error=NULL,order_url=NULL,pending_key=NULL,pending_csr=NULL,updated_at=? WHERE id=? AND pending_key IS NOT NULL")
        .bind(fullchain).bind(expires).bind(renew_at).bind(renew_at).bind(now()).bind(id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit(at,actor,action,target,outcome) VALUES(?,'certificate-worker','certificate.issued',?,'success')")
        .bind(now()).bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

/// Only one certificate worker runs per locked configuration directory.
/// On restart, issuing jobs resume their persisted order and pending private key.
pub async fn process_one(app: &App) -> anyhow::Result<bool> {
    process_one_with(app, |id, staging| async move {
        let account = account(app, staging).await?;
        let mut builder = hickory_resolver::TokioResolver::builder_tokio()?;
        // Do not cache negative responses while a challenge propagates.
        builder.options_mut().cache_size = 0;
        issue(app, &id, account, &builder.build()).await
    })
    .await
}

async fn process_one_with<F, Fut>(app: &App, issue_job: F) -> anyhow::Result<bool>
where
    F: FnOnce(String, bool) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let (id, staging) = {
        let _guard = app.mutation.lock().await;
        anyhow::ensure!(
            app.healthy.load(std::sync::atomic::Ordering::SeqCst),
            "configuration needs restart"
        );
        let row = sqlx::query("SELECT id,staging FROM certificates WHERE (state IN ('queued','issuing') AND next_attempt<=?) OR (auto_renew=1 AND state IN ('issued','failed') AND fullchain IS NOT NULL AND next_attempt<=?) ORDER BY next_attempt,created_at LIMIT 1")
            .bind(now()).bind(now()).fetch_optional(&app.db).await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let id: String = row.get("id");
        sqlx::query("UPDATE certificates SET state='issuing',phase='Connecting to Let’s Encrypt',last_error=NULL,attempts=attempts+1,next_attempt=?+60,updated_at=? WHERE id=?")
            .bind(now()).bind(now()).bind(&id).execute(&app.db).await?;
        (id, row.get::<bool, _>("staging"))
    };
    let result = tokio::time::timeout(
        Duration::from_secs(JOB_TIMEOUT),
        issue_job(id.clone(), staging),
    )
    .await;
    // Cleanup is durable even after cancellation, timeout, CA failure or partial DNS success.
    cleanup(app, &id).await?;
    if !matches!(result, Ok(Ok(()))) {
        let row = sqlx::query("SELECT attempts,phase,auto_renew,fullchain IS NOT NULL AS renewing FROM certificates WHERE id=?")
            .bind(&id)
            .fetch_one(&app.db)
            .await?;
        let attempts: i64 = row.get("attempts");
        let phase: String = row.get("phase");
        let message = format!(
            "{} during {}. Check DNS provider access and outbound connectivity; DNS propagation may take several minutes.",
            if result.is_err() {
                "Timed out"
            } else {
                "Attempt failed"
            },
            phase.to_lowercase()
        );
        let state = if attempts >= 5
            || (row.get::<bool, _>("renewing") && !row.get::<bool, _>("auto_renew"))
        {
            "failed"
        } else {
            "queued"
        };
        let delay = if attempts >= 5 {
            86400
        } else {
            60 * 5_i64.pow(attempts.min(4) as u32 - 1)
        };
        sqlx::query("UPDATE certificates SET state=?,last_error=?,next_attempt=?,updated_at=? WHERE id=? AND state='issuing'")
            .bind(state).bind(message).bind(now()+delay).bind(now()).bind(&id).execute(&app.db).await?;
        store::audit(
            &app.db,
            "certificate-worker",
            "certificate.attempt_failed",
            &id,
            state,
        )
        .await?;
    }
    Ok(true)
}

pub async fn run_worker(app: App) {
    loop {
        let managed = process_one(&app).await;
        let downstream = crate::acme::process_one(&app).await;
        if matches!(managed, Ok(true)) || matches!(downstream, Ok(true)) {
            continue;
        }
        if downstream.is_err() {
            tracing::error!("ACME endpoint worker failed; retrying");
        }
        match managed {
            Ok(true) => continue,
            Ok(false) => {}
            Err(_) => {
                tracing::error!("certificate worker storage or vault operation failed; retrying")
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
#[path = "certificates_tests.rs"]
pub(crate) mod tests;
