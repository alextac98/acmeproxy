use crate::{App, config, now, security};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use std::{collections::BTreeMap, sync::atomic::Ordering, time::Duration};

#[derive(Debug)]
pub struct Error(StatusCode, &'static str);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database operation failed",
        )
    }
}
impl From<anyhow::Error> for Error {
    fn from(_: anyhow::Error) -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "operation could not be completed",
        )
    }
}
type Result<T> = std::result::Result<T, Error>;
fn bad(message: &'static str) -> Error {
    Error(StatusCode::BAD_REQUEST, message)
}
fn conflict(message: &'static str) -> Error {
    Error(StatusCode::CONFLICT, message)
}
fn unauthorized() -> Error {
    Error(StatusCode::UNAUTHORIZED, "invalid or revoked credentials")
}

pub fn router(app: App) -> Router {
    let admin = Router::new()
        .route("/overview", get(overview))
        .route("/providers", post(create_provider))
        .route(
            "/providers/{id}",
            put(update_provider).delete(remove_provider),
        )
        .route("/clients", post(create_client))
        .route("/clients/{id}", delete(revoke_client))
        .route("/challenges/{id}/retry", post(retry_challenge))
        .route("/challenges/{id}/cleanup", post(admin_cleanup))
        .route_layer(middleware::from_fn_with_state(app.clone(), admin_auth));
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../web/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../web/style.css"),
                )
            }),
        )
        .route("/healthz", get(health))
        .route("/present", post(present))
        .route("/cleanup", post(cleanup))
        .nest("/api/admin", admin)
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(tower::limit::ConcurrencyLimitLayer::new(64))
        .layer(middleware::from_fn_with_state(
            app.clone(),
            security_headers,
        ))
        .with_state(app)
}

async fn security_headers(State(app): State<App>, request: Request, next: Next) -> Response {
    if !app.healthy.load(Ordering::SeqCst) {
        return Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "restart required to reconcile configuration",
        )
        .into_response();
    }
    let mut response = next.run(request).await;
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    ] {
        response.headers_mut().insert(
            header::HeaderName::from_static(name),
            header::HeaderValue::from_static(value),
        );
    }
    response
}

fn authorization(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()
}
async fn admin_auth(State(app): State<App>, request: Request, next: Next) -> Result<Response> {
    let token = authorization(request.headers())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)?;
    if !security::matches(token, &app.admin_hash) {
        return Err(unauthorized());
    }
    Ok(next.run(request).await)
}

async fn client_auth(app: &App, headers: &HeaderMap) -> Result<(String, Vec<String>)> {
    let header = authorization(headers).ok_or_else(unauthorized)?;
    let (username, token) = if let Some(encoded) = header.strip_prefix("Basic ") {
        let bytes = STANDARD.decode(encoded).map_err(|_| unauthorized())?;
        let decoded = String::from_utf8(bytes).map_err(|_| unauthorized())?;
        let (name, token) = decoded.split_once(':').ok_or_else(unauthorized)?;
        (Some(name.to_string()), token.to_string())
    } else {
        (
            None,
            header
                .strip_prefix("Bearer ")
                .ok_or_else(unauthorized)?
                .to_string(),
        )
    };
    if token.len() > 256 {
        return Err(unauthorized());
    }
    let row = sqlx::query("SELECT id, scopes FROM clients WHERE token_hash=? AND revoked=0")
        .bind(security::hash(&token))
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(unauthorized)?;
    let id: String = row.get("id");
    if username.is_some_and(|u| u != id) {
        return Err(unauthorized());
    }
    let scopes =
        serde_json::from_str(row.get("scopes")).map_err(|_| bad("invalid stored scopes"))?;
    Ok((id, scopes))
}

async fn health(State(app): State<App>) -> Result<Json<Value>> {
    sqlx::query("SELECT 1").execute(&app.db).await?;
    Ok(Json(
        json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}),
    ))
}

async fn overview(State(app): State<App>) -> Result<Json<Value>> {
    let providers: Vec<Value> = sqlx::query("SELECT id,name,driver,zone,created_at FROM providers ORDER BY name").fetch_all(&app.db).await?
        .iter().map(|r| json!({"id":r.get::<String,_>("id"),"name":r.get::<String,_>("name"),"driver":r.get::<String,_>("driver"),"zone":r.get::<String,_>("zone")})).collect();
    let clients: Vec<Value> = sqlx::query("SELECT id,name,scopes,revoked FROM clients ORDER BY created_at DESC").fetch_all(&app.db).await?
        .iter().map(|r| json!({"id":r.get::<String,_>("id"),"name":r.get::<String,_>("name"),"scopes":serde_json::from_str::<Value>(r.get("scopes")).unwrap_or(json!([])),"revoked":r.get::<bool,_>("revoked")})).collect();
    let challenges: Vec<Value> = sqlx::query("SELECT c.id,c.fqdn,c.state,c.operation,c.attempts,c.expires_at,c.updated_at,c.last_error,cl.name AS client_name FROM challenges c JOIN clients cl ON cl.id=c.client_id ORDER BY c.updated_at DESC LIMIT 100").fetch_all(&app.db).await?
        .iter().map(|r| json!({"id":r.get::<String,_>("id"),"fqdn":r.get::<String,_>("fqdn"),"state":r.get::<String,_>("state"),"operation":r.get::<String,_>("operation"),"attempts":r.get::<i64,_>("attempts"),"expires_at":r.get::<i64,_>("expires_at"),"updated_at":r.get::<i64,_>("updated_at"),"last_error":r.get::<Option<String>,_>("last_error"),"client_name":r.get::<String,_>("client_name")})).collect();
    let audit: Vec<Value> = sqlx::query("SELECT * FROM audit ORDER BY id DESC LIMIT 50").fetch_all(&app.db).await?
        .iter().map(|r| json!({"at":r.get::<i64,_>("at"),"actor":r.get::<String,_>("actor"),"action":r.get::<String,_>("action"),"target":r.get::<String,_>("target"),"outcome":r.get::<String,_>("outcome")})).collect();
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM challenges WHERE state NOT IN ('cleaned','failed')",
    )
    .fetch_one(&app.db)
    .await?;
    let failed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM challenges WHERE state='failed'")
        .fetch_one(&app.db)
        .await?;
    Ok(Json(
        json!({"providers":providers,"clients":clients,"challenges":challenges,"audit":audit,"drivers":*app.drivers,"active":active,"failed":failed}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderInput {
    name: String,
    driver: String,
    zone: String,
    #[serde(default)]
    credentials: BTreeMap<String, String>,
}
async fn create_provider(
    State(app): State<App>,
    Json(input): Json<ProviderInput>,
) -> Result<Json<Value>> {
    save_provider(app, None, input).await
}
async fn update_provider(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<ProviderInput>,
) -> Result<Json<Value>> {
    save_provider(app, Some(id), input).await
}
async fn save_provider(app: App, id: Option<String>, input: ProviderInput) -> Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    let mut next = app.config.lock().await.value.clone();
    let id = id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let existing = next.providers.iter().position(|p| p.id == id);
    let mut provider = config::Provider {
        id: id.clone(),
        name: input.name,
        driver: input.driver,
        zone: input.zone,
        credentials: input.credentials,
        encrypted_credentials: String::new(),
    };
    if provider.credentials.is_empty() {
        provider.encrypted_credentials = existing
            .map(|i| next.providers[i].encrypted_credentials.clone())
            .ok_or(bad("enter provider credentials"))?;
    }
    if let Some(i) = existing {
        next.providers[i] = provider;
    } else {
        next.providers.push(provider);
    }
    config::apply(&app, next, "provider.saved", &id).await.map_err(|_| conflict("could not save provider: check fields and unique zone; restart after file edits; clean up challenges before changing the zone or driver"))?;
    Ok(Json(json!({"id":id})))
}
async fn remove_provider(State(app): State<App>, Path(id): Path<String>) -> Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    let mut next = app.config.lock().await.value.clone();
    next.providers.retain(|p| p.id != id);
    config::apply(&app, next, "provider.removed", &id)
        .await
        .map_err(|_| conflict("clean up outstanding challenges before removing this provider"))?;
    Ok(Json(json!({"status":"removed"})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientInput {
    name: String,
    scopes: Vec<String>,
}
async fn create_client(
    State(app): State<App>,
    Json(input): Json<ClientInput>,
) -> Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    let mut next = app.config.lock().await.value.clone();
    let id = uuid::Uuid::new_v4().to_string();
    let token = security::random_secret();
    next.clients.push(config::Client {
        id: id.clone(),
        name: input.name,
        scopes: input.scopes,
        revoked: false,
        token_hash: URL_SAFE_NO_PAD.encode(security::hash(&token)),
        token: None,
    });
    config::apply(&app, next, "client.created", &id)
        .await
        .map_err(|_| bad("enter a client name and valid domain scopes"))?;
    Ok(Json(json!({"id":id,"token":token})))
}
async fn revoke_client(State(app): State<App>, Path(id): Path<String>) -> Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    let mut next = app.config.lock().await.value.clone();
    let client = next
        .clients
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or(Error(StatusCode::NOT_FOUND, "client not found"))?;
    client.revoked = true;
    config::apply(&app, next, "client.revoked", &id).await?;
    Ok(Json(json!({"status":"revoked"})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeInput {
    fqdn: String,
    value: String,
}
async fn present(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<ChallengeInput>,
) -> Result<Json<Value>> {
    challenge_request(app, headers, input, false).await
}
async fn cleanup(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<ChallengeInput>,
) -> Result<Json<Value>> {
    challenge_request(app, headers, input, true).await
}

async fn challenge_request(
    app: App,
    headers: HeaderMap,
    input: ChallengeInput,
    cleanup: bool,
) -> Result<Json<Value>> {
    let (fqdn, name) = security::challenge(&input.fqdn, &input.value).map_err(bad)?;
    let id;
    {
        let _guard = app.mutation.lock().await;
        let (client, scopes) = client_auth(&app, &headers).await?;
        if !security::allowed(&name, &scopes) {
            crate::store::audit(&app.db, &client, "challenge.denied", &fqdn, "forbidden").await?;
            return Err(Error(
                StatusCode::FORBIDDEN,
                "this client cannot validate that domain",
            ));
        }
        // Longest label-bounded suffix wins; callers never choose a provider or arbitrary record type.
        let providers =
            sqlx::query("SELECT id,zone,credentials FROM providers ORDER BY length(zone) DESC")
                .fetch_all(&app.db)
                .await?;
        let provider = providers
            .iter()
            .find(|r| security::within(&name, r.get("zone")))
            .ok_or(bad("no DNS provider is configured for this domain"))?;
        let provider_id: &str = provider.get("id");
        let existing = sqlx::query("SELECT * FROM challenges WHERE fqdn=? AND value=?")
            .bind(&fqdn)
            .bind(&input.value)
            .fetch_optional(&app.db)
            .await?;
        if let Some(row) = existing {
            if row.get::<String, _>("client_id") != client {
                return Err(conflict("challenge value belongs to another client"));
            }
            id = row.get::<String, _>("id");
            let state: &str = row.get("state");
            if (cleanup && state == "cleaned") || (!cleanup && state == "active") {
                return Ok(Json(json!({"fqdn":input.fqdn,"value":input.value,"id":id})));
            }
            if cleanup && state != "cleanup_pending" {
                sqlx::query("UPDATE challenges SET state='cleanup_pending',operation='cleanup',attempts=0,next_attempt=?,updated_at=? WHERE id=?")
                    .bind(now()).bind(now()).bind(&id).execute(&app.db).await?;
            } else if !cleanup && state != "present_pending" {
                return Err(conflict(
                    "challenge is no longer presentable; use a new ACME challenge or retry from the admin UI",
                ));
            }
        } else if cleanup {
            // Never delete a record this proxy has no ownership record for.
            return Ok(Json(json!({"fqdn":input.fqdn,"value":input.value})));
        } else {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM challenges WHERE client_id=? AND state!='cleaned'",
            )
            .bind(&client)
            .fetch_one(&app.db)
            .await?;
            let global: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM challenges WHERE state!='cleaned'")
                    .fetch_one(&app.db)
                    .await?;
            if count >= 100 || global >= 1000 {
                return Err(Error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "outstanding challenge limit reached",
                ));
            }
            id = uuid::Uuid::new_v4().to_string();
            let ttl = app.config.lock().await.value.server.challenge_ttl_seconds;
            sqlx::query("INSERT INTO challenges(id,client_id,provider_id,credentials_snapshot,fqdn,value,state,operation,next_attempt,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,'present_pending','present',?,?,?,?)")
                .bind(&id).bind(&client).bind(provider_id).bind(provider.get::<Vec<u8>,_>("credentials")).bind(&fqdn).bind(&input.value).bind(now()).bind(now()+ttl).bind(now()).bind(now()).execute(&app.db).await?;
        }
    }
    app.wake.notify_one();
    // Never report DNS success until the adapter has succeeded. Queued work survives HTTP disconnects.
    let deadline = tokio::time::Instant::now() + app.worker.timeout + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let state: String = sqlx::query_scalar("SELECT state FROM challenges WHERE id=?")
            .bind(&id)
            .fetch_one(&app.db)
            .await?;
        if state == if cleanup { "cleaned" } else { "active" } {
            return Ok(Json(json!({"fqdn":input.fqdn,"value":input.value,"id":id})));
        }
        if state == "failed" {
            return Err(Error(
                StatusCode::BAD_GATEWAY,
                "DNS operation failed; inspect the challenge in the admin UI",
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(Error(
        StatusCode::SERVICE_UNAVAILABLE,
        "DNS operation is still pending; retry the same request",
    ))
}

async fn retry_challenge(State(app): State<App>, Path(id): Path<String>) -> Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    let result = sqlx::query("UPDATE challenges SET state=CASE operation WHEN 'present' THEN 'present_pending' ELSE 'cleanup_pending' END,credentials_snapshot=(SELECT credentials FROM providers WHERE providers.id=challenges.provider_id),attempts=0,next_attempt=?,updated_at=? WHERE id=? AND state='failed'")
        .bind(now()).bind(now()).bind(&id).execute(&app.db).await?;
    if result.rows_affected() == 0 {
        return Err(conflict("only failed challenges can be retried"));
    }
    crate::store::audit(&app.db, "admin", "challenge.retried", &id, "queued").await?;
    app.wake.notify_one();
    Ok(Json(json!({"status":"queued"})))
}
async fn admin_cleanup(State(app): State<App>, Path(id): Path<String>) -> Result<Json<Value>> {
    let _guard = app.mutation.lock().await;
    let result = sqlx::query("UPDATE challenges SET state='cleanup_pending',operation='cleanup',attempts=0,next_attempt=?,updated_at=? WHERE id=? AND state!='cleaned'")
        .bind(now()).bind(now()).bind(&id).execute(&app.db).await?;
    if result.rows_affected() == 0 {
        return Err(conflict("challenge is already cleaned or does not exist"));
    }
    crate::store::audit(&app.db, "admin", "challenge.cleanup", &id, "queued").await?;
    app.wake.notify_one();
    Ok(Json(json!({"status":"queued"})))
}
