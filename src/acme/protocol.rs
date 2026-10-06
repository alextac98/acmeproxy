use super::{Mode, Settings, check_domains};
use crate::{App, now, security, store};
use axum::{
    body::to_bytes,
    extract::{ConnectInfo, OriginalUri, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ring::signature;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Row, sqlite::SqliteRow};
use std::{net::SocketAddr, time::Duration};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    prelude::{FromDer, X509CertificationRequest},
};

type Result<T> = std::result::Result<T, Problem>;
struct Problem {
    status: StatusCode,
    kind: &'static str,
    detail: &'static str,
}
fn problem(status: StatusCode, kind: &'static str, detail: &'static str) -> Problem {
    Problem {
        status,
        kind,
        detail,
    }
}
fn malformed(detail: &'static str) -> Problem {
    problem(StatusCode::BAD_REQUEST, "malformed", detail)
}
fn denied(detail: &'static str) -> Problem {
    problem(StatusCode::FORBIDDEN, "unauthorized", detail)
}
fn missing() -> Problem {
    problem(StatusCode::NOT_FOUND, "malformed", "resource not found")
}
impl From<sqlx::Error> for Problem {
    fn from(_: sqlx::Error) -> Self {
        problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serverInternal",
            "storage operation failed",
        )
    }
}
impl From<anyhow::Error> for Problem {
    fn from(_: anyhow::Error) -> Self {
        problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serverInternal",
            "operation failed",
        )
    }
}
impl Problem {
    fn response(self) -> Response {
        (self.status, [(header::CONTENT_TYPE,"application/problem+json")], json!({"type":format!("urn:ietf:params:acme:error:{}",self.kind),"detail":self.detail,"status":self.status.as_u16()}).to_string()).into_response()
    }
}
fn json_response(status: StatusCode, value: Value, location: Option<String>) -> Response {
    let mut response = (status, axum::Json(value)).into_response();
    if let Some(location) = location {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&location).expect("validated URL"),
        );
    }
    response
}
fn decode(text: &str) -> Result<Vec<u8>> {
    B64.decode(text)
        .map_err(|_| malformed("invalid unpadded base64url"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Jose {
    protected: String,
    payload: String,
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Protected {
    alg: String,
    url: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    jwk: Option<Value>,
    #[serde(default)]
    kid: Option<String>,
}
struct Verified {
    account: Option<String>,
    jwk: Value,
    payload: Vec<u8>,
}

/// Return only public, canonical JWK members. Never persist supplied private fields.
fn canonical_jwk(jwk: &Value) -> Result<Value> {
    let get = |key: &str| {
        jwk.get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("invalid public JWK"))
    };
    let object = jwk
        .as_object()
        .ok_or_else(|| malformed("invalid public JWK"))?;
    match get("kty")? {
        "EC" => {
            if object.keys().any(|k| {
                !["kty", "crv", "x", "y", "alg", "use", "kid", "key_ops"].contains(&k.as_str())
            }) || get("crv")? != "P-256"
                || decode(get("x")?)?.len() != 32
                || decode(get("y")?)?.len() != 32
            {
                return Err(problem(
                    StatusCode::BAD_REQUEST,
                    "badPublicKey",
                    "use a public P-256 or RSA account key",
                ));
            }
            Ok(json!({"crv":"P-256","kty":"EC","x":get("x")?,"y":get("y")?}))
        }
        "RSA" => {
            let n = decode(get("n")?)?;
            let e = decode(get("e")?)?;
            if object
                .keys()
                .any(|k| !["kty", "n", "e", "alg", "use", "kid", "key_ops"].contains(&k.as_str()))
                || !(256..=1024).contains(&n.len())
                || n[0] == 0
                || e.is_empty()
                || e.len() > 4
                || e[0] == 0
            {
                return Err(problem(
                    StatusCode::BAD_REQUEST,
                    "badPublicKey",
                    "use a public RSA key of at least 2048 bits",
                ));
            }
            Ok(json!({"e":get("e")?,"kty":"RSA","n":get("n")?}))
        }
        _ => Err(problem(
            StatusCode::BAD_REQUEST,
            "badPublicKey",
            "unsupported account key type",
        )),
    }
}
fn thumbprint(jwk: &Value) -> String {
    B64.encode(security::hash(&jwk.to_string()))
}
fn verify(jose: &Jose, protected: &Protected, jwk: &Value) -> Result<()> {
    let message = format!("{}.{}", jose.protected, jose.payload);
    let sig = decode(&jose.signature)?;
    let valid = match (protected.alg.as_str(), jwk["kty"].as_str()) {
        ("ES256", Some("EC")) => {
            let mut key = vec![4];
            key.extend(decode(jwk["x"].as_str().unwrap())?);
            key.extend(decode(jwk["y"].as_str().unwrap())?);
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key)
                .verify(message.as_bytes(), &sig)
                .is_ok()
        }
        ("RS256", Some("RSA")) => signature::RsaPublicKeyComponents {
            n: decode(jwk["n"].as_str().unwrap())?,
            e: decode(jwk["e"].as_str().unwrap())?,
        }
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            message.as_bytes(),
            &sig,
        )
        .is_ok(),
        _ => {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "badSignatureAlgorithm",
                "supported account signatures are ES256 and RS256",
            ));
        }
    };
    if !valid {
        return Err(malformed("invalid JWS signature"));
    }
    Ok(())
}
async fn authenticate(app: &App, settings: &Settings, path: &str, body: &[u8]) -> Result<Verified> {
    let jose: Jose =
        serde_json::from_slice(body).map_err(|_| malformed("expected flattened JWS"))?;
    let protected: Protected = serde_json::from_slice(&decode(&jose.protected)?)
        .map_err(|_| malformed("invalid protected JWS header"))?;
    if protected.url != format!("{}{path}", settings.base_url) {
        return Err(malformed("JWS URL does not match the configured ACME URL"));
    }
    let (account, jwk) = match (&protected.jwk, &protected.kid) {
        (Some(jwk), None) if path.ends_with("/new-account") || path.ends_with("/revoke-cert") => {
            (None, canonical_jwk(jwk)?)
        }
        (None, Some(kid)) if !path.ends_with("/new-account") => {
            let prefix = settings.url("account/");
            let id = kid
                .strip_prefix(&prefix)
                .filter(|id| uuid::Uuid::parse_str(id).is_ok())
                .ok_or_else(|| malformed("invalid account URL"))?;
            let row = sqlx::query("SELECT jwk,status FROM downstream_accounts WHERE id=?")
                .bind(id)
                .fetch_optional(&app.db)
                .await?
                .ok_or_else(|| {
                    problem(
                        StatusCode::BAD_REQUEST,
                        "accountDoesNotExist",
                        "account does not exist",
                    )
                })?;
            if row.get::<String, _>("status") != "valid" {
                return Err(denied("account is deactivated"));
            }
            (
                Some(id.to_owned()),
                serde_json::from_str(row.get("jwk"))
                    .map_err(|_| malformed("invalid stored account key"))?,
            )
        }
        _ => return Err(malformed("use exactly one of jwk or kid")),
    };
    verify(&jose, &protected, &jwk)?;
    let nonce = protected
        .nonce
        .ok_or_else(|| problem(StatusCode::BAD_REQUEST, "badNonce", "missing replay nonce"))?;
    let used = sqlx::query("DELETE FROM acme_nonces WHERE hash=? AND expires_at>?")
        .bind(security::hash(&nonce))
        .bind(now())
        .execute(&app.db)
        .await?;
    if used.rows_affected() != 1 {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "badNonce",
            "replay nonce is expired or already used",
        ));
    }
    Ok(Verified {
        account,
        jwk,
        payload: decode(&jose.payload)?,
    })
}
async fn new_nonce(app: &App) -> Result<String> {
    let value = security::random_secret();
    let mut tx = app.db.begin().await?;
    sqlx::query("DELETE FROM acme_nonces WHERE expires_at<=?")
        .bind(now())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM acme_nonces WHERE hash IN (SELECT hash FROM acme_nonces ORDER BY expires_at DESC LIMIT -1 OFFSET 9999)").execute(&mut *tx).await?;
    sqlx::query("INSERT INTO acme_nonces(hash,expires_at) VALUES(?,?)")
        .bind(security::hash(&value))
        .bind(now() + 300)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(value)
}

pub(super) async fn handle(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let settings = app.config.lock().await.value.acme.clone();
    if settings.mode == Mode::Disabled {
        return missing().response();
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|v| v.0.ip());
    if !peer.is_some_and(|ip| settings.accepts_ip(ip)) {
        return denied("client address is outside the configured ACME networks").response();
    }
    let method = request.method().clone();
    let path = uri.path();
    let result = async {
        if uri.query().is_some() { return Err(malformed("ACME request URLs must not contain a query")); }
        if path == "/acme/directory" && method == Method::GET {
            return Ok(json_response(StatusCode::OK, json!({"newNonce":settings.url("new-nonce"),"newAccount":settings.url("new-account"),"newOrder":settings.url("new-order"),"revokeCert":settings.url("revoke-cert"),"keyChange":settings.url("key-change"),"meta":{"termsOfService":"https://letsencrypt.org/repository/","externalAccountRequired":false}}), None));
        }
        if path == "/acme/new-nonce" && (method == Method::GET || method == Method::HEAD) {
            return Ok(if method == Method::HEAD { StatusCode::OK } else { StatusCode::NO_CONTENT }.into_response());
        }
        if request.headers().get(header::CONTENT_TYPE).and_then(|v|v.to_str().ok()).and_then(|v|v.split(';').next()) != Some("application/jose+json") {
            return Err(problem(StatusCode::UNSUPPORTED_MEDIA_TYPE,"malformed","Content-Type must be application/jose+json"));
        }
        let body = to_bytes(request.into_body(), 32*1024).await.map_err(|_|malformed("request too large"))?;
        let signed = authenticate(&app, &settings, path, &body).await?;
        dispatch(&app, &settings, path, signed).await
    }.await;
    let mut response = result.unwrap_or_else(Problem::response);
    match new_nonce(&app).await {
        Ok(nonce) => {
            response
                .headers_mut()
                .insert("replay-nonce", HeaderValue::from_str(&nonce).unwrap());
        }
        Err(error) => return error.response(),
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::LINK,
        HeaderValue::from_str(&format!("<{}>;rel=\"index\"", settings.url("directory"))).unwrap(),
    );
    response
}

fn payload(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice(bytes).map_err(|_| malformed("invalid request payload"))
}
fn post_as_get(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(malformed("POST-as-GET requires an empty payload"))
    }
}
fn contacts(value: Option<&Value>) -> Result<String> {
    let empty = json!([]);
    let value = value.unwrap_or(&empty);
    let list = value
        .as_array()
        .ok_or_else(|| malformed("contact must be an array"))?;
    if list.len() > 10
        || list.iter().any(|v| {
            v.as_str().is_none_or(|s| {
                s.len() > 254
                    || !s.starts_with("mailto:")
                    || !s.contains('@')
                    || s.contains(['\n', '\r'])
            })
        })
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "invalidContact",
            "contacts must be mailto addresses",
        ));
    }
    Ok(value.to_string())
}
async fn account_response(
    app: &App,
    settings: &Settings,
    id: &str,
    status: StatusCode,
) -> Result<Response> {
    let row = sqlx::query("SELECT contact,status FROM downstream_accounts WHERE id=?")
        .bind(id)
        .fetch_one(&app.db)
        .await?;
    Ok(json_response(
        status,
        json!({"status":row.get::<String,_>("status"),"contact":serde_json::from_str::<Value>(row.get("contact")).unwrap_or(json!([])),"orders":settings.url(&format!("account/{id}/orders"))}),
        Some(settings.url(&format!("account/{id}"))),
    ))
}
fn timestamp(value: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(value)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
fn order_json(settings: &Settings, row: &SqliteRow) -> Value {
    let id: &str = row.get("id");
    let domains: Vec<String> = serde_json::from_str(row.get("domains")).unwrap_or_default();
    let state: &str = row.get("state");
    let mut value = json!({"status":state,"expires":timestamp(row.get("expires_at")),"identifiers":domains.iter().map(|d|json!({"type":"dns","value":d})).collect::<Vec<_>>(),"authorizations":(0..domains.len()).map(|i|settings.url(&format!("authz/{id}/{i}"))).collect::<Vec<_>>(),"finalize":settings.url(&format!("finalize/{id}"))});
    if state == "valid" {
        value["certificate"] = json!(settings.url(&format!("certificate/{id}")));
    }
    if state == "invalid" {
        value["error"] = json!({"type":"urn:ietf:params:acme:error:unauthorized","detail":row.get::<Option<String>,_>("error").unwrap_or_else(||"order expired or was cancelled".into())});
    }
    value
}
fn order_response(settings: &Settings, row: &SqliteRow, status: StatusCode) -> Response {
    let mut response = json_response(
        status,
        order_json(settings, row),
        Some(settings.url(&format!("order/{}", row.get::<String, _>("id")))),
    );
    if row.get::<String, _>("state") == "processing" {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("3"));
    }
    response
}
async fn owned_order(app: &App, id: &str, account: &str) -> Result<SqliteRow> {
    sqlx::query("UPDATE acme_orders SET state='invalid',error='Order expired',updated_at=? WHERE id=? AND account_id=? AND state IN ('ready','processing') AND expires_at<=?")
        .bind(now()).bind(id).bind(account).bind(now()).execute(&app.db).await?;
    sqlx::query("SELECT * FROM acme_orders WHERE id=? AND account_id=?")
        .bind(id)
        .bind(account)
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(missing)
}

async fn dispatch(
    app: &App,
    settings: &Settings,
    path: &str,
    signed: Verified,
) -> Result<Response> {
    let suffix = path.strip_prefix("/acme/").ok_or_else(missing)?;
    if suffix == "new-account" {
        let input = payload(&signed.payload)?;
        let _guard = app.mutation.lock().await;
        let hash = thumbprint(&signed.jwk);
        let existing = sqlx::query("SELECT id,status FROM downstream_accounts WHERE thumbprint=?")
            .bind(&hash)
            .fetch_optional(&app.db)
            .await?;
        if let Some(row) = existing {
            if row.get::<String, _>("status") != "valid" {
                return Err(denied("account is deactivated"));
            }
            return account_response(app, settings, row.get("id"), StatusCode::OK).await;
        }
        if input["onlyReturnExisting"] == true {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "accountDoesNotExist",
                "account does not exist",
            ));
        }
        if input["termsOfServiceAgreed"] != true {
            return Err(malformed("accept the subscriber agreement"));
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM downstream_accounts")
            .fetch_one(&app.db)
            .await?;
        if count >= 1000 {
            return Err(problem(
                StatusCode::TOO_MANY_REQUESTS,
                "rateLimited",
                "account limit reached",
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO downstream_accounts(id,thumbprint,jwk,contact,created_at) VALUES(?,?,?,?,?)")
            .bind(&id).bind(hash).bind(signed.jwk.to_string()).bind(contacts(input.get("contact"))?).bind(now()).execute(&app.db).await?;
        store::audit(&app.db, &id, "acme.account_registered", &id, "success").await?;
        return account_response(app, settings, &id, StatusCode::CREATED).await;
    }
    if suffix == "revoke-cert" {
        return revoke(app, settings, signed).await;
    }
    let account = signed
        .account
        .as_deref()
        .ok_or_else(|| malformed("account authentication required"))?;
    if suffix == "new-order" {
        return new_order(app, settings, account, &signed.payload).await;
    }
    if suffix == "key-change" {
        return key_change(app, settings, account, &signed).await;
    }
    let parts: Vec<_> = suffix.split('/').collect();
    if parts.len() < 2 {
        return Err(missing());
    }
    let id = parts[1];
    if parts[0] == "account" {
        if id != account {
            return Err(missing());
        }
        if parts.get(2) == Some(&"orders") {
            post_as_get(&signed.payload)?;
            let ids: Vec<String> = sqlx::query_scalar(
                "SELECT id FROM acme_orders WHERE account_id=? ORDER BY created_at DESC",
            )
            .bind(account)
            .fetch_all(&app.db)
            .await?;
            return Ok(json_response(
                StatusCode::OK,
                json!({"orders":ids.iter().map(|id|settings.url(&format!("order/{id}"))).collect::<Vec<_>>()}),
                None,
            ));
        }
        if !signed.payload.is_empty() {
            let input = payload(&signed.payload)?;
            let _guard = app.mutation.lock().await;
            if let Some(status) = input.get("status") {
                if status != "deactivated" {
                    return Err(malformed("only account deactivation is supported"));
                }
                sqlx::query("UPDATE downstream_accounts SET status='deactivated' WHERE id=?")
                    .bind(account)
                    .execute(&app.db)
                    .await?;
            }
            if input.get("contact").is_some() {
                sqlx::query("UPDATE downstream_accounts SET contact=? WHERE id=?")
                    .bind(contacts(input.get("contact"))?)
                    .bind(account)
                    .execute(&app.db)
                    .await?;
            }
        }
        return account_response(app, settings, account, StatusCode::OK).await;
    }
    let row = owned_order(app, id, account).await?;
    match parts[0] {
        "order" => {
            post_as_get(&signed.payload)?;
            Ok(order_response(settings, &row, StatusCode::OK))
        }
        "authz" => {
            post_as_get(&signed.payload)?;
            let domains: Vec<String> = serde_json::from_str(row.get("domains"))
                .map_err(|_| malformed("invalid stored domains"))?;
            let index: usize = parts
                .get(2)
                .and_then(|s| s.parse().ok())
                .ok_or_else(missing)?;
            let domain = domains.get(index).ok_or_else(missing)?;
            let authorized = row.get::<String, _>("state") != "invalid"
                && row.get::<i64, _>("expires_at") > now()
                && settings.accepts_account(account)
                && check_domains(app, settings, &domains).await.is_ok();
            Ok(json_response(
                StatusCode::OK,
                json!({"status":if authorized {"valid"} else {"invalid"},"identifier":{"type":"dns","value":domain.strip_prefix("*.").unwrap_or(domain)},"wildcard":domain.starts_with("*."),"expires":timestamp(row.get("expires_at")),"challenges":[]}),
                None,
            ))
        }
        "finalize" => finalize(app, settings, account, id, &signed.payload).await,
        "certificate" => {
            post_as_get(&signed.payload)?;
            let chain: String = row.get::<Option<String>, _>("fullchain").ok_or_else(|| {
                problem(
                    StatusCode::BAD_REQUEST,
                    "orderNotReady",
                    "certificate not available",
                )
            })?;
            Ok((
                [(header::CONTENT_TYPE, "application/pem-certificate-chain")],
                chain,
            )
                .into_response())
        }
        _ => Err(missing()),
    }
}

#[derive(Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrderInput {
    identifiers: Vec<Identifier>,
    not_before: Option<String>,
    not_after: Option<String>,
}
async fn new_order(
    app: &App,
    _settings: &Settings,
    account: &str,
    bytes: &[u8],
) -> Result<Response> {
    let input: OrderInput =
        serde_json::from_slice(bytes).map_err(|_| malformed("invalid order"))?;
    if input.identifiers.is_empty()
        || input.identifiers.len() > 20
        || input.not_before.is_some()
        || input.not_after.is_some()
    {
        return Err(malformed(
            "request 1–20 DNS identifiers without custom validity dates",
        ));
    }
    let mut domains = Vec::new();
    for identifier in input.identifiers {
        if identifier.kind != "dns" {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "unsupportedIdentifier",
                "only DNS identifiers are supported",
            ));
        }
        let domain = security::scope(&identifier.value).map_err(malformed)?;
        if domain.strip_prefix("*.").unwrap_or(&domain).len() + 15 > 253 {
            return Err(malformed("DNS challenge name is too long"));
        }
        domains.push(domain);
    }
    domains.sort();
    domains.dedup();
    let _guard = app.mutation.lock().await;
    let settings = app.config.lock().await.value.acme.clone();
    if !settings.accepts_account(account) {
        return Err(denied(
            "ACME account requires operator approval in Settings",
        ));
    }
    check_domains(app, &settings, &domains).await.map_err(|_| {
        problem(
            StatusCode::BAD_REQUEST,
            "rejectedIdentifier",
            "domain is outside the configured policy or has no DNS provider",
        )
    })?;
    let recent: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM acme_orders WHERE account_id=? AND created_at>?")
            .bind(account)
            .bind(now() - 3600)
            .fetch_one(&app.db)
            .await?;
    let global_recent: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM acme_orders WHERE created_at>?")
            .bind(now() - 3600)
            .fetch_one(&app.db)
            .await?;
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM acme_orders WHERE state IN ('ready','processing') AND expires_at>?",
    )
    .bind(now())
    .fetch_one(&app.db)
    .await?;
    if recent >= 20 || global_recent >= 100 || pending >= 100 {
        return Err(problem(
            StatusCode::TOO_MANY_REQUESTS,
            "rateLimited",
            "order limit reached; retry later",
        ));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let domains = serde_json::to_string(&domains).unwrap();
    let mut tx = app.db.begin().await?;
    sqlx::query(
        "INSERT INTO clients(id,name,token_hash,scopes,created_at,managed) VALUES(?,?,?,?,?,1)",
    )
    .bind(&id)
    .bind(format!("ACME order {id}"))
    .bind(security::hash(&security::random_secret()))
    .bind(&domains)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO acme_orders(id,account_id,domains,staging,next_attempt,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)").bind(&id).bind(account).bind(domains).bind(settings.staging).bind(now()).bind(now()+86400).bind(now()).bind(now()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit(at,actor,action,target,outcome) VALUES(?,?,'acme.order_created',?,'ready')").bind(now()).bind(account).bind(&id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(order_response(
        &settings,
        &owned_order(app, &id, account).await?,
        StatusCode::CREATED,
    ))
}

/// Verify proof of possession and exact SAN equality before forwarding a client CSR.
pub(super) fn validate_csr(der: &[u8], domains: &[String]) -> anyhow::Result<Vec<u8>> {
    let (remaining, csr) =
        X509CertificationRequest::from_der(der).map_err(|_| anyhow::anyhow!("invalid CSR"))?;
    anyhow::ensure!(remaining.is_empty(), "trailing CSR data");
    csr.certification_request_info
        .attributes_map()
        .map_err(|_| anyhow::anyhow!("duplicate CSR attributes"))?;
    csr.verify_signature()
        .map_err(|_| anyhow::anyhow!("invalid CSR signature"))?;
    let mut names = Vec::new();
    let mut sans = 0;
    let extensions = csr
        .requested_extensions()
        .ok_or_else(|| anyhow::anyhow!("CSR has no SAN extension"))?;
    for extension in extensions {
        if let ParsedExtension::SubjectAlternativeName(san) = extension {
            sans += 1;
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(name) => {
                        names.push(security::scope(name).map_err(anyhow::Error::msg)?)
                    }
                    _ => anyhow::bail!("CSR must only contain DNS identifiers"),
                }
            }
        }
    }
    names.sort();
    names.dedup();
    anyhow::ensure!(
        sans == 1 && names == domains,
        "CSR domains do not match order"
    );
    // If a CN is supplied, it must not introduce another identity.
    for cn in csr.certification_request_info.subject.iter_common_name() {
        let name = security::scope(
            cn.as_str()
                .map_err(|_| anyhow::anyhow!("invalid CSR common name"))?,
        )
        .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(domains.contains(&name), "CSR common name is not in order");
    }
    Ok(csr.certification_request_info.subject_pki.raw.to_vec())
}
async fn finalize(
    app: &App,
    settings: &Settings,
    account: &str,
    id: &str,
    bytes: &[u8],
) -> Result<Response> {
    let input = payload(bytes)?;
    let csr = decode(
        input["csr"]
            .as_str()
            .ok_or_else(|| malformed("CSR is required"))?,
    )?;
    let _guard = app.mutation.lock().await;
    let row = owned_order(app, id, account).await?;
    super::check_order_policy(app, id)
        .await
        .map_err(|_| denied("order is no longer authorized"))?;
    let domains: Vec<String> = serde_json::from_str(row.get("domains"))
        .map_err(|_| malformed("invalid stored domains"))?;
    validate_csr(&csr, &domains).map_err(|_| {
        problem(
            StatusCode::BAD_REQUEST,
            "badCSR",
            "CSR signature or domain names do not match the order",
        )
    })?;
    if let Some(existing) = row.get::<Option<Vec<u8>>, _>("csr") {
        if existing != csr {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "badCSR",
                "this order already has a different CSR",
            ));
        }
    } else {
        if row.get::<String, _>("state") != "ready" {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "orderNotReady",
                "order is not ready",
            ));
        }
        sqlx::query("UPDATE acme_orders SET csr=?,state='processing',phase='Queued for DNS validation',next_attempt=?,updated_at=? WHERE id=?").bind(csr).bind(now()).bind(now()).bind(id).execute(&app.db).await?;
    }
    Ok(order_response(
        settings,
        &owned_order(app, id, account).await?,
        StatusCode::OK,
    ))
}

async fn key_change(
    app: &App,
    settings: &Settings,
    account: &str,
    signed: &Verified,
) -> Result<Response> {
    let inner: Jose =
        serde_json::from_slice(&signed.payload).map_err(|_| malformed("invalid key change JWS"))?;
    let protected: Protected = serde_json::from_slice(&decode(&inner.protected)?)
        .map_err(|_| malformed("invalid key change header"))?;
    if protected.url != settings.url("key-change")
        || protected.kid.is_some()
        || protected.nonce.is_some()
    {
        return Err(malformed("invalid key change protected header"));
    }
    let jwk = canonical_jwk(
        protected
            .jwk
            .as_ref()
            .ok_or_else(|| malformed("new public key required"))?,
    )?;
    verify(&inner, &protected, &jwk)?;
    let input = payload(&decode(&inner.payload)?)?;
    if input["account"] != settings.url(&format!("account/{account}"))
        || canonical_jwk(&input["oldKey"])? != signed.jwk
        || jwk == signed.jwk
    {
        return Err(malformed("key change account or old key mismatch"));
    }
    let _guard = app.mutation.lock().await;
    let result = sqlx::query(
        "UPDATE downstream_accounts SET jwk=?,thumbprint=? WHERE id=? AND jwk=? AND status='valid'",
    )
    .bind(jwk.to_string())
    .bind(thumbprint(&jwk))
    .bind(account)
    .bind(signed.jwk.to_string())
    .execute(&app.db)
    .await;
    match result {
        Ok(r) if r.rows_affected() == 1 => {}
        _ => return Err(malformed("new key is in use or account key changed")),
    }
    store::audit(
        &app.db,
        account,
        "acme.account_key_changed",
        account,
        "success",
    )
    .await?;
    account_response(app, settings, account, StatusCode::OK).await
}

async fn revoke(app: &App, _settings: &Settings, signed: Verified) -> Result<Response> {
    let input = payload(&signed.payload)?;
    let der = decode(
        input["certificate"]
            .as_str()
            .ok_or_else(|| malformed("certificate is required"))?,
    )?;
    let row = sqlx::query(
        "SELECT id,account_id,staging,revoked FROM acme_orders WHERE certificate_der=?",
    )
    .bind(&der)
    .fetch_optional(&app.db)
    .await?
    .ok_or_else(|| denied("certificate was not issued by this endpoint"))?;
    if let Some(account) = &signed.account {
        if account != row.get::<String, _>("account_id").as_str() {
            return Err(denied("certificate belongs to another account"));
        }
    } else {
        let (_, cert) = x509_parser::parse_x509_certificate(&der)
            .map_err(|_| malformed("invalid certificate"))?;
        let key_matches = match cert
            .public_key()
            .parsed()
            .map_err(|_| malformed("invalid certificate key"))?
        {
            x509_parser::public_key::PublicKey::EC(key) if signed.jwk["kty"] == "EC" => {
                let mut public = vec![4];
                public.extend(decode(signed.jwk["x"].as_str().unwrap())?);
                public.extend(decode(signed.jwk["y"].as_str().unwrap())?);
                key.data() == public
            }
            x509_parser::public_key::PublicKey::RSA(key) if signed.jwk["kty"] == "RSA" => {
                let trim = |b: &[u8]| {
                    b.iter()
                        .skip_while(|b| **b == 0)
                        .copied()
                        .collect::<Vec<_>>()
                };
                trim(key.modulus) == decode(signed.jwk["n"].as_str().unwrap())?
                    && trim(key.exponent) == decode(signed.jwk["e"].as_str().unwrap())?
            }
            _ => false,
        };
        if !key_matches {
            return Err(denied("JWS key does not match certificate"));
        }
    }
    if row.get::<bool, _>("revoked") {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "alreadyRevoked",
            "certificate is already revoked",
        ));
    }
    let reason_code = match input.get("reason") {
        None => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| malformed("revocation reason must be a nonnegative integer"))?,
    };
    let reason = match reason_code {
        0 => instant_acme::RevocationReason::Unspecified,
        1 => instant_acme::RevocationReason::KeyCompromise,
        3 => instant_acme::RevocationReason::AffiliationChanged,
        4 => instant_acme::RevocationReason::Superseded,
        5 => instant_acme::RevocationReason::CessationOfOperation,
        9 => instant_acme::RevocationReason::PrivilegeWithdrawn,
        _ => {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "badRevocationReason",
                "unsupported revocation reason",
            ));
        }
    };
    let staging: bool = row.get("staging");
    let revoked = tokio::time::timeout(Duration::from_secs(30), async {
        let account = crate::certificates::account(app, staging).await?;
        let certificate = der.as_slice().into();
        match account
            .revoke(&instant_acme::RevocationRequest {
                certificate: &certificate,
                reason: Some(reason),
            })
            .await
        {
            Ok(()) => Ok(()),
            Err(instant_acme::Error::Api(p))
                if p.r#type.as_deref() == Some("urn:ietf:params:acme:error:alreadyRevoked") =>
            {
                Ok(())
            }
            Err(e) => Err(anyhow::Error::from(e)),
        }
    })
    .await;
    if !matches!(revoked, Ok(Ok(()))) {
        return Err(problem(
            StatusCode::BAD_GATEWAY,
            "serverInternal",
            "upstream revocation failed; retry later",
        ));
    }
    let id: String = row.get("id");
    sqlx::query("UPDATE acme_orders SET revoked=1,updated_at=? WHERE id=?")
        .bind(now())
        .bind(&id)
        .execute(&app.db)
        .await?;
    store::audit(
        &app.db,
        "acme-client",
        "acme.certificate_revoked",
        &id,
        "success",
    )
    .await?;
    Ok(StatusCode::OK.into_response())
}
