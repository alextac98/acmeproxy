use super::*;
use crate::{
    api,
    certificates::tests::{Ca, CaState, Fixture},
};
use axum::{
    body::{Body, Bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use http_body_util::BodyExt;
use instant_acme::{
    Account, AuthorizationStatus, BodyWrapper, BytesResponse, HttpClient, Identifier, NewAccount,
    NewOrder, OrderStatus,
};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tower::ServiceExt;

async fn configure(app: &App, mode: Mode, base_url: &str) {
    let _guard = app.mutation.lock().await;
    let mut next = app.config.lock().await.value.clone();
    next.acme = Settings {
        mode,
        base_url: base_url.into(),
        terms_agreed: true,
        validation_networks: vec!["127.0.0.1/32".into()],
        ..Default::default()
    };
    config::apply(app, next, "test.acme_settings", "acme")
        .await
        .unwrap();
}
#[derive(Clone)]
struct Transport {
    app: App,
}
impl HttpClient for Transport {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<BytesResponse, instant_acme::Error>> + Send>>
    {
        let app = self.app.clone();
        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            parts.extensions.insert(ConnectInfo(
                "127.0.0.1:12000".parse::<std::net::SocketAddr>().unwrap(),
            ));
            let body = body.collect().await.unwrap().to_bytes();
            let response = api::router(app)
                .oneshot(Request::from_parts(parts, Body::from(body)))
                .await
                .unwrap();
            Ok(BytesResponse::from(response))
        })
    }
}
async fn client(app: &App) -> Account {
    Account::builder_with_http(Box::new(Transport { app: app.clone() }))
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            "https://downstream.test/acme/directory".into(),
            None,
        )
        .await
        .unwrap()
        .0
}
fn ca(fixture: &Fixture) -> Ca {
    Ca {
        state: Arc::new(Mutex::new(CaState::default())),
        records: fixture.directory.path().join("records"),
    }
}

#[tokio::test]
async fn admin_reports_certificate_expiry_without_confusing_order_expiry() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let now = crate::now();
    let future_expiry = now + 90 * 86400;
    let past_expiry = now - 2 * 86400;
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = |expires| {
        let mut params = rcgen::CertificateParams::new(vec!["home.example.com".into()]).unwrap();
        params.not_before = time::OffsetDateTime::from_unix_timestamp(now - 100 * 86400).unwrap();
        params.not_after = time::OffsetDateTime::from_unix_timestamp(expires).unwrap();
        params.self_signed(&key).unwrap()
    };
    let valid = certificate(future_expiry);
    let expired = certificate(past_expiry);
    sqlx::query("INSERT INTO downstream_accounts(id,thumbprint,jwk,contact,created_at) VALUES('client','fingerprint','{}','[\"mailto:tls@example.com\"]',?)")
        .bind(now).execute(&app.db).await.unwrap();
    for (id, state, der, fullchain, revoked, expected) in [
        (
            "valid",
            "valid",
            Some(valid.der().to_vec()),
            None,
            false,
            Some(future_expiry),
        ),
        (
            "expired",
            "valid",
            Some(expired.der().to_vec()),
            None,
            false,
            Some(past_expiry),
        ),
        (
            "revoked",
            "valid",
            Some(valid.der().to_vec()),
            None,
            true,
            Some(future_expiry),
        ),
        (
            "legacy",
            "valid",
            None,
            Some(valid.pem()),
            false,
            Some(future_expiry),
        ),
        (
            "fallback",
            "valid",
            Some(vec![0]),
            Some(valid.pem()),
            false,
            Some(future_expiry),
        ),
        ("missing", "valid", None, None, false, None),
        (
            "malformed",
            "valid",
            Some(vec![0]),
            Some("invalid PEM".into()),
            false,
            None,
        ),
        (
            "processing",
            "processing",
            Some(valid.der().to_vec()),
            None,
            false,
            None,
        ),
    ] {
        sqlx::query("INSERT INTO clients(id,name,token_hash,scopes,created_at,managed) VALUES(?,?,?,'[]',?,1)")
            .bind(id).bind(id).bind(security::hash(id)).bind(now).execute(&app.db).await.unwrap();
        sqlx::query("INSERT INTO acme_orders(id,account_id,domains,staging,state,certificate_der,fullchain,revoked,next_attempt,expires_at,created_at,updated_at) VALUES(?,'client','[\"home.example.com\"]',0,?,?,?,?,0,?,?,?)")
            .bind(id).bind(state).bind(der).bind(fullchain).bind(revoked)
            .bind(now + 86400).bind(now).bind(now).execute(&app.db).await.unwrap();
        let response = api::router(app.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/admin/acme/settings")
                    .header("authorization", "Bearer admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let data: Value = serde_json::from_slice(&body).unwrap();
        let order = data["orders"]
            .as_array()
            .unwrap()
            .iter()
            .find(|order| order["id"] == id)
            .unwrap();
        assert_eq!(order["certificate_expires_at"], json!(expected), "{id}");
        assert_eq!(order["revoked"], revoked, "{id}");
        for field in ["certificate_der", "fullchain", "csr"] {
            assert!(
                order.get(field).is_none(),
                "certificate material must not be returned in metadata"
            );
        }
        assert_eq!(data["accounts"][0]["contact"][0], "mailto:tls@example.com");
    }
}

fn csr_for(names: Vec<String>, key: &rcgen::KeyPair) -> rcgen::CertificateSigningRequest {
    let mut params = rcgen::CertificateParams::new(names).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serialize_request(key).unwrap()
}

type HttpResponses = Arc<Mutex<std::collections::BTreeMap<String, String>>>;
async fn serve_http(fixture: &mut Fixture) -> (std::net::SocketAddr, HttpResponses) {
    let responses = HttpResponses::default();
    let values = responses.clone();
    let router = axum::Router::new().route(
        "/.well-known/acme-challenge/{token}",
        axum::routing::get(
            move |axum::extract::Path(token): axum::extract::Path<String>| {
                let values = values.clone();
                async move {
                    match values.lock().unwrap().get(&token) {
                        Some(value) => (StatusCode::OK, format!("{value}\n")),
                        None => (StatusCode::NOT_FOUND, String::new()),
                    }
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    fixture.tasks.push(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    }));
    (address, responses)
}
async fn validate_http(app: &App, address: std::net::SocketAddr) -> bool {
    validation::process_one_with(app, |domain, expected, settings| async move {
        validation::verify_resolved(&domain, &expected, &settings, &[address]).await
    })
    .await
    .unwrap()
}
async fn complete_order(
    app: &App,
    key: &Signer,
    kid: &str,
    order: &Value,
    address: std::net::SocketAddr,
    responses: &HttpResponses,
) {
    for authz in order["authorizations"].as_array().unwrap() {
        let path = url::Url::parse(authz.as_str().unwrap())
            .unwrap()
            .path()
            .to_string();
        let authorization = signed(app, key, kid, &path, Value::Null).await.2;
        let challenge = &authorization["challenges"][0];
        let token = challenge["token"].as_str().unwrap();
        responses.lock().unwrap().insert(
            token.into(),
            format!("{token}.{}", protocol::thumbprint(&key.jwk)),
        );
        let path = url::Url::parse(challenge["url"].as_str().unwrap())
            .unwrap()
            .path()
            .to_string();
        assert_eq!(
            signed(app, key, kid, &path, json!({})).await.0,
            StatusCode::OK
        );
    }
    while validate_http(app, address).await {}
}

#[tokio::test]
async fn standard_acme_client_keeps_private_key_and_uses_upstream_dns01() {
    let mut fixture = Fixture::new().await;
    let resolver = fixture.resolver().await;
    let (address, responses) = serve_http(&mut fixture).await;
    let app = &fixture.app;
    configure(app, Mode::Http01, "https://downstream.test").await;
    let downstream = client(app).await;
    let mut order = downstream
        .new_order(&NewOrder::new(&[
            Identifier::Dns("example.com".into()),
            Identifier::Dns("home.example.com".into()),
        ]))
        .await
        .unwrap();
    assert_eq!(order.state().status, OrderStatus::Pending);
    let mut auths = order.authorizations();
    while let Some(auth) = auths.next().await {
        let mut auth = auth.unwrap();
        assert_eq!(auth.status, AuthorizationStatus::Pending);
        assert_eq!(auth.challenges.len(), 1);
        assert_eq!(
            auth.challenges[0].r#type,
            instant_acme::ChallengeType::Http01
        );
        let mut challenge = auth.challenge(instant_acme::ChallengeType::Http01).unwrap();
        responses.lock().unwrap().insert(
            challenge.token.clone(),
            challenge.key_authorization().as_str().to_string(),
        );
        challenge.set_ready().await.unwrap();
    }
    while validate_http(app, address).await {}
    assert_eq!(
        order
            .poll_ready(&instant_acme::RetryPolicy::default())
            .await
            .unwrap(),
        OrderStatus::Ready
    );
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(vec!["example.com".into(), "home.example.com".into()])
            .unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key).unwrap();
    order.finalize_csr(csr.der()).await.unwrap();
    assert_eq!(order.state().status, OrderStatus::Processing);
    let upstream = ca(&fixture);
    let account = upstream.account().await;
    // Simulate a disconnect after upstream finalization. Retrying uses the saved CSR and order.
    upstream.state.lock().unwrap().fail_download = true;
    worker::process_one_with(app, |id, _| {
        let account = account.clone();
        let resolver = &resolver;
        async move { worker::issue(app, &id, account, resolver).await }
    })
    .await
    .unwrap();
    assert_eq!(upstream.state.lock().unwrap().finalized, 1);
    sqlx::query("UPDATE acme_orders SET next_attempt=0")
        .execute(&app.db)
        .await
        .unwrap();
    worker::process_one_with(app, |id, _| {
        let account = account.clone();
        let resolver = &resolver;
        async move { worker::issue(app, &id, account, resolver).await }
    })
    .await
    .unwrap();
    let chain = order
        .poll_certificate(&instant_acme::RetryPolicy::default())
        .await
        .unwrap();
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain.as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();
    assert_eq!(
        cert.public_key().subject_public_key.data.as_ref(),
        key.public_key_raw()
    );
    assert_eq!(
        upstream.state.lock().unwrap().orders.len(),
        1,
        "resuming must not create a second upstream order"
    );
    assert_eq!(upstream.state.lock().unwrap().finalized, 1);
    let managed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM certificates")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(
        managed, 0,
        "ACME clients must not create centrally managed private keys"
    );
    let stored: Vec<u8> = sqlx::query_scalar("SELECT csr FROM acme_orders")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(stored, csr.der().as_ref());
    let other = client(app).await;
    assert!(
        other.order(order.url().to_string()).await.is_err(),
        "other accounts cannot fetch orders or certificates"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let pending: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM challenges WHERE state!='cleaned'")
                    .fetch_one(&app.db)
                    .await
                    .unwrap();
            if pending == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        std::fs::read_to_string(&upstream.records)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn external_acme_client_issues_directly_using_authenticated_dns_gateway() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let token = security::random_secret();
    let mut next = app.config.lock().await.value.clone();
    next.clients.push(config::Client {
        id: uuid::Uuid::new_v4().to_string(),
        name: "External ACME client".into(),
        scopes: vec!["home.example.com".into()],
        revoked: false,
        token_hash: String::new(),
        token: Some(token.clone()),
    });
    config::apply(app, next, "test.gateway_client", "client")
        .await
        .unwrap();
    let upstream = ca(&fixture);
    let account = upstream.account().await;
    let mut order = account
        .new_order(&NewOrder::new(&[Identifier::Dns(
            "home.example.com".into(),
        )]))
        .await
        .unwrap();
    let mut auths = order.authorizations();
    let mut auth = auths.next().await.unwrap().unwrap();
    let mut challenge = auth.challenge(instant_acme::ChallengeType::Dns01).unwrap();
    let value = challenge.key_authorization().dns_value();
    let gateway = |path: &'static str, credential: String| {
        let value = value.clone();
        async move {
            api::router(app.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {credential}"))
                        .body(Body::from(
                            json!({"fqdn":"_acme-challenge.home.example.com","value":value})
                                .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };
    assert_eq!(
        gateway("/present", "wrong-token".into()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        gateway("/present", token.clone()).await.status(),
        StatusCode::OK
    );
    challenge.set_ready().await.unwrap();
    assert_eq!(
        order
            .poll_ready(&instant_acme::RetryPolicy::default())
            .await
            .unwrap(),
        OrderStatus::Ready
    );
    let key = rcgen::KeyPair::generate().unwrap();
    let csr = csr_for(vec!["home.example.com".into()], &key);
    order.finalize_csr(csr.der()).await.unwrap();
    let chain = order
        .poll_certificate(&instant_acme::RetryPolicy::default())
        .await
        .unwrap();
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain.as_bytes()).unwrap();
    assert_eq!(
        pem.parse_x509()
            .unwrap()
            .public_key()
            .subject_public_key
            .data
            .as_ref(),
        key.public_key_raw()
    );
    assert_eq!(gateway("/cleanup", token).await.status(), StatusCode::OK);
    assert!(
        std::fs::read_to_string(&upstream.records)
            .unwrap()
            .is_empty()
    );
    assert_eq!(upstream.state.lock().unwrap().finalized, 1);
    for table in ["certificates", "acme_orders"] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&app.db)
                .await
                .unwrap(),
            0,
            "the DNS gateway never takes over the client's certificate lifecycle"
        );
    }
}

struct Signer {
    key: signature::EcdsaKeyPair,
    jwk: Value,
}
impl Signer {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let der = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            der.as_ref(),
            &rng,
        )
        .unwrap();
        let bytes = key.public_key().as_ref();
        let jwk = json!({"kty":"EC","crv":"P-256","x":B64.encode(&bytes[1..33]),"y":B64.encode(&bytes[33..])});
        Self { key, jwk }
    }
    fn jws(&self, path: &str, nonce: Option<&str>, kid: Option<&str>, payload: Value) -> Value {
        let mut header = json!({"alg":"ES256","url":format!("https://downstream.test{path}")});
        if let Some(nonce) = nonce {
            header["nonce"] = json!(nonce);
        }
        if let Some(kid) = kid {
            header["kid"] = json!(kid);
        } else {
            header["jwk"] = self.jwk.clone();
        }
        let protected = B64.encode(header.to_string());
        let payload = if payload.is_null() {
            String::new()
        } else {
            B64.encode(payload.to_string())
        };
        let signature = self
            .key
            .sign(
                &SystemRandom::new(),
                format!("{protected}.{payload}").as_bytes(),
            )
            .unwrap();
        json!({"protected":protected,"payload":payload,"signature":B64.encode(signature.as_ref())})
    }
}
async fn call(
    app: &App,
    method: &str,
    path: &str,
    body: Value,
    peer: &str,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/jose+json")
        .header("x-forwarded-for", "127.0.0.1")
        .extension(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()))
        .body(Body::from(if body.is_null() {
            String::new()
        } else {
            body.to_string()
        }))
        .unwrap();
    let response = api::router(app.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
async fn nonce(app: &App) -> String {
    call(
        app,
        "HEAD",
        "/acme/new-nonce",
        Value::Null,
        "127.0.0.1:1234",
    )
    .await
    .1["replay-nonce"]
        .to_str()
        .unwrap()
        .into()
}
async fn register(app: &App, key: &Signer) -> String {
    let body = key.jws(
        "/acme/new-account",
        Some(&nonce(app).await),
        None,
        json!({"termsOfServiceAgreed":true}),
    );
    let (status, headers, value) =
        call(app, "POST", "/acme/new-account", body, "127.0.0.1:1234").await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    headers["location"].to_str().unwrap().into()
}
async fn signed(
    app: &App,
    key: &Signer,
    kid: &str,
    path: &str,
    payload: Value,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    call(
        app,
        "POST",
        path,
        key.jws(path, Some(&nonce(app).await), Some(kid), payload),
        "127.0.0.1:1234",
    )
    .await
}

#[tokio::test]
async fn settings_networks_signatures_nonces_and_self_service_registration() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    assert_eq!(
        call(app, "GET", "/acme/directory", Value::Null, "127.0.0.1:1234")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    configure(app, Mode::Http01, "https://downstream.test").await;
    assert_eq!(
        call(
            app,
            "GET",
            "/acme/directory",
            Value::Null,
            "203.0.113.2:1234"
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "spoofed X-Forwarded-For cannot bypass network policy"
    );
    let key = Signer::new();
    let message = key.jws(
        "/acme/new-account",
        Some(&nonce(app).await),
        None,
        json!({"termsOfServiceAgreed":true}),
    );
    let (status, headers, _) = call(
        app,
        "POST",
        "/acme/new-account",
        message.clone(),
        "127.0.0.1:1234",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let kid = headers["location"].to_str().unwrap();
    let replay = call(
        app,
        "POST",
        "/acme/new-account",
        message.clone(),
        "127.0.0.1:1234",
    )
    .await;
    assert_eq!(replay.2["type"], "urn:ietf:params:acme:error:badNonce");
    assert!(replay.1.contains_key("replay-nonce"));
    let mut tampered = key.jws(
        "/acme/new-account",
        Some(&nonce(app).await),
        None,
        json!({"termsOfServiceAgreed":true}),
    );
    tampered["payload"] = json!(B64.encode("{}"));
    assert_eq!(
        call(app, "POST", "/acme/new-account", tampered, "127.0.0.1:1234")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let input = json!({"identifiers":[{"type":"dns","value":"home.example.com"}]});
    let result = signed(app, &key, kid, "/acme/new-order", input).await;
    assert_eq!(result.0, StatusCode::CREATED);
    assert_eq!(
        result.2["status"], "pending",
        "registration needs no operator approval, but cannot skip HTTP-01"
    );
    let loaded = config::ConfigFile::load(app.config.lock().await.path.clone()).unwrap();
    assert_eq!(
        loaded.value.acme.mode,
        Mode::Http01,
        "HTTP-01 mode persists in TOML"
    );
    configure(app, Mode::Http01, "https://downstream.test").await;
    assert_eq!(
        signed(
            app,
            &key,
            kid,
            "/acme/new-order",
            json!({"identifiers":[{"type":"dns","value":"evil-example.com"}]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let invalid_url = key.jws(
        "/acme/wrong-url",
        Some(&nonce(app).await),
        Some(kid),
        json!({}),
    );
    assert_eq!(
        call(
            app,
            "POST",
            "/acme/new-order",
            invalid_url,
            "127.0.0.1:1234"
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn csr_binding_key_rollover_and_policy_revocation() {
    let mut fixture = Fixture::new().await;
    let (address, responses) = serve_http(&mut fixture).await;
    let app = &fixture.app;
    configure(app, Mode::Http01, "https://downstream.test").await;
    let key = Signer::new();
    let kid = register(app, &key).await;
    let (_, _, order) = signed(
        app,
        &key,
        &kid,
        "/acme/new-order",
        json!({"identifiers":[{"type":"dns","value":"home.example.com"}]}),
    )
    .await;
    let finalize = url::Url::parse(order["finalize"].as_str().unwrap())
        .unwrap()
        .path()
        .to_string();
    complete_order(app, &key, &kid, &order, address, &responses).await;
    let other = rcgen::KeyPair::generate().unwrap();
    let csr = csr_for(vec!["other.example.com".into()], &other);
    assert_eq!(
        signed(
            app,
            &key,
            &kid,
            &finalize,
            json!({"csr":B64.encode(csr.der())})
        )
        .await
        .2["type"],
        "urn:ietf:params:acme:error:badCSR"
    );
    let csr = csr_for(vec!["home.example.com".into()], &other);
    assert_eq!(
        signed(
            app,
            &key,
            &kid,
            &finalize,
            json!({"csr":B64.encode(csr.der())})
        )
        .await
        .0,
        StatusCode::OK
    );
    // The CSR cannot be swapped after finalization was queued.
    let different_key = rcgen::KeyPair::generate().unwrap();
    let changed = csr_for(vec!["home.example.com".into()], &different_key);
    assert_eq!(
        signed(
            app,
            &key,
            &kid,
            &finalize,
            json!({"csr":B64.encode(changed.der())})
        )
        .await
        .2["type"],
        "urn:ietf:params:acme:error:badCSR"
    );
    let next = Signer::new();
    let inner = next.jws(
        "/acme/key-change",
        None,
        None,
        json!({"account":kid,"oldKey":key.jwk}),
    );
    assert_eq!(
        signed(app, &key, &kid, "/acme/key-change", inner).await.0,
        StatusCode::OK
    );
    let account_path = url::Url::parse(&kid).unwrap().path().to_string();
    assert_eq!(
        signed(app, &key, &kid, &account_path, Value::Null).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        signed(app, &next, &kid, &account_path, Value::Null).await.0,
        StatusCode::OK
    );
    configure(app, Mode::Disabled, "https://downstream.test").await;
    worker::process_one_with(
        app,
        |id, _| async move { check_order_policy(app, &id).await },
    )
    .await
    .unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM acme_orders")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(
        state, "invalid",
        "disabling the endpoint must stop queued issuance"
    );
}

#[test]
fn wildcard_policy_and_csr_signature_are_checked() {
    assert!(!permits_domain("*.example.com", &["example.com".into()]));
    assert!(permits_domain(
        "*.apps.example.com",
        &["*.example.com".into()]
    ));
    assert!(!permits_domain("example.com", &["*.example.com".into()]));
    assert!(!permits_domain("badexample.com", &["*.example.com".into()]));
    let key = rcgen::KeyPair::generate().unwrap();
    let csr = csr_for(vec!["home.example.com".into()], &key);
    let mut corrupt = csr.der().to_vec();
    let len = corrupt.len();
    corrupt[len - 1] ^= 1;
    assert!(protocol::validate_csr(&corrupt, &["home.example.com".into()]).is_err());
}

fn resource_path(value: &Value) -> String {
    url::Url::parse(value.as_str().unwrap())
        .unwrap()
        .path()
        .to_string()
}

#[tokio::test]
async fn every_hostname_requires_account_bound_http01_and_failures_cannot_issue() {
    let mut fixture = Fixture::new().await;
    let (address, responses) = serve_http(&mut fixture).await;
    let app = &fixture.app;
    configure(app, Mode::Http01, "https://downstream.test").await;
    let key = Signer::new();
    let kid = register(app, &key).await;
    let order = signed(app, &key, &kid, "/acme/new-order", json!({"identifiers":[{"type":"dns","value":"home.example.com"},{"type":"dns","value":"other.example.com"}]})).await.2;
    let csr_key = rcgen::KeyPair::generate().unwrap();
    let csr = csr_for(
        vec!["home.example.com".into(), "other.example.com".into()],
        &csr_key,
    );
    let finalize = resource_path(&order["finalize"]);
    assert_eq!(
        signed(
            app,
            &key,
            &kid,
            &finalize,
            json!({"csr":B64.encode(csr.der())})
        )
        .await
        .2["type"],
        "urn:ietf:params:acme:error:orderNotReady"
    );
    let another = Signer::new();
    let another_kid = register(app, &another).await;
    for (index, authz) in order["authorizations"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let authz = signed(app, &key, &kid, &resource_path(authz), Value::Null)
            .await
            .2;
        assert_eq!(authz["status"], "pending");
        assert_eq!(authz["challenges"].as_array().unwrap().len(), 1);
        let challenge = &authz["challenges"][0];
        assert_eq!(challenge["type"], "http-01");
        let path = resource_path(&challenge["url"]);
        assert_eq!(
            signed(app, &another, &another_kid, &path, json!({}))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let token = challenge["token"].as_str().unwrap();
        assert!(B64.decode(token).unwrap().len() >= 16);
        let thumbprint = protocol::thumbprint(if index == 0 { &key.jwk } else { &another.jwk });
        responses
            .lock()
            .unwrap()
            .insert(token.into(), format!("{token}.{thumbprint}"));
        assert_eq!(
            signed(app, &key, &kid, &path, json!({})).await.2["status"],
            "processing"
        );
        assert!(validate_http(app, address).await);
        // Repeated acknowledgements cannot reset the attempt or schedule another fetch.
        assert_eq!(
            signed(app, &key, &kid, &path, json!({})).await.0,
            StatusCode::OK
        );
        assert!(!validate_http(app, address).await);
        let state: String = sqlx::query_scalar("SELECT state FROM acme_orders")
            .fetch_one(&app.db)
            .await
            .unwrap();
        assert_eq!(
            state, "pending",
            "one successful hostname does not authorize the whole order"
        );
    }
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM acme_authorizations WHERE state='valid'")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(count, 1);
    for _ in 0..2 {
        sqlx::query("UPDATE acme_authorizations SET next_attempt=0 WHERE state='processing'")
            .execute(&app.db)
            .await
            .unwrap();
        assert!(validate_http(app, address).await);
    }
    let state: String = sqlx::query_scalar("SELECT state FROM acme_orders")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(state, "invalid");
    assert_eq!(
        signed(
            app,
            &key,
            &kid,
            &finalize,
            json!({"csr":B64.encode(csr.der())})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let challenge = signed(
        app,
        &key,
        &kid,
        &resource_path(&order["authorizations"][1]),
        Value::Null,
    )
    .await
    .2;
    assert_eq!(challenge["status"], "invalid");
    assert_eq!(
        challenge["challenges"][0]["error"]["type"],
        "urn:ietf:params:acme:error:unauthorized"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM challenges")
            .fetch_one(&app.db)
            .await
            .unwrap(),
        0,
        "failed local proof must not publish upstream DNS"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM acme_orders WHERE csr IS NOT NULL OR fullchain IS NOT NULL"
        )
        .fetch_one(&app.db)
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn pending_authorizations_resume_after_restart_and_keep_rollover_binding() {
    let mut fixture = Fixture::new().await;
    let (address, responses) = serve_http(&mut fixture).await;
    let app = &fixture.app;
    configure(app, Mode::Http01, "https://downstream.test").await;
    let key = Signer::new();
    let kid = register(app, &key).await;
    let order = signed(
        app,
        &key,
        &kid,
        "/acme/new-order",
        json!({"identifiers":[{"type":"dns","value":"home.example.com"}]}),
    )
    .await
    .2;
    let authz = signed(
        app,
        &key,
        &kid,
        &resource_path(&order["authorizations"][0]),
        Value::Null,
    )
    .await
    .2;
    let challenge = &authz["challenges"][0];
    let token = challenge["token"].as_str().unwrap();
    responses.lock().unwrap().insert(
        token.into(),
        format!("{token}.{}", protocol::thumbprint(&key.jwk)),
    );
    assert_eq!(
        signed(
            app,
            &key,
            &kid,
            &resource_path(&challenge["url"]),
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    let next = Signer::new();
    let inner = next.jws(
        "/acme/key-change",
        None,
        None,
        json!({"account":kid,"oldKey":key.jwk}),
    );
    assert_eq!(
        signed(app, &key, &kid, "/acme/key-change", inner).await.0,
        StatusCode::OK
    );
    let mut restarted = app.clone();
    restarted.db = crate::store::connect(&fixture.directory.path().join("test.sqlite"), &app.vault)
        .await
        .unwrap();
    restarted.config = Arc::new(tokio::sync::Mutex::new(
        config::ConfigFile::load(app.config.lock().await.path.clone()).unwrap(),
    ));
    assert!(validate_http(&restarted, address).await);
    let authz = signed(
        &restarted,
        &next,
        &kid,
        &resource_path(&order["authorizations"][0]),
        Value::Null,
    )
    .await
    .2;
    assert_eq!(authz["status"], "valid");
    assert!(authz["challenges"][0]["validated"].as_str().is_some());
    assert!(
        check_order_policy(
            &restarted,
            order["finalize"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn unsupported_identifiers_wildcards_and_unverified_worker_jobs_fail_closed() {
    let mut fixture = Fixture::new().await;
    let resolver = fixture.resolver().await;
    let app = &fixture.app;
    configure(app, Mode::Http01, "https://downstream.test").await;
    let key = Signer::new();
    let kid = register(app, &key).await;
    for (kind, name, error) in [
        ("dns", "*.example.com", "rejectedIdentifier"),
        ("ip", "127.0.0.1", "unsupportedIdentifier"),
    ] {
        let response = signed(
            app,
            &key,
            &kid,
            "/acme/new-order",
            json!({"identifiers":[{"type":kind,"value":name}]}),
        )
        .await;
        assert_eq!(response.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            response.2["type"],
            format!("urn:ietf:params:acme:error:{error}")
        );
    }
    let order = signed(
        app,
        &key,
        &kid,
        "/acme/new-order",
        json!({"identifiers":[{"type":"dns","value":"home.example.com"}]}),
    )
    .await
    .2;
    let id = order["finalize"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap();
    let csr = csr_for(
        vec!["home.example.com".into()],
        &rcgen::KeyPair::generate().unwrap(),
    );
    // A corrupt/legacy ready job cannot get past the worker's independent proof check.
    sqlx::query("UPDATE acme_orders SET state='processing',csr=? WHERE id=?")
        .bind(csr.der().as_ref())
        .bind(id)
        .execute(&app.db)
        .await
        .unwrap();
    let upstream = ca(&fixture);
    let account = upstream.account().await;
    assert!(
        worker::process_one_with(app, |id, _| async move {
            worker::issue(app, &id, account, &resolver).await
        })
        .await
        .unwrap()
    );
    assert_eq!(upstream.state.lock().unwrap().orders.len(), 0);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM acme_orders")
            .fetch_one(&app.db)
            .await
            .unwrap(),
        "invalid"
    );
}

#[tokio::test]
async fn expiry_and_policy_changes_discard_http01_results() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    configure(app, Mode::Http01, "https://downstream.test").await;
    let key = Signer::new();
    let kid = register(app, &key).await;
    for condition in ["networks", "unhealthy", "expired"] {
        let order = signed(
            app,
            &key,
            &kid,
            "/acme/new-order",
            json!({"identifiers":[{"type":"dns","value":"home.example.com"}]}),
        )
        .await
        .2;
        let authz = signed(
            app,
            &key,
            &kid,
            &resource_path(&order["authorizations"][0]),
            Value::Null,
        )
        .await
        .2;
        let path = resource_path(&authz["challenges"][0]["url"]);
        assert_eq!(
            signed(app, &key, &kid, &path, json!({})).await.0,
            StatusCode::OK
        );
        let id = order["finalize"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        if condition == "expired" {
            sqlx::query("UPDATE acme_orders SET expires_at=0 WHERE id=?")
                .bind(id)
                .execute(&app.db)
                .await
                .unwrap();
            assert!(
                !validation::process_one_with(app, |_, _, _| async {
                    panic!("expired challenges must never fetch HTTP")
                })
                .await
                .unwrap()
            );
        } else {
            assert!(
                validation::process_one_with(app, |_, _, _| async {
                    if condition == "unhealthy" {
                        app.healthy
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                    } else {
                        app.config
                            .lock()
                            .await
                            .value
                            .acme
                            .validation_networks
                            .clear();
                    }
                    Ok(())
                })
                .await
                .unwrap()
            );
        }
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT state FROM acme_orders WHERE id=?")
                .bind(id)
                .fetch_one(&app.db)
                .await
                .unwrap(),
            "invalid"
        );
        app.healthy.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn legacy_access_modes_upgrade_to_mandatory_http01() {
    for mode in ["trusted_network", "approved_accounts"] {
        let settings: Settings =
            serde_json::from_value(json!({"mode":mode,"approved_accounts":["obsolete-approval"]}))
                .unwrap();
        assert_eq!(settings.mode, Mode::Http01);
        let saved = serde_json::to_value(settings).unwrap();
        assert_eq!(saved["mode"], "http01");
        assert!(saved.get("approved_accounts").is_none());
    }
}

#[tokio::test]
async fn upgrading_preserves_issued_chains_but_invalidates_unverified_legacy_orders() {
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    for migration in [
        include_str!("../../migrations/0001_initial.sql"),
        include_str!("../../migrations/0002_audit_retention.sql"),
        include_str!("../../migrations/0003_certificates.sql"),
        include_str!("../../migrations/0004_acme_endpoint.sql"),
    ] {
        sqlx::raw_sql(migration).execute(&db).await.unwrap();
    }
    sqlx::query("INSERT INTO downstream_accounts(id,thumbprint,jwk,created_at) VALUES('account','thumbprint','{}',0)").execute(&db).await.unwrap();
    for state in ["ready", "processing", "valid", "invalid"] {
        sqlx::query("INSERT INTO clients(id,name,token_hash,scopes,created_at,managed) VALUES(?,?,?,'[]',0,1)").bind(state).bind(state).bind(security::hash(state)).execute(&db).await.unwrap();
        sqlx::query("INSERT INTO acme_orders(id,account_id,domains,staging,state,fullchain,next_attempt,expires_at,created_at,updated_at) VALUES(?,'account','[\"home.example.com\"]',1,?,'saved-chain',0,9999999999,0,0)").bind(state).bind(state).execute(&db).await.unwrap();
    }
    sqlx::query("INSERT INTO providers(id,name,driver,zone,credentials,created_at) VALUES('provider','Fixture','dns_test','example.com',X'00',0)").execute(&db).await.unwrap();
    sqlx::query("INSERT INTO challenges(id,client_id,provider_id,credentials_snapshot,fqdn,value,state,operation,next_attempt,expires_at,created_at,updated_at) VALUES('legacy-dns','processing','provider',X'00','_acme-challenge.home.example.com','value','active','present',0,9999999999,0,0)").execute(&db).await.unwrap();
    sqlx::raw_sql(include_str!(
        "../../migrations/0005_http01_verification.sql"
    ))
    .execute(&db)
    .await
    .unwrap();
    for id in ["ready", "processing", "invalid"] {
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT state FROM acme_orders WHERE id=?")
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap(),
            "invalid"
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM acme_orders WHERE id='valid'")
            .fetch_one(&db)
            .await
            .unwrap(),
        "valid"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT fullchain FROM acme_orders WHERE id='valid'")
            .fetch_one(&db)
            .await
            .unwrap(),
        "saved-chain"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM acme_authorizations")
            .fetch_one(&db)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM challenges WHERE id='legacy-dns'")
            .fetch_one(&db)
            .await
            .unwrap(),
        "cleanup_pending"
    );
}

#[tokio::test]
#[ignore = "requires Certbot; set ACMEPROXY_CERTBOT to the executable"]
async fn real_certbot_issues_and_renews_through_http01_without_dns_plugins() {
    let executable = std::env::var("ACMEPROXY_CERTBOT").unwrap_or_else(|_| "certbot".into());
    let mut fixture = Fixture::new().await;
    let resolver = fixture.resolver().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    configure(&fixture.app, Mode::Http01, &origin).await;
    let router = api::router(fixture.app.clone())
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    fixture.tasks.push(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap()
    }));
    let upstream = ca(&fixture);
    let account = upstream.account().await;
    let app = fixture.app.clone();
    fixture.tasks.push(tokio::spawn(async move {
        loop {
            worker::process_one_with(&app, |id, _| {
                let account = account.clone();
                let resolver = &resolver;
                let app = &app;
                async move { worker::issue(app, &id, account, resolver).await }
            })
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }));
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_address = http_listener.local_addr().unwrap();
    drop(http_listener);
    let validation_app = fixture.app.clone();
    fixture.tasks.push(tokio::spawn(async move {
        loop {
            validate_http(&validation_app, http_address).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }));
    let root = fixture.directory.path().join("certbot");
    let run = |args: Vec<String>, expected_success: bool| {
        let executable = executable.clone();
        let root = root.clone();
        async move {
            let result = tokio::time::timeout(
                Duration::from_secs(60),
                tokio::process::Command::new(executable)
                    .args(args)
                    .arg("--config-dir")
                    .arg(root.join("config"))
                    .arg("--work-dir")
                    .arg(root.join("work"))
                    .arg("--logs-dir")
                    .arg(root.join("logs"))
                    .arg("--non-interactive")
                    .arg("--agree-tos")
                    .arg("--register-unsafely-without-email")
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                result.status.success(),
                expected_success,
                "Unexpected Certbot result:\n{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            result
        }
    };
    run(
        vec![
            "certonly".into(),
            "--standalone".into(),
            "--server".into(),
            format!("{origin}/acme/directory"),
            "--cert-name".into(),
            "endpoint-test".into(),
            "-d".into(),
            "example.com".into(),
            "--http-01-port".into(),
            http_address.port().to_string(),
            "--issuance-timeout".into(),
            "45".into(),
        ],
        true,
    )
    .await;
    let live = root.join("config/live/endpoint-test");
    let first = std::fs::read_to_string(live.join("fullchain.pem")).unwrap();
    assert!(
        std::fs::read_to_string(live.join("privkey.pem"))
            .unwrap()
            .contains("PRIVATE KEY")
    );
    run(
        vec![
            "renew".into(),
            "--force-renewal".into(),
            "--no-random-sleep-on-renew".into(),
        ],
        true,
    )
    .await;
    assert_ne!(
        first,
        std::fs::read_to_string(live.join("fullchain.pem")).unwrap()
    );
    assert_eq!(upstream.state.lock().unwrap().orders.len(), 2);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM acme_orders WHERE state='valid'")
        .fetch_one(&fixture.app.db)
        .await
        .unwrap();
    assert_eq!(count, 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM certificates")
            .fetch_one(&fixture.app.db)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM acme_authorizations WHERE state='valid'"
        )
        .fetch_one(&fixture.app.db)
        .await
        .unwrap(),
        2
    );
    for (domain, preference) in [("example.com", "dns"), ("*.example.com", "http")] {
        let result = run(
            vec![
                "certonly".into(),
                "--manual".into(),
                "--manual-auth-hook".into(),
                "true".into(),
                "--server".into(),
                format!("{origin}/acme/directory"),
                "--cert-name".into(),
                "unsupported-test".into(),
                "--preferred-challenges".into(),
                preference.into(),
                "-d".into(),
                domain.into(),
                "--http-01-port".into(),
                http_address.port().to_string(),
            ],
            false,
        )
        .await;
        let error = String::from_utf8_lossy(&result.stderr);
        if domain.starts_with("*.") {
            assert!(
                error.contains("Wildcard certificates are unsupported"),
                "{error}"
            );
        } else {
            assert!(
                error.contains("does not support any combination of challenges"),
                "{error}"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM acme_orders WHERE state='pending'"
                )
                .fetch_one(&fixture.app.db)
                .await
                .unwrap(),
                1,
                "the DNS-only client must reach the HTTP-only server's authorizations"
            );
        }
    }
    assert_eq!(
        upstream.state.lock().unwrap().orders.len(),
        2,
        "unsupported requests must not reach the upstream CA"
    );
    println!(
        "Certbot CLI: HTTP-01 issuance and forced renewal passed; DNS-only and wildcard requests rejected; private keys stayed client-side."
    );
}
