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

fn csr_for(names: Vec<String>, key: &rcgen::KeyPair) -> rcgen::CertificateSigningRequest {
    let mut params = rcgen::CertificateParams::new(names).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serialize_request(key).unwrap()
}

#[tokio::test]
async fn standard_acme_client_keeps_private_key_and_uses_upstream_dns01() {
    let mut fixture = Fixture::new().await;
    let resolver = fixture.resolver().await;
    let app = &fixture.app;
    configure(app, Mode::TrustedNetwork, "https://downstream.test").await;
    let downstream = client(app).await;
    let mut order = downstream
        .new_order(&NewOrder::new(&[
            Identifier::Dns("example.com".into()),
            Identifier::Dns("*.example.com".into()),
        ]))
        .await
        .unwrap();
    assert_eq!(order.state().status, OrderStatus::Ready);
    let mut auths = order.authorizations();
    while let Some(auth) = auths.next().await {
        let auth = auth.unwrap();
        assert_eq!(auth.status, AuthorizationStatus::Valid);
        assert!(
            auth.challenges.is_empty(),
            "client must not be asked to publish DNS"
        );
    }
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(vec!["example.com".into(), "*.example.com".into()]).unwrap();
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
async fn settings_modes_networks_signatures_nonces_and_approval() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    assert_eq!(
        call(app, "GET", "/acme/directory", Value::Null, "127.0.0.1:1234")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    configure(app, Mode::ApprovedAccounts, "https://downstream.test").await;
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
    assert_eq!(
        signed(app, &key, kid, "/acme/new-order", input.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let account = kid.rsplit('/').next().unwrap().to_string();
    let _ = approve_account(
        State(app.clone()),
        Path(account.clone()),
        Json(Approval { approved: true }),
    )
    .await
    .unwrap();
    assert_eq!(
        signed(app, &key, kid, "/acme/new-order", input.clone())
            .await
            .0,
        StatusCode::CREATED
    );
    let _ = approve_account(
        State(app.clone()),
        Path(account),
        Json(Approval { approved: false }),
    )
    .await
    .unwrap();
    assert_eq!(
        signed(app, &key, kid, "/acme/new-order", input).await.0,
        StatusCode::FORBIDDEN
    );
    let loaded = config::ConfigFile::load(app.config.lock().await.path.clone()).unwrap();
    assert_eq!(
        loaded.value.acme.mode,
        Mode::ApprovedAccounts,
        "mode changes persist in TOML"
    );
    configure(app, Mode::TrustedNetwork, "https://downstream.test").await;
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
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    configure(app, Mode::TrustedNetwork, "https://downstream.test").await;
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

#[tokio::test]
#[ignore = "requires Certbot; set ACMEPROXY_CERTBOT to the executable"]
async fn real_certbot_issues_and_renews_without_dns_plugins() {
    let executable = std::env::var("ACMEPROXY_CERTBOT").unwrap_or_else(|_| "certbot".into());
    let mut fixture = Fixture::new().await;
    let resolver = fixture.resolver().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    configure(&fixture.app, Mode::TrustedNetwork, &origin).await;
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
    let root = fixture.directory.path().join("certbot");
    let run = |args: Vec<String>| {
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
            assert!(
                result.status.success(),
                "Certbot failed:\n{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
    };
    run(vec![
        "certonly".into(),
        "--standalone".into(),
        "--server".into(),
        format!("{origin}/acme/directory"),
        "--cert-name".into(),
        "endpoint-test".into(),
        "-d".into(),
        "example.com".into(),
        "-d".into(),
        "*.example.com".into(),
        "--issuance-timeout".into(),
        "45".into(),
    ])
    .await;
    let live = root.join("config/live/endpoint-test");
    let first = std::fs::read_to_string(live.join("fullchain.pem")).unwrap();
    assert!(
        std::fs::read_to_string(live.join("privkey.pem"))
            .unwrap()
            .contains("PRIVATE KEY")
    );
    run(vec![
        "renew".into(),
        "--force-renewal".into(),
        "--no-random-sleep-on-renew".into(),
    ])
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
}
