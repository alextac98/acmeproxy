use super::*;
use crate::{config, provider};
use axum::{
    body::{Body, Bytes},
    http::Request,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig},
    name_server::TokioConnectionProvider,
    proto::{
        op::{Message, MessageType},
        rr::{Name, RData, Record, rdata::TXT},
        xfer::Protocol,
    },
};
use http_body_util::{BodyExt, Full};
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, atomic::AtomicBool},
};
use tower::ServiceExt;

pub(crate) struct Fixture {
    pub(crate) app: App,
    pub(crate) directory: tempfile::TempDir,
    pub(crate) tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Fixture {
    pub(crate) async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let home = root.join("adapters");
        std::fs::create_dir_all(home.join("dnsapi")).unwrap();
        std::fs::create_dir(root.join("scratch")).unwrap();
        std::fs::write(home.join("acme.sh"), "# fake adapter helpers\n").unwrap();
        std::fs::write(
            home.join("dnsapi/dns_test.sh"),
            r#"
dns_test_add() {
  touch "$RECORDS"
  grep -Fxq "$1 $2" "$RECORDS" || printf '%s %s\n' "$1" "$2" >> "$RECORDS"
}
dns_test_rm() {
  grep -Fxv "$1 $2" "$RECORDS" > "$RECORDS.tmp" || true
  mv "$RECORDS.tmp" "$RECORDS"
}
"#,
        )
        .unwrap();
        let vault = security::Vault::new(&security::random_secret()).unwrap();
        let drivers = vec![provider::Driver {
            id: "dns_test".into(),
            name: "Test DNS".into(),
            docs: String::new(),
            fields: vec![provider::Field {
                key: "RECORDS".into(),
                label: String::new(),
            }],
        }];
        let mut value = config::Config::default();
        value.providers.push(config::Provider {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Test".into(),
            driver: "dns_test".into(),
            zone: "example.com".into(),
            credentials: BTreeMap::from([(
                "RECORDS".into(),
                root.join("records").display().to_string(),
            )]),
            encrypted_credentials: String::new(),
        });
        config::normalize(&mut value, &vault, &drivers).unwrap();
        let db = store::connect(&root.join("test.sqlite"), &vault)
            .await
            .unwrap();
        let mut tx = db.begin().await.unwrap();
        config::sync(&mut tx, &value).await.unwrap();
        tx.commit().await.unwrap();
        let path = root.join("config.toml");
        config::write(&path, &value).unwrap();
        let app = App {
            db,
            vault,
            admin_hash: security::hash("admin"),
            worker: provider::Worker {
                home,
                scratch: root.join("scratch"),
                timeout: Duration::from_secs(2),
            },
            drivers: Arc::new(drivers),
            mutation: Arc::new(tokio::sync::Mutex::new(())),
            wake: Arc::new(tokio::sync::Notify::new()),
            config: Arc::new(tokio::sync::Mutex::new(config::ConfigFile { path, value })),
            healthy: Arc::new(AtomicBool::new(true)),
        };
        let worker = tokio::spawn(store::run_worker(app.clone()));
        Self {
            app,
            directory,
            tasks: vec![worker],
        }
    }
    async fn create(&self, domains: &[&str]) -> String {
        create(
            State(self.app.clone()),
            Json(Create {
                domains: domains.iter().map(|s| s.to_string()).collect(),
                staging: true,
                terms_agreed: true,
            }),
        )
        .await
        .unwrap()
        .1
        .0["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    pub(crate) async fn resolver(&mut self) -> hickory_resolver::TokioResolver {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let records = self.directory.path().join("records");
        self.tasks.push(tokio::spawn(async move {
            let mut bytes = [0u8; 4096];
            loop {
                let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes[..len]).unwrap();
                let mut response = Message::new();
                response
                    .set_id(request.id())
                    .set_message_type(MessageType::Response)
                    .set_authoritative(true)
                    .set_recursion_desired(true)
                    .set_recursion_available(true);
                for query in request.queries() {
                    response.add_query(query.clone());
                    for line in std::fs::read_to_string(&records)
                        .unwrap_or_default()
                        .lines()
                    {
                        let (name, value) = line.split_once(' ').unwrap();
                        if query.name() == &Name::from_ascii(format!("{name}.")).unwrap() {
                            response.add_answer(Record::from_rdata(
                                query.name().clone(),
                                0,
                                RData::TXT(TXT::new(vec![value.to_string()])),
                            ));
                        }
                    }
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        }));
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(address, Protocol::Udp));
        let mut builder = hickory_resolver::TokioResolver::builder_with_config(
            config,
            TokioConnectionProvider::default(),
        );
        builder.options_mut().cache_size = 0;
        builder.build()
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        auth: bool,
        body: Value,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if auth {
            request = request.header("authorization", "Bearer admin");
        }
        let response = crate::api::router(self.app.clone())
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        (
            status,
            headers,
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }
}

#[derive(Default)]
pub(crate) struct CaState {
    pub(crate) orders: Vec<TestOrder>,
    thumbprint: String,
    pub(crate) fail_download: bool,
    fail_validation: bool,
    pub(crate) finalized: usize,
}
pub(crate) struct TestOrder {
    names: Vec<String>,
    ready: Vec<bool>,
    chain: Option<String>,
}
#[derive(Clone)]
pub(crate) struct Ca {
    pub(crate) state: Arc<Mutex<CaState>>,
    pub(crate) records: std::path::PathBuf,
}
impl Ca {
    fn order(order: &TestOrder, n: usize, invalid: bool) -> Value {
        json!({"status": if invalid { "invalid" } else if order.chain.is_some() { "valid" } else if order.ready.iter().all(|v| *v) { "ready" } else { "pending" },
            "authorizations": (0..order.names.len()).map(|i| format!("https://ca.test/auth/{n}/{i}")).collect::<Vec<_>>(),
            "finalize":format!("https://ca.test/finalize/{n}"), "certificate":order.chain.as_ref().map(|_|format!("https://ca.test/cert/{n}"))})
    }
    pub(crate) async fn account(&self) -> Account {
        let (account, _) = Account::builder_with_http(Box::new(self.clone()))
            .create(
                &NewAccount {
                    contact: &[],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                "https://ca.test/directory".into(),
                None,
            )
            .await
            .unwrap();
        self.state.lock().unwrap().thumbprint = account.key_thumbprint().to_string();
        account
    }
}
impl HttpClient for Ca {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let ca = self.clone();
        Box::pin(async move {
            let path = req.uri().path().to_string();
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let payload = if body.is_empty() {
                Value::Null
            } else {
                let jws: Value = serde_json::from_slice(&body).unwrap();
                let bytes = URL_SAFE_NO_PAD
                    .decode(jws["payload"].as_str().unwrap())
                    .unwrap();
                if bytes.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes).unwrap()
                }
            };
            let mut state = ca.state.lock().unwrap();
            let mut location = "https://ca.test/account".to_string();
            let mut status = StatusCode::OK;
            let parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
            let n = parts
                .get(1)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            let response = match parts[0] {
                "directory" => json!({"newNonce":"https://ca.test/nonce", "newAccount":"https://ca.test/account", "newOrder":"https://ca.test/new-order"}).to_string(),
                "nonce" => String::new(),
                "account" => json!({"status":"valid"}).to_string(),
                "new-order" => {
                    let names: Vec<String> = payload["identifiers"].as_array().unwrap().iter().map(|v| v["value"].as_str().unwrap().to_owned()).collect();
                    let order = TestOrder { ready: vec![false; names.len()], names, chain: None };
                    let n = state.orders.len(); location = format!("https://ca.test/order/{n}"); status = StatusCode::CREATED;
                    let response = Ca::order(&order, n, false).to_string(); state.orders.push(order); response
                },
                "order" => Ca::order(&state.orders[n], n, state.fail_validation).to_string(),
                "auth" => {
                    let i: usize = parts[2].parse().unwrap(); let order = &state.orders[n]; let name = &order.names[i];
                    json!({"status":if order.ready[i] { "valid" } else { "pending" }, "identifier":{"type":"dns", "value":name.strip_prefix("*.").unwrap_or(name)}, "wildcard":name.starts_with("*."),
                        "challenges":[{"type":"dns-01","status":"pending","url":format!("https://ca.test/challenge/{n}/{i}"),"token":format!("token-{n}-{i}")}] }).to_string()
                },
                "challenge" => {
                    let i: usize = parts[2].parse().unwrap();
                    let expected = URL_SAFE_NO_PAD.encode(security::hash(&format!("token-{n}-{i}.{}", state.thumbprint)));
                    let name = &state.orders[n].names[i]; let name = name.strip_prefix("*.").unwrap_or(name);
                    assert!(std::fs::read_to_string(&ca.records).unwrap().lines().any(|l| l == format!("_acme-challenge.{name} {expected}")), "CA validation must find the actual DNS-01 digest");
                    state.orders[n].ready[i] = true;
                    json!({"type":"dns-01","status":"valid","url":format!("https://ca.test/challenge/{n}/{i}"),"token":format!("token-{n}-{i}")}).to_string()
                },
                "finalize" => {
                    assert!(state.orders[n].ready.iter().all(|v| *v));
                    let der = URL_SAFE_NO_PAD.decode(payload["csr"].as_str().unwrap()).unwrap();
                    let mut csr = rcgen::CertificateSigningRequestParams::from_der(&der.into()).unwrap();
                    csr.params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
                    csr.params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(6);
                    let mut issuer_params = rcgen::CertificateParams::default();
                    issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                    let issuer = rcgen::CertifiedIssuer::self_signed(issuer_params, rcgen::KeyPair::generate().unwrap()).unwrap();
                    state.orders[n].chain = Some(format!("{}{}", csr.signed_by(&issuer).unwrap().pem(), issuer.pem())); state.finalized += 1;
                    Ca::order(&state.orders[n], n, false).to_string()
                },
                "cert" => {
                    if state.fail_download { state.fail_download = false; return Err(instant_acme::Error::Str("simulated disconnect after finalization")); }
                    state.orders[n].chain.clone().unwrap()
                },
                _ => panic!("unexpected ACME request {path}"),
            };
            Ok(BytesResponse::from(
                axum::http::Response::builder()
                    .status(status)
                    .header("replay-nonce", security::random_secret())
                    .header("location", location)
                    .body(Full::new(Bytes::from(response)))
                    .unwrap(),
            ))
        })
    }
}

async fn drain(app: &App, id: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM challenges WHERE client_id=? AND state!='cleaned'",
            )
            .bind(id)
            .fetch_one(&app.db)
            .await
            .unwrap();
            if count == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn automated_dns01_issuance_resume_renewal_and_download() {
    let mut fixture = Fixture::new().await;
    let resolver = fixture.resolver().await;
    let app = &fixture.app;
    let id = fixture.create(&["example.com", "*.example.com"]).await;
    let ca = Ca {
        state: Arc::new(Mutex::new(CaState {
            fail_download: true,
            ..Default::default()
        })),
        records: fixture.directory.path().join("records"),
    };
    let account = ca.account().await;
    assert!(
        process_one_with(app, |id, staging| {
            assert!(staging);
            let account = account.clone();
            let resolver = &resolver;
            async move { issue(app, &id, account, resolver).await }
        })
        .await
        .unwrap()
    );
    drain(app, &id).await;
    let pending: Vec<u8> = sqlx::query_scalar("SELECT pending_key FROM certificates WHERE id=?")
        .bind(&id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    let pending_plain = app
        .vault
        .open(&format!("certificate:{id}"), &pending)
        .unwrap();
    assert!(!String::from_utf8_lossy(&pending).contains("PRIVATE KEY"));
    assert_eq!(ca.state.lock().unwrap().finalized, 1);
    assert_eq!(ca.state.lock().unwrap().orders.len(), 1);
    // Simulate recovery from a process exit with the same encrypted DB and key.
    sqlx::query("UPDATE certificates SET state='issuing',next_attempt=0 WHERE id=?")
        .bind(&id)
        .execute(&app.db)
        .await
        .unwrap();
    assert!(
        process_one_with(app, |id, _| {
            let account = account.clone();
            let resolver = &resolver;
            async move { issue(app, &id, account, resolver).await }
        })
        .await
        .unwrap()
    );
    let row = sqlx::query("SELECT * FROM certificates WHERE id=?")
        .bind(&id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("state"), "issued");
    assert_eq!(row.get::<Vec<u8>, _>("private_key"), pending);
    assert!(row.get::<Option<Vec<u8>>, _>("pending_key").is_none());
    assert_eq!(
        ca.state.lock().unwrap().finalized,
        1,
        "must not finalize twice"
    );
    assert_eq!(
        ca.state.lock().unwrap().orders.len(),
        1,
        "must resume the existing order"
    );
    let renew_at: i64 = row.get("renew_at");
    let expires_at: i64 = row.get("expires_at");
    assert!(
        renew_at > now() + 3 * 86400 && renew_at < expires_at - 86400,
        "renewal adapts to a six-day certificate"
    );
    for file in ["fullchain.pem", "privkey.pem", "bundle.pem"] {
        let path = format!("/api/admin/certificates/{id}/{file}");
        assert_eq!(
            fixture.request("GET", &path, false, Value::Null).await.0,
            StatusCode::UNAUTHORIZED
        );
        let (status, headers, content) = fixture.request("GET", &path, true, Value::Null).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["cache-control"], "no-store");
        assert!(
            headers["content-disposition"]
                .to_str()
                .unwrap()
                .contains(file)
        );
        if file != "fullchain.pem" {
            assert!(content.starts_with(&pending_plain));
        }
    }
    let summary = fixture
        .request("GET", "/api/admin/certificates", true, Value::Null)
        .await
        .2;
    assert!(!String::from_utf8_lossy(&summary).contains("PRIVATE KEY"));
    // A routine config save must not revoke the internal owner or expose it as a client.
    let next = app.config.lock().await.value.clone();
    config::apply(app, next, "test", "test").await.unwrap();
    let revoked: bool = sqlx::query_scalar("SELECT revoked FROM clients WHERE id=?")
        .bind(&id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert!(!revoked);
    let overview: Value = serde_json::from_slice(
        &fixture
            .request("GET", "/api/admin/overview", true, Value::Null)
            .await
            .2,
    )
    .unwrap();
    assert!(overview["clients"].as_array().unwrap().is_empty());
    // Pausing renewal prevents a due certificate from being claimed.
    sqlx::query("UPDATE certificates SET next_attempt=0,auto_renew=0 WHERE id=?")
        .bind(&id)
        .execute(&app.db)
        .await
        .unwrap();
    assert!(
        !process_one_with(app, |_, _| async { panic!("paused renewal ran") })
            .await
            .unwrap()
    );
    sqlx::query("UPDATE certificates SET auto_renew=1 WHERE id=?")
        .bind(&id)
        .execute(&app.db)
        .await
        .unwrap();
    assert!(
        process_one_with(app, |id, _| {
            let account = account.clone();
            let resolver = &resolver;
            async move { issue(app, &id, account, resolver).await }
        })
        .await
        .unwrap()
    );
    drain(app, &id).await;
    assert_eq!(ca.state.lock().unwrap().orders.len(), 2);
    let renewed: Vec<u8> = sqlx::query_scalar("SELECT private_key FROM certificates WHERE id=?")
        .bind(&id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_ne!(
        renewed, pending,
        "renewal rotates the key and atomically replaces the pair"
    );
    assert!(std::fs::read_to_string(&ca.records).unwrap().is_empty());
}

#[tokio::test]
async fn failed_validation_cleans_dns_and_preserves_existing_certificate() {
    let mut fixture = Fixture::new().await;
    let resolver = fixture.resolver().await;
    let app = &fixture.app;
    let id = fixture.create(&["home.example.com"]).await;
    let ca = Ca {
        state: Arc::new(Mutex::new(CaState::default())),
        records: fixture.directory.path().join("records"),
    };
    let account = ca.account().await;
    process_one_with(app, |id, _| {
        let account = account.clone();
        let resolver = &resolver;
        async move { issue(app, &id, account, resolver).await }
    })
    .await
    .unwrap();
    drain(app, &id).await;
    let old: String = sqlx::query_scalar("SELECT fullchain FROM certificates WHERE id=?")
        .bind(&id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    ca.state.lock().unwrap().fail_validation = true;
    sqlx::query("UPDATE certificates SET next_attempt=0,attempts=4 WHERE id=?")
        .bind(&id)
        .execute(&app.db)
        .await
        .unwrap();
    process_one_with(app, |id, _| {
        let account = account.clone();
        let resolver = &resolver;
        async move { issue(app, &id, account, resolver).await }
    })
    .await
    .unwrap();
    drain(app, &id).await;
    let row = sqlx::query("SELECT * FROM certificates WHERE id=?")
        .bind(&id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("state"), "failed");
    assert_eq!(row.get::<String, _>("fullchain"), old);
    assert!(row.get::<i64, _>("next_attempt") >= now() + 86390);
    assert!(row.get::<Option<String>, _>("order_url").is_none());
    assert_eq!(
        fixture
            .request(
                "GET",
                &format!("/api/admin/certificates/{id}/fullchain.pem"),
                true,
                Value::Null
            )
            .await
            .0,
        StatusCode::OK
    );
    assert!(std::fs::read_to_string(&ca.records).unwrap().is_empty());
}

#[tokio::test]
async fn request_validation_authentication_deduplication_and_removal() {
    let fixture = Fixture::new().await;
    for (input, status) in [
        (
            json!({"domains":["home.example.com"]}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"domains":[],"terms_agreed":true}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"domains":["badexample.com"],"terms_agreed":true}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"domains":["$(id).example.com"],"terms_agreed":true}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"domains":["home.example.com"],"terms_agreed":true,"directory":"https://evil.test"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        assert_eq!(
            fixture
                .request("POST", "/api/admin/certificates", true, input)
                .await
                .0,
            status
        );
    }
    let input = json!({"domains":["HOME.example.com.", "home.example.com"], "terms_agreed":true,"staging":true});
    assert_eq!(
        fixture
            .request("POST", "/api/admin/certificates", false, input.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, bytes) = fixture
        .request("POST", "/api/admin/certificates", true, input.clone())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let id = serde_json::from_slice::<Value>(&bytes).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _, duplicate) = fixture
        .request("POST", "/api/admin/certificates", true, input)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(duplicate, bytes);
    assert_eq!(
        fixture
            .request(
                "GET",
                &format!("/api/admin/certificates/{id}/privkey.pem"),
                true,
                Value::Null
            )
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                &format!("/api/admin/certificates/{id}/retry"),
                true,
                Value::Null
            )
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture
            .request(
                "DELETE",
                &format!("/api/admin/certificates/{id}"),
                true,
                Value::Null
            )
            .await
            .0,
        StatusCode::OK
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM clients WHERE managed=1")
        .fetch_one(&fixture.app.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn dns_failure_cleanup_and_failed_initial_requests_stop_retrying() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let id = fixture.create(&["home.example.com"]).await;
    sqlx::query("UPDATE certificates SET attempts=4 WHERE id=?")
        .bind(&id)
        .execute(&app.db)
        .await
        .unwrap();
    process_one_with(app, |id, _| async move {
        let value = security::random_secret();
        let challenge = present(app, &id, "_acme-challenge.home.example.com", &value).await?;
        wait_present(app, &challenge).await?;
        anyhow::bail!("simulated failure after successful DNS mutation")
    })
    .await
    .unwrap();
    drain(app, &id).await;
    sqlx::query("UPDATE certificates SET next_attempt=0 WHERE id=?")
        .bind(&id)
        .execute(&app.db)
        .await
        .unwrap();
    assert!(
        !process_one_with(app, |_, _| async {
            panic!("failed initial issuance must stop after five attempts")
        })
        .await
        .unwrap()
    );
    assert_eq!(
        fixture
            .request(
                "POST",
                &format!("/api/admin/certificates/{id}/retry"),
                true,
                Value::Null
            )
            .await
            .0,
        StatusCode::OK
    );
    let state: String = sqlx::query_scalar("SELECT state FROM certificates WHERE id=?")
        .bind(&id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(state, "queued");
}

#[tokio::test]
async fn mismatched_certificate_cannot_replace_stored_key_or_chain() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let id = fixture.create(&["home.example.com"]).await;
    let pending = rcgen::KeyPair::generate().unwrap();
    let sealed = app
        .vault
        .seal(
            &format!("certificate:{id}"),
            pending.serialize_pem().as_bytes(),
        )
        .unwrap();
    sqlx::query(
        "UPDATE certificates SET pending_key=?,fullchain='previous certificate' WHERE id=?",
    )
    .bind(sealed)
    .bind(&id)
    .execute(&app.db)
    .await
    .unwrap();
    for (names, key) in [
        (vec!["other.example.com".to_string()], pending),
        (
            vec!["home.example.com".to_string()],
            rcgen::KeyPair::generate().unwrap(),
        ),
    ] {
        let cert = rcgen::CertificateParams::new(names)
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert!(save_issued(app, &id, &cert.pem()).await.is_err());
        let chain: String = sqlx::query_scalar("SELECT fullchain FROM certificates WHERE id=?")
            .bind(&id)
            .fetch_one(&app.db)
            .await
            .unwrap();
        assert_eq!(chain, "previous certificate");
    }
}

#[tokio::test]
async fn managed_owner_cannot_authenticate_and_survives_config_reload() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let id = fixture.create(&["home.example.com"]).await;
    sqlx::query("UPDATE clients SET token_hash=? WHERE id=?")
        .bind(security::hash("known-internal-token"))
        .bind(&id)
        .execute(&app.db)
        .await
        .unwrap();
    let response = crate::api::router(app.clone()).oneshot(Request::builder().method("POST").uri("/present")
        .header("authorization", "Bearer known-internal-token").header("content-type", "application/json")
        .body(Body::from(json!({"fqdn":"_acme-challenge.home.example.com", "value":security::random_secret()}).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let reloaded = config::ConfigFile::load(app.config.lock().await.path.clone()).unwrap();
    let mut tx = app.db.begin().await.unwrap();
    config::sync(&mut tx, &reloaded.value).await.unwrap();
    tx.commit().await.unwrap();
    let revoked: bool = sqlx::query_scalar("SELECT revoked FROM clients WHERE id=?")
        .bind(&id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert!(!revoked);
    // File imports cannot replace an internal owner with an externally authenticating client.
    let mut next = reloaded.value;
    next.clients.push(config::Client {
        id,
        name: "conflicting import".into(),
        scopes: vec!["home.example.com".into()],
        token_hash: URL_SAFE_NO_PAD.encode(security::hash("external")),
        token: None,
        revoked: false,
    });
    let mut tx = app.db.begin().await.unwrap();
    assert!(config::sync(&mut tx, &next).await.is_err());
}
