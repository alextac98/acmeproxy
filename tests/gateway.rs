use acmeproxy::{
    App, api, config, now,
    provider::{Driver, Field, Worker, WorkerState},
    security, store,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use tower::ServiceExt;

struct Harness {
    app: App,
    directory: tempfile::TempDir,
    admin: String,
    worker: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}
impl Harness {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("adapters");
        std::fs::create_dir_all(home.join("dnsapi")).unwrap();
        std::fs::write(
            home.join("acme.sh"),
            "# Test fixture; does not contact external DNS\n",
        )
        .unwrap();
        std::fs::write(
            home.join("dnsapi/dns_test.sh"),
            r#"
dns_test_add() {
  [ "$API_TOKEN" = "fixture-secret" ] || return 1
  [ -z "$ACMEPROXY_ADMIN_TOKEN" ] || return 1
  [ "$MODE" != "fail" ] || return 1
  if [ "$MODE" = "timeout" ]; then (sleep 1; touch "$RECORDS.late") & wait; fi
  touch "$RECORDS"
  grep -Fxq "$1 $2" "$RECORDS" || printf '%s %s\n' "$1" "$2" >> "$RECORDS"
  printf 'record_state=preserved\n' > "$DOMAIN_CONF"
}
dns_test_rm() {
  [ "$MODE" != "fail" ] || return 1
  grep -q 'record_state=preserved' "$DOMAIN_CONF" || return 1
  grep -Fxv "$1 $2" "$RECORDS" > "$RECORDS.new" || true
  mv "$RECORDS.new" "$RECORDS"
}
"#,
        )
        .unwrap();
        let scratch = directory.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let vault = security::Vault::new(&security::random_secret()).unwrap();
        let db = store::connect(&directory.path().join("state.sqlite"), &vault)
            .await
            .unwrap();
        let admin = security::random_secret();
        let value = config::Config::default();
        let path = directory.path().join("config.toml");
        config::write(&path, &value).unwrap();
        let app = App {
            db,
            vault,
            admin_hash: security::hash(&admin),
            worker: Worker {
                home,
                scratch,
                timeout: Duration::from_secs(2),
            },
            drivers: Arc::new(vec![Driver {
                id: "dns_test".into(),
                name: "Test DNS".into(),
                docs: "https://example.com".into(),
                fields: ["API_TOKEN", "RECORDS", "MODE"]
                    .iter()
                    .map(|key| Field {
                        key: key.to_string(),
                        label: key.to_string(),
                    })
                    .collect(),
            }]),
            mutation: Arc::new(tokio::sync::Mutex::new(())),
            wake: Arc::new(tokio::sync::Notify::new()),
            config: Arc::new(tokio::sync::Mutex::new(config::ConfigFile { path, value })),
            healthy: Arc::new(AtomicBool::new(true)),
        };
        Self {
            app,
            directory,
            admin,
            worker: None,
        }
    }
    fn start(&mut self) {
        self.worker = Some(tokio::spawn(store::run_worker(self.app.clone())));
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        auth: Option<String>,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(auth) = auth {
            request = request.header("authorization", auth);
        }
        let response = api::router(self.app.clone())
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(json!({"non_json":true})),
        )
    }
    async fn admin(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        self.request(method, path, Some(format!("Bearer {}", self.admin)), body)
            .await
    }
    async fn provider(&self, mode: &str) -> String {
        let (status,body)=self.admin("POST","/api/admin/providers",json!({"name":"Example DNS","driver":"dns_test","zone":"example.com","credentials":{"API_TOKEN":"fixture-secret","RECORDS":self.directory.path().join("records"),"MODE":mode}})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["id"].as_str().unwrap().into()
    }
    async fn client(&self, scope: &str) -> (String, String) {
        let (status, body) = self
            .admin(
                "POST",
                "/api/admin/clients",
                json!({"name":"Service","scopes":[scope]}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (
            body["id"].as_str().unwrap().into(),
            body["token"].as_str().unwrap().into(),
        )
    }
    fn basic(client: &(String, String)) -> Option<String> {
        Some(format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", client.0, client.1))
        ))
    }
}

#[tokio::test]
async fn compatible_protocol_owns_exact_values_and_keeps_secrets_private() {
    let mut h = Harness::new().await;
    h.provider("ok").await;
    let client = h.client("app.example.com").await;
    h.start();
    let first =
        json!({"fqdn":"_acme-challenge.app.example.com.","value":security::random_secret()});
    let second =
        json!({"fqdn":"_acme-challenge.app.example.com","value":security::random_secret()});
    for body in [&first, &first, &second] {
        let (status, response) = h
            .request("POST", "/present", Harness::basic(&client), body.clone())
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert_eq!(response["value"], body["value"]);
    }
    let records = h.directory.path().join("records");
    assert_eq!(
        std::fs::read_to_string(&records).unwrap().lines().count(),
        2
    );
    assert_eq!(
        h.request("POST", "/cleanup", Harness::basic(&client), first.clone())
            .await
            .0,
        StatusCode::OK
    );
    let remaining = std::fs::read_to_string(&records).unwrap();
    assert!(remaining.contains(second["value"].as_str().unwrap()));
    assert!(!remaining.contains(first["value"].as_str().unwrap()));
    assert_eq!(
        h.request("POST", "/cleanup", Harness::basic(&client), first)
            .await
            .0,
        StatusCode::OK
    );
    let (_, overview) = h.admin("GET", "/api/admin/overview", json!(null)).await;
    let public = overview.to_string();
    assert!(!public.contains("fixture-secret"));
    assert!(!public.contains(&client.1));
    assert!(!public.contains("token_hash"));
    let config = std::fs::read_to_string(h.directory.path().join("config.toml")).unwrap();
    assert!(config.contains("encrypted_credentials"));
    assert!(!config.contains("fixture-secret"));
    assert!(!config.contains(&client.1));
    let row = sqlx::query("SELECT credentials FROM providers")
        .fetch_one(&h.app.db)
        .await
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&row.get::<Vec<u8>, _>("credentials")).contains("fixture-secret")
    );
}

#[tokio::test]
async fn authorization_denies_cross_domain_cross_client_and_admin_access() {
    let mut h = Harness::new().await;
    h.provider("ok").await;
    let first = h.client("*.example.com").await;
    let other = h.client("app.example.com").await;
    h.start();
    let body = json!({"fqdn":"_acme-challenge.app.example.com","value":security::random_secret()});
    assert_eq!(
        h.request("POST", "/present", None, body.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.request(
            "GET",
            "/api/admin/overview",
            Some(format!("Bearer {}", first.1)),
            json!(null)
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    for name in [
        "_acme-challenge.example.com",
        "_acme-challenge.badexample.com",
        "_acme-challenge.example.com.evil.net",
    ] {
        assert_eq!(
            h.request(
                "POST",
                "/present",
                Harness::basic(&first),
                json!({"fqdn":name,"value":security::random_secret()})
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        h.request("POST", "/present", Harness::basic(&first), body.clone())
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        h.request("POST", "/cleanup", Harness::basic(&other), body)
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        h.admin(
            "DELETE",
            &format!("/api/admin/clients/{}", first.0),
            json!(null)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        h.request(
            "POST",
            "/present",
            Harness::basic(&first),
            json!({"fqdn":"_acme-challenge.app.example.com","value":security::random_secret()})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM challenges WHERE state!='cleaned'")
        .fetch_one(&h.app.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn pending_jobs_resume_and_expired_records_are_cleaned() {
    let mut h = Harness::new().await;
    let provider = h.provider("ok").await;
    let client = h.client("app.example.com").await;
    let id = uuid::Uuid::new_v4().to_string();
    let credentials: Vec<u8> = sqlx::query_scalar("SELECT credentials FROM providers WHERE id=?")
        .bind(&provider)
        .fetch_one(&h.app.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO challenges(id,client_id,provider_id,credentials_snapshot,fqdn,value,state,operation,next_attempt,expires_at,created_at,updated_at) VALUES(?,?,?,?,'_acme-challenge.app.example.com',?,'present_pending','present',?,?,?,?)")
        .bind(&id).bind(&client.0).bind(&provider).bind(credentials).bind(security::random_secret()).bind(now()).bind(now()+100).bind(now()).bind(now()).execute(&h.app.db).await.unwrap();
    // Reopen the database as a new server would, then rebuild config projection.
    h.app.db.close().await;
    h.app.db = store::connect(&h.directory.path().join("state.sqlite"), &h.app.vault)
        .await
        .unwrap();
    assert!(store::process_one(&h.app).await.unwrap());
    let state: String = sqlx::query_scalar("SELECT state FROM challenges WHERE id=?")
        .bind(&id)
        .fetch_one(&h.app.db)
        .await
        .unwrap();
    assert_eq!(state, "active");
    sqlx::query("UPDATE challenges SET expires_at=? WHERE id=?")
        .bind(now() - 1)
        .bind(&id)
        .execute(&h.app.db)
        .await
        .unwrap();
    assert!(store::process_one(&h.app).await.unwrap());
    let state: String = sqlx::query_scalar("SELECT state FROM challenges WHERE id=?")
        .bind(&id)
        .fetch_one(&h.app.db)
        .await
        .unwrap();
    assert_eq!(state, "cleaned");
    assert_eq!(
        std::fs::read_to_string(h.directory.path().join("records")).unwrap(),
        ""
    );
}

#[tokio::test]
async fn file_config_is_authoritative_and_rotation_waits_for_cleanup() {
    let mut h = Harness::new().await;
    let provider = h.provider("ok").await;
    let client = h.client("app.example.com").await;
    h.start();
    let body = json!({"fqdn":"_acme-challenge.app.example.com","value":security::random_secret()});
    assert_eq!(
        h.request("POST", "/present", Harness::basic(&client), body)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        h.admin(
            "DELETE",
            &format!("/api/admin/providers/{provider}"),
            json!(null)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let mut on_disk = config::ConfigFile::load(h.directory.path().join("config.toml")).unwrap();
    on_disk.value.providers[0].name = "Edited in file".into();
    config::write(&on_disk.path, &on_disk.value).unwrap();
    assert_eq!(
        h.admin(
            "POST",
            "/api/admin/clients",
            json!({"name":"Late UI edit","scopes":["a.example.com"]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert!(
        std::fs::read_to_string(&on_disk.path)
            .unwrap()
            .contains("Edited in file")
    );
}

#[tokio::test]
async fn worker_timeout_kills_descendants_and_removes_plaintext_scratch() {
    let h = Harness::new().await;
    let mut worker = h.app.worker.clone();
    worker.timeout = Duration::from_millis(100);
    let records = h.directory.path().join("records");
    let credentials = BTreeMap::from([
        ("API_TOKEN".into(), "fixture-secret".into()),
        ("MODE".into(), "timeout".into()),
        ("RECORDS".into(), records.to_string_lossy().into_owned()),
    ]);
    let result = worker
        .run(
            "dns_test",
            "add",
            "_acme-challenge.example.com",
            &security::random_secret(),
            &credentials,
            WorkerState::default(),
        )
        .await
        .unwrap();
    assert!(result.error.is_some());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(!records.with_extension("late").exists());
    assert_eq!(std::fs::read_dir(&worker.scratch).unwrap().count(), 0);
}

#[tokio::test]
async fn wrong_master_key_fails_closed() {
    let h = Harness::new().await;
    let wrong = security::Vault::new(&security::random_secret()).unwrap();
    assert!(
        store::connect(&h.directory.path().join("state.sqlite"), &wrong)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rotating_credentials_preserves_active_challenge_cleanup() {
    let mut h = Harness::new().await;
    let provider = h.provider("ok").await;
    let client = h.client("app.example.com").await;
    h.start();
    let body = json!({"fqdn":"_acme-challenge.app.example.com","value":security::random_secret()});
    assert_eq!(
        h.request("POST", "/present", Harness::basic(&client), body.clone())
            .await
            .0,
        StatusCode::OK
    );
    let (status, response) = h.admin("PUT", &format!("/api/admin/providers/{provider}"), json!({"name":"Rotated DNS","driver":"dns_test","zone":"example.com","credentials":{"API_TOKEN":"different-secret","MODE":"fail","RECORDS":h.directory.path().join("new-records")}})).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    // Cleanup must still use the original credentials and original worker state.
    assert_eq!(
        h.request("POST", "/cleanup", Harness::basic(&client), body)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        std::fs::read_to_string(h.directory.path().join("records")).unwrap(),
        ""
    );
}

#[tokio::test]
async fn disconnected_requests_persist_and_failed_operations_can_use_fixed_credentials() {
    let h = Harness::new().await;
    let provider = h.provider("fail").await;
    let client = h.client("app.example.com").await;
    let request = Request::builder()
        .method("POST")
        .uri("/present")
        .header("content-type", "application/json")
        .header("authorization", Harness::basic(&client).unwrap())
        .body(Body::from(
            json!({"fqdn":"_acme-challenge.app.example.com","value":security::random_secret()})
                .to_string(),
        ))
        .unwrap();
    let pending = tokio::spawn(api::router(h.app.clone()).oneshot(request));
    let id: String = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(id) = sqlx::query_scalar::<_, String>("SELECT id FROM challenges LIMIT 1")
                .fetch_optional(&h.app.db)
                .await
                .unwrap()
            {
                break id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    pending.abort();
    for _ in 0..5 {
        sqlx::query("UPDATE challenges SET next_attempt=0")
            .execute(&h.app.db)
            .await
            .unwrap();
        assert!(store::process_one(&h.app).await.unwrap());
    }
    let state: String = sqlx::query_scalar("SELECT state FROM challenges WHERE id=?")
        .bind(&id)
        .fetch_one(&h.app.db)
        .await
        .unwrap();
    assert_eq!(state, "failed");
    assert_eq!(h.admin("PUT", &format!("/api/admin/providers/{provider}"), json!({"name":"Fixed DNS","driver":"dns_test","zone":"example.com","credentials":{"API_TOKEN":"fixture-secret","MODE":"ok","RECORDS":h.directory.path().join("records")}})).await.0,StatusCode::OK);
    assert_eq!(
        h.admin(
            "POST",
            &format!("/api/admin/challenges/{id}/retry"),
            json!(null)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(store::process_one(&h.app).await.unwrap());
    let state: String = sqlx::query_scalar("SELECT state FROM challenges WHERE id=?")
        .bind(&id)
        .fetch_one(&h.app.db)
        .await
        .unwrap();
    assert_eq!(state, "active");
}

#[test]
fn plaintext_file_import_is_encrypted_and_rejects_unlisted_environment_keys() {
    let vault = security::Vault::new(&security::random_secret()).unwrap();
    let drivers = vec![Driver {
        id: "dns_test".into(),
        name: "Test DNS".into(),
        docs: String::new(),
        fields: vec![Field {
            key: "API_TOKEN".into(),
            label: "Token".into(),
        }],
    }];
    let mut file:config::Config=toml::from_str("[server]\n[[providers]]\nname='DNS'\ndriver='dns_test'\nzone='EXAMPLE.COM.'\n[providers.credentials]\nAPI_TOKEN='private-value'\n").unwrap();
    config::normalize(&mut file, &vault, &drivers).unwrap();
    let text = toml::to_string(&file).unwrap();
    assert!(!text.contains("private-value"));
    assert!(text.contains("encrypted_credentials"));
    assert_eq!(file.providers[0].zone, "example.com");
    assert!(
        acmeproxy::provider::validate_credentials(
            &drivers[0],
            &BTreeMap::from([("BASH_ENV".into(), "/tmp/evil".into())])
        )
        .is_err()
    );
}
