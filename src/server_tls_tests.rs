use super::*;
use crate::{
    acme::{Mode, Settings},
    api::{self, ListenerKind},
    certificates::tests::Fixture,
    config::{self, Config, PlainHttp},
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
    serve::ListenerExt,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};
use tower::ServiceExt;

pub(crate) const DOMAIN: &str = "certs.example.com";
pub(crate) const HTTPS: &str = "https://certs.example.com";
pub(crate) const HTTP: &str = "http://certs.example.com:8080";

pub(crate) fn tls_config(plain_http: PlainHttp, origin: &str) -> Tls {
    Tls {
        listen: "127.0.0.1:8443".into(),
        domain: DOMAIN.into(),
        staging: false,
        terms_agreed: true,
        plain_http,
        plain_http_origin: origin.into(),
    }
}

/// Apply what an operator sets before restarting, plus the startup certificate request.
pub(crate) async fn enable(app: &App, plain_http: PlainHttp, origin: &str) -> String {
    let tls = tls_config(plain_http, origin);
    {
        let _guard = app.mutation.lock().await;
        let mut next = app.config.lock().await.value.clone();
        next.server.tls = Some(tls.clone());
        next.acme = Settings {
            mode: Mode::Http01,
            base_url: HTTPS.into(),
            terms_agreed: true,
            ..Default::default()
        };
        config::apply(app, next, "test.tls", "tls").await.unwrap();
    }
    let mut tx = app.db.begin().await.unwrap();
    ensure_certificate(&mut tx, &tls).await.unwrap();
    tx.commit().await.unwrap();
    sqlx::query_scalar("SELECT id FROM certificates WHERE domains=? AND staging=0")
        .bind(certificate_domains(&tls))
        .fetch_one(&app.db)
        .await
        .unwrap()
}

pub(crate) struct Issued {
    chain: String,
    key: String,
    pub(crate) root: CertificateDer<'static>,
}
pub(crate) fn issue_for(name: &str, expired: bool) -> Issued {
    let mut authority = rcgen::CertificateParams::default();
    authority.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let issuer =
        rcgen::CertifiedIssuer::self_signed(authority, rcgen::KeyPair::generate().unwrap())
            .unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
    if expired {
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(90);
        params.not_after = now - time::Duration::days(1);
    }
    let leaf = params.signed_by(&key, &issuer).unwrap();
    Issued {
        chain: format!("{}{}", leaf.pem(), issuer.pem()),
        key: key.serialize_pem(),
        root: issuer.der().clone(),
    }
}
async fn store(app: &App, id: &str, issued: &Issued) {
    sqlx::query("UPDATE certificates SET fullchain=?,private_key=?,state='issued' WHERE id=?")
        .bind(&issued.chain)
        .bind(
            app.vault
                .seal(&format!("certificate:{id}"), issued.key.as_bytes())
                .unwrap(),
        )
        .bind(id)
        .execute(&app.db)
        .await
        .unwrap();
}

pub(crate) async fn serve(app: &App) -> (SocketAddr, JoinHandle<()>) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let listener = listen(tcp, app.server_cert.clone()).unwrap().tap_io(|_| {});
    let router = api::listener_router(app.clone(), ListenerKind::Tls);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (address, server)
}

/// One HTTPS request that trusts only `root`; an `Err` is a failed TLS handshake.
pub(crate) async fn fetch(
    address: SocketAddr,
    root: CertificateDer<'static>,
    path: &str,
) -> std::io::Result<String> {
    let mut roots = RootCertStore::empty();
    roots.add(root).unwrap();
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = TcpStream::connect(address).await?;
    let mut stream = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(DOMAIN).unwrap(), tcp)
        .await?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {DOMAIN}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    // Servers may close without close_notify; everything sent has been read by then.
    let _ = stream.read_to_end(&mut response).await;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

#[tokio::test]
async fn handshakes_fail_closed_until_a_certificate_is_loaded_then_swap_live() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let id = enable(app, PlainHttp::Full, HTTP).await;
    let (address, _server) = serve(app).await;
    let first = issue_for(DOMAIN, false);
    assert!(
        fetch(address, first.root.clone(), "/healthz")
            .await
            .is_err()
    );

    store(app, &id, &first).await;
    reload(app).await.unwrap();
    let response = fetch(address, first.root.clone(), "/healthz")
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let second = issue_for(DOMAIN, false);
    store(app, &id, &second).await;
    reload(app).await.unwrap();
    assert!(
        fetch(address, second.root.clone(), "/healthz")
            .await
            .is_ok()
    );
    assert!(
        fetch(address, first.root.clone(), "/healthz")
            .await
            .is_err(),
        "new connections must use the replacement certificate"
    );
}

#[tokio::test]
async fn an_expired_certificate_is_still_served_so_clients_report_the_real_problem() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let id = enable(app, PlainHttp::Full, HTTP).await;
    let expired = issue_for(DOMAIN, true);
    store(app, &id, &expired).await;
    reload(app).await.unwrap();
    let (address, _server) = serve(app).await;
    let error = fetch(address, expired.root.clone(), "/healthz")
        .await
        .unwrap_err()
        .to_string()
        .to_lowercase();
    assert!(error.contains("expired"), "{error}");
}

#[tokio::test]
async fn a_broken_stored_certificate_keeps_the_previous_one() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let id = enable(app, PlainHttp::Full, HTTP).await;
    let good = issue_for(DOMAIN, false);
    store(app, &id, &good).await;
    reload(app).await.unwrap();
    let mut mismatched = issue_for(DOMAIN, false);
    mismatched.key = issue_for(DOMAIN, false).key;
    store(app, &id, &mismatched).await;
    assert!(reload(app).await.is_err());
    let (address, _server) = serve(app).await;
    assert!(fetch(address, good.root.clone(), "/healthz").await.is_ok());
}

#[tokio::test]
async fn a_client_stalled_in_its_handshake_does_not_block_others() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let id = enable(app, PlainHttp::Full, HTTP).await;
    let issued = issue_for(DOMAIN, false);
    store(app, &id, &issued).await;
    reload(app).await.unwrap();
    let (address, _server) = serve(app).await;
    let _stalled = TcpStream::connect(address).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        fetch(address, issued.root.clone(), "/healthz"),
    )
    .await
    .expect("stalled client held up the accept loop")
    .unwrap();
}

#[tokio::test]
async fn acme_network_policy_sees_the_real_peer_through_tls() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let id = enable(app, PlainHttp::Full, HTTP).await;
    let issued = issue_for(DOMAIN, false);
    store(app, &id, &issued).await;
    reload(app).await.unwrap();
    let (address, _server) = serve(app).await;
    let allowed = fetch(address, issued.root.clone(), "/acme/directory")
        .await
        .unwrap();
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
    assert!(allowed.contains(&format!("\"newOrder\":\"{HTTPS}/acme/new-order\"")));

    app.config.lock().await.value.acme.allowed_networks = vec!["10.0.0.0/8".into()];
    let denied = fetch(address, issued.root.clone(), "/acme/directory")
        .await
        .unwrap();
    assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");
}

#[tokio::test]
async fn startup_adopts_a_matching_certificate_and_restores_renewal() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let tls = tls_config(PlainHttp::Full, HTTP);
    let mut tx = app.db.begin().await.unwrap();
    let id = certificates::insert_request(&mut tx, "admin", &[DOMAIN.to_owned()], false)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    sqlx::query(
        "UPDATE certificates SET auto_renew=0,state='failed',attempts=6,next_attempt=? WHERE id=?",
    )
    .bind(now() + 86400)
    .bind(&id)
    .execute(&app.db)
    .await
    .unwrap();
    let mut tx = app.db.begin().await.unwrap();
    ensure_certificate(&mut tx, &tls).await.unwrap();
    ensure_certificate(&mut tx, &tls).await.unwrap();
    tx.commit().await.unwrap();
    let rows = sqlx::query("SELECT id,auto_renew,state,attempts,next_attempt FROM certificates")
        .fetch_all(&app.db)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "must adopt rather than duplicate");
    assert_eq!(rows[0].get::<String, _>("id"), id);
    assert!(rows[0].get::<bool, _>("auto_renew"));
    assert_eq!(rows[0].get::<String, _>("state"), "queued");
    assert_eq!(rows[0].get::<i64, _>("attempts"), 0);
    assert!(rows[0].get::<i64, _>("next_attempt") <= now());
}

async fn plain(app: &App, method: &str, uri: &str, listener: ListenerKind) -> Response {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, "Bearer admin")
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:12000".parse::<SocketAddr>().unwrap(),
        ))
        .body(Body::empty())
        .unwrap();
    api::listener_router(app.clone(), listener)
        .oneshot(request)
        .await
        .unwrap()
}

#[tokio::test]
async fn full_plain_http_leaves_every_surface_available() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    enable(app, PlainHttp::Full, HTTP).await;
    for (uri, status) in [
        ("/overview", StatusCode::OK),
        ("/api/admin/overview", StatusCode::OK),
        ("/healthz", StatusCode::OK),
        ("/acme/directory", StatusCode::OK),
    ] {
        assert_eq!(
            plain(app, "GET", uri, ListenerKind::Plain).await.status(),
            status,
            "{uri}"
        );
    }
}

#[tokio::test]
async fn acme_only_keeps_bearer_tokens_off_plain_http() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    enable(app, PlainHttp::AcmeOnly, HTTP).await;

    let redirect = plain(app, "GET", "/overview?tab=a", ListenerKind::Plain).await;
    assert_eq!(redirect.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        redirect.headers()[header::LOCATION],
        format!("{HTTPS}/overview?tab=a")
    );
    assert_eq!(redirect.headers()["x-content-type-options"], "nosniff");

    for (method, uri) in [
        ("GET", "/api/admin/overview"),
        ("POST", "/present"),
        ("POST", "/cleanup"),
        ("POST", "/overview"),
    ] {
        assert_eq!(
            plain(app, method, uri, ListenerKind::Plain).await.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri}"
        );
    }
    for uri in ["/healthz", "/acme/directory"] {
        assert_eq!(
            plain(app, "GET", uri, ListenerKind::Plain).await.status(),
            StatusCode::OK,
            "{uri}"
        );
    }
    assert_eq!(
        plain(app, "GET", "/api/admin/overview", ListenerKind::Tls)
            .await
            .status(),
        StatusCode::OK,
        "the policy applies only to the plain listener"
    );
}

#[tokio::test]
async fn invalid_tls_configuration_is_rejected() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let base = app.config.lock().await.value.clone();
    let check = |change: &dyn Fn(&mut Config)| {
        let mut config = base.clone();
        config.server.tls = Some(tls_config(PlainHttp::Full, HTTP));
        config.acme.base_url = HTTPS.into();
        change(&mut config);
        config::normalize(&mut config, &app.vault, &app.drivers).map(|_| config)
    };
    let valid = check(&|_| {}).expect("valid configuration");
    assert_eq!(valid.server.tls.unwrap().plain_http_origin, HTTP);
    assert!(
        check(&|c| c.acme.base_url.clear()).is_ok(),
        "full mode never redirects, so it needs no public URL"
    );

    fn tls(config: &mut Config) -> &mut Tls {
        config.server.tls.as_mut().unwrap()
    }
    type Change = Box<dyn Fn(&mut Config)>;
    let cases: Vec<(&str, Change)> = vec![
        ("terms", Box::new(|c| tls(c).terms_agreed = false)),
        (
            "wildcard",
            Box::new(|c| tls(c).domain = "*.example.com".into()),
        ),
        (
            "no provider",
            Box::new(|c| tls(c).domain = "certs.other.test".into()),
        ),
        (
            "same socket",
            Box::new(|c| {
                let listen = c.server.listen.clone();
                tls(c).listen = listen;
            }),
        ),
        (
            "https plain origin",
            Box::new(|c| tls(c).plain_http_origin = HTTPS.into()),
        ),
        (
            "plain origin path",
            Box::new(|c| tls(c).plain_http_origin = format!("{HTTP}/path")),
        ),
        ("http base url", Box::new(|c| c.acme.base_url = HTTP.into())),
        (
            "other base url host",
            Box::new(|c| c.acme.base_url = "https://other.example.com".into()),
        ),
        (
            "acme_only without a redirect target",
            Box::new(|c| {
                tls(c).plain_http = PlainHttp::AcmeOnly;
                c.acme.base_url.clear();
            }),
        ),
    ];
    for (name, change) in cases {
        assert!(check(&*change).is_err(), "{name}");
    }
}

#[tokio::test]
async fn tls_configuration_round_trips_through_the_config_file() {
    let fixture = Fixture::new().await;
    let app = &fixture.app;
    let mut config = app.config.lock().await.value.clone();
    config.server.tls = Some(tls_config(PlainHttp::AcmeOnly, HTTP));
    let path = fixture.directory.path().join("round-trip.toml");
    config::write(&path, &config).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("[server.tls]"), "{text}");
    assert!(text.contains("plain_http = \"acme_only\""), "{text}");
    let tls = config::ConfigFile::load(path)
        .unwrap()
        .value
        .server
        .tls
        .unwrap();
    assert_eq!(tls.domain, DOMAIN);
    assert_eq!(tls.plain_http, PlainHttp::AcmeOnly);
    assert_eq!(tls.plain_http_origin, HTTP);
}
