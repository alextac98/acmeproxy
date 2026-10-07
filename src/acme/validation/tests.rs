use super::*;
use axum::{
    Router,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct Server {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn serve(router: Router) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    Server {
        address,
        task: tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }),
    }
}
fn private_settings() -> Settings {
    Settings {
        validation_networks: vec!["127.0.0.1/32".into()],
        ..Default::default()
    }
}

#[test]
fn public_private_mapped_and_metadata_destination_policy() {
    let mut settings = Settings::default();
    for address in ["8.8.8.8", "2606:4700:4700::1111"] {
        assert!(
            accepts_address(&settings, address.parse().unwrap()),
            "{address}"
        );
    }
    for address in [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.1.2",
        "100.64.1.1",
        "::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "2001:db8::1",
    ] {
        assert!(
            !accepts_address(&settings, address.parse().unwrap()),
            "{address}"
        );
    }
    settings.validation_networks =
        vec!["127.0.0.0/8".into(), "10.0.0.0/8".into(), "fc00::/7".into()];
    for address in ["127.0.0.1", "10.1.2.3", "fc00::1", "::ffff:127.0.0.1"] {
        assert!(
            accepts_address(&settings, address.parse().unwrap()),
            "{address}"
        );
    }
    settings.validation_networks = vec!["0.0.0.0/0".into(), "::/0".into()];
    for address in [
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "169.254.169.254",
        "::ffff:169.254.169.254",
        "100.100.100.200",
        "::",
        "fe80::1",
        "ff02::1",
        "fd00:ec2::254",
        "64:ff9b::a9fe:a9fe",
        "2002:a9fe:a9fe::1",
        "2001::1",
    ] {
        assert!(
            !accepts_address(&settings, address.parse().unwrap()),
            "{address}"
        );
    }
}

#[test]
fn redirects_keep_hostname_path_and_standard_ports() {
    let path = "/.well-known/acme-challenge/token";
    let current = url::Url::parse(&format!("http://service.example.com{path}")).unwrap();
    for target in [
        format!("https://service.example.com{path}"),
        format!("http://service.example.com:80{path}"),
        path.into(),
    ] {
        assert!(
            redirect_url(&current, &target, "service.example.com", path).is_ok(),
            "{target}"
        );
    }
    for target in [
        format!("http://other.example.com{path}"),
        format!("http://127.0.0.1{path}"),
        format!("https://service.example.com:8443{path}"),
        format!("http://user:password@service.example.com{path}"),
        "/admin".into(),
        format!("{path}?target=internal"),
        format!("{path}#fragment"),
        "file:///etc/passwd".into(),
    ] {
        assert!(
            redirect_url(&current, &target, "service.example.com", path).is_err(),
            "{target}"
        );
    }
}

#[tokio::test]
async fn pinned_http_host_account_binding_status_and_body_limit() {
    let value = Arc::new(Mutex::new((
        StatusCode::OK,
        "token.thumbprint\r\n".to_string(),
    )));
    let response = value.clone();
    let server = serve(Router::new().route(
        "/.well-known/acme-challenge/token",
        get(move |headers: HeaderMap| {
            assert_eq!(headers["host"], "service.example.com");
            let value = response.lock().unwrap().clone();
            async move { value }
        }),
    ))
    .await;
    let settings = private_settings();
    assert!(
        verify_resolved(
            "service.example.com",
            "token.thumbprint",
            &settings,
            &[server.address]
        )
        .await
        .is_ok()
    );
    for body in [
        "token.other-account".into(),
        "token".into(),
        " token.thumbprint".into(),
        "x".repeat(4097),
    ] {
        *value.lock().unwrap() = (StatusCode::OK, body);
        assert_eq!(
            verify_resolved(
                "service.example.com",
                "token.thumbprint",
                &settings,
                &[server.address]
            )
            .await
            .unwrap_err()
            .kind,
            "unauthorized"
        );
    }
    *value.lock().unwrap() = (StatusCode::NOT_FOUND, "token.thumbprint".into());
    assert!(
        verify_resolved(
            "service.example.com",
            "token.thumbprint",
            &settings,
            &[server.address]
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn blocked_dns_answers_never_make_an_http_request() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let server = serve(Router::new().fallback(get(move || {
        seen.fetch_add(1, Ordering::SeqCst);
        async { "token.thumbprint" }
    })))
    .await;
    let public: SocketAddr = "8.8.8.8:80".parse().unwrap();
    for addresses in [vec![], vec![server.address], vec![public, server.address]] {
        assert!(
            verify_resolved(
                "service.example.com",
                "token.thumbprint",
                &Settings::default(),
                &addresses
            )
            .await
            .is_err()
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn redirects_cannot_fetch_other_hosts_paths_or_loop_forever() {
    let target = Arc::new(Mutex::new(String::new()));
    let location = target.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let server = serve(Router::new().fallback(get(move || {
        seen.fetch_add(1, Ordering::SeqCst);
        let target = location.lock().unwrap().clone();
        async move { (StatusCode::FOUND, [("location", target)], "").into_response() }
    })))
    .await;
    for destination in [
        "http://169.254.169.254/latest/meta-data/",
        "http://other.example.com/.well-known/acme-challenge/token",
        "/admin",
    ] {
        *target.lock().unwrap() = destination.into();
        assert!(
            verify_resolved(
                "service.example.com",
                "token.thumbprint",
                &private_settings(),
                &[server.address]
            )
            .await
            .is_err()
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "forbidden redirect targets are never fetched"
    );
    *target.lock().unwrap() = "/.well-known/acme-challenge/token".into();
    assert_eq!(
        verify_resolved(
            "service.example.com",
            "token.thumbprint",
            &private_settings(),
            &[server.address]
        )
        .await
        .unwrap_err()
        .detail,
        "Too many HTTP-01 redirects"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 14);
}
