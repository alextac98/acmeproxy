//! Durable, independent downstream HTTP-01 validation. Never publishes DNS.
use super::{Settings, check_order_access};
use crate::{App, now};
use sqlx::Row;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[derive(Debug)]
pub(super) struct Failure {
    kind: &'static str,
    detail: &'static str,
}
impl Failure {
    fn new(kind: &'static str, detail: &'static str) -> Self {
        Self { kind, detail }
    }
    fn json(&self) -> serde_json::Value {
        serde_json::json!({"type":format!("urn:ietf:params:acme:error:{}",self.kind),"detail":self.detail})
    }
}
type Result<T> = std::result::Result<T, Failure>;

fn accepts_address(settings: &Settings, address: IpAddr) -> bool {
    let address = address.to_canonical();
    // Never visit unspecified, multicast, link-local or metadata destinations,
    // even when an operator grants a broad private-network exception.
    match address {
        IpAddr::V4(ip)
            if ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_link_local()
                || ip == std::net::Ipv4Addr::new(100, 100, 100, 200) =>
        {
            return false;
        }
        IpAddr::V6(ip)
            if ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip == "fd00:ec2::254".parse::<std::net::Ipv6Addr>().unwrap() =>
        {
            return false;
        }
        _ => {}
    }
    let reserved = match address {
        IpAddr::V4(_) => [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "240.0.0.0/4",
        ]
        .iter()
        .any(|net| net.parse::<ipnet::IpNet>().unwrap().contains(&address)),
        IpAddr::V6(_) => {
            !"2000::/3"
                .parse::<ipnet::IpNet>()
                .unwrap()
                .contains(&address)
                || ["2001::/23", "2001:db8::/32", "2002::/16"]
                    .iter()
                    .any(|net| net.parse::<ipnet::IpNet>().unwrap().contains(&address))
        }
    };
    // Transition mechanisms can tunnel to otherwise forbidden IPv4 addresses.
    if ["64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32"]
        .iter()
        .any(|net| net.parse::<ipnet::IpNet>().unwrap().contains(&address))
    {
        return false;
    }
    !reserved
        || settings.validation_networks.iter().any(|net| {
            net.parse::<ipnet::IpNet>()
                .is_ok_and(|net| net.contains(&address))
        })
}

fn redirect_url(current: &url::Url, location: &str, domain: &str, path: &str) -> Result<url::Url> {
    let next = current
        .join(location)
        .map_err(|_| Failure::new("unauthorized", "Invalid HTTP-01 redirect"))?;
    if !matches!(next.scheme(), "http" | "https")
        || next.host_str() != Some(domain)
        || next.path() != path
        || next.query().is_some()
        || next.fragment().is_some()
        || !next.username().is_empty()
        || next.password().is_some()
        || !matches!(
            (next.scheme(), next.port_or_known_default()),
            ("http", Some(80)) | ("https", Some(443))
        )
    {
        return Err(Failure::new(
            "unauthorized",
            "HTTP-01 redirects must keep the hostname and challenge path on HTTP port 80 or HTTPS port 443",
        ));
    }
    Ok(next)
}

async fn verify_http(domain: &str, expected: &str, settings: &Settings) -> Result<()> {
    let lookup = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((domain, 80)),
    )
    .await;
    let addresses: Vec<_> = lookup
        .map_err(|_| Failure::new("dns", "HTTP-01 DNS lookup timed out"))?
        .map_err(|_| Failure::new("dns", "HTTP-01 DNS lookup failed"))?
        .map(|address| SocketAddr::new(address.ip().to_canonical(), 80))
        .collect();
    verify_resolved(domain, expected, settings, &addresses).await
}

// The resolved addresses are pinned for the entire redirect chain. The production
// resolver always uses port 80; tests can map a hostname to an isolated high port.
pub(super) async fn verify_resolved(
    domain: &str,
    expected: &str,
    settings: &Settings,
    addresses: &[SocketAddr],
) -> Result<()> {
    if addresses.is_empty() {
        return Err(Failure::new("dns", "No HTTP-01 addresses found"));
    }
    if addresses
        .iter()
        .any(|address| !accepts_address(settings, address.ip()))
    {
        return Err(Failure::new(
            "connection",
            "HTTP-01 destination is outside the permitted validation networks",
        ));
    }
    let token = expected
        .split_once('.')
        .ok_or_else(|| Failure::new("serverInternal", "Missing HTTP-01 key authorization"))?
        .0;
    let path = format!("/.well-known/acme-challenge/{token}");
    let mut url = url::Url::parse(&format!("http://{domain}{path}"))
        .map_err(|_| Failure::new("malformed", "Invalid HTTP-01 hostname"))?;
    for _ in 0..=10 {
        let targets: Vec<_> = addresses
            .iter()
            .map(|address| {
                SocketAddr::new(
                    address.ip(),
                    if url.scheme() == "https" {
                        443
                    } else {
                        address.port()
                    },
                )
            })
            .collect();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .http1_only()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            // Like LE, allow bootstrap HTTPS redirects with expired/self-signed certs.
            // This client is used exclusively for HTTP-01, with pinned destinations.
            .danger_accept_invalid_certs(true)
            .resolve_to_addrs(domain, &targets)
            .user_agent("AcmeProxy HTTP-01 validator")
            .build()
            .map_err(|_| {
                Failure::new("serverInternal", "Could not initialize HTTP-01 validation")
            })?;
        let mut response = client.get(url.clone()).send().await.map_err(|_| {
            Failure::new(
                "connection",
                "HTTP-01 request failed; check DNS, routing and port 80",
            )
        })?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| {
                    Failure::new("unauthorized", "HTTP-01 redirect has no valid Location")
                })?;
            url = redirect_url(&url, location, domain, &path)?;
            continue;
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(Failure::new(
                "unauthorized",
                "HTTP-01 challenge endpoint did not return HTTP 200",
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Failure::new("connection", "Could not read HTTP-01 response"))?
        {
            if body.len() + chunk.len() > 4096 {
                return Err(Failure::new(
                    "unauthorized",
                    "HTTP-01 response exceeds 4096 bytes",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        if body.trim_ascii_end() != expected.as_bytes() {
            return Err(Failure::new(
                "unauthorized",
                "HTTP-01 response does not match the requesting ACME account",
            ));
        }
        return Ok(());
    }
    Err(Failure::new("unauthorized", "Too many HTTP-01 redirects"))
}

pub(super) async fn process_one_with<F, Fut>(app: &App, perform: F) -> anyhow::Result<bool>
where
    F: FnOnce(String, String, Settings) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let (id, index, domain, expected, settings) = {
        let _guard = app.mutation.lock().await;
        anyhow::ensure!(
            app.healthy.load(std::sync::atomic::Ordering::SeqCst),
            "configuration needs restart"
        );
        sqlx::query("UPDATE acme_orders SET state='invalid',error='Order expired',updated_at=? WHERE state IN ('pending','ready','processing') AND expires_at<=?")
            .bind(now()).bind(now()).execute(&app.db).await?;
        sqlx::query("UPDATE acme_authorizations SET state='invalid',error=? WHERE state IN ('pending','processing') AND order_id IN (SELECT id FROM acme_orders WHERE state='invalid')")
            .bind(Failure::new("unauthorized", "Order expired or was cancelled").json().to_string()).execute(&app.db).await?;
        let row = sqlx::query("SELECT a.* FROM acme_authorizations a JOIN acme_orders o ON o.id=a.order_id WHERE a.state='processing' AND a.next_attempt<=? AND o.state='pending' ORDER BY a.next_attempt,o.created_at,a.identifier_index LIMIT 1")
            .bind(now()).fetch_optional(&app.db).await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let id: String = row.get("order_id");
        let index: i64 = row.get("identifier_index");
        sqlx::query("UPDATE acme_authorizations SET attempts=attempts+1,next_attempt=? WHERE order_id=? AND identifier_index=?")
            .bind(now()+45).bind(&id).bind(index).execute(&app.db).await?;
        (
            id,
            index,
            row.get::<String, _>("domain"),
            row.get::<String, _>("key_authorization"),
            app.config.lock().await.value.acme.clone(),
        )
    };
    let result = if check_order_access(app, &id).await.is_err() {
        Err(Failure::new(
            "unauthorized",
            "Order is no longer authorized",
        ))
    } else {
        tokio::time::timeout(
            Duration::from_secs(30),
            perform(domain, expected, settings.clone()),
        )
        .await
        .unwrap_or_else(|_| Err(Failure::new("connection", "HTTP-01 validation timed out")))
    };
    let _guard = app.mutation.lock().await;
    let policy_changed = check_order_access(app, &id).await.is_err()
        || app.config.lock().await.value.acme.validation_networks != settings.validation_networks;
    let result = if policy_changed {
        Err(Failure::new(
            "unauthorized",
            "HTTP-01 policy changed or the order expired",
        ))
    } else {
        result
    };
    let mut tx = app.db.begin().await?;
    match result {
        Ok(()) => {
            sqlx::query("UPDATE acme_authorizations SET state='valid',validated_at=?,error=NULL WHERE order_id=? AND identifier_index=? AND state='processing'")
                .bind(now()).bind(&id).bind(index).execute(&mut *tx).await?;
            sqlx::query("UPDATE acme_orders SET state='ready',phase='Awaiting client CSR',updated_at=? WHERE id=? AND state='pending' AND NOT EXISTS(SELECT 1 FROM acme_authorizations WHERE order_id=? AND state!='valid')")
                .bind(now()).bind(&id).bind(&id).execute(&mut *tx).await?;
        }
        Err(failure) => {
            sqlx::query("UPDATE acme_authorizations SET state=CASE WHEN attempts>=3 OR ? THEN 'invalid' ELSE 'processing' END,error=?,next_attempt=? WHERE order_id=? AND identifier_index=? AND state='processing'")
                .bind(policy_changed).bind(failure.json().to_string()).bind(now()+10).bind(&id).bind(index).execute(&mut *tx).await?;
            sqlx::query("UPDATE acme_orders SET state='invalid',error=?,updated_at=? WHERE id=? AND EXISTS(SELECT 1 FROM acme_authorizations WHERE order_id=? AND state='invalid')")
                .bind(failure.detail).bind(now()).bind(&id).bind(&id).execute(&mut *tx).await?;
        }
    }
    sqlx::query("INSERT INTO audit(at,actor,action,target,outcome) SELECT ?,'http01-validator','acme.http01_validated',?,state FROM acme_authorizations WHERE order_id=? AND identifier_index=?")
        .bind(now()).bind(format!("{id}/{index}")).bind(&id).bind(index).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn run_worker(app: App) {
    loop {
        let result = process_one_with(&app, |domain, expected, settings| async move {
            verify_http(&domain, &expected, &settings).await
        })
        .await;
        if matches!(result, Ok(true)) {
            continue;
        }
        if result.is_err() {
            tracing::error!("HTTP-01 validation worker failed; retrying");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests;
