//! Native HTTPS for this server's own listeners. The certificate comes from the managed
//! certificate worker, which only needs outbound access to the CA and DNS provider, so
//! issuing it never depends on these listeners being up.
use crate::{App, certificates, config::Tls, now};
use sqlx::{Row, Sqlite, Transaction};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
    task::JoinHandle,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        crypto::{CryptoProvider, ring},
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
        server::{ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
    },
    server::TlsStream,
};

const MAX_HANDSHAKES: usize = 256;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The certificate presented to clients. With none loaded, handshakes fail: a self-signed
/// stand-in would only teach operators to click through a warning with their admin token.
#[derive(Debug, Default)]
pub struct ServerCert(RwLock<Option<Arc<CertifiedKey>>>);
impl ServerCert {
    fn set(&self, key: CertifiedKey) {
        *self.0.write().expect("certificate lock") = Some(Arc::new(key));
    }
}
impl ResolvesServerCert for ServerCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.read().expect("certificate lock").clone()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn certificate_domains(tls: &Tls) -> String {
    serde_json::Value::from(vec![tls.domain.as_str()]).to_string()
}

/// The `certificates` row serving HTTPS is whichever matches the configured name and CA.
pub(crate) async fn identity(app: &App) -> Option<(String, bool)> {
    let config = app.config.lock().await;
    let tls = config.value.server.tls.as_ref()?;
    Some((certificate_domains(tls), tls.staging))
}

/// Request the server certificate, or adopt a matching one requested through the UI.
pub async fn ensure_certificate(tx: &mut Transaction<'_, Sqlite>, tls: &Tls) -> anyhow::Result<()> {
    // Writing first takes SQLite's write lock up front; a read-then-write transaction
    // fails immediately if another connection commits in between.
    // A restart is the operator's signal to retry now instead of on the daily schedule.
    let adopted = sqlx::query("UPDATE certificates SET auto_renew=1,attempts=CASE WHEN state='failed' THEN 0 ELSE attempts END,next_attempt=CASE WHEN state='failed' THEN ? ELSE next_attempt END,state=CASE WHEN state='failed' THEN 'queued' ELSE state END WHERE domains=? AND staging=?")
        .bind(now())
        .bind(certificate_domains(tls))
        .bind(tls.staging)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    if adopted == 0 {
        certificates::insert_request(tx, "system", std::slice::from_ref(&tls.domain), tls.staging)
            .await?;
    }
    Ok(())
}

fn certified_key(fullchain: &[u8], private_key: &[u8]) -> anyhow::Result<CertifiedKey> {
    let chain = CertificateDer::pem_slice_iter(fullchain).collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(!chain.is_empty(), "certificate chain is empty");
    Ok(CertifiedKey::from_der(
        chain,
        PrivateKeyDer::from_pem_slice(private_key)?,
        &provider(),
    )?)
}

/// Swap in the stored certificate. New handshakes use it; open connections are unaffected.
pub async fn reload(app: &App) -> anyhow::Result<()> {
    let Some((domains, staging)) = identity(app).await else {
        return Ok(());
    };
    let Some(row) = sqlx::query("SELECT id,fullchain,private_key FROM certificates WHERE domains=? AND staging=? AND fullchain IS NOT NULL AND private_key IS NOT NULL")
        .bind(domains)
        .bind(staging)
        .fetch_optional(&app.db)
        .await?
    else {
        return Ok(());
    };
    let id: String = row.get("id");
    let private_key = app
        .vault
        .open(&format!("certificate:{id}"), row.get("private_key"))?;
    let chain: String = row.get("fullchain");
    app.server_cert
        .set(certified_key(chain.as_bytes(), &private_key)?);
    tracing::info!("HTTPS certificate loaded");
    Ok(())
}

/// Accepts TLS connections for `axum::serve`, which awaits `accept` serially. Handshakes
/// run on their own tasks so that one slow client cannot hold up every new connection.
pub struct TlsListener {
    connections: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    address: SocketAddr,
    accepting: JoinHandle<()>,
}
impl Drop for TlsListener {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}
impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.connections.recv().await {
            Some(connection) => connection,
            // The accept task only exits when this listener is dropped.
            None => std::future::pending().await,
        }
    }
    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.address)
    }
}

pub fn listen(listener: TcpListener, certificate: Arc<ServerCert>) -> anyhow::Result<TlsListener> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(certificate);
    // The server is built without axum's http2 feature.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let address = listener.local_addr()?;
    let (sender, connections) = mpsc::channel(64);
    let accepting = tokio::spawn(async move {
        let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
        loop {
            // Waiting here leaves excess connections in the kernel's accept backlog.
            let Ok(permit) = handshakes.clone().acquire_owned().await else {
                return;
            };
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let sender = sender.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream));
                let Ok(Ok(stream)) = handshake.await else {
                    return;
                };
                let _ = sender.send((stream, peer)).await;
            });
        }
    });
    Ok(TlsListener {
        connections,
        address,
        accepting,
    })
}

#[cfg(test)]
#[path = "server_tls_tests.rs"]
pub(crate) mod tests;
