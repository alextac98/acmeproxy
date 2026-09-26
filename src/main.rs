use acmeproxy::{App, api, config, provider, security, store};
use fs2::FileExt;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

fn private_dir(path: &std::path::Path) -> anyhow::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "acmeproxy=info".into()),
        )
        .init();
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "serve".into());
    if mode == "--version" {
        println!(
            "acmeproxy {}",
            acmeproxy::build_info::current().display_version
        );
        return Ok(());
    }
    let data = match args.next().as_deref() {
        Some("--config-dir") => PathBuf::from(
            args.next()
                .ok_or_else(|| anyhow::anyhow!("--config-dir requires a directory"))?,
        ),
        None => PathBuf::from("data"),
        _ => anyhow::bail!("usage: acmeproxy [init|serve] [--config-dir DIRECTORY]"),
    };
    anyhow::ensure!(args.next().is_none(), "unexpected extra argument");
    private_dir(&data)?;
    if mode == "init" {
        if !data.join("master.key").exists() {
            let encrypted_config = fs::read_to_string(data.join("config.toml"))
                .is_ok_and(|text| text.contains("encrypted_credentials"));
            anyhow::ensure!(
                !data.join("acmeproxy.sqlite").exists() && !encrypted_config,
                "existing encrypted state has no master.key; restore the original key from backup"
            );
        }
        for filename in ["master.key", "admin.token"] {
            let path = data.join(filename);
            if path.exists() {
                continue;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            writeln!(file, "{}", security::random_secret())?;
            file.sync_all()?;
        }
        if !data.join("config.toml").exists() {
            config::write(&data.join("config.toml"), &config::Config::default())?;
        }
        println!(
            "Initialized {}. Edit config.toml; read admin.token locally to sign in. Back up this directory securely.",
            data.display()
        );
        return Ok(());
    }
    anyhow::ensure!(mode == "serve", "usage: acmeproxy [init|serve]");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(data.join("server.lock"))?;
    lock.try_lock_exclusive()
        .map_err(|_| anyhow::anyhow!("another server is already using this data directory"))?;
    let vault = security::Vault::new(
        &fs::read_to_string(data.join("master.key"))
            .map_err(|_| anyhow::anyhow!("missing master.key; run acmeproxy init first"))?,
    )?;
    let admin = fs::read_to_string(data.join("admin.token"))?;
    anyhow::ensure!(
        admin.trim().len() >= 32,
        "admin token must contain at least 32 characters"
    );
    let mut file = config::ConfigFile::load(data.join("config.toml"))?;
    let home = data
        .join(&file.value.server.dnsapi_home)
        .canonicalize()
        .map_err(|_| anyhow::anyhow!("DNS adapters missing; run sh scripts/install-dnsapi.sh"))?;
    anyhow::ensure!(
        home.join("acme.sh").is_file(),
        "DNS adapter directory has no acme.sh"
    );
    let scratch = data.join("scratch");
    // No other process can own a worker here after acquiring the exclusive lock.
    // Production should mount scratch on tmpfs so interrupted jobs leave no secrets on disk.
    private_dir(&scratch)?;
    for entry in fs::read_dir(&scratch)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("job-") && entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        }
    }
    let drivers = provider::catalog(&home);
    config::normalize(&mut file.value, &vault, &drivers)?;
    let db = store::connect(&data.join("acmeproxy.sqlite"), &vault).await?;
    let mut tx = db.begin().await?;
    config::sync(&mut tx, &file.value).await?;
    config::write(&file.path, &file.value)?;
    tx.commit().await?;
    let address = file.value.server.listen.clone();
    let timeout = Duration::from_secs(file.value.server.worker_timeout_seconds);
    let app = App {
        db,
        vault,
        admin_hash: security::hash(admin.trim()),
        drivers: Arc::new(drivers),
        worker: provider::Worker {
            home,
            scratch: scratch.canonicalize()?,
            timeout,
        },
        mutation: Arc::new(tokio::sync::Mutex::new(())),
        wake: Arc::new(tokio::sync::Notify::new()),
        config: Arc::new(tokio::sync::Mutex::new(file)),
        healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    let listener = tokio::net::TcpListener::bind(&address).await?;
    let worker = tokio::spawn(store::run_worker(app.clone()));
    let certificates = tokio::spawn(acmeproxy::certificates::run_worker(app.clone()));
    tracing::info!(%address, providers=app.drivers.len(), "ACME Proxy listening");
    axum::serve(
        listener,
        api::router(app).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    })
    .await?;
    certificates.abort();
    let _ = certificates.await;
    worker.abort();
    let _ = worker.await;
    drop(lock);
    Ok(())
}
