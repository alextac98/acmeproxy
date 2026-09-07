pub mod api;
pub mod config;
pub mod provider;
pub mod security;
pub mod store;

use sqlx::SqlitePool;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, Notify};

#[derive(Clone)]
pub struct App {
    pub db: SqlitePool,
    pub vault: security::Vault,
    pub admin_hash: Vec<u8>,
    pub worker: provider::Worker,
    pub drivers: Arc<Vec<provider::Driver>>,
    pub mutation: Arc<Mutex<()>>,
    pub wake: Arc<Notify>,
    pub config: Arc<Mutex<config::ConfigFile>>,
    pub healthy: Arc<std::sync::atomic::AtomicBool>,
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
