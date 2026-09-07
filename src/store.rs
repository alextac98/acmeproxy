use crate::{App, now, provider::WorkerState};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{path::Path, time::Duration};

pub async fn connect(path: &Path, vault: &crate::security::Vault) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5));
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    sqlx::migrate!().run(&db).await?;
    let marker: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT value FROM metadata WHERE key='vault_check'")
            .fetch_optional(&db)
            .await?;
    match marker {
        Some(bytes) => {
            anyhow::ensure!(
                vault.open("vault_check", &bytes)? == b"acmeproxy",
                "invalid vault marker"
            );
        }
        None => {
            sqlx::query("INSERT INTO metadata(key,value) VALUES('vault_check',?)")
                .bind(vault.seal("vault_check", b"acmeproxy")?)
                .execute(&db)
                .await?;
        }
    }
    Ok(db)
}

pub async fn audit(
    db: &SqlitePool,
    actor: &str,
    action: &str,
    target: &str,
    outcome: &str,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO audit(at,actor,action,target,outcome) VALUES(?,?,?,?,?)")
        .bind(now())
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(outcome)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn process_one(app: &App) -> anyhow::Result<bool> {
    // One worker and one process per DB. The same lock protects credential rotation and ownership changes.
    let _guard = app.mutation.lock().await;
    anyhow::ensure!(
        app.healthy.load(std::sync::atomic::Ordering::SeqCst),
        "restart required to reconcile configuration"
    );
    sqlx::query("UPDATE challenges SET state='cleanup_pending', operation='cleanup', attempts=0, next_attempt=?, updated_at=? WHERE expires_at<=? AND (state IN ('active','present_pending') OR (state='failed' AND operation='present'))")
        .bind(now()).bind(now()).bind(now()).execute(&app.db).await?;
    let Some(job) = sqlx::query("SELECT c.*, p.driver FROM challenges c JOIN providers p ON c.provider_id=p.id WHERE c.state IN ('present_pending','cleanup_pending') AND c.next_attempt<=? ORDER BY CASE c.operation WHEN 'cleanup' THEN 0 ELSE 1 END, c.next_attempt, c.created_at LIMIT 1")
        .bind(now()).fetch_optional(&app.db).await? else { return Ok(false); };
    let id: String = job.get("id");
    let provider: String = job.get("provider_id");
    let operation: String = job.get("operation");
    let credentials = serde_json::from_slice(
        &app.vault
            .open(&provider, &job.get::<Vec<u8>, _>("credentials_snapshot"))?,
    )?;
    let state = match job.get::<Option<Vec<u8>>, _>("worker_state") {
        Some(bytes) => serde_json::from_slice(&app.vault.open(&id, &bytes)?)?,
        None => WorkerState::default(),
    };
    let attempts: i64 = job.get::<i64, _>("attempts") + 1;
    // Persist the attempt before touching DNS. A process crash leaves a retryable pending operation.
    sqlx::query("UPDATE challenges SET attempts=?, next_attempt=?, updated_at=? WHERE id=?")
        .bind(attempts)
        .bind(now() + 30)
        .bind(now())
        .bind(&id)
        .execute(&app.db)
        .await?;
    let result = app
        .worker
        .run(
            job.get("driver"),
            if operation == "present" { "add" } else { "rm" },
            job.get("fqdn"),
            job.get("value"),
            &credentials,
            state,
        )
        .await;
    let (state, error) = match result {
        Ok(result) => (
            Some(app.vault.seal(&id, &serde_json::to_vec(&result.state)?)?),
            result.error,
        ),
        Err(_) => (None, Some("DNS worker could not complete the operation")),
    };
    let status = if error.is_none() {
        if operation == "present" {
            "active"
        } else {
            "cleaned"
        }
    } else if attempts >= 5 {
        "failed"
    } else if operation == "present" {
        "present_pending"
    } else {
        "cleanup_pending"
    };
    let mut tx = app.db.begin().await?;
    sqlx::query("UPDATE challenges SET state=?, worker_state=COALESCE(?,worker_state), last_error=?, updated_at=?, next_attempt=? WHERE id=?")
        .bind(status).bind(state).bind(error).bind(now()).bind(now()+2_i64.pow(attempts.min(8) as u32))
        .bind(&id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit(at,actor,action,target,outcome) VALUES(?,'worker',?,?,?)")
        .bind(now())
        .bind(&operation)
        .bind(&id)
        .bind(status)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!(challenge_id=%id, operation=%operation, state=status, "DNS operation completed");
    Ok(true)
}

pub async fn run_worker(app: App) {
    loop {
        match process_one(&app).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(_) => tracing::error!("worker storage or vault operation failed; retrying"),
        }
        tokio::select! {
            _ = app.wake.notified() => {},
            _ = tokio::time::sleep(Duration::from_secs(1)) => {},
        }
    }
}
