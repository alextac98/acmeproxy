use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::process::Command;

#[derive(Clone, Serialize, Deserialize)]
pub struct Driver {
    pub id: String,
    pub name: String,
    pub fields: Vec<Field>,
    pub docs: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Field {
    pub key: String,
    pub label: String,
}

pub fn catalog(home: &Path) -> Vec<Driver> {
    let candidates: Vec<Driver> =
        serde_json::from_str(include_str!("../docs/providers.json")).expect("bundled catalog");
    candidates
        .into_iter()
        .filter(|p| home.join("dnsapi").join(format!("{}.sh", p.id)).is_file())
        .collect()
}

pub fn validate_credentials(
    driver: &Driver,
    credentials: &BTreeMap<String, String>,
) -> Result<(), &'static str> {
    if credentials.is_empty() {
        return Err("enter at least one provider credential");
    }
    for (key, value) in credentials {
        if !driver.fields.iter().any(|f| f.key == *key) {
            return Err("credential field is not in the provider catalog");
        }
        if value.is_empty() || value.len() > 4096 || value.contains(['\0', '\n', '\r']) {
            return Err("credential values must be nonempty single lines of at most 4096 bytes");
        }
    }
    Ok(())
}

// Config files can contain provider record IDs needed for cleanup, as well as credentials.
// The caller encrypts this bundle before persisting it.
#[derive(Default, Serialize, Deserialize)]
pub struct WorkerState {
    pub account: Vec<u8>,
    pub domain: Vec<u8>,
}

pub struct WorkerResult {
    pub state: WorkerState,
    pub error: Option<&'static str>,
}

struct ProcessGroup(u32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        let _ = killpg(Pid::from_raw(self.0 as i32), Signal::SIGKILL);
    }
}

#[derive(Clone)]
pub struct Worker {
    pub home: PathBuf,
    pub scratch: PathBuf,
    pub timeout: Duration,
}
impl Worker {
    pub async fn run(
        &self,
        driver: &str,
        action: &str,
        fqdn: &str,
        value: &str,
        credentials: &BTreeMap<String, String>,
        state: WorkerState,
    ) -> anyhow::Result<WorkerResult> {
        let directory = tempfile::Builder::new()
            .prefix("job-")
            .tempdir_in(&self.scratch)?;
        tokio::fs::write(directory.path().join("account.conf"), &state.account).await?;
        tokio::fs::write(directory.path().join("domain.conf"), &state.domain).await?;
        let mut command = Command::new("/bin/bash");
        command
            .arg("-c")
            .arg(include_str!("../scripts/dnsapi-worker.sh"))
            .arg("dnsapi-worker")
            .arg(&self.home)
            .arg(driver)
            .arg(action)
            .arg(fqdn)
            .arg(value)
            .arg(directory.path())
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", directory.path())
            .env("TMPDIR", directory.path())
            .env("LC_ALL", "C")
            .envs(credentials)
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = command.spawn()?;
        let group = ProcessGroup(
            child
                .id()
                .ok_or_else(|| anyhow::anyhow!("worker has no process ID"))?,
        );
        let error = match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(Ok(status)) if status.success() => None,
            Ok(_) => Some(
                "DNS provider rejected the operation; check credentials and provider requirements",
            ),
            Err(_) => Some("DNS provider timed out; the remote outcome may be unknown"),
        };
        drop(group); // Also terminates grandchildren after timeouts or shell exit.
        let _ = child.wait().await;
        async fn read_config(path: PathBuf) -> anyhow::Result<Vec<u8>> {
            let meta = tokio::fs::symlink_metadata(&path).await?;
            anyhow::ensure!(
                meta.is_file() && meta.len() <= 1024 * 1024,
                "invalid provider state file"
            );
            Ok(tokio::fs::read(path).await?)
        }
        Ok(WorkerResult {
            state: WorkerState {
                account: read_config(directory.path().join("account.conf")).await?,
                domain: read_config(directory.path().join("domain.conf")).await?,
            },
            error,
        })
    }
}
