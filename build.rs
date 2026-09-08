use std::{env, path::PathBuf, process::Command};

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args([
            "-c",
            &format!("safe.directory={}", env::current_dir().ok()?.display()),
        ])
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    env::set_current_dir(&root).unwrap();
    // Include new/untracked files and Git-only changes when deciding whether to recapture state.
    println!("cargo:rerun-if-changed={}", root.display());
    for location in ["--git-dir", "--git-common-dir"] {
        if let Some(path) = git(&["rev-parse", location]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    for name in ["ACMEPROXY_REVISION", "ACMEPROXY_RELEASE"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let head = git(&["rev-parse", "HEAD"]);
    let supplied = env::var("ACMEPROXY_REVISION")
        .ok()
        .filter(|s| !s.is_empty() && s != "unknown");
    if let (Some(head), Some(supplied)) = (&head, &supplied) {
        assert_eq!(
            head, supplied,
            "Supplied revision must match the source checkout"
        );
    }
    let checkout_available = head.is_some();
    let revision = head
        .or(supplied)
        .filter(|s| s.len() == 40 && s.bytes().all(|c| c.is_ascii_hexdigit()));
    let status = git(&["status", "--porcelain", "--untracked-files=normal"]);
    let dirty = status.as_ref().is_some_and(|s| !s.is_empty());
    let release = env::var("ACMEPROXY_RELEASE").is_ok_and(|s| s == "true");
    assert!(
        !release || (checkout_available && revision.is_some() && status.is_some() && !dirty),
        "Release builds require a known commit and clean checkout"
    );
    println!(
        "cargo:rustc-env=ACMEPROXY_BUILD_REVISION={}",
        revision.as_deref().unwrap_or("unknown")
    );
    println!("cargo:rustc-env=ACMEPROXY_BUILD_DIRTY={dirty}");
    println!("cargo:rustc-env=ACMEPROXY_BUILD_RELEASE={release}");
}
