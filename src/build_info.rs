use serde::Serialize;

#[derive(Serialize)]
pub struct BuildInfo {
    pub version: &'static str,
    pub revision: &'static str,
    pub dirty: bool,
    pub release: bool,
    pub display_version: String,
    pub version_url: Option<String>,
}

pub fn current() -> BuildInfo {
    describe(
        env!("CARGO_PKG_VERSION"),
        env!("ACMEPROXY_BUILD_REVISION"),
        env!("ACMEPROXY_BUILD_DIRTY") == "true",
        env!("ACMEPROXY_BUILD_RELEASE") == "true",
    )
}

fn describe(
    version: &'static str,
    revision: &'static str,
    dirty: bool,
    release: bool,
) -> BuildInfo {
    let known = revision.len() == 40 && revision.bytes().all(|c| c.is_ascii_hexdigit());
    let repo = "https://github.com/alextac98/acmeproxy";
    let (display_version, version_url) = if release {
        (
            format!("v{version}"),
            Some(format!("{repo}/releases/tag/v{version}")),
        )
    } else {
        let commit = if known { &revision[..7] } else { "dev" };
        (
            format!("v{version}-{commit}{}", if dirty { "-dirty" } else { "" }),
            known.then(|| format!("{repo}/commit/{revision}")),
        )
    };
    BuildInfo {
        version,
        revision,
        dirty,
        release,
        display_version,
        version_url,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SHA: &str = "abcdef01abcdef01abcdef01abcdef01abcdef01";

    #[test]
    fn dev_builds_link_to_commit_and_mark_changes() {
        for dirty in [false, true] {
            let info = describe("0.1.0", SHA, dirty, false);
            assert_eq!(
                info.display_version,
                if dirty {
                    "v0.1.0-abcdef0-dirty"
                } else {
                    "v0.1.0-abcdef0"
                }
            );
            assert_eq!(
                info.version_url,
                Some(format!(
                    "https://github.com/alextac98/acmeproxy/commit/{SHA}"
                ))
            );
        }
    }

    #[test]
    fn releases_link_to_version_tag() {
        let info = describe("0.1.0", SHA, false, true);
        assert_eq!(info.display_version, "v0.1.0");
        assert_eq!(
            info.version_url.as_deref(),
            Some("https://github.com/alextac98/acmeproxy/releases/tag/v0.1.0")
        );
    }

    #[test]
    fn source_without_git_does_not_invent_a_commit() {
        let info = describe("0.1.0", "unknown", false, false);
        assert_eq!(info.display_version, "v0.1.0-dev");
        assert!(info.version_url.is_none());
    }
}
