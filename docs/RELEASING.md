# Release ACME Proxy

`main` is staging. Releases are deliberate snapshots: merging code does not publish anything.

## Make a release

1. Test your changes on `main`, including a real DNS provider when relevant.
2. Set `package.version` in `Cargo.toml`, the single source of truth. Run `cargo check` to refresh `Cargo.lock`, then commit and push both to `main`. Use a version newer than the last release.
3. In GitHub Actions, select **Release → Run workflow → main**. There are no inputs or follow-up workflows.

The workflow runs CI, builds AMD64/ARM64 images, and tests installation, upgrades, and backup/restore with mocked DNS. It then publishes the Git tag, versioned GHCR image, and GitHub release with installation instructions and a deployment kit. Stable releases also update `latest`; prereleases do not.

For example, version `0.1.1` produces GitHub release `v0.1.1` and image `ghcr.io/alextac98/acmeproxy:0.1.1`. The kit pins the exact tested image, so deployments update only when their owners choose. The release page links to readable install and upgrade guides; the archive includes offline copies.

The GHCR package must be **Public** (Packages → acmeproxy → Package settings). After publication, use the [smoke-test checklist](SMOKE_TESTING.md) to verify the public download and installation.

## If something fails

Fix transient issues and **rerun failed jobs in the same workflow run**. This preserves the already-tested image digests and lets an interrupted publication finish. An incomplete draft may briefly exist while assets upload; the workflow publishes it automatically.

If code needs changing, fix it on `main`. If the failed attempt already created a version tag or release, use a new patch version. Never overwrite a published version. A new workflow run or “rerun all jobs” will reject an existing version.

## Release tooling

To refresh an existing release's description without rebuilding, download its `release.json`, then run:

```sh
python3 -m venv .local/release-venv
source .local/release-venv/bin/activate
python3 -m pip install -r scripts/requirements-release.txt
python3 scripts/release.py describe --metadata release.json \
  --repo alextac98/acmeproxy --output release-description.md
# Review the generated Markdown, then update the matching release:
gh release edit v0.1.0 --repo alextac98/acmeproxy --notes-file release-description.md
```

Replace `v0.1.0` with the tag in the downloaded metadata. This edits only the release-page text.

Edit the Markdown in [scripts/templates](../scripts/templates/) to change the release page. It uses Jinja2; the workflows install its pinned dependency automatically. With the environment above active, run `python3 -m unittest discover -s tests/release` to check release tooling.


The workflow marks images as release builds (`v0.1.1`). Local builds show the version plus the short Git commit and `-dirty` for uncommitted changes. The footer links to the release or commit.
