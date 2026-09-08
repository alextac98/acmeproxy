# Release ACME Proxy

Releases are manual snapshots of `main`. **Prepare** builds and tests a release; **Publish** makes those same images available to users. Merging code does not release it.

## Make a release

1. Edit `package.version` in `Cargo.toml`—the single source of truth. Run `cargo check` to refresh `Cargo.lock`, then commit both files. The first release is `0.1.0`.
2. Merge to `main`. In GitHub Actions, run **Prepare Release** from `main`.
3. Wait for it to pass. It builds and tests AMD64/ARM64 images and creates a draft release containing the deployment kit.
4. Download the kit, verify `SHA256SUMS`, and follow its `INSTALL.md`. Try it on your own instance, including an upgrade when applicable. Automated DNS tests use fixtures; verify real providers separately.
5. Run **Publish Release** from `main`, entering the successful Prepare run ID—the number in its Actions URL.

Publishing uses the exact images you tested, without rebuilding. Stable releases update `latest`; beta releases do not. Deployment kits pin an exact image, so users choose when to upgrade.

## If something fails

- **Prepare, before a draft exists:** fix the problem and rerun failed jobs.
- **Prepare, after a draft exists:** delete only that unpublished draft and its unpublished tag, if present, then prepare again.
- **Publish:** fix the problem and rerun with the same Prepare run ID.

Prepare one release at a time and publish within 90 days, before its Actions artifacts expire. Never replace a published version; use a new patch version.

For implementation details, see [the workflows](../.github/workflows/) and [release script](../scripts/release.py). Local checks are in the [README](../README.md#development).

The release workflow marks its images as release builds (`v0.1.0`). Local builds, including optimized builds, show the version plus the short Git commit and `-dirty` when there are uncommitted changes. The footer links to the corresponding release or commit. Git metadata is used only during the Docker build and is not included in the runtime image.
