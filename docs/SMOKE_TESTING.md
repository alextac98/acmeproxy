# Smoke-test a release

Run this after the **Release** workflow finishes. Use the published image, without rebuilding it locally. Test real providers on `main` before releasing when relevant; this checklist verifies the public installation afterward.

## 1. Check Docker

You need Python 3, Docker Engine, and Docker Compose with `up --wait` support:

```sh
docker version
docker compose version
docker run --rm hello-world
```

`docker version` must show both Client and Server. For setup, follow Docker's [installation](https://docs.docker.com/engine/install/) and [post-installation](https://docs.docker.com/engine/install/linux-postinstall/) instructions. After joining the Docker group, log out and back in, including restarting your editor or agent session.

Use Docker for this check. Podman rejected the kit's tmpfs ownership options in our testing; a workaround does not validate the shipping Docker configuration.

## 2. Download the release kit

Open [GitHub Releases](https://github.com/alextac98/acmeproxy/releases) while signed out. Download these three files from the same release into an empty directory:

- `acmeproxy-VERSION-deploy.tar.gz`
- `release.json`
- `SHA256SUMS`

In the directory containing those files, run:

```sh
sha256sum --check SHA256SUMS
tar -xzf acmeproxy-*-deploy.tar.gz
cd acmeproxy-*-deploy
RELEASE_IMAGE=$(docker compose config --images)
docker pull "$RELEASE_IMAGE"
```

Both checksums must pass. Keep this terminal open for the next steps.

The GHCR package must be **Public** for anonymous pulls (Packages → acmeproxy → Package settings). A public image alone does not mean the GitHub release and its downloads are published; verify both.

## 3. Run the automated lifecycle test

Use a source checkout at the `commit` recorded in `release.json`. From the terminal above, replace the script path with that checkout's path:

```sh
python3 /path/to/acmeproxy/scripts/smoke-compose.py --image "$RELEASE_IMAGE"
```

For subsequent releases, also test upgrading from the `previous_image` recorded in `release.json`:

```sh
python3 /path/to/acmeproxy/scripts/smoke-compose.py \
  --image "$RELEASE_IMAGE" --previous-image 'PREVIOUS_IMAGE_REFERENCE'
```

Expect exit code 0 and the final “Compose fresh install … passed” message. This checks startup, missing-key protection, encrypted credentials, mocked DNS challenge creation/cleanup, container replacement, and backup/restore. It uses temporary ports and volumes and removes its test resources afterward.

This exercises the repository's Compose template on your machine's architecture. The Release workflow covers AMD64 and ARM64; the next step checks the actual downloaded kit.

## 4. Try the downloaded kit

Use a disposable Docker host with port 8080 free and no existing `acmeproxy-config` volume. Changing the Compose project name alone does not isolate that explicitly named volume.

From the unpacked kit directory:

```sh
docker compose up -d --wait
docker compose exec acmeproxy cat /config/admin.token
curl --fail http://127.0.0.1:8080/healthz
```

- Sign in at http://127.0.0.1:8080 with the token; don't paste it into test reports.
- Check About and the footer show `vVERSION`, without a commit suffix or `dirty`. Health should report `release: true`, `dirty: false`, and the commit in `release.json`. The version link should open the published release.
- Add a test provider and client. Issue a certificate for a test domain, preferably using your ACME client's staging CA, and confirm the challenge TXT record is cleaned up. Automated tests use fake DNS and do not cover this.
- Run `docker compose restart acmeproxy`, sign in again, and confirm settings persist.
- Stop with `docker compose down`. Keep the volume if needed; use `docker compose down -v` only to delete this disposable test installation.

## 5. Record the result

Record the version, release workflow run ID, image digest, tested architecture, automated result, and real-provider result (or explicitly mark it untested). If a published release fails, fix it on `main` and release a new patch version through the same **Release** workflow.
