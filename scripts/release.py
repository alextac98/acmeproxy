#!/usr/bin/env python3
"""Manual GHCR releases from main. Only the release subcommand writes remotely."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.parse
import urllib.request

from jinja2 import Environment, FileSystemLoader, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(alpha|beta|rc)\.(0|[1-9]\d*))?')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def version_key(version):
    m = VERSION.fullmatch(version)
    require(m, 'Version must be X.Y.Z or X.Y.Z-{alpha,beta,rc}.N (no leading zeroes)')
    a, b, c, channel, n = m.groups()
    return (int(a), int(b), int(c), {'alpha': 0, 'beta': 1, 'rc': 2, None: 3}[channel], int(n or 0))


def validate(meta):
    version_key(meta['version'])
    require(re.fullmatch(r'[0-9a-f]{40}', meta['commit']), 'Invalid commit')
    require(re.fullmatch(r'ghcr.io/[a-z0-9_.-]+/[a-z0-9_.-]+', meta['image']), 'Invalid image')
    require(DIGEST.fullmatch(meta['digest']), 'Invalid digest')
    require(str(meta['run_id']).isdigit() and str(meta['attempt']).isdigit(), 'Invalid workflow identity')
    require(meta['tag'] == 'v' + meta['version'], 'Tag mismatch')


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def api(path, payload=None, optional=False):
    command = ['gh', 'api', path]
    if payload is not None:
        command += ['--method', 'POST', '--input', '-']
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            text=True, capture_output=True)
    if result.returncode:
        if optional and '(HTTP 404)' in result.stderr:
            return None
        raise RuntimeError(result.stderr)
    return json.loads(result.stdout) if result.stdout else None


def all_releases(repo):
    # Listing with the maintainer token includes drafts even before their Git tag exists.
    pages = json.loads(run('gh', 'api', f'repos/{repo}/releases?per_page=100', '--paginate', '--slurp'))
    return [r for page in pages for r in page]


def releases(repo):
    return [r for r in all_releases(repo) if not r['draft'] and VERSION.fullmatch(r['tag_name'].removeprefix('v'))]


def find_release(repo, tag):
    return next((r for r in all_releases(repo) if r['tag_name'] == tag), None)


def output(values):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
        for key, value in values.items():
            require('\n' not in str(value), 'Invalid workflow output')
            f.write(f'{key}={value}\n')


def digest(ref):
    value = json.loads(run('docker', 'buildx', 'imagetools', 'inspect', ref, '--format', '{{json .Manifest}}'))['digest']
    require(DIGEST.fullmatch(value), 'Registry returned invalid digest')
    return value


def anonymous_pull(meta):
    """Use an anonymous scoped token; never fall back to the runner's registry login."""
    name = meta['image'].removeprefix('ghcr.io/')
    query = urllib.parse.urlencode({'service': 'ghcr.io', 'scope': f'repository:{name}:pull'})
    with urllib.request.urlopen('https://ghcr.io/token?' + query, timeout=30) as response:
        token = json.load(response)['token']
    request = urllib.request.Request(f'https://ghcr.io/v2/{name}/manifests/{meta["digest"]}',
        headers={'Authorization': 'Bearer ' + token,
                 'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        require(response.headers.get('Docker-Content-Digest') == meta['digest'], 'Anonymous image digest mismatch')


def project_version():
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']['version']
    version_key(version)
    lock = tomllib.loads((ROOT / 'Cargo.lock').read_text())
    require(any(p['name'] == 'acmeproxy' and p['version'] == version for p in lock['package']), 'Cargo.lock is stale; run cargo check and commit the updated lockfile')
    return version


def preflight():
    require(os.environ['GITHUB_REF'] == 'refs/heads/main', 'Release must run from main')
    repo = os.environ['GITHUB_REPOSITORY']
    version = project_version()
    require(api(f'repos/{repo}/git/ref/tags/v{version}', optional=True) is None, 'Version tag already exists')
    require(find_release(repo, 'v' + version) is None, 'Release already exists; rerun failed jobs in its original workflow or use a new version')
    published = releases(repo)
    previous = ''
    if published:
        latest = max(published, key=lambda r: version_key(r['tag_name'][1:]))
        require(version_key(version) > version_key(latest['tag_name'][1:]), 'New version must exceed published versions')
        with tempfile.TemporaryDirectory() as tmp:
            run('gh', 'release', 'download', latest['tag_name'], '--repo', repo, '--pattern', 'release.json', '--dir', tmp)
            meta = json.loads((Path(tmp) / 'release.json').read_text())
            validate(meta)
            require(meta['image'] == 'ghcr.io/' + repo.lower(), 'Previous release image belongs to another repository')
            previous = meta['image'] + '@' + meta['digest']
    output({'version': version, 'image': 'ghcr.io/' + repo.lower(), 'previous': previous,
            'build_tag': f"{version}-build-{os.environ['GITHUB_RUN_ID']}"})


def kit(meta, destination):
    validate(meta)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    folder = destination / f"acmeproxy-{meta['version']}-deploy"
    folder.mkdir(exist_ok=True)
    ref = f"{meta['image']}:{meta['version']}@{meta['digest']}"
    (folder / 'compose.yaml').write_text((ROOT / 'deploy/compose.yaml').read_text().replace('@IMAGE@', ref))
    for name in ('INSTALL.md', 'UPGRADE.md'):
        shutil.copyfile(ROOT / 'deploy' / name, folder / name)
    shutil.copyfile(ROOT / 'examples/container.toml', folder / 'config.example.toml')
    archive = destination / (folder.name + '.tar.gz')
    with tarfile.open(archive, 'w:gz') as tar:
        tar.add(folder, arcname=folder.name)
    (destination / 'release.json').write_text(json.dumps(meta, indent=2) + '\n')
    paths = [archive, destination / 'release.json']
    (destination / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in paths))
    return archive


def release_description(meta, repo, template='release.md.j2'):
    validate(meta)
    folder = f"acmeproxy-{meta['version']}-deploy"
    download = f"https://github.com/{repo}/releases/download/{meta['tag']}"
    source = f"https://github.com/{repo}/blob/{meta['commit']}"
    environment = Environment(
        loader=FileSystemLoader(ROOT / 'scripts/templates'),
        undefined=StrictUndefined,
        autoescape=False,  # Markdown, not HTML.
        keep_trailing_newline=True,
    )
    return environment.get_template(template).render(
        release=meta, repo=repo, folder=folder, download=download, source=source,
    )


def verify_bundle(directory):
    directory = Path(directory)
    meta = json.loads((directory / 'release.json').read_text())
    validate(meta)
    expected = {'release.json', f"acmeproxy-{meta['version']}-deploy.tar.gz"}
    seen = set()
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        checksum, name = line.split('  ', 1)
        require(name in expected and name not in seen, 'Unexpected checksum path')
        require(hashlib.sha256((directory / name).read_bytes()).hexdigest() == checksum, 'Artifact checksum mismatch')
        seen.add(name)
    require(seen == expected, 'Missing artifact checksum')
    return meta


def release(args):
    require(os.environ['GITHUB_REF'] == 'refs/heads/main', 'Release must run from main')
    repo = os.environ['GITHUB_REPOSITORY']
    require(args.image == 'ghcr.io/' + repo.lower(), 'Image belongs to another repository')
    source = args.image + ':' + args.build_tag
    index = json.loads(run('docker', 'buildx', 'imagetools', 'inspect', source, '--raw'))
    platforms = {(m.get('platform', {}).get('os'), m.get('platform', {}).get('architecture')) for m in index.get('manifests', [])}
    require({('linux', 'amd64'), ('linux', 'arm64')} <= platforms, 'Image lacks a supported architecture')
    version = project_version()
    meta = {'version': version, 'tag': 'v' + version, 'commit': os.environ['GITHUB_SHA'],
            'image': args.image, 'digest': digest(source), 'run_id': os.environ['GITHUB_RUN_ID'],
            'attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'previous_image': args.previous}
    validate(meta)
    require(all(version_key(r['tag_name'][1:]) <= version_key(version) for r in releases(repo)),
            'Refusing to move release channels backwards')
    existing = find_release(repo, meta['tag'])
    if existing:
        require(existing['target_commitish'] == meta['commit'], 'Existing release belongs to another commit')
        if not existing['draft']:
            # A failed final step may be retried, but published assets are never replaced.
            with tempfile.TemporaryDirectory() as tmp:
                run('gh', 'release', 'download', meta['tag'], '--repo', repo, '--dir', tmp)
                published = verify_bundle(tmp)
            require(all(published[k] == meta[k] for k in ('commit', 'digest', 'image', 'version', 'run_id')),
                    'Published release differs from this workflow')
    tag = api(f'repos/{repo}/git/ref/tags/{meta["tag"]}', optional=True)
    if tag:
        require(tag['object']['type'] == 'commit' and tag['object']['sha'] == meta['commit'],
                'Existing Git tag does not match release')
    anonymous_pull(meta)
    source = meta['image'] + '@' + meta['digest']
    target = meta['image'] + ':' + version
    result = subprocess.run(['docker', 'buildx', 'imagetools', 'inspect', target], capture_output=True, text=True)
    if result.returncode == 0:
        require(digest(target) == meta['digest'], 'Existing version image has different contents')
    else:
        require('not found' in result.stderr.lower() or 'manifest unknown' in result.stderr.lower(), result.stderr)
        run('docker', 'buildx', 'imagetools', 'create', '--tag', target, source)
        require(digest(target) == meta['digest'], 'Promotion changed image digest')
    stable = '-' not in version
    if not existing or existing['draft']:
        archive = kit(meta, args.directory)
        directory = Path(args.directory)
        description = directory / 'description.md'
        description.write_text(release_description(meta, repo))
        assets = [str(archive), str(directory / 'release.json'), str(directory / 'SHA256SUMS')]
        # Keep incomplete uploads hidden; this draft is published automatically in this job.
        if not existing:
            run('gh', 'release', 'create', meta['tag'], *assets, '--repo', repo, '--draft',
                '--target', meta['commit'], '--title', 'ACME Proxy ' + meta['tag'], '--notes-file', str(description))
        else:
            run('gh', 'release', 'upload', meta['tag'], *assets, '--repo', repo, '--clobber')
            run('gh', 'release', 'edit', meta['tag'], '--repo', repo, '--notes-file', str(description))
        if not tag:
            api(f'repos/{repo}/git/refs', {'ref': 'refs/tags/' + meta['tag'], 'sha': meta['commit']})
        run('gh', 'release', 'edit', meta['tag'], '--repo', repo, '--draft=false',
            '--prerelease=' + str(not stable).lower(), '--latest=' + str(stable).lower())
    if stable:
        run('docker', 'buildx', 'imagetools', 'create', '--tag', meta['image'] + ':latest', source)
        require(digest(meta['image'] + ':latest') == meta['digest'], 'Latest digest mismatch')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as f:
            f.write(release_description(meta, repo))
    print(f"Published {meta['tag']} from {meta['commit']} at {meta['digest']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('preflight')
    p = sub.add_parser('release')
    for arg in ('image', 'build-tag', 'directory'):
        p.add_argument('--' + arg, required=True)
    p.add_argument('--previous', default='')
    p = sub.add_parser('kit')
    p.add_argument('--metadata', required=True)
    p.add_argument('--directory', required=True)
    p = sub.add_parser('describe', help='Render release-page Markdown without publishing')
    p.add_argument('--metadata', required=True)
    p.add_argument('--repo', required=True)
    p.add_argument('--output', required=True)
    args = parser.parse_args()
    if args.command == 'preflight':
        preflight()
    elif args.command == 'release':
        release(args)
    elif args.command == 'describe':
        Path(args.output).write_text(release_description(json.loads(Path(args.metadata).read_text()), args.repo))
    else:
        kit(json.loads(Path(args.metadata).read_text()), args.directory)


if __name__ == '__main__':
    main()
