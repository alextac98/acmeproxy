#!/usr/bin/env python3
"""Check image initialization, HTTP service, and persistence using a disposable volume."""
import argparse
import json
import pathlib
import subprocess
import time
import urllib.request
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--engine', default='podman')
parser.add_argument('--image', default='localhost/acmeproxy:dev')
parser.add_argument('--dev-entrypoint', action='store_true')
args = parser.parse_args()
name = 'acmeproxy-smoke-' + uuid.uuid4().hex[:10]
volume = name + '-config'

def run(*command, **kwargs):
    return subprocess.check_output([args.engine, *command], **kwargs)

try:
    run('volume', 'create', volume)
    volume_options = ':/config:U' if args.engine == 'podman' else ':/config'
    if not args.dev_entrypoint:
        run('run', '--rm', '-v', volume + volume_options, args.image, 'init', '--config-dir', '/config')
        run('run', '--rm', '-i', '--entrypoint', '/bin/sh', '-v', volume + ':/config', args.image,
            '-c', 'cat > /config/config.toml', input=pathlib.Path('examples/container.toml').read_bytes())
    scratch = ['--mount', 'type=tmpfs,destination=/config/scratch,tmpfs-mode=0700,tmpfs-size=64m,chown=true,noexec,nosuid,nodev'] if args.engine == 'podman' else ['--tmpfs', '/config/scratch:rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700,size=64m']
    entrypoint = ['--entrypoint', '/bin/sh'] if args.dev_entrypoint else []
    command = ['/usr/local/bin/acmeproxy-dev-entrypoint'] if args.dev_entrypoint else []
    run('run', '-d', '--name', name, '-v', volume + volume_options, *scratch, *entrypoint,
        '-p', '127.0.0.1:18081:8080', args.image, *command)
    def ready():
        for _ in range(50):
            try:
                with urllib.request.urlopen('http://127.0.0.1:18081/healthz', timeout=1) as response:
                    assert json.load(response)['status'] == 'ok'
                return
            except (OSError, AssertionError):
                time.sleep(.1)
        raise AssertionError('Container did not become healthy')
    ready()
    token = run('exec', name, 'cat', '/config/admin.token').decode().strip()
    master_key = run('exec', name, 'cat', '/config/master.key')
    request = urllib.request.Request('http://127.0.0.1:18081/api/admin/overview',
                                     headers={'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(request) as response:
        overview = json.load(response)
        assert len(overview['drivers']) == 184
    run('exec', name, 'sed', '-i', 's/challenge_ttl_seconds = 3600/challenge_ttl_seconds = 1234/', '/config/config.toml')
    run('restart', name)
    ready()
    assert run('exec', name, 'cat', '/config/admin.token').decode().strip() == token
    assert run('exec', name, 'cat', '/config/master.key') == master_key
    assert 'challenge_ttl_seconds = 1234' in run('exec', name, 'cat', '/config/config.toml').decode()
    print('Container init, 184-adapter catalog, authenticated UI API, and persistent restart passed.')
finally:
    subprocess.run([args.engine, 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([args.engine, 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
