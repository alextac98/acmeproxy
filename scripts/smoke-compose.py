#!/usr/bin/env python3
"""Exercise the shipping Compose template using disposable volumes and fake DNS only."""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--previous-image', default='')
    args = parser.parse_args()
    name = 'acmeproxy-test-' + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix=name) as tmp:
        path = Path(tmp)
        fixture = path / 'dns_cf.sh'
        fixture.write_text('''dns_cf_add() {
  [ "$CF_Token" = "fixture-secret" ] || return 1
  printf 'fixture=preserved\\n' > "$DOMAIN_CONF"
}
dns_cf_rm() {
  [ "$CF_Token" = "fixture-secret" ] || return 1
  grep -q 'fixture=preserved' "$DOMAIN_CONF"
}
''')
        # Docker daemon can read this fixture; no real credentials or DNS transport are used.
        os.chmod(tmp, 0o755)
        fixture.chmod(0o644)
        template = (ROOT / 'deploy/compose.yaml').read_text()
        template = template.replace('name: acmeproxy\n', 'name: ' + name + '\n', 1)
        template = template.replace('127.0.0.1:8080:8080', '127.0.0.1::8080')
        template = template.replace('      - config:/config', f'      - config:/config\n      - {fixture}:/opt/acme.sh/dnsapi/dns_cf.sh:ro')
        compose = path / 'compose.yaml'
        volumes = [name + '-config', name + '-restored', name + '-fresh']

        def write(image, volume):
            compose.write_text(template.replace('@IMAGE@', image).replace('name: acmeproxy-config', 'name: ' + volume))

        def dc(*command, **kwargs):
            return subprocess.check_output(['docker', 'compose', '-f', str(compose), *command], **kwargs)

        def start():
            dc('up', '-d', '--force-recreate', '--wait', '--wait-timeout', '90')
            port = dc('port', 'acmeproxy', '8080').decode().strip().rsplit(':', 1)[1]
            return 'http://127.0.0.1:' + port

        def read(filename):
            return dc('exec', '-T', 'acmeproxy', 'cat', '/config/' + filename)

        def request(route, payload=None, auth=None):
            headers = {'Content-Type': 'application/json'}
            if auth:
                headers['Authorization'] = auth
            req = urllib.request.Request(url + route, data=json.dumps(payload).encode() if payload is not None else None, headers=headers)
            for _ in range(30):
                try:
                    with urllib.request.urlopen(req, timeout=15) as response:
                        return json.load(response)
                except urllib.error.HTTPError as exc:
                    if exc.code != 503:
                        raise
                    time.sleep(.2)
            raise AssertionError('Challenge did not finish')

        try:
            write(args.image, volumes[2])
            url = start()
            assert request('/healthz')['status'] == 'ok'
            assert read('admin.token').strip()
            assert dc('exec', '-T', 'acmeproxy', 'id', '-u').strip() == b'10001'
            # Confirm a partially lost installation fails closed, not silently reinitialized.
            dc('exec', '-T', 'acmeproxy', 'rm', '/config/admin.token')
            dc('stop')
            result = subprocess.run(['docker', 'compose', '-f', str(compose), 'run', '--rm', '--no-deps', 'acmeproxy'], capture_output=True)
            assert result.returncode != 0 and b'Incomplete existing configuration' in result.stderr
            dc('down')
            write(args.previous_image or args.image, volumes[0])
            url = start()
            token, key = read('admin.token'), read('master.key')
            admin = 'Bearer ' + token.decode().strip()
            request('/api/admin/providers', {'name': 'Fixture', 'driver': 'dns_cf', 'zone': 'example.com', 'credentials': {'CF_Token': 'fixture-secret'}}, admin)
            client = request('/api/admin/clients', {'name': 'Fixture client', 'scopes': ['test.example.com']}, admin)
            client_auth = 'Basic ' + base64.b64encode((client['id'] + ':' + client['token']).encode()).decode()
            challenge = {'fqdn': '_acme-challenge.test.example.com', 'value': 'A' * 43}
            request('/present', challenge, client_auth)
            config = read('config.toml')
            assert b'fixture-secret' not in config and b'encrypted_credentials' in config
            assert any(c['state'] == 'active' for c in request('/api/admin/overview', auth=admin)['challenges'])
            dc('stop')
            backup = dc('run', '--rm', '--no-deps', '-T', '--entrypoint', 'tar', 'acmeproxy', '--exclude=./scratch', '-C', '/config', '-czf', '-', '.')
            write(args.image, volumes[0])
            url = start()
            assert read('admin.token') == token and read('master.key') == key
            request('/cleanup', challenge, client_auth)
            assert all(c['state'] == 'cleaned' for c in request('/api/admin/overview', auth=admin)['challenges'])
            dc('down')
            # Restore the original snapshot with its original image into a new volume.
            write(args.previous_image or args.image, volumes[1])
            dc('run', '--rm', '--no-deps', '-T', '--entrypoint', 'tar', 'acmeproxy', '-C', '/config', '-xzf', '-', input=backup)
            url = start()
            assert read('admin.token') == token and read('master.key') == key
            request('/cleanup', challenge, client_auth)
            assert all(c['state'] == 'cleaned' for c in request('/api/admin/overview', auth=admin)['challenges'])
            print('Compose fresh install, missing-key protection, encrypted state, challenge lifecycle, replacement/upgrade and backup restore passed.')
        finally:
            dc('down', '--remove-orphans')
            for volume in volumes:
                subprocess.run(['docker', 'volume', 'rm', volume], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
