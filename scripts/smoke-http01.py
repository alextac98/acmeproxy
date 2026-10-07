#!/usr/bin/env python3
"""Verify the shipping HTTP-01 worker over real Docker DNS and port 80, without a CA request."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    name = 'acmeproxy-http01-' + uuid.uuid4().hex[:10]
    network, app, responder, volume = [name + '-' + suffix for suffix in ('net', 'app', 'http', 'config')]

    def docker(*arguments):
        return subprocess.check_output(['docker', *arguments], stderr=subprocess.STDOUT).decode().strip()

    with tempfile.TemporaryDirectory(prefix=name) as directory:
        challenge_root = Path(directory)
        challenge_root.chmod(0o755)
        files = challenge_root / '.well-known' / 'acme-challenge'
        files.mkdir(parents=True)
        try:
            docker('network', 'create', network)
            subnet = json.loads(docker('network', 'inspect', network))[0]['IPAM']['Config'][0]['Subnet']
            docker('run', '-d', '--name', responder, '--network', network,
                   '--network-alias', 'service.example.com', '--network-alias', 'blocked.example.com',
                   '--mount', f'type=bind,source={directory},target=/challenge,readonly',
                   'python:3.14-slim', 'python', '-m', 'http.server', '80', '--directory', '/challenge')
            docker('run', '-d', '--name', app, '--network', network,
                   '-p', '127.0.0.1::8080', '--mount', f'type=volume,source={volume},target=/config', args.image)
            port = json.loads(docker('inspect', app))[0]['NetworkSettings']['Ports']['8080/tcp'][0]['HostPort']
            origin = f'http://127.0.0.1:{port}'

            def request(path, body=None, auth=None, method=None):
                headers = {'Content-Type': 'application/json'}
                if auth:
                    headers['Authorization'] = auth
                data = None if body is None else json.dumps(body).encode()
                req = urllib.request.Request(origin + path, data=data, headers=headers, method=method)
                with urllib.request.urlopen(req, timeout=10) as response:
                    if method == 'HEAD':
                        return response.headers
                    return json.load(response)

            for _ in range(100):
                try:
                    request('/healthz')
                    break
                except (urllib.error.URLError, ConnectionError):
                    time.sleep(0.1)
            else:
                raise AssertionError('HTTP-01 fixture server failed to start')
            admin = 'Bearer ' + docker('exec', app, 'cat', '/config/admin.token')
            request('/api/admin/providers', {'name': 'HTTP-01 fixture', 'driver': 'dns_cf', 'zone': 'example.com',
                    'credentials': {'CF_Token': 'fixture-never-used'}}, admin)
            settings = {'mode': 'http01', 'base_url': origin, 'allowed_networks': [subnet],
                        'validation_networks': [subnet], 'allowed_domains': ['*.example.com'],
                        'staging': True, 'terms_agreed': True}
            request('/api/admin/acme/settings', settings, admin, 'PUT')
            key = ec.generate_private_key(ec.SECP256R1())
            numbers = key.public_key().public_numbers()

            def b64(value):
                return base64.urlsafe_b64encode(value).decode().rstrip('=')

            jwk = {'crv': 'P-256', 'kty': 'EC', 'x': b64(numbers.x.to_bytes(32, 'big')), 'y': b64(numbers.y.to_bytes(32, 'big'))}
            thumbprint = b64(hashlib.sha256(json.dumps(jwk, sort_keys=True, separators=(',', ':')).encode()).digest())
            kid = None

            def signed(path, payload):
                protected = {'alg': 'ES256', 'url': origin + path,
                             'nonce': request('/acme/new-nonce', method='HEAD')['Replay-Nonce']}
                protected['kid' if kid else 'jwk'] = kid or jwk
                header = b64(json.dumps(protected).encode())
                encoded = '' if payload is None else b64(json.dumps(payload).encode())
                r, s = utils.decode_dss_signature(key.sign(f'{header}.{encoded}'.encode(), ec.ECDSA(hashes.SHA256())))
                data = json.dumps({'protected': header, 'payload': encoded, 'signature': b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}).encode()
                req = urllib.request.Request(origin + path, data=data, headers={'Content-Type': 'application/jose+json'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    return json.load(response), response.headers

            _, headers = signed('/acme/new-account', {'termsOfServiceAgreed': True})
            kid = headers['Location']

            def order_for(domain):
                order, headers = signed('/acme/new-order', {'identifiers': [{'type': 'dns', 'value': domain}]})
                assert order['status'] == 'pending'
                authz, _ = signed(order['authorizations'][0].removeprefix(origin), None)
                assert [item['type'] for item in authz['challenges']] == ['http-01']
                challenge = authz['challenges'][0]
                (files / challenge['token']).write_text(challenge['token'] + '.' + thumbprint)
                signed(challenge['url'].removeprefix(origin), {})
                return headers['Location'].removeprefix(origin), challenge['url'].removeprefix(origin)

            order_path, challenge_path = order_for('service.example.com')
            for _ in range(100):
                order, _ = signed(order_path, None)
                if order['status'] == 'ready':
                    break
                assert order['status'] == 'pending', order
                time.sleep(0.1)
            else:
                raise AssertionError('Production HTTP-01 worker did not validate the port 80 responder')
            challenge, _ = signed(challenge_path, None)
            assert challenge['status'] == 'valid' and challenge['validated']
            settings['validation_networks'] = []
            request('/api/admin/acme/settings', settings, admin, 'PUT')
            _, blocked_path = order_for('blocked.example.com')
            for _ in range(100):
                challenge, _ = signed(blocked_path, None)
                if challenge.get('error'):
                    break
                time.sleep(0.1)
            assert challenge['error']['type'].endswith(':connection'), challenge
            assert 'validation networks' in challenge['error']['detail'], challenge
            overview = request('/api/admin/overview', auth=admin)
            assert not overview['challenges'], 'Local validation must never publish upstream DNS'
            print('Production HTTP-01 worker passed: Docker DNS, actual port 80, account-bound proof, ready order, private-network denial, and no upstream DNS mutations.')
        finally:
            subprocess.run(['docker', 'rm', '-f', app, responder], capture_output=True)
            subprocess.run(['docker', 'network', 'rm', network], capture_output=True)
            subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True)


if __name__ == '__main__':
    main()
