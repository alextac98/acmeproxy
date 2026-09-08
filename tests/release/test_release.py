import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('release', ROOT / 'scripts/release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def metadata():
    return {'version': '0.1.0', 'tag': 'v0.1.0', 'commit': 'a' * 40,
            'image': 'ghcr.io/alextac98/acmeproxy', 'digest': 'sha256:' + 'b' * 64,
            'run_id': '123', 'attempt': '1', 'previous_image': ''}


class ReleaseTests(unittest.TestCase):
    def test_project_version_comes_from_manifest_and_checks_generated_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'Cargo.toml').write_text('[package]\nname = "acmeproxy"\nversion = "0.2.0"\n')
            lock = root / 'Cargo.lock'
            lock.write_text('[[package]]\nname = "acmeproxy"\nversion = "0.1.0"\n')
            with patch.object(release, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'cargo check'):
                    release.project_version()
                lock.write_text('[[package]]\nname = "acmeproxy"\nversion = "0.2.0"\n')
                self.assertEqual(release.project_version(), '0.2.0')

    def test_draft_lookup_does_not_require_a_published_tag(self):
        draft = {'draft': True, 'tag_name': 'v0.1.0-beta.1'}
        with patch.object(release, 'all_releases', return_value=[draft]):
            self.assertEqual(release.find_release('owner/repo', draft['tag_name']), draft)
            self.assertEqual(release.releases('owner/repo'), [])

    def test_version_order_and_rejections(self):
        versions = ['0.1.0-alpha.1', '0.1.0-beta.1', '0.1.0-beta.10', '0.1.0-rc.1', '0.1.0', '0.1.1', '0.2.0', '1.0.0']
        self.assertEqual(sorted(reversed(versions), key=release.version_key), versions)
        for value in ['v1.0.0', '01.0.0', '1.0.0-beta.01', '../x', '1.0.0\n', '1.0.0;echo BAD']:
            with self.assertRaises(ValueError):
                release.version_key(value)

    def test_kit_pins_digest_and_contains_only_deployment_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = release.kit(metadata(), tmp)
            self.assertEqual(release.verify_bundle(tmp), metadata())
            with tarfile.open(archive) as tar:
                files = [m for m in tar.getmembers() if m.isfile()]
                self.assertEqual({Path(m.name).name for m in files}, {'compose.yaml', 'INSTALL.md', 'UPGRADE.md', 'config.example.toml'})
                compose = tar.extractfile(next(m for m in files if m.name.endswith('compose.yaml'))).read().decode()
                self.assertIn('ghcr.io/alextac98/acmeproxy:0.1.0@sha256:' + 'b' * 64, compose)
                self.assertNotIn('@IMAGE@', compose)
                self.assertNotIn(':latest', compose)

    def test_tampering_or_missing_checksums_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = release.kit(metadata(), tmp)
            archive.write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                release.verify_bundle(tmp)
            release.kit(metadata(), tmp)
            (Path(tmp) / 'SHA256SUMS').write_text('')
            with self.assertRaises(ValueError):
                release.verify_bundle(tmp)

    def test_checksum_paths_cannot_escape_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            release.kit(metadata(), tmp)
            (Path(tmp) / 'SHA256SUMS').write_text('a' * 64 + '  ../secret\n')
            with self.assertRaises(ValueError):
                release.verify_bundle(tmp)

    def test_invalid_metadata_rejected_before_writing(self):
        for field, value in [('version', '../../x'), ('tag', 'v9.9.9'), ('image', 'other.example/app'), ('digest', 'latest'), ('commit', 'main')]:
            meta = metadata()
            meta[field] = value
            with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
                release.kit(meta, tmp)

    def test_api_only_treats_404_as_absence(self):
        from subprocess import CompletedProcess
        with patch.object(release.subprocess, 'run', return_value=CompletedProcess([], 1, '', 'gh: Not Found (HTTP 404)')):
            self.assertIsNone(release.api('test', optional=True))
        with patch.object(release.subprocess, 'run', return_value=CompletedProcess([], 1, '', 'gh: Forbidden (HTTP 403)')):
            with self.assertRaises(RuntimeError):
                release.api('test', optional=True)

    def test_release_rejects_other_branches(self):
        from argparse import Namespace
        with patch.dict(release.os.environ, {'GITHUB_REF': 'refs/heads/feature'}), patch.object(release, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'main'):
                release.release(Namespace())
            run.assert_not_called()

    def test_preflight_rejects_an_existing_version(self):
        env = {'GITHUB_REF': 'refs/heads/main', 'GITHUB_REPOSITORY': 'alextac98/acmeproxy'}
        with patch.dict(release.os.environ, env), patch.object(release, 'project_version', return_value='0.1.0'), \
             patch.object(release, 'api', return_value={'object': {}}), patch.object(release, 'output') as output:
            with self.assertRaisesRegex(ValueError, 'already exists'):
                release.preflight()
            output.assert_not_called()

    def simulate_release(self, stable=True, existing=None, conflict=None, missing_tag=False):
        from argparse import Namespace
        from subprocess import CompletedProcess
        import shutil
        meta = metadata()
        if not stable:
            meta.update(version='0.1.0-beta.1', tag='v0.1.0-beta.1')
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / 'source'
            release.kit(meta, source)

            def command(*args, **kwargs):
                calls.append(args)
                if args[:3] == ('gh', 'release', 'download'):
                    destination = Path(args[args.index('--dir') + 1])
                    for p in source.iterdir():
                        if p.is_file():
                            shutil.copyfile(p, destination / p.name)
                if '--raw' in args:
                    return json.dumps({'manifests': [{'platform': {'os': 'linux', 'architecture': a}}
                                                   for a in (['amd64'] if conflict == 'platform' else ['amd64', 'arm64'])]})
                return ''

            def image_digest(ref):
                if conflict == 'image' and ref.endswith(':' + meta['version']):
                    return 'sha256:' + 'c' * 64
                return meta['digest']

            def request(path, payload=None, **kwargs):
                if payload:
                    calls.append(('git-tag', payload['ref'], payload['sha']))
                return None if missing_tag else {'object': {'type': 'commit', 'sha': meta['commit']}}

            current = None if existing is None else {'draft': existing == 'draft',
                'target_commitish': 'c' * 40 if conflict == 'commit' else meta['commit']}
            env = {'GITHUB_REF': 'refs/heads/main', 'GITHUB_REPOSITORY': 'alextac98/acmeproxy',
                   'GITHUB_SHA': meta['commit'], 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'}
            inspection = CompletedProcess([], 1, '', 'manifest unknown') if missing_tag else CompletedProcess([], 0, '', '')
            with patch.dict(release.os.environ, env), patch.object(release, 'api', side_effect=request), \
                 patch.object(release, 'run', side_effect=command), patch.object(release, 'project_version', return_value=meta['version']), \
                 patch.object(release, 'releases', return_value=[{'tag_name': 'v9.0.0'}] if conflict == 'older' else []), \
                 patch.object(release, 'digest', side_effect=image_digest), patch.object(release, 'anonymous_pull'), \
                 patch.object(release, 'find_release', return_value=current), \
                 patch.object(release.subprocess, 'run', return_value=inspection):
                release.release(Namespace(image=meta['image'], build_tag='0.1.0-build-123', previous='', directory=str(base / 'output')))
        return calls

    def test_single_run_creates_assets_and_publishes_stable_release(self):
        calls = self.simulate_release(missing_tag=True)
        create = next(c for c in calls if c[:3] == ('gh', 'release', 'create'))
        self.assertTrue(any(c.endswith('.tar.gz') for c in create))
        edit = next(c for c in calls if c[:3] == ('gh', 'release', 'edit'))
        self.assertIn('--draft=false', edit)
        self.assertIn('--latest=true', edit)
        self.assertIn(('git-tag', 'refs/tags/v0.1.0', 'a' * 40), calls)
        promotions = [c for c in calls if c[:4] == ('docker', 'buildx', 'imagetools', 'create')]
        self.assertEqual(len(promotions), 2)
        self.assertIn('ghcr.io/alextac98/acmeproxy:0.1.0', promotions[0])
        self.assertIn('ghcr.io/alextac98/acmeproxy:latest', promotions[1])

    def test_beta_does_not_advance_latest(self):
        calls = self.simulate_release(stable=False)
        edit = next(c for c in calls if c[:3] == ('gh', 'release', 'edit'))
        self.assertIn('--prerelease=true', edit)
        self.assertIn('--latest=false', edit)
        self.assertFalse(any(c[:4] == ('docker', 'buildx', 'imagetools', 'create') for c in calls))

    def test_published_retry_only_repairs_latest(self):
        calls = self.simulate_release(existing='published')
        self.assertFalse(any(c[:3] in [('gh', 'release', 'edit'), ('gh', 'release', 'upload'), ('gh', 'release', 'create')] for c in calls))
        self.assertTrue(any('ghcr.io/alextac98/acmeproxy:latest' in c for c in calls))

    def test_draft_retry_finishes_automatically(self):
        calls = self.simulate_release(existing='draft')
        self.assertTrue(any(c[:3] == ('gh', 'release', 'upload') for c in calls))
        self.assertTrue(any('--draft=false' in c for c in calls))

    def test_conflicting_release_or_incomplete_image_rejected(self):
        for conflict in ('image', 'commit', 'platform', 'older'):
            with self.subTest(conflict=conflict), self.assertRaises(ValueError):
                self.simulate_release(existing='published', conflict=conflict)

    def test_description_is_rendered_for_the_release(self):
        description = release.release_description(metadata(), 'alextac98/acmeproxy')
        self.assertIn('ghcr.io/alextac98/acmeproxy:0.1.0', description)
        self.assertIn('/releases/download/v0.1.0/', description)
        self.assertIn('docker compose up -d --wait', description)
        self.assertNotIn('Prepare', description)
        self.assertNotIn('{{', description)


if __name__ == '__main__':
    unittest.main()
