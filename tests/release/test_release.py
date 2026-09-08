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

    def test_publish_rejects_untrusted_run_before_download(self):
        from argparse import Namespace
        env = {'GITHUB_REF': 'refs/heads/main', 'GITHUB_REPOSITORY': 'alextac98/acmeproxy'}
        record = {'path': '.github/workflows/ci.yml', 'event': 'push', 'head_branch': 'main', 'conclusion': 'success'}
        with patch.dict(release.os.environ, env), patch.object(release, 'api', return_value=record), patch.object(release, 'run') as run:
            with self.assertRaises(ValueError):
                release.publish(Namespace(run_id='123', directory='unused'))
            run.assert_not_called()

    def simulate_publish(self, stable=False, conflicting=False, already_published=False):
        from argparse import Namespace
        from subprocess import CompletedProcess
        import hashlib
        import shutil
        meta = metadata()
        if not stable:
            meta.update(version='0.1.0-beta.1', tag='v0.1.0-beta.1')
        record = {'path': '.github/workflows/prepare-release.yml', 'event': 'workflow_dispatch',
                  'head_branch': 'main', 'conclusion': 'success', 'head_sha': meta['commit'], 'run_attempt': 1}
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / 'source'
            source.mkdir()
            (source / 'release.json').write_text(json.dumps(meta))
            archive = source / f"acmeproxy-{meta['version']}-deploy.tar.gz"
            archive.write_bytes(b'tested archive')
            (source / 'SHA256SUMS').write_text(''.join(
                f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
                for p in [source / 'release.json', archive]))

            def command(*args, **kwargs):
                calls.append(args)
                if args[:3] in [('gh', 'run', 'download'), ('gh', 'release', 'download')]:
                    destination = Path(args[args.index('--dir') + 1])
                    for p in source.iterdir():
                        shutil.copyfile(p, destination / p.name)
                return ''

            def request(path, *args, **kwargs):
                if '/actions/runs/' in path:
                    return record
                if '/releases/tags/' in path:
                    return {'draft': not already_published}
                return {'object': {'type': 'commit', 'sha': meta['commit']}}

            def image_digest(ref):
                if conflicting and ref.endswith(':' + meta['version']):
                    return 'sha256:' + 'c' * 64
                return meta['digest']

            env = {'GITHUB_REF': 'refs/heads/main', 'GITHUB_REPOSITORY': 'alextac98/acmeproxy'}
            with patch.dict(release.os.environ, env), patch.object(release, 'api', side_effect=request), \
                 patch.object(release, 'run', side_effect=command), patch.object(release, 'releases', return_value=[]), \
                 patch.object(release, 'digest', side_effect=image_digest), patch.object(release, 'anonymous_pull'), \
                 patch.object(release, 'find_release', return_value={'draft': not already_published}), \
                 patch.object(release.subprocess, 'run', return_value=CompletedProcess([], 0, '', '')):
                release.publish(Namespace(run_id='123', directory=str(base / 'download')))
        return calls

    def test_beta_publish_does_not_advance_latest(self):
        calls = self.simulate_publish()
        edit = next(c for c in calls if c[:3] == ('gh', 'release', 'edit'))
        self.assertIn('--prerelease=true', edit)
        self.assertIn('--latest=false', edit)
        self.assertFalse(any(c[:4] == ('docker', 'buildx', 'imagetools', 'create') for c in calls))

    def test_stable_retry_repairs_latest_without_rebuilding(self):
        calls = self.simulate_publish(stable=True, already_published=True)
        self.assertFalse(any(c[:3] == ('gh', 'release', 'edit') for c in calls))
        promotion = next(c for c in calls if c[:4] == ('docker', 'buildx', 'imagetools', 'create'))
        self.assertIn('ghcr.io/alextac98/acmeproxy:latest', promotion)
        self.assertTrue(promotion[-1].endswith('@sha256:' + 'b' * 64))

    def test_existing_version_cannot_be_overwritten(self):
        with self.assertRaisesRegex(ValueError, 'different contents'):
            self.simulate_publish(conflicting=True)


if __name__ == '__main__':
    unittest.main()
