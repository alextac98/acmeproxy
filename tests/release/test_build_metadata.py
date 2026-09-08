"""Exercise metadata capture against real, disposable Git repositories."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BuildMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = tempfile.TemporaryDirectory()
        cls.script = Path(cls.tools.name) / 'build-metadata'
        subprocess.run(['rustc', str(ROOT / 'build.rs'), '-o', str(cls.script)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tools.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git('init', '-q')
        (self.root / '.gitignore').write_text('ignored\n')
        (self.root / 'source').write_text('original\n')
        self.git('add', '.')
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '-qm', 'Fixture')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, text=True).strip()

    def capture(self, **extra):
        env = {k: v for k, v in os.environ.items() if k not in ('ACMEPROXY_REVISION', 'ACMEPROXY_RELEASE')}
        env.update(CARGO_MANIFEST_DIR=str(self.root), **extra)
        return subprocess.run([str(self.script)], env=env, text=True, capture_output=True)

    def test_clean_dev_and_release_metadata(self):
        for released in ['false', 'true']:
            result = self.capture(ACMEPROXY_RELEASE=released)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('ACMEPROXY_BUILD_REVISION=' + self.git('rev-parse', 'HEAD'), result.stdout)
            self.assertIn('ACMEPROXY_BUILD_DIRTY=false', result.stdout)
            self.assertIn('ACMEPROXY_BUILD_RELEASE=' + released, result.stdout)

    def test_unstaged_staged_and_untracked_changes_are_dirty(self):
        (self.root / 'source').write_text('changed\n')
        self.assertIn('ACMEPROXY_BUILD_DIRTY=true', self.capture().stdout)
        self.git('add', 'source')
        self.assertIn('ACMEPROXY_BUILD_DIRTY=true', self.capture().stdout)
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '-qm', 'Change')
        (self.root / 'new-file').write_text('new')
        self.assertIn('ACMEPROXY_BUILD_DIRTY=true', self.capture().stdout)

    def test_ignored_files_are_not_dirty(self):
        (self.root / 'ignored').write_text('local runtime data')
        self.assertIn('ACMEPROXY_BUILD_DIRTY=false', self.capture().stdout)

    def test_dirty_release_and_mismatched_revision_are_rejected(self):
        self.assertNotEqual(self.capture(ACMEPROXY_REVISION='a' * 40).returncode, 0)
        (self.root / 'source').write_text('changed')
        self.assertNotEqual(self.capture(ACMEPROXY_RELEASE='true').returncode, 0)

    def test_committing_changes_updates_metadata(self):
        before = self.git('rev-parse', 'HEAD')
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '--allow-empty', '-qm', 'New commit')
        result = self.capture()
        self.assertNotIn('ACMEPROXY_BUILD_REVISION=' + before, result.stdout)
        self.assertIn('ACMEPROXY_BUILD_REVISION=' + self.git('rev-parse', 'HEAD'), result.stdout)
        self.assertIn('ACMEPROXY_BUILD_DIRTY=false', result.stdout)
