#!/usr/bin/env python3
"""Real Git comparisons, with synthetic base/tree pins confined to the fixture."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('late-confirmation-review.py').resolve()

class ReviewTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('review', SCRIPT)
        self.review = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.review)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        old = os.getcwd()
        os.chdir(self.temp.name)
        self.addCleanup(os.chdir, old)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.write('cmd/sbxr/main.go', 'runtime fixture\n')
        self.write('go.mod', 'build fixture\n')
        self.write('cmd/sbxr-release/testdata/r24-late-confirmation.json', '{}')
        self.base = self.commit()
        self.review.BASE = self.base
        self.review.TREE = hashlib.sha256(self.git('ls-tree', '-r', self.base, '--', 'cmd/sbxr', 'internal/proxyinstallation', 'go.mod', 'go.sum')).hexdigest()
        self.review.SUPPLEMENT = hashlib.sha256(b'{}').hexdigest()

    def git(self, *args):
        return subprocess.check_output(['git', *args], stderr=subprocess.PIPE)

    def write(self, path, value):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value)

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD').decode().strip()

    def test_exact_policy_delta(self):
        self.write('internal/softwarelifecycle/late_confirmation.go', 'policy fixture\n')
        target = self.commit()
        facts = self.review.review(target)
        self.assertEqual(facts['target_commit'], target)
        self.assertEqual(facts['base_commit'], self.base)
        self.assertEqual(facts['target_sequence'], 159)
        self.assertEqual(facts['policy_diff_sha256'], hashlib.sha256(self.git('diff', '--binary', '--no-ext-diff', self.base, target)).hexdigest())

    def test_runtime_change_refuses(self):
        self.write('cmd/sbxr/main.go', 'changed runtime\n')
        with self.assertRaisesRegex(ValueError, 'runtime/build inputs changed'):
            self.review.review(self.commit())

    def test_unreviewed_lifecycle_change_refuses(self):
        self.write('internal/softwarelifecycle/update.go', 'changed production\n')
        with self.assertRaisesRegex(ValueError, 'unreviewed production'):
            self.review.review(self.commit())

    def test_evidence_change_refuses(self):
        self.write('cmd/sbxr-release/testdata/r24-late-confirmation.json', '{"changed":true}')
        with self.assertRaisesRegex(ValueError, 'approved evidence changed'):
            self.review.review(self.commit())

    def test_base_and_non_commit_refuse(self):
        for commit in [self.base, 'HEAD', '--help', 'a' * 39]:
            with self.assertRaises(ValueError):
                self.review.review(commit)

if __name__ == '__main__':
    unittest.main()
