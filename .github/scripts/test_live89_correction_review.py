#!/usr/bin/env python3
"""Real Git and tar/identity boundaries; synthetic pins stay in the fixtures."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('live89-correction-review.py').resolve()


class ReviewTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('live89_review', SCRIPT)
        self.review = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.review)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        previous = os.getcwd()
        os.chdir(self.temp.name)
        self.addCleanup(os.chdir, previous)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        for path in ['cmd/sbxr/main.go', 'internal/softwarelifecycle/runtime.go',
                     'internal/proxyinstallation/runtime.go', 'go.mod', 'go.sum',
                     'cmd/sbxr-release/bootstrap.go']:
            self.write(path, 'unchanged product input\n')
        self.write('cmd/sbxr-release/testdata/live89-correction.json', '{"evidence":[]}')
        self.base = self.commit()
        self.review.BASE = self.base
        self.review.TREE = hashlib.sha256(self.git('ls-tree', '-r', self.base, '--', *self.review.PRODUCT_PATHS)).hexdigest()
        self.review.EVIDENCE = hashlib.sha256(b'{"evidence":[]}').hexdigest()
        self.write('cmd/sbxr-release/correction.go', 'policy fixture\n')
        self.target = self.commit()
        self.raw_payload = b'unchanged pure-Go executable fixture'
        self.review.PAYLOADS = {arch: hashlib.sha256(self.raw_payload).hexdigest() for arch in ['amd64', 'arm64']}

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

    def executable(self, architecture='amd64', **overrides):
        identity = dict(schema=1, repository='albertloky/SBXR', tag='v3.1.90',
                        commit=self.target, sequence=168, architecture=architecture,
                        payload_sha256=hashlib.sha256(self.raw_payload).hexdigest())
        identity.update(overrides)
        document = json.dumps(identity, separators=(',', ':')).encode()
        return self.raw_payload + document + hashlib.sha256(document).digest() + struct.pack('<Q', len(document)) + self.review.MAGIC

    def archive(self, executable, architecture='amd64', extra=False):
        path = Path(f'sbxr-linux-{architecture}.tar.gz')
        with tarfile.open(path, 'w:gz') as archive:
            info = tarfile.TarInfo('sbxr')
            info.size, info.mode = len(executable), 0o755
            archive.addfile(info, io.BytesIO(executable))
            if extra:
                archive.addfile(tarfile.TarInfo('extra'))
        return path

    def test_exact_policy_delta(self):
        facts = self.review.review(self.target)
        self.assertEqual(facts['target_commit'], self.target)
        self.assertEqual(facts['base_commit'], self.base)
        self.assertEqual(facts['target_tag'], 'v3.1.90')
        self.assertEqual(facts['target_sequence'], 168)
        self.assertEqual(facts['evidence_sha256'], self.review.EVIDENCE)
        self.assertEqual(facts['policy_diff_sha256'], hashlib.sha256(self.git('diff', '--binary', '--no-ext-diff', self.base, self.target)).hexdigest())

    def test_every_product_input_change_refuses(self):
        for path in self.review.PRODUCT_PATHS:
            with self.subTest(path=path):
                self.git('reset', '--hard', self.target)
                file = path + '/new_test.go' if path in ['cmd/sbxr', 'internal'] else path
                self.write(file, 'changed input\n')
                with self.assertRaisesRegex(ValueError, 'product/runtime/build inputs changed'):
                    self.review.review(self.commit())

    def test_evidence_change_refuses(self):
        self.write('cmd/sbxr-release/testdata/live89-correction.json', '{"evidence":["changed"]}')
        with self.assertRaisesRegex(ValueError, 'accepted archived evidence changed'):
            self.review.review(self.commit())

    def test_base_symbolic_and_unrelated_commit_refuse(self):
        for commit in [self.base, 'HEAD', '--help', 'a' * 39]:
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                self.review.review(commit)
        self.git('checkout', '--orphan', 'unrelated')
        self.git('rm', '-rf', '.')
        self.write('unrelated.txt', 'different ancestry')
        with self.assertRaises(subprocess.CalledProcessError):
            self.review.review(self.commit())

    def test_only_identity_changes_payload_exact(self):
        for architecture in ['amd64', 'arm64']:
            with self.subTest(architecture=architecture):
                identity = self.review.payload(self.archive(self.executable(architecture), architecture), self.target)
                self.assertEqual(identity['payload_sha256'], self.review.PAYLOADS[architecture])
                self.assertEqual(identity['tag'], 'v3.1.90')
                self.assertEqual(identity['sequence'], 168)

    def test_changed_payload_refuses_even_with_matching_identity_digest(self):
        self.raw_payload = b'changed executable fixture'
        with self.assertRaisesRegex(ValueError, 'tested executable payload changed'):
            self.review.payload(self.archive(self.executable()), self.target)

    def test_identity_mismatch_and_extra_fields_refuse(self):
        for overrides in [dict(tag='v3.1.89'), dict(sequence=167), dict(commit=self.base),
                          dict(architecture='arm64'), dict(repository='other/repository'),
                          dict(schema=2), dict(extra='unreviewed'), dict(payload_sha256='f' * 64)]:
            with self.subTest(overrides=overrides), self.assertRaisesRegex(ValueError, 'exact fresh release identity refused'):
                self.review.payload(self.archive(self.executable(**overrides)), self.target)

    def test_corrupt_missing_oversized_identity_refuse(self):
        valid = self.executable()
        missing = valid[:-1]
        corrupt = bytearray(valid)
        corrupt[-len(self.review.MAGIC) - 9] ^= 1
        oversized = valid[:-len(self.review.MAGIC) - 8] + struct.pack('<Q', 4097) + self.review.MAGIC
        for executable in [missing, bytes(corrupt), oversized]:
            with self.subTest(executable=executable[-60:]), self.assertRaises(ValueError):
                self.review.payload(self.archive(executable), self.target)

    def test_extra_archive_member_refuses(self):
        with self.assertRaisesRegex(ValueError, 'one bounded executable archive required'):
            self.review.payload(self.archive(self.executable(), extra=True), self.target)


if __name__ == '__main__':
    unittest.main()
