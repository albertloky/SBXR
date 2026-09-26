#!/usr/bin/env python3
"""Exact recovery-checkpoint refusals; filesystem cases require root Linux.

The full streamed SSH -> actual lifecycle Update/controller -> observer ->
public menu Recover rehearsal lives in test_mvp_inspect_window_linux.py.
"""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('observer', Path(__file__).with_name('mvp-inspect-window.py'))
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
sha = lambda b: hashlib.sha256(b).hexdigest()


class InputContracts(unittest.TestCase):
    def test_no_blanket_hardlink_opt_in(self):
        for wanted in (None, {}, {k: 'a' * 64 for k in o.RECOVERY_FIELDS | {'allow_hardlinks'}}):
            with self.subTest(wanted=wanted), self.assertRaisesRegex(o.Refused, 'expectation-fields'):
                o.recovery_observation('recovery-precommit', {}, wanted, 900, '/must-not-read')
        wanted = {k: 'a' * 64 for k in o.RECOVERY_FIELDS}
        wanted['candidate_executable_sha256'] = 'b' * 64
        for value in (1, '', 'A' * 64, 'a' * 63):
            with self.subTest(value=value), self.assertRaisesRegex(o.Refused, 'expectation-digests'):
                o.recovery_observation('recovery-precommit', {}, dict(wanted, ownership_sha256=value), 900, '/must-not-read')

    def test_duplicate_json_is_refused(self):
        with self.assertRaisesRegex(o.Refused, 'duplicate-json-key'):
            json.loads('{"schema":1,"schema":2}', object_pairs_hook=o.exact_object)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'requires real root-owned Linux files')
class RecoveryFiles(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, phase='recovery-precommit'):
        with tempfile.TemporaryDirectory(prefix='recovery-window-') as temp:
            root = Path(temp)
            def path(name):
                p = Path(name)
                return p if p.is_relative_to(root) else root / str(p).lstrip('/')
            def write(name, body, mode=0o600):
                p = path(name); p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(body); p.chmod(mode); return p
            source, target = b'fixture source executable', b'fixture target executable'
            def installed(tag, sequence, binary):
                return dict(schema=1, repository='albertloky/SBXR', tag=tag, commit='c' * 40,
                            release_index_sha256='d' * 64, sequence=sequence, architecture='amd64',
                            executable_sha256=sha(binary))
            prior = json.dumps(installed('v3.1.81', 159, source)).encode() + b'\n'
            candidate = json.dumps(installed('v3.1.83', 161, target)).encode() + b'\n'
            owner = b'{"schema":2,"phase":"Running","unfinished_direction":"none"}'
            wanted = dict(prior_executable_sha256=sha(source), prior_installed_record_sha256=sha(prior),
                          candidate_executable_sha256=sha(target), candidate_installed_record_sha256=sha(candidate),
                          ownership_sha256=sha(owner))
            prepared = phase == 'recovery-precommit'
            active = write('/usr/local/bin/sbxr', source if prepared else target, 0o755)
            old = path('/usr/local/bin/.sbxr-update-prior')
            if prepared:
                os.link(active, old)
                write('/usr/local/bin/.sbxr-update-candidate', target, 0o755)
                write('/var/lib/sbxr/.installed.json.candidate', candidate)
            else:
                write(old, source, 0o755)
            write('/var/lib/sbxr/installed.json', prior if prepared else candidate)
            write('/var/lib/sbxr/.installed.json.prior', prior)
            write('/var/lib/sbxr/proxy-ownership.json', owner)
            checkpoint = dict(wanted, schema=2, checkpoint='Prepared' if prepared else 'Committed')
            write('/var/lib/sbxr/update.json', json.dumps(checkpoint).encode())
            request = dict(not_before=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 10)),
                           deadline_unix=int(time.time()) + 1500, scenario_limit_seconds=1800,
                           qualification_manifest_sha256='e' * 64,
                           scenario_id='source-v3.1.81-' + phase.removeprefix('recovery-'), required_checks=['fixture-only'])
            request_path = write('/root/request.json', json.dumps(request).encode())
            expected = {'qualification_manifest_sha256': 'e' * 64}
            with patch.object(o, 'Path', side_effect=path):
                self.path, self.write, self.wanted, self.request = path, write, wanted, request
                self.checkpoint, self.request_path = checkpoint, request_path
                self.observe = lambda: o.recovery_observation(phase, expected, wanted, 900, request_path)
                yield root

    def test_exact_prepared_and_committed_are_read_only(self):
        for phase in o.RECOVERY_PHASES:
            with self.subTest(phase=phase), self.fixture(phase) as root:
                before = {p: (o.metadata(p), p.read_bytes()) for p in root.rglob('*') if p.is_file()}
                self.assertEqual(self.observe()['checkpoint'], o.RECOVERY_PHASES[phase])
                self.assertEqual(before, {p: (o.metadata(p), p.read_bytes()) for p in before})
                if phase == 'recovery-precommit':
                    self.assertTrue(os.path.samefile(self.path('/usr/local/bin/sbxr'), self.path('/usr/local/bin/.sbxr-update-prior')))
                    with self.assertRaisesRegex(o.Refused, 'unsafe-file:'):
                        o.protected_file(self.path('/usr/local/bin/sbxr'))

    def test_exact_link_relationship_not_simply_count_two(self):
        for shape in ('copy', 'two-separate-pairs', 'extra-alias'):
            with self.subTest(shape=shape), self.fixture() as root:
                active = self.path('/usr/local/bin/sbxr'); prior = self.path('/usr/local/bin/.sbxr-update-prior')
                if shape == 'extra-alias': os.link(active, root / 'third')
                else:
                    prior.unlink(); self.write(prior, active.read_bytes(), 0o755)
                    if shape == 'two-separate-pairs':
                        os.link(active, root / 'one'); os.link(prior, root / 'two')
                with self.assertRaisesRegex(o.Refused, 'unsafe-recovery-file|recovery-prior-hardlink'):
                    self.observe()

    def test_wrong_metadata_and_aliases_refused_on_every_bound_file(self):
        names = ['/usr/local/bin/sbxr', '/usr/local/bin/.sbxr-update-prior', '/usr/local/bin/.sbxr-update-candidate',
                 '/var/lib/sbxr/installed.json', '/var/lib/sbxr/.installed.json.prior', '/var/lib/sbxr/.installed.json.candidate',
                 '/var/lib/sbxr/update.json', '/var/lib/sbxr/proxy-ownership.json', '/root/request.json']
        for name in names:
            for change in ('hardlink', 'mode', 'owner', 'group', 'xattr', 'symlink', 'fifo'):
                with self.subTest(name=name, change=change), self.fixture() as root:
                    p = self.path(name)
                    if change == 'hardlink': os.link(p, root / 'alias')
                    elif change == 'mode': p.chmod(0o777)
                    elif change == 'owner': os.chown(p, 1, 0)
                    elif change == 'group': os.chown(p, 0, 1)
                    elif change == 'xattr': os.setxattr(p, 'user.fixture', b'x')
                    elif change == 'symlink': p.rename(root / 'actual'); p.symlink_to(root / 'actual')
                    else: p.unlink(); os.mkfifo(p, 0o600)
                    with self.assertRaises((o.Refused, OSError)):
                        self.observe()

    def test_altered_material_or_independent_expectation_refused(self):
        for name in ('/usr/local/bin/sbxr', '/usr/local/bin/.sbxr-update-candidate', '/var/lib/sbxr/installed.json',
                     '/var/lib/sbxr/.installed.json.prior', '/var/lib/sbxr/.installed.json.candidate', '/var/lib/sbxr/proxy-ownership.json'):
            with self.subTest(name=name), self.fixture():
                p = self.path(name); p.write_bytes(p.read_bytes() + b' ')
                with self.assertRaisesRegex(o.Refused, 'recovery-digest'): self.observe()
        for field in o.RECOVERY_FIELDS:
            with self.subTest(field=field), self.fixture():
                self.wanted[field] = '0' * 64
                with self.assertRaises(o.Refused): self.observe()

    def test_schema_checkpoint_unknown_and_duplicate_members_refused(self):
        for change in ({'schema': 1}, {'schema': True}, {'checkpoint': 'Committed'}, {'extra': True}):
            with self.subTest(change=change), self.fixture():
                self.write('/var/lib/sbxr/update.json', json.dumps(dict(self.checkpoint, **change)).encode())
                with self.assertRaisesRegex(o.Refused, 'recovery-checkpoint'): self.observe()
        with self.fixture():
            raw = json.dumps(self.checkpoint).encode()
            self.write('/var/lib/sbxr/update.json', raw[:-1] + b',"schema":2}')
            with self.assertRaisesRegex(o.Refused, 'duplicate-json-key'): self.observe()

    def test_staging_residue_and_missing_material_refused(self):
        for phase, names in [('recovery-precommit', ['/var/lib/sbxr/.update.json.next']),
                             ('recovery-postcommit', ['/var/lib/sbxr/.update.json.next', '/var/lib/sbxr/.installed.json.candidate', '/usr/local/bin/.sbxr-update-candidate'])]:
            for name in names:
                for symlink in (False, True):
                    with self.subTest(phase=phase, name=name, symlink=symlink), self.fixture(phase):
                        if symlink: self.path(name).symlink_to('/missing')
                        else: self.write(name, b'stale')
                        with self.assertRaisesRegex(o.Refused, 'recovery-unexpected-staging'): self.observe()
        for name in ('/var/lib/sbxr/update.json', '/usr/local/bin/.sbxr-update-prior', '/var/lib/sbxr/.installed.json.prior'):
            with self.subTest(name=name), self.fixture():
                self.path(name).unlink()
                with self.assertRaises((o.Refused, OSError)): self.observe()

    def test_request_binding_and_deadline_are_not_extended(self):
        for change in ({'scenario_id': 'source-v3.1.81-upgrade'}, {'scenario_id': 'source-v3.1.80-precommit'},
                       {'qualification_manifest_sha256': 'f' * 64}, {'deadline_unix': int(time.time()) - 1},
                       {'deadline_unix': int(time.time()) + 899}, {'deadline_unix': int(time.time()) + 2000},
                       {'scenario_limit_seconds': 7200}, {'not_before': '2999-01-01T00:00:00Z'}):
            with self.subTest(change=change), self.fixture():
                self.write(self.request_path, json.dumps(dict(self.request, **change)).encode())
                with self.assertRaises(o.Refused): self.observe()

    def test_installed_identity_and_ownership_schema_are_not_just_hashes(self):
        for change in ({'schema': 2}, {'schema': True}, {'tag': 'v3.1.80'}, {'sequence': 162},
                       {'architecture': 'arm64'}, {'repository': 'untrusted/SBXR'}, {'extra': 1}):
            with self.subTest(change=change), self.fixture():
                p = self.path('/var/lib/sbxr/.installed.json.prior')
                body = json.dumps(dict(json.loads(p.read_bytes()), **change)).encode()
                self.write(p, body); self.write('/var/lib/sbxr/installed.json', body)
                self.wanted['prior_installed_record_sha256'] = sha(body)
                self.write('/var/lib/sbxr/update.json', json.dumps(dict(self.wanted, schema=2, checkpoint='Prepared')).encode())
                with self.assertRaises(o.Refused): self.observe()
        with self.fixture():
            body = b'{"schema":1,"phase":"Running","unfinished_direction":"none"}'
            self.write('/var/lib/sbxr/proxy-ownership.json', body); self.wanted['ownership_sha256'] = sha(body)
            self.write('/var/lib/sbxr/update.json', json.dumps(dict(self.wanted, schema=2, checkpoint='Prepared')).encode())
            with self.assertRaisesRegex(o.Refused, 'recovery-ownership'): self.observe()

    def test_changed_path_during_read_is_refused(self):
        with self.fixture():
            original = o.os.fstat
            calls = []
            def changed(fd):
                result = original(fd); calls.append(fd)
                if len(calls) == 2:
                    p = self.request_path; body = p.read_bytes(); p.unlink(); self.write(p, body)
                return result
            with patch.object(o.os, 'fstat', side_effect=changed):
                with self.assertRaisesRegex(o.Refused, 'recovery-file-changed'): self.observe()


if __name__ == '__main__':
    unittest.main()
