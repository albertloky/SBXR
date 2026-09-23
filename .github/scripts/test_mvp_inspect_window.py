#!/usr/bin/env python3
"""Portable contract regressions; real dpkg/SSH/window rehearsal is adjacent."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('observer', Path(__file__).with_name('mvp-inspect-window.py'))
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)
RECEIPT = {'repository': 'https://deb.sagernet.org/', 'name': 'sing-box',
           'version': '1.13.19', 'architecture': 'amd64', 'size': 24597120,
           'sha256': 'fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf'}


class PackageObservation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='mvp-observer-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        def path(name):
            return self.root / str(name).lstrip('/')
        self.path = path
        self.patches = [patch.object(OBSERVER, 'Path', side_effect=path),
                        patch.object(OBSERVER, 'protected_file')]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.expected = {'proxy_package': RECEIPT, 'installed_binary_sha256': '1' * 64}
        self.command = patch.object(OBSERVER, 'command', return_value='1.13.19\tamd64\thold ok installed').start()
        self.addCleanup(patch.stopall)
        self.ownership = {'phase': 'Running', 'unfinished_direction': 'none',
                          'proxy_package_identity': OBSERVER.ownership_identity(RECEIPT)}
        for name in ('/var/lib/sbxr/installed.json', '/usr/local/bin/sbxr', '/usr/bin/sing-box'):
            self.write(name, '{}')
        self.write('/var/lib/sbxr/proxy-ownership.json', json.dumps(self.ownership))
        patch.object(OBSERVER, 'digest', return_value='1' * 64).start()

    def write(self, name, text):
        p = self.path(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def observe(self, phase='running'):
        return OBSERVER.package_observation(phase, self.expected)

    def test_running_observes_held_package_without_temporary_deb(self):
        self.assertEqual(self.observe()['status'], 'hold ok installed')
        self.command.assert_called_once()

    def test_ownership_is_product_string_not_declaration_object(self):
        self.assertEqual(self.observe()['ownership_package_identity'], OBSERVER.ownership_identity(RECEIPT))
        self.ownership['proxy_package_identity'] = RECEIPT
        self.write('/var/lib/sbxr/proxy-ownership.json', json.dumps(self.ownership))
        with self.assertRaisesRegex(OBSERVER.Refused, 'ownership-package'):
            self.observe()

    def test_unheld_wrong_version_architecture_and_config_only_refused(self):
        for status in ('1.13.19\tamd64\tinstall ok installed',
                       '1.13.18\tamd64\thold ok installed',
                       '1.13.19\tarm64\thold ok installed',
                       '1.13.19\tamd64\tdeinstall ok config-files', None):
            with self.subTest(status=status):
                self.command.return_value = status
                with self.assertRaisesRegex(OBSERVER.Refused, 'installed-proxy-package'):
                    self.observe()

    def test_artifact_and_broken_symlink_refused(self):
        artifact = self.path('/var/lib/sbxr/sing-box_1.13.19_amd64.deb')
        for symlink in (False, True):
            if symlink:
                artifact.symlink_to(self.root / 'missing')
            else:
                artifact.write_bytes(b'leftover')
            with self.assertRaisesRegex(OBSERVER.Refused, 'temporary-package-artifact'):
                self.observe()
            artifact.unlink()

    def test_renewal_idle_is_checked_without_deb(self):
        for evidence in ({'attempts': [{'completion': None}]}, {'attempts': {}}, {}):
            self.write('/var/lib/sbxr/renewal-attempts.json', json.dumps(evidence))
            with self.assertRaisesRegex(OBSERVER.Refused, 'renewal'):
                self.observe()
        for attempts in (None, [], [{'completion': {'exit_code': 0}}]):
            self.write('/var/lib/sbxr/renewal-attempts.json', json.dumps({'attempts': attempts}))
            self.assertEqual(self.observe()['status'], 'hold ok installed')

    def test_absent_states_and_stale_paths(self):
        self.command.return_value = None
        for name in ('/var/lib/sbxr/proxy-ownership.json', '/usr/bin/sing-box'):
            self.path(name).unlink()
        self.assertIsNone(self.observe('not-set-up'))
        for name in ('/usr/local/bin/sbxr', '/var/lib/sbxr/installed.json'):
            self.path(name).unlink()
        for phase in ('not-installed', 'removed'):
            self.assertIsNone(self.observe(phase))
        self.path('/var/lib/sbxr/proxy-ownership.json').symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(OBSERVER.Refused, 'unexpected-owned-path'):
            self.observe('removed')

    def test_wrong_binary_and_incomplete_ownership_refused(self):
        with patch.object(OBSERVER, 'digest', return_value='2' * 64):
            with self.assertRaisesRegex(OBSERVER.Refused, 'installed-proxy-binary'):
                self.observe()
        for field, value in (('phase', 'Package installed'),
                             ('unfinished_direction', 'cleanup required')):
            record = dict(self.ownership, **{field: value})
            self.write('/var/lib/sbxr/proxy-ownership.json', json.dumps(record))
            with self.assertRaisesRegex(OBSERVER.Refused, 'ownership-phase'):
                self.observe()

    def test_absence_is_not_inferred_from_missing_deb(self):
        for phase in ('not-installed', 'not-set-up', 'removed'):
            with self.subTest(phase=phase):
                with self.assertRaisesRegex(OBSERVER.Refused, 'unexpected-proxy-package'):
                    self.observe(phase)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                     'real root-owned snap/cache filesystem tests require root Linux')
class SnapObservation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='mvp-snap-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.snaps = self.root / 'snaps'
        self.cache = self.root / 'cache'
        self.snaps.mkdir(mode=0o755)
        self.cache.mkdir(mode=0o700)
        self.expected = {}
        for name in ('certbot', 'core24', 'snapd'):
            path = self.snaps / (name + '_123.snap')
            path.write_bytes(('fixture ' + name).encode())
            path.chmod(0o600)
            os.link(path, self.cache / name)
            self.assertEqual(path.stat().st_nlink, 2)
            self.assertTrue(os.path.samefile(path, self.cache / name))
            self.expected[name] = {'version': 'fixture', 'revision': '123',
                                   'snap_sha256': OBSERVER.digest(path),
                                   'snap_size': path.stat().st_size}
        # Only the snap CLI and absolute directory are fixtures. Metadata,
        # hard links, file reads, hashes, ownership and xattrs are real Linux.
        paths = patch.object(OBSERVER, 'Path', side_effect=self.snap_path)
        paths.start()
        self.addCleanup(paths.stop)
        commands = patch.object(OBSERVER, 'command', side_effect=self.snap_list)
        self.command = commands.start()
        self.addCleanup(commands.stop)
        self.image = self.snaps / 'certbot_123.snap'

    def snap_path(self, name):
        self.assertEqual(str(name), '/var/lib/snapd/snaps')
        return self.snaps

    def snap_list(self, *args):
        self.assertEqual(args[:2], ('snap', 'list'))
        self.assertIn(args[2], self.expected)
        return 'Name Version Rev\n' + args[2] + ' fixture 123'

    def observe(self):
        return OBSERVER.snap_observation(self.expected)

    def test_cache_hardlinks_are_accepted_without_mutation(self):
        before = {p: (OBSERVER.metadata(p), p.read_bytes())
                  for parent in (self.snaps, self.cache) for p in parent.iterdir()}
        self.assertEqual(self.observe(), self.expected)
        self.assertEqual(self.command.call_count, 3)
        self.assertEqual(before, {p: (OBSERVER.metadata(p), p.read_bytes()) for p in before})

    def test_single_link_images_are_also_accepted(self):
        for path in self.cache.iterdir():
            path.unlink()
        self.assertEqual(self.observe(), self.expected)

    def test_group_or_other_writable_image_is_refused(self):
        for mode in (0o620, 0o602, 0o666):
            with self.subTest(mode=oct(mode)):
                self.image.chmod(mode)
                with self.assertRaisesRegex(OBSERVER.Refused, 'unsafe-file:'):
                    self.observe()

    def test_nonroot_owner_or_group_is_refused(self):
        for uid, gid in ((1, 0), (0, 1)):
            with self.subTest(uid=uid, gid=gid):
                os.chown(self.image, uid, gid)
                with self.assertRaisesRegex(OBSERVER.Refused, 'unsafe-file:'):
                    self.observe()

    def test_xattrs_are_refused(self):
        os.setxattr(self.image, 'user.mvp-fixture', b'present')
        with self.assertRaisesRegex(OBSERVER.Refused, 'unsafe-file:'):
            self.observe()

    def test_symlink_directory_and_fifo_are_refused(self):
        self.image.unlink()
        for kind in ('symlink', 'broken-symlink', 'directory', 'fifo'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    self.image.symlink_to(self.cache / 'certbot')
                elif kind == 'broken-symlink':
                    self.image.symlink_to(self.root / 'missing')
                elif kind == 'directory':
                    self.image.mkdir()
                else:
                    os.mkfifo(self.image, 0o600)
                try:
                    with self.assertRaisesRegex(OBSERVER.Refused, 'unsafe-file:'):
                        self.observe()
                finally:
                    if kind == 'directory':
                        self.image.rmdir()
                    else:
                        self.image.unlink()

    def test_changed_content_through_cache_link_is_refused(self):
        # Same length ensures the digest check, not just size, finds the drift.
        cache = self.cache / 'certbot'
        cache.write_bytes(b'x' * cache.stat().st_size)
        with self.assertRaisesRegex(OBSERVER.Refused, 'snap-receipt-drift'):
            self.observe()

    def test_receipt_fields_are_still_checked(self):
        original = dict(self.expected['certbot'])
        for key, value in (('version', 'wrong'), ('revision', '124'),
                           ('snap_size', 1), ('snap_sha256', '0' * 64)):
            with self.subTest(field=key):
                self.expected['certbot'] = dict(original, **{key: value})
                with self.assertRaisesRegex(OBSERVER.Refused, 'snap-receipt-drift'):
                    self.observe()

    def test_other_protected_files_still_require_one_link(self):
        # Including a .snap suffix: the exception must be explicit at the
        # snap observation call, not inferred from a filename or global rule.
        for name in ('operator.sh', 'installed.json', 'proxy-ownership.json',
                     'renewal-attempts.json', 'sbxr.lock', 'unrelated.snap'):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(b'private')
                path.chmod(0o600)
                OBSERVER.protected_file(path, 0o600)
                os.link(path, self.root / (name + '.link'))
                with self.assertRaisesRegex(OBSERVER.Refused, 'unsafe-file:'):
                    OBSERVER.protected_file(path, 0o600)


if __name__ == '__main__':
    unittest.main()
