#!/usr/bin/env python3
"""Portable contract regressions; real dpkg/SSH/window rehearsal is adjacent."""
import importlib.util
import json
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


if __name__ == '__main__':
    unittest.main()
