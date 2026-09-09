#!/usr/bin/env python3
"""Receipt-binding refusals at the controller's actual validation interface."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('managed_hold', Path(__file__).with_name('managed-hold.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ReceiptBinding(unittest.TestCase):
    def setUp(self):
        self.before = {'recorder_id': 'r', 'attempts': []}
        self.item = {'attempt_id': 'a'*32, 'invocation': 'snap-certbot-renew-v1', 'recorder_pid': 12, 'process_tick': 345, 'boot_id': 'boot'}
        self.after = {'recorder_id': 'r', 'attempts': [self.item]}

    def test_live_receipt(self):
        self.assertEqual(m.new_attempt(self.before, self.after, 12, 345, 'boot'), self.item)

    def test_identity_reuse_and_false_completion_refused(self):
        for field, changed in [('recorder_pid', 13), ('process_tick', 346), ('boot_id', 'old'), ('invocation', 'snap-certbot-certonly-v1'), ('completion', {'exit_code': 0}), ('attempt_id', 'invalid')]:
            with self.subTest(field=field):
                after = copy.deepcopy(self.after)
                after['attempts'][0][field] = changed
                with self.assertRaises(ValueError):
                    m.new_attempt(self.before, after, 12, 345, 'boot')

    def test_no_new_or_multiple_attempts_refused(self):
        for after in [self.before, {'recorder_id': 'r', 'attempts': [self.item, dict(self.item, attempt_id='b'*32)]}, dict(self.after, recorder_id='other')]:
            with self.assertRaises(ValueError):
                m.new_attempt(self.before, after, 12, 345, 'boot')
        with self.assertRaises(ValueError):
            m.new_attempt(self.after, self.after, 12, 345, 'boot')

    def test_duplicate_protected_keys_refused(self):
        with self.assertRaises(ValueError):
            json.loads('{"schema":1,"schema":1}', object_pairs_hook=m.unique)

    @unittest.skipUnless(os.geteuid() == 0, 'Linux root fixture required for protected root metadata')
    def test_symlink_hardlink_and_mode_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'receipt')
            path.write_text('{"schema":1,"attempts":[]}')
            path.chmod(0o600)
            self.assertEqual(m.receipt(path)[0]['schema'], 1)
            link = Path(directory, 'link')
            link.symlink_to(path)
            with self.assertRaises(OSError):
                m.receipt(link)
            link.unlink()
            os.link(path, link)
            with self.assertRaises(ValueError):
                m.receipt(path)
            link.unlink()
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                m.receipt(path)


if __name__ == '__main__':
    unittest.main()
