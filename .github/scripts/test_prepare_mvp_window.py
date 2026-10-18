"""Offline archive/role regression; no executable or host operation is run."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('prepare_window', HERE/'prepare-mvp-window.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


def package(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:gz') as archive:
        for name, body, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    raw = b'!<arch>\n'
    for name, body in [('debian-binary', b'2.0\n'), ('data.tar.gz', data.getvalue())]:
        header = f'{name + "/":<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(body):<10}`\n'.encode()
        raw += header + body + (b'\n' if len(body) % 2 else b'')
    return raw


class Roles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proxy = b'fixture sing-box executable; never executed'
        self.sbxr = b'distinct fixture SBXR executable; never executed'
        self.deb = self.root/'proxy.deb'
        self.expected = {'proxy_package': {'name': 'sing-box', 'version': '1.13.19', 'architecture': 'amd64'},
                         'installed_binary_sha256': hashlib.sha256(self.sbxr).hexdigest(),
                         'log_parent': {'fixture': True}, 'log_children': {}, 'snap_packages': {},
                         'operator_sha256': {}}
        self.write_package([('./usr/bin/sing-box', self.proxy, tarfile.REGTYPE)])

    def write_package(self, entries):
        raw = package(entries)
        self.deb.write_bytes(raw)
        self.expected['proxy_package'].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    def test_derives_proxy_role_and_preserves_all_other_inputs(self):
        before = copy.deepcopy(self.expected)
        result = prepare.prepare(self.expected, self.deb)
        self.assertEqual(result['installed_binary_sha256'], hashlib.sha256(self.proxy).hexdigest())
        self.assertNotEqual(result['installed_binary_sha256'], self.expected['installed_binary_sha256'])
        self.assertNotEqual(result['installed_binary_sha256'], self.expected['proxy_package']['sha256'])
        self.assertEqual(self.expected, before)
        del result['installed_binary_sha256'];del before['installed_binary_sha256']
        self.assertEqual(result, before)

    def test_unverified_deb_refuses_before_archive_parsing(self):
        for key, value in [('size', 1), ('sha256', '0'*64)]:
            with self.subTest(key=key):
                expected = copy.deepcopy(self.expected);expected['proxy_package'][key] = value
                with self.assertRaisesRegex(ValueError, 'size or SHA-256'):
                    prepare.prepare(expected, self.deb)

    def test_missing_duplicate_or_nonregular_proxy_refuses(self):
        for entries in [[], [('./usr/bin/sbxr', self.sbxr, tarfile.REGTYPE)],
                        [('./usr/bin/sing-box', self.proxy, tarfile.REGTYPE)]*2,
                        [('./usr/bin/sing-box', b'', tarfile.SYMTYPE)]]:
            with self.subTest(entries=entries):
                self.write_package(entries)
                with self.assertRaisesRegex(ValueError, 'executable'):
                    prepare.prepare(self.expected, self.deb)

    def test_cli_preserves_input_and_refuses_output_replay(self):
        source, output = self.root/'input.json', self.root/'output.json'
        source.write_text(json.dumps(self.expected));before=source.read_bytes()
        argv = [sys.executable, '-B', str(HERE/'prepare-mvp-window.py'), '--input', str(source),
                '--proxy-deb', str(self.deb), '--output', str(output)]
        p = subprocess.run(argv, capture_output=True);self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(output.read_bytes())['installed_binary_sha256'], hashlib.sha256(self.proxy).hexdigest())
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        original = output.read_bytes()
        self.assertNotEqual(subprocess.run(argv, capture_output=True).returncode, 0)
        self.assertEqual(source.read_bytes(), before);self.assertEqual(output.read_bytes(), original)

    def test_duplicate_input_is_not_normalized_into_an_expectation(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate expectation member'):
            json.loads('{"proxy_package":{},"proxy_package":{}}', object_pairs_hook=prepare.unique)


if __name__ == '__main__':
    unittest.main()
