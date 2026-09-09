#!/usr/bin/env python3
import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import urllib.parse

ROOT = Path(__file__).parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

scanner = load("secret_containment", "secret-containment.py")
sandbox = load("sandbox_token_probe", "sandbox-token-probe.py")

class SecretContainmentTest(unittest.TestCase):
    def test_plain_base64_and_url_encodings_are_detected_without_match_output(self):
        secret = b"opaque+/ qualification secret"
        variants = scanner.secret_variants(secret)
        encoded = [secret, base64.b64encode(secret), base64.urlsafe_b64encode(secret).rstrip(b"="), urllib.parse.quote_from_bytes(secret, safe="").encode()]
        for body in encoded:
            with self.subTest(body=body[:6]):
                with self.assertRaisesRegex(scanner.SecretFound, "protected content detected"):
                    scanner.scan_bytes(b"prefix " + body + b" suffix", variants)
        scanner.scan_bytes(b"safe diagnostic with no protected values", variants)

    def test_private_key_and_authorization_headers_are_always_prohibited(self):
        for body in (b"-----BEGIN PRIVATE KEY-----", b"authorization: Bearer redacted", b"Authorization : Basic redacted"):
            with self.assertRaises(scanner.SecretFound):
                scanner.scan_bytes(body, ())

    def test_known_secret_input_requires_each_rotated_category(self):
        values = [
            {"id":"private-1","kind":"private-key","value":"A"*43}, {"id":"private-2","kind":"private-key","value":"B"*43},
            {"id":"uuid-1","kind":"client-uuid","value":"11111111-1111-4111-8111-111111111111"}, {"id":"uuid-2","kind":"client-uuid","value":"22222222-2222-4222-8222-222222222222"},
            {"id":"subscription-1","kind":"subscription-credential","value":"C"*43}, {"id":"subscription-2","kind":"subscription-credential","value":"D"*43},
            {"id":"transport","kind":"qualification-secret","value":"qualification-only-token"},
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "secrets.json"); path.write_text(json.dumps({"schema":scanner.SECRET_SCHEMA,"secrets":values}))
            variants, kinds = scanner.load_secrets(path, require_root=False)
            self.assertEqual(kinds, {"private-key":2,"client-uuid":2,"subscription-credential":2,"qualification-secret":1})
            self.assertIn(b"A"*43, variants)
            path.write_text(json.dumps({"schema":scanner.SECRET_SCHEMA,"secrets":values[:-2] + values[-1:]}))
            with self.assertRaisesRegex(scanner.CoverageError, "category coverage"):
                scanner.load_secrets(path, require_root=False)

    def spec(self, root, surfaces=None):
        surfaces = surfaces or scanner.SURFACES
        captures = []
        for surface in sorted(surfaces):
            path = root / f"{surface}.log"; path.write_text("safe\n")
            captures.append({"surface":surface,"path":str(path)})
        protected = root / "protected"; protected.write_text("protected body"); protected.chmod(0o600)
        preserved = root / "preserved"; preserved.write_text("owner data"); preserved.chmod(0o600)
        return {"schema":scanner.SCHEMA,"captures":captures,"units":["sbxr-subscription.service"],"proc_root":"/proc",
                "protected_objects":[{"path":str(protected),"state":"present","kind":"file","mode":"0600","uid":protected.stat().st_uid,"gid":protected.stat().st_gid,"nlink":1}],
                "preserved_objects":[{"path":str(preserved),"state":"present","kind":"file","mode":"0600","uid":preserved.stat().st_uid,"gid":preserved.stat().st_gid,"nlink":1,"sha256":scanner.hashlib.sha256(preserved.read_bytes()).hexdigest()}],
                "cleanup_paths":[str(root / "gone")],"cleanup_processes":[{"pid":99999999,"start_tick":1}]}

    def write_spec(self, root, value):
        path = root / "spec.json"; path.write_text(json.dumps(value)); return path

    def test_missing_surface_duplicate_path_and_symlink_refuse_coverage(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaisesRegex(scanner.CoverageError, "capture coverage incomplete"):
                scanner.validate_spec(self.write_spec(root, self.spec(root, scanner.SURFACES - {"mac"})))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); value = self.spec(root); value["captures"][1]["path"] = value["captures"][0]["path"]
            with self.assertRaisesRegex(scanner.CoverageError, "distinct"):
                scanner.validate_spec(self.write_spec(root, value))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); target = root / "target"; target.write_text("safe"); link = root / "link"; link.symlink_to(target)
            with self.assertRaisesRegex(scanner.CoverageError, "symlink"):
                scanner.capture_files(link)

    def test_capture_refuses_same_size_rewrite_during_scan(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "capture"); path.write_bytes(b"safe")
            current = path.stat()
            changed = types.SimpleNamespace(st_mode=current.st_mode, st_dev=current.st_dev,
                st_ino=current.st_ino, st_size=current.st_size,
                st_mtime_ns=current.st_mtime_ns + 1, st_ctime_ns=current.st_ctime_ns + 1)
            actual_fstat = os.fstat
            results = iter([current, changed])
            with mock.patch.object(scanner.os, "fstat", side_effect=lambda descriptor: next(results)):
                with self.assertRaisesRegex(scanner.CoverageError, "capture changed"):
                    scanner.read_regular(path)

    def test_protection_and_cleanup_use_declared_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); value = self.spec(root); spec = scanner.validate_spec(self.write_spec(root, value))
            self.assertEqual(scanner.check_protection(spec), (1, 1))
            self.assertEqual(scanner.check_cleanup(spec), (1, 1))
            Path(value["cleanup_paths"][0]).write_text("unexpected")
            with self.assertRaisesRegex(scanner.CoverageError, "remains"):
                scanner.check_cleanup(spec)

    def test_sandbox_probe_uses_mount_namespace_root_and_drops_capabilities(self):
        args = types.SimpleNamespace(token="/token", staging="/staging", unit="sbxr-subscription.service", executable="/sbxr", argument=["--subscription-serving"], fragment="/unit")
        before = {"pid":44,"start_tick":55,"exe_device":1,"exe_inode":2,"mount_namespace":"mnt:[3]"}
        completed = sandbox.subprocess.CompletedProcess([], 42, b"", b"")
        with mock.patch.object(sandbox.os, "geteuid", return_value=0), mock.patch.object(sandbox, "host_object"), \
             mock.patch.object(sandbox, "identity", side_effect=[before,before]), mock.patch.object(sandbox.subprocess, "run", return_value=completed) as run:
            result = sandbox.run(args)
        command = run.call_args.args[0]
        self.assertIn("--mount=/proc/44/ns/mnt", command); self.assertIn("--root=/proc/44/root", command)
        self.assertIn("--bounding-set=-all", command); self.assertIn("--no-new-privs", command)
        self.assertEqual(result["protected_reads_refused"], 2)

    def test_sandbox_identity_requires_zero_capabilities_and_no_new_privileges(self):
        safe = "\n".join(["CapInh:\t0000000000000000","CapPrm:\t0000000000000000","CapEff:\t0000000000000000","CapBnd:\t0000000000000000","CapAmb:\t0000000000000000","NoNewPrivs:\t1"])
        with mock.patch.object(sandbox.Path, "read_text", return_value=safe):
            self.assertEqual(sandbox.status_fields(44)["CapEff"], "0000000000000000")
        with mock.patch.object(sandbox.Path, "read_text", return_value=safe.replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001")):
            with self.assertRaisesRegex(ValueError, "capability containment"):
                sandbox.status_fields(44)

if __name__ == "__main__":
    unittest.main()
