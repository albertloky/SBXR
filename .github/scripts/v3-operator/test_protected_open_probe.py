#!/usr/bin/env python3
import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location("protected_open_probe", ROOT / "protected-open-probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProtectedOpenProbeTest(unittest.TestCase):
    def child(self, open_effect):
        runtime = tempfile.TemporaryDirectory()
        self.addCleanup(runtime.cleanup)
        info = types.SimpleNamespace(st_mode=0o40700, st_uid=123, st_gid=456)
        def opening(*_args):
            if isinstance(open_effect, BaseException):
                raise open_effect
            return open_effect
        with mock.patch.object(probe.os, "getuid", return_value=123), \
             mock.patch.object(probe.os, "geteuid", return_value=123), \
             mock.patch.object(probe.os, "getgid", return_value=456), \
             mock.patch.object(probe.os, "getgroups", return_value=[]), \
             mock.patch.object(probe.os, "stat", return_value=info), \
             mock.patch.object(probe.os, "chdir"), \
             mock.patch.object(probe, "status_fields", return_value={}), \
             mock.patch.object(probe.os, "open", side_effect=opening), \
             mock.patch.object(probe.os, "close"):
            return probe.child_run(["/protected/a", "/protected/b"], runtime.name)

    def test_child_requires_permission_refusal_for_every_existing_object(self):
        result = self.child(PermissionError(errno.EACCES, "denied"))
        self.assertEqual(result["protected_reads_refused"], 2)
        self.assertEqual({item["errno"] for item in result["refusals"]}, {"EACCES"})

    def test_child_rejects_missing_object_and_successful_open(self):
        with self.assertRaisesRegex(ValueError, "not a permission refusal"):
            self.child(FileNotFoundError(errno.ENOENT, "missing"))
        with self.assertRaisesRegex(ValueError, "unexpectedly succeeded"):
            self.child(9)

    def test_status_requires_all_capabilities_zero_and_no_new_privileges(self):
        safe = "\n".join([name + ":\t0000000000000000" for name in probe.ZERO_CAPABILITY_FIELDS] +
                         ["NoNewPrivs:\t1"])
        with mock.patch.object(probe.Path, "read_text", return_value=safe):
            self.assertEqual(probe.status_fields()["NoNewPrivs"], "1")
        with mock.patch.object(probe.Path, "read_text", return_value=safe.replace(
                "CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001")):
            with self.assertRaisesRegex(ValueError, "capability containment"):
                probe.status_fields()

    def exercise_operator(self, child_returncode=0, supplementary=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        runtime_parent = Path(temporary.name)
        account = types.SimpleNamespace(pw_name="sbxr24-010203040506", pw_dir="/nonexistent",
                                        pw_shell="/usr/sbin/nologin", pw_uid=123, pw_gid=456)
        child = {"protected_reads_refused": 2,
                 "refusals": [{"path": "/protected/a", "errno": "EACCES"},
                              {"path": "/protected/b", "errno": "EPERM"}],
                 "capabilities_zero": True, "no_new_privileges": True,
                 "private_runtime_empty": True}
        calls = []

        def run(command, **_kwargs):
            calls.append(command)
            if command[0] == "/usr/bin/setpriv":
                return subprocess.CompletedProcess(command, child_returncode,
                    json.dumps(child).encode() if child_returncode == 0 else b"", b"")
            return subprocess.CompletedProcess(command, 0, b"", b"")

        identity = {"path": "/protected/a", "device": 1}
        with mock.patch.object(probe.sys, "platform", "linux"), \
             mock.patch.object(probe.os, "geteuid", return_value=0), \
             mock.patch.object(probe, "load_paths", return_value=["/protected/a", "/protected/b"]), \
             mock.patch.object(probe, "object_identity", return_value=identity), \
             mock.patch.object(probe.secrets, "token_hex", return_value="010203040506"), \
             mock.patch.object(probe, "account_absent", side_effect=[True, True]), \
             mock.patch.object(probe.pwd, "getpwnam", return_value=account), \
             mock.patch.object(probe.os, "getgrouplist", return_value=[456, 999] if supplementary else [456]), \
             mock.patch.object(probe.os, "chown"), \
             mock.patch.object(probe.subprocess, "run", side_effect=run):
            error = None
            try:
                result = probe.run(paths_file="/paths", runtime_parent=str(runtime_parent))
            except Exception as caught:
                result, error = None, caught
        return result, error, calls, list(runtime_parent.iterdir())

    def test_operator_uses_fresh_account_clear_groups_zero_caps_and_cleans_success(self):
        result, error, calls, remains = self.exercise_operator()
        self.assertIsNone(error)
        self.assertTrue(result["account_removed"] and result["runtime_removed"])
        setpriv = next(command for command in calls if command[0] == "/usr/bin/setpriv")
        self.assertIn("--clear-groups", setpriv)
        self.assertIn("--bounding-set=-all", setpriv)
        self.assertIn("--no-new-privs", setpriv)
        self.assertIn("-", setpriv)
        self.assertNotIn(str(ROOT), " ".join(setpriv))
        self.assertEqual(remains, [])
        self.assertEqual(calls[-1], ["/usr/sbin/userdel", "sbxr24-010203040506"])

    def test_operator_cleans_account_and_runtime_on_probe_or_group_failure(self):
        for returncode, supplementary in ((1, False), (0, True)):
            with self.subTest(returncode=returncode, supplementary=supplementary):
                result, error, calls, remains = self.exercise_operator(returncode, supplementary)
                self.assertIsNone(result)
                self.assertIsNotNone(error)
                self.assertEqual(calls[-1], ["/usr/sbin/userdel", "sbxr24-010203040506"])
                self.assertEqual(remains, [])


if __name__ == "__main__":
    unittest.main()
