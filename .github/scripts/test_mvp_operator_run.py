#!/usr/bin/env python3
"""Exercise nested operator captures with actual files and process execution."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).with_name("mvp-operator-run.py")

# The September 29 live.py remote() boundary: outer stderr existed before
# this guard ran. The inner command is a local fixture; no SSH or observation.
INNER = r"""
import pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1]); label = sys.argv[2]
out = root / (label + '.private'); err = root / (label + '.stderr')
assert not out.exists() and not err.exists()
with out.open('wb') as o, err.open('wb') as e:
    result = subprocess.run([sys.executable, '-c',
        "import sys; print('inner stdout'); print('inner stderr', file=sys.stderr)"],
        stdout=o, stderr=e)
(root / (label + '.receipt.json')).write_text(str(result.returncode))
print('outer stdout: ' + sys.stdin.read())
print('outer stderr', file=sys.stderr)
"""


class OperatorRunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="operator-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inner = self.root / "inner.py"
        self.inner.write_text(INNER)
        self.label = "s1-finish"

    def call(self, command=None, label=None, directory=None):
        command = command or [sys.executable, str(self.inner), str(self.root), self.label]
        return subprocess.run([sys.executable, str(SCRIPT), "--run-directory", str(directory or self.root),
                               "--label", self.label if label is None else label, "--", *command],
                              input=b"stdin preserved", capture_output=True, timeout=10)

    def test_original_outer_stderr_collision_stops_inner_before_launch(self):
        with (self.root / (self.label + ".stderr")).open("xb") as err:
            result = subprocess.run([sys.executable, str(self.inner), str(self.root), self.label],
                                    stderr=err, capture_output=False, stdout=subprocess.PIPE, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"AssertionError", (self.root / (self.label + ".stderr")).read_bytes())
        self.assertFalse((self.root / (self.label + ".private")).exists())
        self.assertFalse((self.root / (self.label + ".receipt.json")).exists())

    def test_outer_logs_and_inner_captures_are_disjoint(self):
        result = self.call()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, b"")
        expected = {".operator.stdout": b"outer stdout: stdin preserved\n",
                    ".operator.stderr": b"outer stderr\n",
                    ".private": b"inner stdout\n", ".stderr": b"inner stderr\n",
                    ".receipt.json": b"0"}
        for suffix, body in expected.items():
            path = self.root / (self.label + suffix)
            self.assertEqual(path.read_bytes(), body)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        self.assertNotEqual(self.call().returncode, 0)
        self.assertEqual({p.name: p.read_bytes() for p in self.root.iterdir()}, before)

    def test_existing_regular_linked_and_broken_link_paths_refuse_without_launch(self):
        for suffix in (".operator.stdout", ".operator.stderr", ".private", ".stderr", ".receipt.json"):
            for kind in ("file", "hardlink", "symlink", "broken-symlink"):
                with self.subTest(suffix=suffix, kind=kind), tempfile.TemporaryDirectory(dir=self.root) as name:
                    directory = Path(name)
                    path = directory / (self.label + suffix)
                    target = directory / "retained"
                    target.write_bytes(b"retained evidence")
                    if kind == "file":
                        path.write_bytes(b"retained evidence")
                    elif kind == "hardlink":
                        os.link(target, path)
                    else:
                        path.symlink_to(target if kind == "symlink" else directory / "absent")
                    before = set(directory.iterdir())
                    result = self.call(directory=directory)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b"command not launched", result.stderr)
                    self.assertEqual(set(directory.iterdir()), before)
                    self.assertEqual(target.read_bytes(), b"retained evidence")
                    if kind != "broken-symlink":
                        self.assertEqual(path.read_bytes(), b"retained evidence")

    def test_exit_status_and_failure_output_preserved(self):
        result = self.call([sys.executable, "-c",
                            "import sys; print('failure stdout'); print('failure stderr', file=sys.stderr); sys.exit(23)"])
        self.assertEqual(result.returncode, 23)
        self.assertEqual((self.root / (self.label + ".operator.stdout")).read_bytes(), b"failure stdout\n")
        self.assertEqual((self.root / (self.label + ".operator.stderr")).read_bytes(), b"failure stderr\n")

    def test_cancellation_reaches_the_same_process_without_orphan(self):
        pid_file = self.root / "command.pid"
        command = [sys.executable, "-c",
                   "import os, pathlib, sys, time; p=pathlib.Path(sys.argv[1]); t=p.with_suffix('.next'); t.write_text(str(os.getpid())); t.rename(p); time.sleep(30)",
                   str(pid_file)]
        process = subprocess.Popen([sys.executable, str(SCRIPT), "--run-directory", str(self.root),
                                    "--label", self.label, "--", *command],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not pid_file.exists() and time.monotonic() < deadline and process.poll() is None:
                time.sleep(0.01)
            self.assertTrue(pid_file.exists(), "command did not start")
            self.assertEqual(int(pid_file.read_text()), process.pid)
            process.terminate()
            self.assertEqual(process.wait(timeout=5), -signal.SIGTERM)
            with self.assertRaises(ProcessLookupError):
                os.kill(process.pid, 0)
        finally:
            # Clean every fixture descendant even if a future regression adds
            # a supervisor and the same-PID assertion fails.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=5)

    def test_invalid_label_does_not_launch(self):
        for label in ("../escape", "", ".", "s1.finish"):
            self.assertNotEqual(self.call(label=label).returncode, 0)
        self.assertEqual(set(p.name for p in self.root.iterdir()), {"inner.py"})


if __name__ == "__main__":
    unittest.main()
