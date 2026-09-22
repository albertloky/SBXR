#!/usr/bin/env python3
"""Real-SSH regression with a locked caller account, without changing the host."""

import ctypes
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parent
LOCKED_SHADOW = b"root:!:20000:0:99999:7:::\n"


def locked_caller(root):
    """Run the unchanged fixture in a caller namespace with a locked root."""
    if os.getpid() != 1:
        raise RuntimeError("account regression requires its PID namespace")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    shadow = root / "caller-shadow"
    shadow.write_bytes(LOCKED_SHADOW)
    shadow.chmod(0o600)
    subprocess.run(["mount", "--bind", str(shadow), "/etc/shadow"], check=True)
    subprocess.run(["mount", "-o", "remount,bind,ro", "/etc/shadow"], check=True)
    script = root / "checkout/.github/scripts/test_ssh_boundary.py"
    spec = importlib.util.spec_from_file_location("ssh_boundary", script)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    # Calling outer directly retains the locked caller so we can verify that
    # success and intentional failure both restore its exact account view.
    try:
        return fixture.outer()
    finally:
        if Path("/etc/shadow").read_bytes() != LOCKED_SHADOW:
            raise RuntimeError("SSH fixture changed the caller account")


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
                     "requires root Linux")
class LockedAccountTests(unittest.TestCase):
    def exercise(self, fail_after_ready=False):
        for tool in ("unshare", "mount", "sshd", "ssh", "ssh-keygen", "jq", "sha256sum"):
            if shutil.which(tool) is None:
                self.skipTest("missing " + tool)
        shadow = Path("/etc/shadow")
        before = shadow.read_bytes(), shadow.stat()

        def unchanged_host_account():
            # Compare privately: an assertion must never print shadow records.
            self.assertTrue(shadow.read_bytes() == before[0], "host shadow contents changed")
            after = shadow.stat()
            for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_mtime_ns"):
                self.assertEqual(getattr(after, field), getattr(before[1], field), field)

        self.addCleanup(unchanged_host_account)
        with tempfile.TemporaryDirectory(prefix="sbxr-ssh-account-") as name:
            root = Path(name)
            scripts = root / "checkout/.github/scripts"
            scripts.mkdir(parents=True)
            for filename in ("test_ssh_boundary.py", "v3-packaged-live.sh",
                             "v3-menu-session.py", "v3-recurring-evidence.sh"):
                shutil.copyfile(SOURCE / filename, scripts / filename)
            docs = root / "checkout/docs/acceptance"
            docs.mkdir(parents=True)
            target = docs / "mvp-live-acceptance.md"
            if fail_after_ready:
                target.write_text("Deliberately missing the handoff example.\n")
            else:
                shutil.copyfile(SOURCE.parents[1] / "docs/acceptance/mvp-live-acceptance.md", target)
            command = ["unshare", "--mount", "--pid", "--fork", "--mount-proc",
                       "--kill-child=KILL", sys.executable, str(Path(__file__).resolve()),
                       "--locked-caller", str(root)]
            parent_pid = os.getpid()

            def bind_parent_lifetime():
                libc = ctypes.CDLL(None, use_errno=True)
                if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
                    raise OSError(ctypes.get_errno(), "parent-death signal")
                if os.getppid() != parent_pid:
                    os.kill(os.getpid(), signal.SIGKILL)

            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True, preexec_fn=bind_parent_lifetime)
            try:
                stdout, stderr = process.communicate(timeout=115)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate(timeout=5)
            if fail_after_ready:
                self.assertEqual(process.returncode, 1, (stdout, stderr))
                self.assertEqual(stdout, b"")
                self.assertEqual(stderr, b"SSH_BOUNDARY_REFUSED case=candidate-handoff-example\n")
            else:
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stdout, b"SSH_BOUNDARY_CASES_PASSED count=21\n")
                self.assertEqual(stderr, b"")

    def test_locked_caller_success(self):
        self.exercise()

    def test_locked_caller_failure_cleanup(self):
        self.exercise(fail_after_ready=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--locked-caller":
        raise SystemExit(locked_caller(Path(sys.argv[2])))
    unittest.main()
