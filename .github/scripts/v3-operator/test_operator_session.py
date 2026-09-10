"""Exercise observation failures in a persistent strict Bash session on a PTY.

This is local operator regression coverage, not live SSH qualification evidence.
"""
import errno
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent


class OperatorSessionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # Initialization checks real paths and loads the real packaged module.
        # No candidate or host actions are invoked by these observation tests.
        manifest = self.root / "manifest.json"
        request = self.root / "request.json"
        manifest.write_text("{}")
        request.write_text("{}")
        self.environment = {
            "PATH": os.environ["PATH"],
            "SBXR_V3_PACKAGED_LIVE_MODULE": str(HERE.parent / "v3-packaged-live.sh"),
            "SBXR_QUALIFICATION_MANIFEST": str(manifest),
            "SBXR_QUALIFICATION_REQUEST": str(request),
            "SBXR_INSTALLED_RECORD": str(self.root / "installed.json"),
            "SBXR_EXECUTABLE": str(self.root / "sbxr"),
            "SBXR_OPERATOR_STATE_DIR": str(self.root),
            "SBXR_OPERATOR_EVIDENCE_DIR": str(self.root),
            "SBXR_TRANSPORT_ROOT": str(self.root),
            "SBXR_TRANSPORT_UNIT": "sbxr-qualification-v3.service",
        }
        session = self.root / "session.sh"
        session.write_text(
            'set -euo pipefail\n'
            'source "$1"\n'
            'printf "SESSION_READY:%s\\n" "$$"\n'
            'while IFS= read -r command; do eval "$command"; done\n'
        )
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execve("/bin/bash", ["bash", "--noprofile", "--norc",
                                  str(session), str(HERE / "operator-support.sh")],
                      self.environment)
        self.reaped = False
        self.output = b""
        self.addCleanup(self.close_session)
        self.read_until(f"SESSION_READY:{self.pid}\r\n")

    def close_session(self):
        os.close(self.fd)
        if not self.reaped:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(self.pid, 0)

    def send(self, command):
        os.write(self.fd, command.encode() + b"\n")

    def read_until(self, expected):
        deadline = time.monotonic() + 5
        while expected.encode() not in self.output:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.fd], [], [], remaining)[0]:
                self.fail(f"missing {expected!r}: {self.output!r}")
            try:
                chunk = os.read(self.fd, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b""
            if not chunk:
                self.fail(f"session closed before {expected!r}: {self.output!r}")
            self.output += chunk

    def expect_exit(self, code):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            # Drain echoed input/output while Bash exits. A PTY can otherwise
            # keep terminal teardown pending even after the shell has stopped.
            if select.select([self.fd], [], [], 0)[0]:
                try:
                    self.output += os.read(self.fd, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.reaped = True
                self.assertTrue(os.WIFEXITED(status))
                self.assertEqual(os.WEXITSTATUS(status), code)
                return
            time.sleep(0.01)
        self.fail("strict session did not exit")

    def test_unwrapped_nonzero_status_probe_closes_original_session(self):
        # The reported pattern: a successful scenario followed by an optional
        # read-only status pipeline whose final command returns nonzero.
        marker = self.root / "incorrect-continuation"
        self.send("printf 'Not set up\\n' | grep -q '^Running$'; "
                  + f"touch {shlex.quote(str(marker))}")
        self.expect_exit(1)
        self.assertFalse(marker.exists())

    def observe(self, script, status):
        self.output = b""
        self.send("operator_observe " + shlex.quote(script))
        self.read_until(f"OPERATOR_OBSERVATION_EXIT={status}\r\n")
        self.send('test "$OPERATOR_OBSERVATION_STATUS" -eq ' + str(status)
                  + '; printf "SESSION_ALIVE:%s\\n" "$$"')
        self.read_until(f"SESSION_ALIVE:{self.pid}\r\n")

    def test_failed_probes_preserve_same_session_and_exact_status(self):
        marker = self.root / "incorrect-probe-continuation"
        continuation = f"; touch {shlex.quote(str(marker))}"
        for script, status in [
            ("printf 'Not set up\\n' | grep -q '^Running$'", 1),
            ("false | cat" + continuation, 1),
            ("exit 17", 17),
            ('printf "%s" "$UNSET_PROBE_VARIABLE"', 1),
            ("printf 'observed\\n'", 0),
        ]:
            with self.subTest(script=script):
                self.observe(script, status)
        self.assertFalse(marker.exists(), "child must retain strict pipefail")
        self.send("exit 0")
        self.expect_exit(0)

    def test_probe_cannot_change_parent_options_directory_or_consume_commands(self):
        self.send('original_directory=$PWD')
        self.observe("cd /; set +e +u; set +o pipefail; read -r ignored", 1)
        self.send('test "$PWD" = "$original_directory"; '
                  '[[ $- == *e* && $- == *u* ]]; '
                  'test "$(set -o | awk \'$1 == "pipefail" {print $2}\')" = on; '
                  'printf "OPTIONS_PRESERVED:%s\\n" "$$"')
        self.read_until(f"OPTIONS_PRESERVED:{self.pid}\r\n")
        self.send("exit 0")
        self.expect_exit(0)

    def test_required_assertion_still_stops_after_failed_observation(self):
        self.observe("exit 23", 23)
        marker = self.root / "incorrect-scenario-continuation"
        self.send('test "$OPERATOR_OBSERVATION_STATUS" -eq 0; '
                  + f"touch {shlex.quote(str(marker))}")
        self.expect_exit(1)
        self.assertFalse(marker.exists())

    def test_probe_ignores_inherited_bash_startup_hooks_and_functions(self):
        startup_marker = self.root / "startup-ran"
        continuation = self.root / "incorrect-startup-continuation"
        startup = self.root / "startup.sh"
        startup.write_text("set +e +u; set +o pipefail\n"
                           + f"touch {shlex.quote(str(startup_marker))}\n")
        self.send("export BASH_ENV=" + shlex.quote(str(startup)))
        self.observe("false | cat; touch " + shlex.quote(str(continuation)), 1)
        self.assertFalse(startup_marker.exists())
        self.assertFalse(continuation.exists())
        self.send("unset BASH_ENV; false() { return 0; }; export -f false")
        self.observe("false; touch " + shlex.quote(str(continuation)), 1)
        self.assertFalse(continuation.exists())
        self.send("exit 0")
        self.expect_exit(0)


if __name__ == "__main__":
    unittest.main()
