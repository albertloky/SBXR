"""Regression coverage for the packaged-live menu interruption boundary.

These tests source the real shell function and launch only a temporary fixture.
They do not install or invoke the SBXR product.
"""

import ctypes
import fcntl
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
MODULE = HERE.parent / "v3-packaged-live.sh"


FIXTURE = r'''#!/usr/bin/env python3
import fcntl
import os
from pathlib import Path
import sys
import time

root = Path(os.environ["SBXR_INTERRUPT_FIXTURE_ROOT"])
mode = os.environ["SBXR_INTERRUPT_FIXTURE_MODE"]
(root / "started").write_text(str(os.getpid()))
sys.stdin.readline()
sys.stdin.readline()

child = os.fork()
if child == 0:
    (root / "child.pid").write_text(str(os.getpid()))
    grandchild = os.fork()
    if grandchild == 0:
        if mode == "escaped-event":
            os.setsid()
        lock = open(root / "held.lock", "w")
        fcntl.flock(lock, fcntl.LOCK_EX)
        (root / "grandchild.pid").write_text(str(os.getpid()))
        while True:
            time.sleep(10)
    os.waitpid(grandchild, 0)
    os._exit(0)

deadline = time.monotonic() + 3
while not (root / "grandchild.pid").exists():
    if time.monotonic() >= deadline:
        os._exit(91)
    time.sleep(0.005)

if mode == "early-exit":
    os._exit(0)
if mode == "delayed-event":
    time.sleep(float(os.environ.get("SBXR_INTERRUPT_FIXTURE_DELAY", "0.3")))
    print("Progress: target-event", flush=True)
elif mode == "event":
    print("Progress: target-event", flush=True)
elif mode == "escaped-event":
    print("Progress: target-event", flush=True)
elif mode == "partial-then-event":
    print("Progress: target-event suffix", flush=True)
    time.sleep(float(os.environ.get("SBXR_INTERRUPT_FIXTURE_DELAY", "0.3")))
    print("Progress: target-event", flush=True)
elif mode == "long-partial-then-event":
    print("Progress: target-event " + "x" * 70000, flush=True)
    time.sleep(float(os.environ.get("SBXR_INTERRUPT_FIXTURE_DELAY", "0.3")))
    print("Progress: target-event", flush=True)
elif mode != "no-event":
    os._exit(92)
os.waitpid(child, 0)
'''


@unittest.skipUnless(sys.platform.startswith("linux"),
                     "process-group interruption semantics require Linux setsid")
class InterruptMenuTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        if self.libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
            self.fail(f"PR_GET_CHILD_SUBREAPER failed: {ctypes.get_errno()}")
        self.previous_subreaper = previous.value
        if self.libc.prctl(36, 1, 0, 0, 0) != 0:
            self.fail(f"PR_SET_CHILD_SUBREAPER failed: {ctypes.get_errno()}")
        self.addCleanup(self.restore_subreaper)
        self.root = Path(self.temporary.name)
        self.fixture = self.root / "sbxr-fixture"
        self.fixture.write_text(FIXTURE)
        self.fixture.chmod(0o700)
        self.work = self.root / "work"
        self.work.mkdir()
        self.request = self.root / "request.json"
        self.hook = self.root / "hook"
        self.hook.mkdir()
        (self.hook / "sitecustomize.py").write_text(r'''
import os
from pathlib import Path
import signal
import subprocess
import sys

if sys.argv[0] == "-":
    original_popen = subprocess.Popen

    def interrupt_after_spawn(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        Path(os.environ["SBXR_INTERRUPT_HOOK_CHILD"]).write_text(str(child.pid))
        os.kill(os.getpid(), signal.SIGTERM)
        return child

    subprocess.Popen = interrupt_after_spawn
''')
        self.read_hook = self.root / "read-hook"
        self.read_hook.mkdir()
        (self.read_hook / "sitecustomize.py").write_text(r'''
import builtins
import os
import signal
import sys

if sys.argv[0] == "-":
    original_open = builtins.open

    class InterruptingReader:
        def __init__(self, reader):
            self.reader = reader
            self.interrupted = False

        def __enter__(self):
            self.reader.__enter__()
            return self

        def __exit__(self, *args):
            return self.reader.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.reader, name)

        def read(self, *args, **kwargs):
            content = self.reader.read(*args, **kwargs)
            if not self.interrupted and b"Progress: target-event\n" in content:
                self.interrupted = True
                os.kill(os.getpid(), signal.SIGTERM)
            return content

    def interrupting_open(file, mode="r", *args, **kwargs):
        reader = original_open(file, mode, *args, **kwargs)
        if mode == "rb" and os.fspath(file) == sys.argv[2]:
            return InterruptingReader(reader)
        return reader

    builtins.open = interrupting_open
''')
        self.spawned_pids = set()
        self.addCleanup(self.cleanup_fixture_processes)

    def restore_subreaper(self):
        self.libc.prctl(36, self.previous_subreaper, 0, 0, 0)

    def cleanup_fixture_processes(self):
        self.collect_fixture_pids()
        for pid in self.spawned_pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 3
        unreaped = set(self.spawned_pids)
        while unreaped and time.monotonic() < deadline:
            for pid in list(unreaped):
                try:
                    waited, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    # It may still belong to a live fixture parent and become
                    # our child only after that parent dies (subreaper adoption).
                    if not Path(f"/proc/{pid}").exists():
                        unreaped.remove(pid)
                    continue
                if waited:
                    unreaped.remove(pid)
            if unreaped:
                time.sleep(0.01)

    def collect_fixture_pids(self):
        for name in ("started", "child.pid", "grandchild.pid", "hook-child.pid"):
            path = self.root / name
            if path.exists():
                try:
                    self.spawned_pids.add(int(path.read_text()))
                except (ValueError, OSError):
                    pass

    def run_interrupt(self, mode, timeout=2, *, request_deadline=None,
                      number="case", delay="0.3", signal_controller=False,
                      spawn_signal_hook=False, read_signal_hook=False):
        for name in ("started", "child.pid", "grandchild.pid", "held.lock",
                     "hook-child.pid", "scan.capture"):
            try:
                (self.root / name).unlink()
            except FileNotFoundError:
                pass
        environment = os.environ.copy()
        environment.update({
            "SBXR_EXECUTABLE": str(self.fixture),
            "SBXR_INTERRUPT_FIXTURE_ROOT": str(self.root),
            "SBXR_INTERRUPT_FIXTURE_MODE": mode,
            "SBXR_INTERRUPT_FIXTURE_DELAY": delay,
            "WORK": str(self.work),
        })
        if request_deadline is not None:
            self.request.write_text(json.dumps({"deadline_unix": request_deadline}))
            environment["SBXR_QUALIFICATION_REQUEST"] = str(self.request)
        else:
            environment.pop("SBXR_QUALIFICATION_REQUEST", None)
        if spawn_signal_hook:
            environment["PYTHONPATH"] = str(self.hook)
            environment["SBXR_INTERRUPT_HOOK_CHILD"] = str(
                self.root / "hook-child.pid")
        if read_signal_hook:
            environment["PYTHONPATH"] = str(self.read_hook)

        # The slash-named function keeps this harness compatible with the old
        # implementation for a fast red run. The fixed function instead uses
        # SBXR_EXECUTABLE. Limiting seq scales the old 6000-poll bug to 50 ms;
        # the replacement deadline loop does not use seq.
        shell = f'''
set -euo pipefail
source {shlex.quote(str(MODULE))}
menu_number() {{ printf '1\n'; }}
scan_vps_capture() {{ cp -- "$1" {shlex.quote(str(self.root / "scan.capture"))}; }}
seq() {{ command seq 1 5; }}
function /usr/local/bin/sbxr() {{ exec "$SBXR_EXECUTABLE"; }}
interrupt_at 'Start setup' y target-event {shlex.quote(number)} {timeout}
'''
        started = time.monotonic()
        stdout_path = self.root / "controller.stdout"
        stderr_path = self.root / "controller.stderr"
        with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
            process = subprocess.Popen(
                ["/bin/bash", "--noprofile", "--norc", "-c", shell],
                env=environment,
                stdout=stdout,
                stderr=stderr,
                text=True,
            )
            if signal_controller:
                signal_deadline = time.monotonic() + 3
                children_path = (Path(f"/proc/{process.pid}/task") /
                                 str(process.pid) / "children")
                controller = None
                while time.monotonic() < signal_deadline:
                    if (self.root / "started").exists() and children_path.exists():
                        children = children_path.read_text().split()
                        if len(children) == 1:
                            controller = int(children[0])
                            break
                    time.sleep(0.01)
                self.assertIsNotNone(controller, "controller process did not start")
                os.kill(controller, signal.SIGTERM)
            returncode = process.wait(timeout=timeout + 5)
        result = subprocess.CompletedProcess(process.args, returncode)
        result.stdout = stdout_path.read_text()
        result.stderr = stderr_path.read_text()
        elapsed = time.monotonic() - started
        self.collect_fixture_pids()
        return result, elapsed

    def assert_fixture_tree_dead(self):
        self.collect_fixture_pids()
        deadline = time.monotonic() + 3
        living = set(self.spawned_pids)
        while living and time.monotonic() < deadline:
            for pid in list(living):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    living.remove(pid)
            if living:
                time.sleep(0.02)
        self.assertEqual(living, set(), f"fixture processes survived: {living}")

    def assert_lock_released(self):
        with (self.root / "held.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def assert_work_files_removed(self, number):
        self.assertFalse((self.work / f"input-{number}").exists())
        self.assertFalse((self.work / f"output-{number}").exists())

    def test_delayed_target_uses_deadline_instead_of_fixed_poll_count(self):
        result, elapsed = self.run_interrupt("delayed-event", timeout=2,
                                             number="delayed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(elapsed, 0.25)
        self.assertLess(elapsed, 2)
        self.assertIn("Progress: target-event",
                      (self.root / "scan.capture").read_text())
        self.assert_fixture_tree_dead()
        self.assert_lock_released()
        self.assert_work_files_removed("delayed")
        self.assertIn("INTERRUPTION_RESULT reason=boundary-observed "
                      "descendants_reaped=true", result.stdout)

    def test_intended_event_kills_all_owned_descendants(self):
        result, _ = self.run_interrupt("event", timeout=2, number="event")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_fixture_tree_dead()
        self.assert_lock_released()
        self.assert_work_files_removed("event")
        self.assertIn("descendants_reaped=true", result.stdout)

    def test_timeout_without_target_cleans_descendants_and_returns_failure(self):
        result, elapsed = self.run_interrupt("no-event", timeout=1,
                                             number="timeout")
        self.assertNotEqual(result.returncode, 0)
        self.assertGreaterEqual(elapsed, 0.8)
        self.assertLess(elapsed, 2.5)
        self.assert_fixture_tree_dead()
        self.assert_lock_released()
        self.assert_work_files_removed("timeout")
        self.assertIn("reason=deadline-before-boundary", result.stdout)
        self.assertIn("descendants_reaped=true", result.stdout)

    def test_early_parent_exit_still_cleans_its_process_group(self):
        result, elapsed = self.run_interrupt("early-exit", timeout=2,
                                             number="parent-exit")
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 1)
        self.assert_fixture_tree_dead()
        self.assert_lock_released()
        self.assert_work_files_removed("parent-exit")
        self.assertIn("reason=menu-exited-before-boundary", result.stdout)
        self.assertIn("descendants_reaped=true", result.stdout)

    def test_request_deadline_caps_longer_function_timeout(self):
        function_timeout = 5
        result, elapsed = self.run_interrupt(
            "no-event", timeout=function_timeout, number="deadline-cap",
            # deadline_unix is an integer. Leave more than two full seconds
            # of startup margin for this after-start case, distinct from
            # the separately tested expired-before-start case.
            request_deadline=int(time.time()) + 3,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertGreaterEqual(elapsed, 1.5)
        self.assertLess(elapsed, function_timeout - 0.5)
        self.assertTrue((self.root / "started").exists())
        self.assert_fixture_tree_dead()
        self.assert_lock_released()
        self.assert_work_files_removed("deadline-cap")
        self.assertIn("reason=deadline-before-boundary", result.stdout)
        self.assertIn("descendants_reaped=true", result.stdout)

    def test_expired_request_deadline_refuses_to_start_child(self):
        result, elapsed = self.run_interrupt(
            "event", timeout=5, number="expired",
            request_deadline=int(time.time()) - 1,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 1)
        self.assertIn("reason=deadline-expired-before-start", result.stdout)
        self.assertIn("descendants_reaped=true", result.stdout)
        self.assertFalse((self.root / "started").exists())
        self.assert_work_files_removed("expired")

    def test_only_an_exact_complete_progress_line_triggers_interruption(self):
        result, elapsed = self.run_interrupt("long-partial-then-event", timeout=2,
                                             number="exact-line")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(elapsed, 0.25)
        self.assert_fixture_tree_dead()
        self.assert_lock_released()
        self.assert_work_files_removed("exact-line")

    def test_descendant_that_escapes_session_is_still_reaped(self):
        result, _ = self.run_interrupt("escaped-event", timeout=2,
                                       number="escaped")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_fixture_tree_dead()
        self.assert_lock_released()
        self.assert_work_files_removed("escaped")
        self.assertIn("descendants_reaped=true", result.stdout)

    def test_controller_term_cleans_the_started_fixture_tree(self):
        result, elapsed = self.run_interrupt(
            "no-event", timeout=5, number="controller-term",
            signal_controller=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 2)
        self.assert_fixture_tree_dead()
        self.assert_lock_released()
        self.assert_work_files_removed("controller-term")
        self.assertIn("reason=controller-interrupted", result.stdout)
        self.assertIn("descendants_reaped=true", result.stdout)

    def test_controller_term_immediately_after_spawn_cleans_returned_child(self):
        result, elapsed = self.run_interrupt(
            "event", timeout=5, number="spawn-term", spawn_signal_hook=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 2)
        self.assertTrue((self.root / "hook-child.pid").exists())
        self.assert_fixture_tree_dead()
        if (self.root / "held.lock").exists():
            self.assert_lock_released()
        self.assert_work_files_removed("spawn-term")
        self.assertIn("reason=controller-interrupted", result.stdout)
        self.assertIn("descendants_reaped=true", result.stdout)

    def test_controller_term_during_target_read_cannot_report_success(self):
        result, elapsed = self.run_interrupt(
            "event", timeout=5, number="read-term", read_signal_hook=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 2)
        self.assert_fixture_tree_dead()
        self.assert_lock_released()
        self.assert_work_files_removed("read-term")
        self.assertIn("reason=controller-interrupted", result.stdout)
        self.assertIn("descendants_reaped=true", result.stdout)

    def test_unrelated_process_is_not_signaled(self):
        unrelated = subprocess.Popen(["sleep", "30"], start_new_session=True)
        def cleanup_unrelated():
            if unrelated.poll() is None:
                unrelated.kill()
            unrelated.wait(timeout=3)
        self.addCleanup(cleanup_unrelated)
        result, _ = self.run_interrupt("event", timeout=2,
                                       number="unrelated")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(unrelated.poll())
        self.assert_fixture_tree_dead()
        self.assert_lock_released()
        self.assert_work_files_removed("unrelated")


if __name__ == "__main__":
    unittest.main()
