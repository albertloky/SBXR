#!/usr/bin/env python3
"""Exercise nested operator captures with actual files and process execution."""
import json
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


# All members remain in the foreground command's process group. Each fixture
# also expires independently, so failed assertions cannot leave it running.
GROUP = r"""
import json, os, pathlib, signal, subprocess, sys, time
signal.alarm(8)
stubborn = sys.argv[2] == 'stubborn'
child = subprocess.Popen([sys.executable, '-c',
    "import signal,time; signal.alarm(8); " +
    "; ".join("signal.signal(signal.%s, %s)" % (name, "signal.SIG_IGN" if stubborn else "lambda *_: exit(0)")
              for name in ('SIGINT','SIGTERM','SIGHUP')) + "; time.sleep(30)"])
def stop(signum, frame):
    child.wait(timeout=2)
    raise SystemExit(0)
for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(signum, signal.SIG_IGN if stubborn else stop)
time.sleep(.05)
p = pathlib.Path(sys.argv[1]); tmp = p.with_suffix('.next')
tmp.write_text(json.dumps([os.getpid(), child.pid])); tmp.rename(p)
if sys.argv[2] == 'leader-exits':
    raise SystemExit(23)
time.sleep(30)
"""

# Alter only the budget clock reader, keeping actual process creation, signals,
# waits, file I/O and supervision clocks real. No production test-only switches.
CLOCK_SHIM = r"""
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location('operator_fixture', sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
mode, marker = sys.argv[2:4]; del sys.argv[1:4]
original = m.read_clocks

def read():
    wall, mono = original()
    if pathlib.Path(marker).exists():
        if mode == 'failed': raise OSError('private-clock-detail')
        if mode == 'nonfinite': return float('nan'), mono
        if mode == 'forward': wall += 3600
        if mode == 'backward': wall -= 3600
    return wall, mono
m.read_clocks = read
m.exit_status(m.main())
"""


class BoundedOperatorRunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='operator-bound-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.group = self.root / 'group.py'
        self.group.write_text(GROUP)
        self.shim = self.root / 'clock.py'
        self.shim.write_text(CLOCK_SHIM)

    def argv(self, command, *, label='step', cutoff=None, timeout=2, reserve=0, prefix=None):
        return [*(prefix or [sys.executable, str(SCRIPT)]), '--run-directory', str(self.root),
                '--label', label, '--cutoff-unix', str(time.time() + 30 if cutoff is None else cutoff),
                '--timeout', str(timeout), '--reserve', str(reserve), '--', *command]

    def call(self, command, **kwargs):
        return subprocess.run(self.argv(command, **kwargs), input=b'private stdin', capture_output=True,
                              timeout=15, cwd=self.root)

    def read_error(self, label='step'):
        return (self.root / (label + '.operator.stderr')).read_bytes()

    def await_file(self, path, process):
        until = time.monotonic() + 4
        while not path.exists() and time.monotonic() < until and process.poll() is None:
            time.sleep(.01)
        error = self.root / (path.name + '.operator.stderr')
        self.assertTrue(path.exists(), 'fixture did not become ready: ' +
                        (error.read_text() if error.exists() else 'no command log'))

    def clean_fixture(self, process, marker):
        # Cleanup remains independent of the implementation under test.
        if marker.exists():
            leader, child = json.loads(marker.read_text())
            try:
                os.killpg(leader, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)

    def assert_not_running(self, pid):
        # A killed orphan may briefly remain a zombie on Linux until PID 1
        # reaps it. It cannot execute; do not require a particular init policy.
        until = time.monotonic() + 2
        while time.monotonic() < until:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            status = Path('/proc') / str(pid) / 'stat'
            if sys.platform.startswith('linux'):
                try:
                    if status.read_text().rsplit(') ', 1)[1].split()[0] == 'Z':
                        return
                except FileNotFoundError:
                    return
            time.sleep(.01)
        self.fail('owned fixture process remains running')

    def test_success_preserves_io_cwd_environment_private_logs_and_status(self):
        command = [sys.executable, '-c',
                   "import os,sys; print(sys.stdin.read()); print(os.getcwd()); "
                   "print(os.environ['PATH']); print('private stderr',file=sys.stderr); sys.exit(23)"]
        result = self.call(command)
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(result.stdout + result.stderr, b'')
        self.assertEqual((self.root / 'step.operator.stdout').read_text().splitlines(),
                         ['private stdin', str(self.root), os.environ['PATH']])
        self.assertEqual(self.read_error(), b'private stderr\n')
        for suffix in ('.operator.stdout', '.operator.stderr'):
            self.assertEqual((self.root / ('step' + suffix)).stat().st_mode & 0o777, 0o600)

    def test_child_signal_status_is_preserved(self):
        for signum in (signal.SIGTERM, signal.SIGKILL):
            result = self.call([sys.executable, '-c', 'import os,sys; os.kill(os.getpid(),int(sys.argv[1]))', str(int(signum))],
                               label='signal' + str(int(signum)))
            self.assertEqual(result.returncode, -signum)

    def test_partial_invalid_and_insufficient_budgets_never_launch(self):
        marker = self.root / 'launched'
        command = [sys.executable, '-c', 'import pathlib,sys; pathlib.Path(sys.argv[1]).touch()', str(marker)]
        base = [sys.executable, str(SCRIPT), '--run-directory', str(self.root), '--label', 'refused']
        cases = [['--timeout', '1'], ['--reserve', '0'], ['--cutoff-unix', str(time.time()+30)],
                 ['--cutoff-unix', str(time.time()+30), '--timeout', '1'],
                 ['--cutoff-unix', str(time.time()+30), '--reserve', '0'], ['--timeout', '1', '--reserve', '0']]
        for field, value in (('--timeout', '0'), ('--timeout', '-1'), ('--timeout', 'nan'),
                             ('--timeout', 'inf'), ('--cutoff-unix', '0'), ('--cutoff-unix', 'nan'),
                             ('--cutoff-unix', 'inf'), ('--reserve', '-1'), ('--reserve', 'nan'),
                             ('--reserve', 'inf')):
            args = {'--cutoff-unix': str(time.time()+30), '--timeout': '1', '--reserve': '0'}
            args[field] = value
            cases.append([part for pair in args.items() for part in pair])
        for args in cases:
            with self.subTest(args=args):
                result = subprocess.run([*base, *args, '--', *command], capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
        for label, cutoff, timeout, reserve in [('expired', time.time()-1, 1, 0),
                                                ('stop-reserve', time.time()+10, .1, 0),
                                                ('downstream', time.time()+15, 1, 5)]:
            result = self.call(command, label=label, cutoff=cutoff, timeout=timeout, reserve=reserve)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertIn(b'command not launched', result.stderr + self.read_error(label))

    def test_existing_logs_or_capture_refuse_unchanged(self):
        marker = self.root / 'launched'
        for index, suffix in enumerate(('.private', '.stderr', '.receipt.json', '.operator.stdout', '.operator.stderr')):
            label = 'retained' + str(index)
            path = self.root / (label + suffix)
            path.write_bytes(b'retained')
            result = self.call([sys.executable, '-c', 'import pathlib,sys; pathlib.Path(sys.argv[1]).touch()', str(marker)], label=label)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertEqual(path.read_bytes(), b'retained')

    def test_missing_command_preserves_private_diagnostic(self):
        result = self.call([str(self.root / 'secret-missing-command')])
        self.assertEqual(result.returncode, 127)
        self.assertEqual(self.read_error(), b'could not launch operator command\n')
        self.assertNotIn(b'secret', result.stderr + self.read_error())

    def test_timeout_stops_stubborn_child_and_same_group_descendant(self):
        marker = self.root / 'members'
        process = subprocess.Popen(self.argv([sys.executable, str(self.group), str(marker), 'stubborn'], timeout=2),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        started = time.monotonic()
        try:
            self.await_file(marker, process)
            self.assertEqual(process.wait(timeout=12), 124)
            self.assertLess(time.monotonic() - started, 10)
            for pid in json.loads(marker.read_text()):
                self.assert_not_running(pid)
            self.assertIn(b'outcome requires verification', self.read_error())
        finally:
            self.clean_fixture(process, marker)

    def test_cancellation_reaches_owned_group_and_preserves_signal(self):
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(signum=signum):
                label = 'cancel' + str(int(signum))
                marker = self.root / label
                process = subprocess.Popen(self.argv([sys.executable, str(self.group), str(marker), 'cooperate'],
                                                     label=label, timeout=12), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    self.await_file(marker, process)
                    process.send_signal(signum)
                    self.assertEqual(process.wait(timeout=12), -signum)
                    for pid in json.loads(marker.read_text()):
                        self.assert_not_running(pid)
                finally:
                    self.clean_fixture(process, marker)

    def test_exited_leader_is_not_reaped_before_surviving_group_is_stopped(self):
        marker = self.root / 'members'
        process = subprocess.Popen(self.argv([sys.executable, str(self.group), str(marker), 'leader-exits']),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.await_file(marker, process)
            self.assertEqual(process.wait(timeout=8), 23)
            for pid in json.loads(marker.read_text()):
                self.assert_not_running(pid)
        finally:
            self.clean_fixture(process, marker)

    def test_shared_absolute_cutoff_is_not_reset_for_next_command(self):
        cutoff = time.time() + 14
        first = self.call([sys.executable, '-c', 'import time; time.sleep(.8)'],
                          label='first', cutoff=cutoff, timeout=2)
        self.assertEqual(first.returncode, 0, first.stderr + self.read_error('first'))
        marker = self.root / 'second-launched'
        second = self.call([sys.executable, '-c', 'import pathlib,sys; pathlib.Path(sys.argv[1]).touch()', str(marker)],
                           label='second', cutoff=cutoff, timeout=3.5)
        self.assertNotEqual(second.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertIn(b'command not launched', second.stderr + self.read_error('second'))

    def test_clock_changes_or_failure_do_not_leave_child_running(self):
        for mode in ('forward', 'backward', 'failed', 'nonfinite'):
            with self.subTest(mode=mode):
                marker = self.root / mode
                prefix = [sys.executable, str(self.shim), str(SCRIPT), mode, str(marker)]
                process = subprocess.Popen(self.argv([sys.executable, str(self.group), str(marker), 'cooperate'],
                                                     label=mode, timeout=6 if mode == 'forward' else 2, prefix=prefix),
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                started = time.monotonic()
                try:
                    self.await_file(marker, process)
                    ready = time.monotonic()
                    self.assertEqual(process.wait(timeout=12), 1 if mode in ('failed', 'nonfinite') else 124)
                    self.assertLess(time.monotonic() - ready, 3)
                    self.assertLess(time.monotonic() - started, 6)
                    for pid in json.loads(marker.read_text()):
                        self.assert_not_running(pid)
                    error = self.read_error(mode)
                    self.assertNotIn(b'private-clock-detail', error)
                    self.assertNotIn(b'Traceback', error)
                finally:
                    self.clean_fixture(process, marker)


    def test_clock_failure_before_spawn_refuses_without_launch(self):
        for mode in ('failed', 'nonfinite'):
            with self.subTest(mode=mode):
                trigger = self.root / ('clock-' + mode)
                trigger.touch()
                marker = self.root / ('launched-' + mode)
                prefix = [sys.executable, str(self.shim), str(SCRIPT), mode, str(trigger)]
                result = self.call([sys.executable, '-c', 'import pathlib,sys; pathlib.Path(sys.argv[1]).touch()', str(marker)],
                                   prefix=prefix, label=mode)
                self.assertEqual(result.returncode, 1)
                self.assertFalse(marker.exists())
                self.assertEqual(self.read_error(mode), b'Operator budget unavailable; command not launched.\n')


if __name__ == "__main__":
    unittest.main()
