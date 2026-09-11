#!/usr/bin/env python3
"""Exercise ordered holds on one threaded Go process; no product execution."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('transition', HERE / 'transition-operator.py')
transition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transition)


def reap_descendants(root):
    # Adopt fixture orphans so kill cases can assert actual reaping, independent
    # of the host PID 1 reaper. Gate still owns its ptrace cleanup.
    pids = [int(value) for value in (root / 'pids').read_text().splitlines()]
    deadline = time.monotonic() + 5
    while True:
        pending = []
        for pid in pids:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
            if Path('/proc/%d' % pid).exists():
                pending.append(pid)
        if not pending:
            return
        assert time.monotonic() < deadline, ('fixture processes not reaped', pending)
        time.sleep(.01)


def run(fixture):
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(36, 1, 0, 0, 0) == 0, 'fixture subreaper setup failed'
    cgroup = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
                  if line.startswith('0::'))
    with tempfile.TemporaryDirectory(prefix='sbxr-sequence-fixture-') as directory:
        root = Path(directory)
        executable = root / 'fixture'
        shutil.copyfile(fixture, executable)
        executable.chmod(0o700)
        for decision in ('release', 'early-release', 'kill', 'extra-continue'):
            record, first, second, third, marker = (root / name for name in ('record', 'first', 'second', 'third', 'marker'))
            gate = subprocess.Popen([
                sys.executable, str(HERE / 'syscall-gate.py'), str(executable), cgroup,
                'before-open', str(first), '--record', str(record), '--field', 'phase',
                '--value', 'first', '--then-value', 'second', '--then-path', str(second),
                '--then-value', 'third', '--then-path', str(third),
                '--timeout', '30',
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
            stream = transition.LineStream(gate.stdout)
            deadline = time.monotonic() + 35
            event = lambda: json.loads(stream.line(deadline))
            child = None
            try:
                assert event()['state'] == 'armed'
                child = subprocess.Popen([str(executable), 'sequence', str(record), str(first), str(second), str(third), str(marker)])
                for index, phase in enumerate(('first', 'second', 'third')):
                    held = event()
                    assert held['state'] == 'boundary-held' and held['boundary_index'] == index, held
                    assert held['path'] == str((first, second, third)[index])
                    assert held['pid'] == child.pid
                    assert json.loads(record.read_text()) == {'phase': phase}
                    assert (root / 'work-done').read_text() == str((first, second, third)[index])
                    assert not (first, second, third)[index].exists()
                    assert (root / 'live-ready').read_text() == 'ready'
                    if index:
                        assert (root / 'live-progress').read_text() == 'continued'
                    assert not (root / 'live-done').exists()
                    assert (marker.read_text() if marker.exists() else '') == (str(index) if index else '')
                    command = 'continue' if index < 2 else 'release'
                    if decision == 'early-release':
                        command = 'release'
                    elif decision == 'kill':
                        command = 'kill'
                    elif decision == 'extra-continue' and index == 2:
                        command = 'continue'
                    gate.stdin.write((command + '\n').encode())
                    gate.stdin.flush()
                    if command != 'continue' or index == 2:
                        result = event()
                        assert result['state'] == {'release': 'released', 'kill': 'interrupted'}.get(decision, 'refused'), result
                        break
                gate_code = gate.wait(timeout=5)
                child_code = child.wait(timeout=5)
                assert (gate_code == 0) == (decision in ('release', 'kill'))
                assert (child_code == 0) == (decision == 'release')
                assert (marker.read_text() if marker.exists() else '') == ('3' if decision == 'release' else '2' if decision == 'extra-continue' else '')
                if decision == 'release':
                    assert (root / 'live-done').read_text() == 'released'
                reap_descendants(root)
                print('ordered boundary ' + decision + ': pass with child workload and reaped descendants', flush=True)
            finally:
                if gate.poll() is None:
                    gate.kill()
                gate.wait(timeout=5)
                if child is not None and child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                if (root / 'pids').exists():
                    reap_descendants(root)
                for path in (record, first, second, third, marker, *(root / name for name in ('pids', 'work-done', 'live-ready', 'live-progress', 'live-done'))):
                    path.unlink(missing_ok=True)


if __name__ == '__main__':
    run(sys.argv[1])
