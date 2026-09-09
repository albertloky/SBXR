#!/usr/bin/env python3
"""Actual Linux file boundary fixture; no SBXR or certificate state."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('fixture', nargs='?')
parser.add_argument('--with-child', action='store_true')
parser.add_argument('--repeat', type=int, default=1)
options = parser.parse_args()
if not 1 <= options.repeat <= 8 or options.with_child and not options.fixture:
    parser.error('repeat must be 1..8 and child mode requires the Go fixture')
cgroup = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
with tempfile.TemporaryDirectory(prefix='sbxr-syscall-fixture-') as directory:
    root = Path(directory)
    executable = root/'python'
    go_fixture = options.fixture
    child_fixture = options.with_child
    shutil.copyfile(go_fixture or sys.executable, executable)
    executable.chmod(0o700)
    record, target, marker = root/'record', root/'target', root/'marker'
    for boundary, decision in [('before-open', 'kill'), ('before-open', 'release'), ('after-close', 'kill'), ('after-close', 'release')]*options.repeat:
        record.write_text('{"phase":"ready"}')
        record.chmod(0o600)
        if boundary == 'after-close':
            target.write_text('original')
        script = ("import os,fcntl; fd=os.open(%r,os.O_WRONLY|os.O_CREAT,0o600); " % str(target))
        if boundary == 'after-close':
            script += 'fcntl.flock(fd,fcntl.LOCK_EX); os.close(fd); '
        script += "open(%r,'w').write('ran')" % str(marker)
        gate_args = [sys.executable, str(HERE/'syscall-gate.py'), str(executable), cgroup, boundary, str(target), '--record', str(record), '--field', 'phase', '--value', 'ready', '--timeout', '30']
        if child_fixture:
            gate_args[gate_args.index('--field')+1] = 'attempts.-1.recorder_pid'
            gate_args[gate_args.index('--value')+1] = '@root-pid'
            gate_args += ['--child-executable', '/usr/bin/true', '--no-child']
        controller = subprocess.Popen(gate_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        child = None
        def event():
            assert select.select([controller.stdout], [], [], 35)[0], 'event deadline'
            return json.loads(controller.stdout.readline())
        try:
            assert event()['state'] == 'armed'
            command = [str(executable), boundary, str(record), str(target), str(marker)] if go_fixture else [str(executable), '-S', '-c', script]
            child = subprocess.Popen(['/bin/sh', '-c', 'exec "$@"', 'fixture']+command, stderr=subprocess.DEVNULL, env={**os.environ, **({'SBXR_FIXTURE_CHILD': '/usr/bin/true'} if child_fixture else {})})
            held = event()
            assert held['state'] == 'boundary-held', held
            assert held['pid'] == child.pid and not marker.exists()
            if child_fixture:
                assert len(held['children']) == 1 and held['children'][0]['exit_code'] == 0
            if boundary == 'before-open':
                assert not target.exists()
            else:
                with target.open('r') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(lock, fcntl.LOCK_UN)
                assert target.read_text() == 'original'
            controller.stdin.write(decision+'\n')
            controller.stdin.flush()
            outcome = event()
            assert outcome['state'] == ('interrupted' if decision == 'kill' else 'released'), outcome
            assert controller.wait(timeout=5) == 0
            status = child.wait(timeout=5)
            if decision == 'release':
                assert status == 0 and marker.read_text() == 'ran'
            else:
                assert status != 0 and not marker.exists()
            print(boundary+' '+decision+': pass confirmed-gone='+str(len(held.get('vanished_tracees', []))), flush=True)
        finally:
            if controller.poll() is None:
                controller.kill()
            controller.wait()
            if child is not None and child.poll() is None:
                child.kill()
                child.wait()
            for path in [record, target, marker]:
                path.unlink(missing_ok=True)
