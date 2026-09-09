#!/usr/bin/env python3
"""Root Linux fixture: no SBXR, snap, certificate or external network access."""
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import uuid


def event(process):
    ready, _, _ = select.select([process.stdout], [], [], 5)
    assert ready, 'gate event timed out'
    return json.loads(process.stdout.readline())


def main():
    assert sys.platform == 'linux' and os.geteuid() == 0
    gate = Path(__file__).with_name('exec-gate.py')
    cgroup = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    with tempfile.TemporaryDirectory(prefix='sbxr-exec-fixture-') as directory:
        target = Path(directory, 'fixture-python')
        shutil.copyfile(sys.executable, target)
        target.chmod(0o700)
        marker = Path(directory, 'ran')
        # A marker is the very first fixture instruction. If it cannot run,
        # neither can any following network operation. No network is attempted.
        command = [str(target), '-S', '-c', 'from pathlib import Path; Path(%r).write_text("ran")' % str(marker)]
        subprocess.run(command, check=True)
        assert marker.read_text() == 'ran'
        marker.unlink()
        for mode in ('deny', 'kill-controller', 'eof', 'timeout', 'unrelated-cgroup', 'release'):
            controller = subprocess.Popen([sys.executable, str(gate), str(target), cgroup if mode != 'unrelated-cgroup' else '/wrong', '--timeout', '2'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            child = None
            try:
                assert event(controller)['state'] == 'armed'
                child = subprocess.Popen(["/bin/sh", "-c", 'exec "$@"', "fixture"] + command, stderr=subprocess.DEVNULL)
                state = event(controller)
                if mode == 'unrelated-cgroup':
                    assert state['state'] == 'refused'
                else:
                    assert state['state'] == 'held'
                    assert state['pid'] == child.pid
                    assert child.poll() is None and not marker.exists()
                    if mode == 'deny':
                        sibling_marker = Path(directory, 'sibling')
                        subprocess.run([str(target), '-S', '-c', 'from pathlib import Path; Path(%r).touch()' % str(sibling_marker)], check=True, timeout=1)
                        assert sibling_marker.exists() and not marker.exists()
                        sibling_marker.unlink()
                    if mode == 'kill-controller':
                        controller.kill()
                    elif mode in ('deny', 'release'):
                        controller.stdin.write(mode+'\n')
                        controller.stdin.flush()
                    elif mode == 'eof':
                        controller.stdin.close()
                controller.wait(timeout=5)
                status = child.wait(timeout=5)
                if mode in ('release', 'unrelated-cgroup'):
                    assert status == 0 and marker.read_text() == 'ran'
                    marker.unlink()
                else:
                    assert status != 0
                    assert not marker.exists(), mode + ' executed target code'
                print(mode + ': pass', flush=True)
            finally:
                if controller.poll() is None:
                    controller.kill()
                controller.wait()
                if child is not None and child.poll() is None:
                    child.kill()
                    child.wait()
        # A child escaping the service cgroup is still linked to its recorder
        # ancestor. Refuse its exec, while unrelated inode users above continue.
        owned = Path('/sys/fs/cgroup', 'sbxr-fixture-'+uuid.uuid4().hex)
        escaped = Path('/sys/fs/cgroup', 'sbxr-fixture-'+uuid.uuid4().hex)
        owned.mkdir(); escaped.mkdir()
        controller = subprocess.Popen([sys.executable, str(gate), str(target), '/'+owned.name, '--timeout', '4'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        parent = None
        program = """import os,sys
open(sys.argv[1]+'/cgroup.procs','w').write(str(os.getpid()))
pid=os.fork()
if pid == 0:
 open(sys.argv[2]+'/cgroup.procs','w').write(str(os.getpid()))
 os.execv(sys.argv[3],sys.argv[3:])
_,status=os.waitpid(pid,0)
sys.exit(0 if status != 0 else 1)
"""
        try:
            assert event(controller)['state'] == 'armed'
            parent = subprocess.Popen([sys.executable,'-c',program,str(owned),str(escaped)]+command,stderr=subprocess.DEVNULL)
            assert event(controller)['state'] == 'refused'
            assert controller.wait(timeout=5) != 0
            assert parent.wait(timeout=5) == 0
            assert not marker.exists()
            print('escaped child denied through recorder ancestry: pass')
        finally:
            if controller.poll() is None: controller.kill()
            controller.wait()
            if parent is not None and parent.poll() is None:
                parent.kill(); parent.wait()
            owned.rmdir(); escaped.rmdir()
    print('fixture only; no real snap-route or pre-seize controller-death proof')


if __name__ == '__main__':
    main()
