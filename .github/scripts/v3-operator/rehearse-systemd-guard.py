#!/usr/bin/env python3
"""Test-only transient systemd unit: cgroup exists and is guarded before launch."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import uuid

spec = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('network-guard.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
name = 'sbxr-fixture-' + uuid.uuid4().hex + '.service'
group = Path('/sys/fs/cgroup/system.slice', name)
group.mkdir()
guard = None
listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.listen()
port = listener.getsockname()[1]
try:
    before = group.stat()
    guard = module.EgressGuard(str(group))
    with tempfile.TemporaryDirectory(prefix='sbxr-systemd-fixture-') as directory:
        result = Path(directory, 'result')
        code = '''import os,socket,sys,time
from pathlib import Path
s=socket.socket();s.settimeout(.3)
try:s.connect(("127.0.0.1",int(sys.argv[1]))); outcome="escaped"
except OSError:outcome="denied"
Path(sys.argv[2]).write_text(outcome)
time.sleep(2)
'''
        subprocess.run(['systemd-run', '--quiet', '--unit', name, '--property=Type=exec', sys.executable, '-c', code, str(port), str(result)], check=True)
        # Unit must reuse the very inode guarded before ExecStart.
        after = group.stat()
        assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
        import time
        deadline = time.monotonic()+5
        while not result.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        assert result.read_text() == 'denied'
        print('transient unit reuses preguarded cgroup; loopback egress denied: pass')
finally:
    subprocess.run(['systemctl', 'stop', name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if guard:
        guard.close()
    subprocess.run(['systemctl', 'reset-failed', name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    listener.close()
    if group.exists():
        group.rmdir()
