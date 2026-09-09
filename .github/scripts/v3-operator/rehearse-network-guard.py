#!/usr/bin/env python3
"""Loopback-only BPF rehearsal in a newly created, test-owned cgroup."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import uuid

spec = importlib.util.spec_from_file_location('network_guard', Path(__file__).with_name('network-guard.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
group = Path('/sys/fs/cgroup', 'sbxr-fixture-' + uuid.uuid4().hex)
group.mkdir()
guard = None
listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.listen()
port = listener.getsockname()[1]
script = '''import os,socket,sys
open(sys.argv[1]+"/cgroup.procs","w").write(str(os.getpid()))
s=socket.socket(); s.settimeout(.25)
try: s.connect(("127.0.0.1",int(sys.argv[2]))); print("connected")
except OSError: print("denied")
'''
def probe():
    return subprocess.check_output([sys.executable, '-c', script, str(group), str(port)], text=True).strip()
try:
    assert probe() == 'connected'
    listener.accept()[0].close()
    guard = module.EgressGuard(str(group))
    assert probe() == 'denied'
    # Sibling traffic remains possible.
    sibling = socket.create_connection(('127.0.0.1', port), timeout=1)
    listener.accept()[0].close()
    sibling.close()
    guard.close()
    guard = None
    assert probe() == 'connected'
    listener.accept()[0].close()
    print('guard denies fixture egress; sibling preserved; exact detach restores: pass')
    code = "import importlib.util,sys,time; s=importlib.util.spec_from_file_location('g',sys.argv[1]); m=importlib.util.module_from_spec(s);s.loader.exec_module(m);g=m.EgressGuard(sys.argv[2]);print('armed',flush=True);time.sleep(30)"
    owner = subprocess.Popen([sys.executable, '-c', code, str(Path(__file__).with_name('network-guard.py')), str(group)], stdout=subprocess.PIPE, text=True)
    try:
        assert owner.stdout.readline().strip() == 'armed'
        owner.kill()
        owner.wait()
        assert probe() == 'denied'
        print('egress stays denied after guard owner death: pass')
    finally:
        if owner.poll() is None:
            owner.kill()
        owner.wait()
finally:
    if guard:
        guard.close()
    listener.close()
    group.rmdir()
