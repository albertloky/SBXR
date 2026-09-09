#!/usr/bin/env python3
"""Real iptables fixture, refused unless already in a separate network namespace."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import time

if os.geteuid() != 0 or os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/%d/ns/net' % os.getppid()).st_ino:
    raise SystemExit('run only with unshare -n; host firewall is forbidden')
spec = importlib.util.spec_from_file_location('firewall', Path(__file__).with_name('firewall-control.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
with tempfile.TemporaryDirectory(prefix='sbxr-firewall-fixture-') as directory:
    m.STATE = Path(directory, 'state.json')
    subprocess.run([m.IPTABLES, '-P', 'INPUT', 'ACCEPT'], check=True)
    subprocess.run([m.IPTABLES, '-A', 'INPUT', '-s', '192.0.2.1/32', '-j', 'ACCEPT'], check=True)
    assert m.add('203.0.113.7')['installed']
    time.sleep(1.1)  # generated timestamps must not be mistaken for rule drift
    assert m.remove()['restored']
    assert not m.STATE.exists()
    print('real namespace iptables add/remove preserves unrelated rule: pass')
