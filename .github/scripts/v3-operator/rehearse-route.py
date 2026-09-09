#!/usr/bin/env python3
"""Actual systemd route rehearsal using only uniquely named test-owned units."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

spec = importlib.util.spec_from_file_location('route', Path(__file__).with_name('route-control.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
name = 'sbxr-fixture-' + uuid.uuid4().hex
service = Path('/run/systemd/system', name+'.service')
timer = Path('/run/systemd/system', name+'.timer')
service.write_text('[Unit]\nDescription=SBXR isolated route fixture\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
service.chmod(0o644)
timer.write_text('[Unit]\nDescription=SBXR isolated timer fixture\n[Timer]\nOnCalendar=2100-01-01 00:00:00 UTC\nPersistent=false\n[Install]\nWantedBy=timers.target\n')
timer.chmod(0o644)
m.UNIT, m.HIDDEN = service, service.with_suffix('.hidden')
m.SERVICE, m.TIMER = service.name, timer.name
try:
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    # Give the fixture real previous service invocation metadata, as the real
    # renewal unit has after earlier scenarios. The command only exits success.
    subprocess.run(['systemctl', 'start', service.name], check=True)
    subprocess.run(['systemctl', 'start', timer.name], check=True)
    with tempfile.TemporaryDirectory(prefix='sbxr-route-fixture-') as directory:
        m.STATE = Path(directory, 'state')
        before = m.identity(service)
        m.inject()
        assert not service.exists() and m.HIDDEN.exists()
        assert m.restore()['restored']
        assert m.identity(service) == before and not m.STATE.exists()
        print('real systemd hide/restore preserves unit inode and timer state: pass')
finally:
    subprocess.run(['systemctl', 'stop', timer.name, service.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['systemctl', 'disable', timer.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for path in [service, timer, m.HIDDEN]:
        path.unlink(missing_ok=True)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'reset-failed', service.name, timer.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
