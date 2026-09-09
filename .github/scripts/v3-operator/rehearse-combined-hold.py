#!/usr/bin/env python3
"""Combine guards on a disposable systemd fixture, never a Certbot invocation.

An optional real interpreter path tests the snap inode with harmless -S -c code.
It does not prove SBXR's recorder receipt or the full snap launch chain.
"""
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import uuid

spec = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('network-guard.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
release_child = '--release' in sys.argv[3:]
snap_chain = len(sys.argv) >= 3 and sys.argv[2] in ('--snap-version', '--snap-renew-version')
executable = os.path.realpath(sys.argv[1] if len(sys.argv) >= 2 else sys.executable)
suffix = '-snap.certbot.renew.service.service' if snap_chain and sys.argv[2] == '--snap-renew-version' else '.service'
name = 'sbxr-fixture-' + uuid.uuid4().hex + suffix
group = Path('/sys/fs/cgroup/system.slice', name)
group.mkdir()
guard = None
controller = None
try:
    before = group.stat()
    guard = module.EgressGuard(str(group))
    controller = subprocess.Popen([sys.executable, str(Path(__file__).with_name('exec-gate.py')), executable, '/system.slice/'+name, '--timeout', '10'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    def event():
        assert select.select([controller.stdout], [], [], 5)[0]
        return json.loads(controller.stdout.readline())
    assert event()['state'] == 'armed'
    with tempfile.TemporaryDirectory(prefix='sbxr-combined-fixture-') as directory:
        marker = Path(directory, 'executed')
        code = 'open(%r,"w").write("ran")' % str(marker)
        # --no-block is necessary: Type=exec does not complete while the
        # executable permission event is held, by design.
        app = 'certbot.renew' if snap_chain and sys.argv[2] == '--snap-renew-version' else 'certbot'
        command = ['/usr/bin/snap', 'run', app, '--version'] if snap_chain else [executable, '-S', '-c', code]
        subprocess.run(['systemd-run', '--quiet', '--no-block', '--unit', name, '--property=Type=exec', '--property=RemainAfterExit=yes'] + command, check=True)
        held = event()
        assert held['state'] == 'held', held
        assert not marker.exists()
        after = group.stat()
        assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
        assert str(held['pid']) in (group/'cgroup.procs').read_text().splitlines()
        if snap_chain:
            args = Path('/proc/%d/cmdline' % held['pid']).read_bytes().split(b'\0')
            assert b'--version' in args and any(arg.endswith(b'/bin/certbot') for arg in args)
        controller.stdin.write('release\n' if release_child else 'deny\n')
        controller.stdin.flush()
        assert event()['state'] == ('released' if release_child else 'denied')
        assert controller.wait(timeout=5) == 0
        if release_child:
            import time
            deadline = time.monotonic()+5
            while subprocess.check_output(['systemctl', 'show', name, '--property=SubState', '--value'], text=True).strip() not in ('exited', 'failed'):
                if time.monotonic() >= deadline:
                    raise TimeoutError('fixture completion')
                time.sleep(.025)
            assert subprocess.check_output(['systemctl', 'show', name, '--property=ExecMainStatus', '--value'], text=True).strip() == '0'
        subprocess.run(['systemctl', 'stop', name], check=True)
        assert not marker.exists() if snap_chain or not release_child else marker.read_text() == 'ran'
        print(('snap launcher chain' if snap_chain else 'direct interpreter') + ': preguarded systemd cgroup + actual image hold + '+('release' if release_child else 'deny')+': pass')
finally:
    if controller:
        if controller.poll() is None:
            controller.kill()
        controller.wait()
    subprocess.run(['systemctl', 'stop', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if guard:
        guard.close()
    subprocess.run(['systemctl', 'reset-failed', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if group.exists():
        group.rmdir()
