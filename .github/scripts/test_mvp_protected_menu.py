#!/usr/bin/env python3
"""Real driver/wrapper process tests; destructive disposable Linux VM only.

The numbered menu is a protocol fixture. No certificate is issued and no
packaged SBXR behavior is claimed. Real /var/log, kernel processes, locks,
driver, launcher, permission wrapper and restoration are exercised unchanged.
"""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


ROOT = Path('/root/sbxr-mvp-log-parent')
PRODUCT = Path('/usr/local/bin/sbxr')
LOG = Path('/var/log')
SHARED = LOG / 'letsencrypt'
STATE = ROOT / 'window.state'
SOURCE = Path(__file__).resolve().parent


def identity(path):
    s = path.lstat()
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_nlink, stat.S_IMODE(s.st_mode))


def process(pid):
    try:
        parts = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
        return {'pid': pid, 'state': parts[0], 'parent': int(parts[1]),
                'group': int(parts[2]), 'tick': int(parts[19])}
    except FileNotFoundError:
        return None


def live(saved):
    current = process(saved['pid'])
    return current and current['tick'] == saved['tick'] and current['state'] != 'Z'


def command(args, status=0, **kwargs):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=20, **kwargs)
    if result.returncode != status:
        raise AssertionError((args, result.returncode, result.stdout.decode(), result.stderr.decode()))
    return result


def write(path, body, mode=0o600):
    path.write_text(body)
    path.chmod(mode)


FIXTURE = r'''#!/usr/bin/env python3
import fcntl, json, os, signal, stat, subprocess, sys, time
from pathlib import Path
case = Path(os.environ['MVP_WINDOW_FIXTURE'])
def mark():
    p = Path(f'/proc/{os.getpid()}/stat').read_text().rsplit(') ', 1)[1].split()
    data = {'pid': os.getpid(), 'tick': int(p[19]), 'group': int(p[2])}
    target = case / f'{os.getpid()}.json'
    target.with_suffix('.pending').write_text(json.dumps(data))
    target.with_suffix('.pending').replace(target)
mark()
if len(sys.argv) > 1:
    if sys.argv[1] == 'child':
        held = open(case / 'certbot-like.lock', 'a+')
        fcntl.lockf(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        subprocess.Popen([sys.executable, __file__, 'escaped'], start_new_session=True)
    while True: time.sleep(1)
assert stat.S_IMODE(os.stat('/var/log').st_mode) == 0o755
mode = os.environ['MVP_WINDOW_MODE']
if mode == 'exit37': raise SystemExit(37)
menu = 'SBXR V3\n1. Check\n0. Exit'
print(menu, flush=True)
assert sys.stdin.readline().strip() == '1'
if mode == 'normal':
    subprocess.run(['/bin/sh', '-c', 'test "$(stat -c %a /var/log)" = 755'], check=True)
    print('Code: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT', flush=True)
    print(menu, flush=True)
    assert sys.stdin.readline().strip() == '0'
    raise SystemExit(0)
subprocess.Popen(['/bin/sh', '-c', 'exec "$@"', 'certbot-like', sys.executable, __file__, 'child'])
deadline = time.monotonic() + 5
while len(list(case.glob('*.json'))) != 3:
    if time.monotonic() >= deadline: raise SystemExit(92)
    time.sleep(.01)
(case / 'ready.pending').write_text('ready\n')
(case / 'ready.pending').replace(case / 'ready')
if mode == 'protocol': print('Unexpected action? [y/N]', flush=True)
while True: time.sleep(1)
'''


def run():
    if not sys.platform.startswith('linux') or os.geteuid() != 0:
        raise RuntimeError('requires root in disposable Linux/systemd VM')
    marker = Path('/run/sbxr-isolated-test-host')
    if marker.read_bytes() != b'disposable SBXR test VM\n' or identity(marker)[2:4] != (0, 0) or marker.is_symlink() or identity(marker)[5] != 0o600:
        raise RuntimeError('isolated VM marker required')
    for path in (ROOT, PRODUCT, SHARED):
        if os.path.lexists(path):
            raise RuntimeError(f'fixture refuses existing path: {path}')
    baseline = identity(LOG)
    if baseline[2] != 0 or baseline[5] != 0o775 or os.listxattr(LOG):
        raise RuntimeError('original /var/log baseline required')
    ROOT.mkdir(mode=0o700)
    active = None
    journal = []
    try:
        for source, target, mode in (
            (SOURCE / 'mvp-protected-menu.sh', ROOT / 'mvp-protected-menu.sh', 0o700),
            (SOURCE / 'sbxr-snapshot-recovery/with-protected-log-parent.sh', ROOT / 'with-protected-log-parent.sh', 0o700),
            (SOURCE / 'sbxr-snapshot-recovery/protected_command_supervisor.py', ROOT / 'protected_command_supervisor.py', 0o600),
        ):
            shutil.copyfile(source, target)
            target.chmod(mode)
            print(f'INPUT {source.name} {hashlib.sha256(target.read_bytes()).hexdigest()}', flush=True)
        write(PRODUCT, FIXTURE, 0o700)
        launcher = str(ROOT / 'mvp-protected-menu.sh')
        wrapper = str(ROOT / 'with-protected-log-parent.sh')
        driver = str(SOURCE / 'v3-menu-session.py')

        def restored():
            assert identity(LOG) == protected_baseline
            for path in (STATE, Path(str(STATE) + '.control'), Path(str(STATE) + '.result')):
                assert not os.path.lexists(path), path

        # Missing shared log directory must refuse before changing the parent.
        command([launcher], status=1)
        assert identity(LOG) == baseline and not STATE.exists()
        print('PASS missing-shared-log-directory-refused-before-window', flush=True)
        SHARED.symlink_to('/var/log')
        command([launcher], status=1)
        assert identity(LOG) == baseline and not STATE.exists()
        SHARED.unlink()
        SHARED.mkdir(mode=0o775)
        SHARED.chmod(0o775)
        assert identity(SHARED)[5] == 0o775
        refusal = command([launcher], status=1)
        assert b'existing protected Certbot log directory required' in refusal.stderr
        assert identity(LOG)[5] == 0o775 and not STATE.exists()
        SHARED.chmod(0o700)
        protected_baseline = identity(LOG)
        print('PASS unsafe-shared-log-directory-refused-before-window', flush=True)
        command([launcher, 'unexpected'], status=1)
        restored()
        print('PASS launcher-rejects-arguments', flush=True)

        for mode in ('normal', 'exit37', 'protocol', 'deadline', 'cancel'):
            case = Path(tempfile.mkdtemp(prefix=mode + '-', dir=ROOT))
            # Keep identity markers until all descendants are proved gone. A
            # failed assertion must not delete the facts needed for cleanup.
            env = dict(os.environ, MVP_WINDOW_FIXTURE=str(case), MVP_WINDOW_MODE=mode)
            env.pop('SBXR_QUALIFICATION_REQUEST', None)
            env.pop('SBXR_EXECUTABLE', None)
            args = [launcher] if mode == 'exit37' else [sys.executable, driver, 'action', 'Check', 'SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT', '--executable', launcher, '--timeout', '3' if mode == 'deadline' else '15']
            active = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      start_new_session=True)
            if mode == 'cancel':
                deadline = time.monotonic() + 5
                while not (case / 'ready').exists():
                    if active.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError('active-menu readiness failed')
                    time.sleep(.01)
                # The exact wrapper must refuse restore while its group is live.
                command(['bash', wrapper, 'restore', str(STATE)], status=1)
                assert identity(LOG)[5] == 0o755
                active.send_signal(signal.SIGTERM)
            output, error = active.communicate(timeout=20)
            expected = 0 if mode == 'normal' else 37 if mode == 'exit37' else 1
            assert active.returncode == expected, (mode, active.returncode, output, error)
            journal = [json.loads(path.read_text()) for path in case.glob('*.json')]
            assert journal and all(not live(entry) for entry in journal), (mode, journal)
            if mode in ('protocol', 'deadline', 'cancel'):
                assert len(journal) == 3
                assert identity(LOG)[5] == 0o755 and STATE.exists()
                assert b'SBXR_MENU_SESSION_REFUSED' in error
                assert b'process-cleanup' not in error and b'descendant-cleanup' not in error
                with open(case / 'certbot-like.lock', 'a+') as held:
                    fcntl.lockf(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.lockf(held, fcntl.LOCK_UN)
                # A failed window is never silently reused or discarded.
                command([launcher], status=1, env=env)
                assert identity(LOG)[5] == 0o755 and STATE.exists()
                command(['bash', wrapper, 'restore', str(STATE)])
            restored()
            active = None
            journal = []
            shutil.rmtree(case)
            print(f'PASS real-driver-{mode}-processes-locks-and-restoration', flush=True)

        # File activity within the existing shared directory keeps the parent
        # link count stable, unlike adding a new immediate /var/log directory.
        inside = SHARED / 'window-fixture.log'
        command(['bash', wrapper, 'run', str(STATE), '--', '/bin/sh', '-c', 'printf fixture > /var/log/letsencrypt/window-fixture.log'])
        inside.unlink()
        restored()
        SHARED.rmdir()
        assert identity(LOG) == baseline
        command(['bash', wrapper, 'run', str(STATE), '--', '/bin/mkdir', '-m', '0700', str(SHARED)], status=1)
        assert identity(LOG)[5] == 0o755 and STATE.exists()
        command(['bash', wrapper, 'restore', str(STATE)], status=1)
        # Only the test's newly created, verified-empty fixture is removed.
        # A live mismatch must be retained and reported instead.
        SHARED.rmdir()
        command(['bash', wrapper, 'restore', str(STATE)])
        assert identity(LOG) == baseline
        print('PASS changed-parent-link-count-refuses-and-retains-state', flush=True)
    finally:
        if active is not None and active.poll() is None:
            active.send_signal(signal.SIGTERM)
            try:
                active.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                active.kill()
                active.communicate(timeout=5)
        # Exact identity-bound test descendants only; never signal a reused PID.
        for path in ROOT.glob('*/*.json'):
            saved = json.loads(path.read_text())
            if live(saved):
                os.kill(saved['pid'], signal.SIGKILL)
        if SHARED.is_symlink():
            assert os.readlink(SHARED) == str(LOG), 'unexpected shared-log fixture symlink'
            SHARED.unlink()
        if STATE.exists():
            saved = dict(line.split('=', 1) for line in STATE.read_text().splitlines()[1:])
            current = identity(LOG)
            if current[4] != int(saved['links']):
                # The only immediate log child this test creates is SHARED.
                # Refuse any topology difference beyond that exact empty case.
                assert current[4] == int(saved['links']) + 1 and SHARED.is_dir() and not SHARED.is_symlink()
                assert identity(SHARED)[2:4] == (0, 0) and identity(SHARED)[5] == 0o700
                SHARED.rmdir()
            command(['bash', str(ROOT / 'with-protected-log-parent.sh'), 'restore', str(STATE)])
        if SHARED.exists():
            for path in SHARED.iterdir():
                if path.name != 'window-fixture.log' or not path.is_file():
                    raise RuntimeError('unexpected shared fixture content; retained')
                path.unlink()
            SHARED.rmdir()
        assert identity(LOG) == baseline, 'log parent restoration unproved'
        if PRODUCT.exists():
            assert PRODUCT.read_text() == FIXTURE
            PRODUCT.unlink()
        shutil.rmtree(ROOT)
        print('CLEANUP original-log-parent-and-absent-fixture-paths', flush=True)


if __name__ == '__main__':
    run()
