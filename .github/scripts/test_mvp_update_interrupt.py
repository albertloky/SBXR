#!/usr/bin/env python3
"""Destructive syscall-controller rehearsal on a marked disposable root VM.

The supplied Go executable is a synthetic fixture, not packaged SBXR. Real
ptrace, Go threads, fork/exec, fsync, file locks and the reviewed permission
wrapper are exercised. Never contacts a CA or establishes live acceptance.
"""

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


SOURCE = Path(__file__).resolve().parent
WINDOW = Path('/root/sbxr-mvp-log-parent')
PRODUCT = Path('/usr/local/bin/sbxr')
STATE = Path('/var/lib/sbxr')
LOCK = Path('/run/lock/sbxr.lock')
SHARED = Path('/var/log/letsencrypt')


def digest(body):
    return hashlib.sha256(body).hexdigest()


def identity(path):
    s = path.lstat()
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_nlink, stat.S_IMODE(s.st_mode))


def write(path, body, mode=0o600):
    with open(path, 'xb') as stream:
        stream.write(body)
    path.chmod(mode)


def process(pid):
    try:
        tail = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
        return (tail[0], int(tail[19]))
    except FileNotFoundError:
        return None


def run(fixture):
    assert sys.platform.startswith('linux') and os.geteuid() == 0
    marker = Path('/run/sbxr-isolated-test-host')
    assert marker.read_bytes() == b'disposable SBXR test VM\n'
    assert identity(marker)[2:] == (0, 0, 1, 0o600) and not marker.is_symlink()
    for path in (WINDOW, PRODUCT, STATE, LOCK, SHARED,
                 PRODUCT.parent / '.sbxr-update-prior', PRODUCT.parent / '.sbxr-update-candidate'):
        assert not os.path.lexists(path), path
    baseline = identity(Path('/var/log'))
    assert baseline[2] == 0 and baseline[-1] == 0o775
    original = fixture.read_bytes()
    root = Path(tempfile.mkdtemp(prefix='update-interrupt-'))
    active = None
    try:
        WINDOW.mkdir(mode=0o700)
        for name, mode in (('with-protected-log-parent.sh', 0o700),
                           ('protected_command_supervisor.py', 0o600)):
            write(WINDOW / name, (SOURCE / 'sbxr-snapshot-recovery' / name).read_bytes(), mode)
        write(WINDOW / 'v3-menu-session.py', (SOURCE / 'v3-menu-session.py').read_bytes())
        SHARED.mkdir(mode=0o700)
        protected = identity(Path('/var/log'))
        cases = [
            ('precommit', 'normal', False), ('postcommit', 'normal', False),
            ('precommit', 'normal', True), ('postcommit', 'normal', True),
            ('precommit', 'wrong-record', True), ('precommit', 'unlocked', True),
            ('precommit', 'no-directory-sync', True), ('postcommit', 'no-directory-sync', True),
            ('precommit', 'refusal', True), ('precommit', 'wrong-prompt', True),
            ('precommit', 'slow', True), ('precommit', 'cancel', True),
            ('precommit', 'expired-request', True), ('precommit', 'wrong-request', True),
            ('precommit', 'short-request', True), ('precommit', 'wrong-source', True),
            ('precommit', 'existing-transcript', True),
            ('precommit', 'future-request', True),
        ]
        for number, (boundary, mode, wrapped) in enumerate(cases):
            case = root / str(number)
            case.mkdir(mode=0o700)
            STATE.mkdir(mode=0o700)
            write(PRODUCT, original, 0o755)
            prior_record, candidate_record = b'{"fixture":"prior"}\n', b'{"fixture":"candidate"}\n'
            ownership = b'{"fixture":"unchanged ownership"}\n'
            candidate = original + b'\nsynthetic candidate identity\n'
            write(STATE / 'installed.json', prior_record)
            write(STATE / 'proxy-ownership.json', ownership)
            write(case / 'candidate', candidate, 0o755)
            write(case / 'candidate.json', candidate_record)
            expected = dict(prior_executable_sha256=digest(original),
                            prior_installed_record_sha256=digest(prior_record),
                            candidate_executable_sha256=digest(candidate),
                            candidate_installed_record_sha256=digest(candidate_record),
                            ownership_sha256=digest(ownership))
            write(case / 'expected.json', json.dumps(expected).encode())
            command = [sys.executable, str(SOURCE / 'mvp-update-interrupt.py'), boundary,
                       '--expectation', str(case / 'expected.json'),
                       '--transcript', str(case / 'transcript'), '--timeout',
                       '3' if mode == 'slow' else '30']
            if wrapped:
                command.append('--protected-log-parent')
            env = dict(os.environ, SBXR_INTERRUPT_FIXTURE=str(case),
                       SBXR_INTERRUPT_BOUNDARY=boundary,
                       SBXR_INTERRUPT_MODE='slow' if mode in ('cancel', 'short-request') else mode)
            env.pop('SBXR_QUALIFICATION_REQUEST', None)
            if mode in ('expired-request', 'wrong-request', 'short-request', 'future-request'):
                now = int(time.time())
                value = {'scenario_id': 'source-v3.1.81-' + ('upgrade' if mode == 'wrong-request' else boundary),
                         'not_before': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + (60 if mode == 'future-request' else -30))),
                         'deadline_unix': now + (-1 if mode == 'expired-request' else 90 if mode == 'future-request' else 2),
                         'scenario_limit_seconds': 1800, 'qualification_manifest_sha256': 'a'*64,
                         'required_checks': ['fixture-only']}
                write(case / 'request.json', json.dumps(value).encode())
                env['SBXR_QUALIFICATION_REQUEST'] = str(case / 'request.json')
            if mode == 'wrong-source':
                expected['prior_executable_sha256'] = '0'*64
                (case / 'expected.json').write_text(json.dumps(expected))
            if mode == 'existing-transcript':
                write(case / 'transcript', b'preserved earlier transcript\n')
            active = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            if mode in ('cancel', 'no-directory-sync'):
                ready = case / ('visible-unsynced' if mode == 'no-directory-sync' else 'product.pid')
                deadline = time.monotonic() + 20
                while not ready.exists():
                    assert active.poll() is None and time.monotonic() < deadline
                    time.sleep(0.01)
                if mode == 'no-directory-sync':
                    assert ready.read_text() == ('Prepared' if boundary == 'precommit' else 'Committed')
                    assert active.poll() is None, 'accepted visibility without directory fsync'
                active.send_signal(signal.SIGTERM)
            output, error = active.communicate(timeout=40)
            assert active.returncode == (0 if mode == 'normal' else 1), (number, output, error, (case / 'transcript').read_bytes())
            active = None
            ids = [int(p.stem) for p in case.glob('*.child')]
            if (case / 'product.pid').exists():
                ids.append(int((case / 'product.pid').read_text()))
            assert all(process(pid) is None for pid in ids), (number, ids)
            if mode in ('expired-request', 'wrong-request', 'wrong-source', 'existing-transcript', 'future-request'):
                assert not (case / 'product.pid').exists(), 'refused input launched product'
            if (case / 'transcript').exists():
                assert stat.S_IMODE((case / 'transcript').stat().st_mode) == 0o600
            if mode == 'existing-transcript':
                assert (case / 'transcript').read_bytes() == b'preserved earlier transcript\n'
            assert not (case / 'runtime-completed').exists(), number
            assert (STATE / 'proxy-ownership.json').read_bytes() == ownership
            if mode == 'normal':
                assert output.startswith(b'SBXR_UPDATE_INTERRUPTED ')
                receipt = json.loads(output.decode().split(' ', 1)[1])
                assert receipt['boundary'] == boundary and receipt['syscall_result'] == 0
                record = json.loads((STATE / 'update.json').read_bytes())
                assert record['checkpoint'] == ('Prepared' if boundary == 'precommit' else 'Committed')
                assert (case / 'after-prepared').exists() == (boundary == 'postcommit')
                assert digest((PRODUCT.parent / '.sbxr-update-prior').read_bytes()) == digest(original)
                assert not (WINDOW / 'window.state').exists()
                assert identity(Path('/var/log')) == protected
            else:
                assert b'SBXR_UPDATE_INTERRUPTED ' not in output
                # A refused window remains evidence; only explicit restoration
                # after dead-process/lock checks returns to the original mode.
                state = WINDOW / 'window.state'
                if state.exists():
                    # A whole-invocation deadline can cancel wrapper startup
                    # before chmod, or cancel restoration after chmod back.
                    # Both exact identities are legal retained-state phases;
                    # the wrapper itself validates and cleans that state.
                    current = identity(Path('/var/log'))
                    assert current in (protected, protected[:-1] + (0o755,))
                    result = subprocess.run(['bash', str(WINDOW / 'with-protected-log-parent.sh'),
                                             'restore', str(state)], capture_output=True, timeout=15)
                    assert result.returncode == 0, (result.stdout, result.stderr)
                assert identity(Path('/var/log')) == protected
            for suffix in ('', '.control', '.result'):
                assert not os.path.lexists(WINDOW / ('window.state' + suffix)), (
                    number, mode, suffix,
                    {p.name: identity(p) for p in WINDOW.iterdir()},
                    output, error,
                )
            assert {p.name for p in WINDOW.iterdir()} == {
                'with-protected-log-parent.sh', 'protected_command_supervisor.py', 'v3-menu-session.py'}
            PRODUCT.unlink()
            for path in (PRODUCT.parent / '.sbxr-update-prior', PRODUCT.parent / '.sbxr-update-candidate', LOCK):
                if path.exists():
                    path.unlink()
            shutil.rmtree(STATE)
            print(f'PASS boundary={boundary} mode={mode} wrapped={wrapped}', flush=True)
    finally:
        if active is not None:
            active.send_signal(signal.SIGTERM)
            active.communicate(timeout=20)
        # Only our fixture paths were absent at entry. Preserve a failed
        # wrapper state if its own verified restoration cannot succeed.
        state = WINDOW / 'window.state'
        if state.exists():
            subprocess.run(['bash', str(WINDOW / 'with-protected-log-parent.sh'),
                            'restore', str(state)], check=True, timeout=15)
        for path in (PRODUCT, PRODUCT.parent / '.sbxr-update-prior', PRODUCT.parent / '.sbxr-update-candidate', LOCK):
            if path.exists():
                path.unlink()
        if STATE.exists():
            shutil.rmtree(STATE)
        if WINDOW.exists():
            shutil.rmtree(WINDOW)
        SHARED.rmdir()
        assert identity(Path('/var/log')) == baseline
        shutil.rmtree(root)
    print('UPDATE_INTERRUPT_FIXTURE_PASSED count=18; not packaged/live evidence', flush=True)


if __name__ == '__main__':
    run(Path(sys.argv[1]).resolve())
