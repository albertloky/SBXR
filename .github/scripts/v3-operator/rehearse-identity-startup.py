#!/usr/bin/env python3
"""Prove denied systemd starts leave a fixture able to start after authorization.

Only a unique temporary fixture unit and a sleep process are used. This is
systemd mechanism evidence, never an installed SBXR startup or qualification.
"""
import json
import importlib.util
import os
import pwd
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('startup', Path(__file__).with_name('identity-startup.py'))
startup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(startup)
spec = importlib.util.spec_from_file_location('admission', Path(__file__).with_name('admission-race-operator.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def command(*argv, codes=(0,)):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=20)
    assert result.returncode in codes, 'fixture command refused'
    return result.stdout.strip()


def menu_readiness(root):
    unit = root.name + '-menu.service'
    # Delay creation so the real controller must tolerate an absent unit/PID.
    menu = subprocess.Popen([sys.executable, '-c',
        'import os,sys,time; time.sleep(0.2); os.execvp(sys.argv[1],sys.argv[1:])',
        'systemd-run', '--quiet', '--wait', '--collect', '--service-type=exec',
        '--unit=' + unit, '/usr/bin/sleep', '60'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    original = admission.EXECUTABLE
    try:
        admission.EXECUTABLE = Path('/usr/bin/sleep')
        identity = admission.wait_menu_identity(menu, unit, time.monotonic() + 10)
        assert identity['pid'] > 1 and identity['start_tick'] > 0 and identity['unit'] == unit
        assert identity['cgroup'] == '/system.slice/' + unit
        print(json.dumps({'fixture': 'delayed-transient-menu-readiness',
                          'passed': True, 'live_evidence': False}), flush=True)
    finally:
        admission.EXECUTABLE = original
        command('systemctl', 'stop', unit, codes=(0, 5))
        menu.wait(timeout=10)
        assert not (Path('/sys/fs/cgroup/system.slice') / unit).exists()


def run():
    assert os.geteuid() == 0
    with tempfile.TemporaryDirectory(prefix='sbxr-startup-unit-fixture-', dir='/var/lib') as temporary:
        root = Path(temporary)
        unit = root.name + '.service'
        unit_path = Path('/run/systemd/system') / unit
        target = root.name + '.target'
        target_path = Path('/run/systemd/system') / target
        guard, allowed, condition_uid = root / 'guard', root / 'allowed', root / 'condition-uid'
        account = pwd.getpwnam('nobody')
        assert account.pw_uid > 0 and account.pw_gid > 0
        guard.write_text('#!/bin/sh\n/usr/bin/id -u > ' + shlex.quote(str(condition_uid)) +
                         '\ntest -f ' + shlex.quote(str(allowed)) +
                         ' || exit 1\n/usr/bin/rm -- ' + shlex.quote(str(allowed)) + '\n')
        guard.chmod(0o700)
        descriptor = os.open(unit_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write('[Service]\nType=simple\nUser=' + str(account.pw_uid) +
                         '\nGroup=' + str(account.pw_gid) +
                         '\nProtectSystem=strict\nPrivateTmp=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n' +
                         'ExecCondition=+' + str(guard) +
                         '\nExecStart=/usr/bin/sleep 60\nKillMode=control-group\nRestart=no\n')
        descriptor = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, 'w') as stream:
            # Retain the unit just as the enabled product unit is retained by
            # multi-user.target; otherwise systemd GC discards command status.
            stream.write('[Unit]\nWants=' + unit + '\nAfter=' + unit + '\n')
        prop = lambda name: command('systemctl', 'show', '--property=' + name, '--value', unit)
        try:
            command('systemctl', 'daemon-reload')
            command('systemctl', 'start', target)
            for action in ('start', 'restart'):
                command('systemctl', action, unit, codes=(0, 1))
                condition = prop('ExecCondition')
                assert prop('ActiveState') == 'inactive' and prop('MainPID') == '0'
                startup.exact_condition(condition, denied=True, expected_path=str(guard), expected_arguments=str(guard))
                assert re.search(r'pid=[1-9][0-9]*\s*;', condition)
                assert ('path=' + str(guard)) in condition
                assert condition_uid.read_text().strip() == '0'
            allowed.touch(mode=0o600)
            command('systemctl', 'start', unit)
            assert prop('ActiveState') == 'active' and int(prop('MainPID')) > 1
            assert 'status=0' in prop('ExecCondition')
            assert condition_uid.read_text().strip() == '0' and not allowed.exists()
            status = Path('/proc/%s/status' % prop('MainPID')).read_text().splitlines()
            fields = dict(line.split(':', 1) for line in status if ':' in line)
            assert fields['Uid'].split() == [str(account.pw_uid)] * 4
            assert fields['Gid'].split() == [str(account.pw_gid)] * 4
            assert fields['NoNewPrivs'].strip() == '1' and int(fields['CapEff'].strip(), 16) == 0
            assert prop('ProtectSystem') == 'strict' and prop('PrivateTmp') == 'yes'
            startup.exact_condition(prop('ExecCondition'), expected_path=str(guard), expected_arguments=str(guard))
            command('systemctl', 'stop', unit)
            assert prop('ActiveState') == 'inactive' and prop('MainPID') == '0'
            print(json.dumps({'fixture': 'ordinary-startup-denial-then-authorized-start',
                              'condition_uid': 0, 'main_uid': account.pw_uid,
                              'authorization_consumed': True, 'main_sandbox_retained': True,
                              'passed': True, 'live_evidence': False}), flush=True)
            menu_readiness(root)
        finally:
            command('systemctl', 'stop', target, codes=(0, 5))
            command('systemctl', 'stop', unit, codes=(0, 5))
            unit_path.unlink()
            target_path.unlink()
            command('systemctl', 'daemon-reload')
            assert prop('LoadState') == 'not-found'
            group = Path('/sys/fs/cgroup/system.slice') / unit
            assert not group.exists()


if __name__ == '__main__':
    run()
