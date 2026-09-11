#!/usr/bin/env python3
"""Observe startup effects while the same reviewed identity action is held.

These checks never edit product authority or create a startup handoff. Ordinary
service requests exercise the installed ExecCondition. During the action the
whole-host lock also denies external admission, so a pre-gate active-service
start is recorded only as a no-op, never as proof of source admission.
"""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('observations', HERE / 'observations.py')
observations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observations)

CHECKPOINTS = ('target prepared', 'startup integration published', 'systemd reloaded',
               'startup route verified', 'source quiescent')
CHECKS = ('startup-publication', 'reload', 'effective-route', 'source-only-before-gate',
          'ordinary-start-denied-after-gate')
DROP_IN = Path('/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf')
DROP_IN_BYTES = b'[Service]\nExecCondition=/usr/local/bin/sbxr --proxy-start-authorize\n'
CONFIG = Path('/etc/sing-box/config.json')
TARGET = Path('/var/lib/sbxr/client-identity-target.json')
TOKEN = Path('/run/sbxr-client-identity-start')
GROUP = Path('/sys/fs/cgroup/system.slice/sing-box.service')
UNIT = 'sing-box.service'


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def exact_condition(value, denied=False, expected_path='/usr/local/bin/sbxr',
                    expected_arguments='/usr/local/bin/sbxr --proxy-start-authorize'):
    require(value.count('{') == 1 and value.count('}') == 1, 'one startup condition required')
    fields = {}
    for field in value.strip('{} \n').split(';'):
        if '=' not in field:
            continue
        key, current = field.strip().split('=', 1)
        require(key in ('path', 'argv[]', 'ignore_errors', 'start_time', 'stop_time', 'pid', 'code', 'status')
                and key not in fields, 'unknown or duplicate startup condition field')
        fields[key] = current
    require(fields.get('path') == expected_path and
            fields.get('argv[]') == expected_arguments and
            fields.get('ignore_errors') == 'no', 'effective startup route mismatch')
    if denied:
        require(fields.get('code') == 'exited' and fields.get('status') == '1' and
                re.fullmatch(r'[1-9][0-9]*', fields.get('pid', '')) is not None,
                'ordinary ExecCondition refusal not observed')
    return fields


class Observer:
    def __init__(self, initial, reader, deadline):
        self.reader, self.deadline = reader, deadline
        self.source = initial['configuration_sha256']
        require(re.fullmatch(r'[a-f0-9]{64}', self.source) is not None, 'source authority digest required')
        self.source_process = self.running_source()
        self.next_index = 0

    def command(self, argv, codes=(0,)):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'startup observation deadline')
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=min(15, remaining))
        require(result.returncode in codes and len(result.stdout) <= 65536 and len(result.stderr) <= 65536,
                'startup command refused')
        return result.stdout.decode('utf-8').strip()

    def property(self, name):
        return self.command(['systemctl', 'show', '--property=' + name, '--value', UNIT])

    def running_source(self):
        require(self.property('ActiveState') == 'active', 'source proxy is not active')
        pid = int(self.property('MainPID'))
        require(pid > 1, 'source process absent')
        fields = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
        require('0::/system.slice/sing-box.service' in Path('/proc/%d/cgroup' % pid).read_text().splitlines(),
                'source process group mismatch')
        require(self.command(['pgrep', '-x', 'sing-box']) == str(pid), 'unexpected proxy process')
        require(hashlib.sha256(self.reader(CONFIG, 0o640)).hexdigest() == self.source,
                'canonical source changed')
        return {'pid': pid, 'start_tick': int(fields[19])}

    def quiescent(self):
        require(self.property('ActiveState') == 'inactive' and self.property('MainPID') == '0',
                'ordinary request started a proxy')
        require(not Path('/proc/%d' % self.source_process['pid']).exists(), 'source process remains')
        require(self.command(['pgrep', '-x', 'sing-box'], codes=(1,)) == '', 'proxy process remains')
        require(self.command(['ss', '-H', '-ltnp', 'sport', '=', ':443']) == '', 'proxy listener remains')
        # systemd may remove an empty stopped cgroup. Unknown/symlink state is
        # never absence. An extant group must have no live descendants.
        if GROUP.exists():
            require(not GROUP.is_symlink() and 'populated 0' in (GROUP / 'cgroup.events').read_text().splitlines()
                    and not (GROUP / 'cgroup.procs').read_text().strip(), 'proxy descendants remain')
        else:
            require(not GROUP.is_symlink() and GROUP.parent.is_dir(), 'proxy cgroup absence unknown')

    def observe(self, checkpoint, record, action_process):
        index = self.next_index
        require(index < len(CHECKPOINTS) and checkpoint == CHECKPOINTS[index], 'startup observation order')
        operation = record.get('client_identity_rotation', {})
        require(operation.get('checkpoint') == checkpoint and operation.get('direction') == 'cleanup' and
                operation.get('source_configuration_sha256') == self.source and
                record.get('configuration_sha256') == self.source, 'startup boundary source mismatch')
        target = operation.get('target_configuration_sha256')
        require(isinstance(target, str) and re.fullmatch(r'[a-f0-9]{64}', target) is not None and target != self.source,
                'prepared target authority required')
        require(hashlib.sha256(self.reader(TARGET, 0o600)).hexdigest() == target and
                hashlib.sha256(self.reader(CONFIG, 0o640)).hexdigest() == self.source,
                'source or prepared target changed')
        require(not TOKEN.exists() and not TOKEN.is_symlink(), 'unexpected private startup token')
        drop_in = self.reader(DROP_IN, 0o644)
        require(drop_in == DROP_IN_BYTES and
                record.get('proxy_startup', {}).get('drop_in_sha256') == hashlib.sha256(drop_in).hexdigest(),
                'startup integration publication mismatch')
        require(DROP_IN.stat().st_gid == 0, 'startup integration group mismatch')
        detail = {'drop_in_sha256': hashlib.sha256(drop_in).hexdigest()}
        if index >= 1:
            exact_condition(self.property('ExecCondition'))
            require(self.property('NeedDaemonReload') == 'no', 'startup reload remains required')
            detail['loaded_condition_exact'] = True
        if index < 4:
            require(self.running_source() == self.source_process, 'source runtime replaced before gate')
        if index == 3:
            lock = observations.observe_flock('/run/lock/sbxr.lock')
            require(lock.get('lock_state') == 'locked' and
                    {'mode': 'WRITE', 'pid': action_process['pid']} in lock.get('holders', []),
                    'actual action does not own whole-host exclusion')
            self.command(['systemctl', 'start', UNIT])
            require(self.running_source() == self.source_process, 'pre-gate no-op changed source')
            detail.update({'source_process': self.source_process, 'target_staged_only': True,
                           'ordinary_active_start': 'no-op', 'whole_host_owner': action_process['pid']})
        if index == 4:
            self.quiescent()
            denied = []
            for action in ('start', 'restart'):
                # ExecCondition status 1 can make systemctl return success.
                # Demand its actual refusal and no runtime after each request.
                self.command(['systemctl', action, UNIT], codes=(0, 1))
                exact_condition(self.property('ExecCondition'), denied=True)
                self.quiescent()
                denied.append(action)
            detail.update({'ordinary_requests_denied': denied, 'main_pid': 0,
                           'owned_processes_and_descendants_absent': True})
        self.next_index += 1
        return {'check': CHECKS[index], 'observed_at': timestamp(), 'details': detail}
