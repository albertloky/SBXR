#!/usr/bin/env python3
"""Observe the subscription runtime at link-rotation syscall boundaries.

The observer reads only digests and durable authority.  It never retains a
subscription credential or performs public traffic; the outside observer owns
those checks.  A stopped service is accepted only when its original process,
cgroup descendants, listener, and accepted sockets are all absent.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


EXECUTABLE = Path('/usr/local/bin/sbxr')
CONFIG = Path('/etc/sing-box/config.json')
SERVING_STATE = Path('/var/lib/sbxr/subscription-serving.json')
SERVING_TOKEN = Path('/var/lib/sbxr/subscription-token')
TARGET_DIR = Path('/var/lib/sbxr/subscription-staging')
TARGET_TOKEN = Path('/var/lib/sbxr/subscription-staging/credential')
TARGET_STATE = Path('/var/lib/sbxr/subscription-staging/serving.json')
GROUP = Path('/sys/fs/cgroup/system.slice/sbxr-subscription.service')
SUBSCRIPTION_UNIT = 'sbxr-subscription.service'
PROXY_UNIT = 'sing-box.service'
AUTHORITY_KEYS = {'link_id', 'credential_sha256', 'certificate_generation', 'certificate_sha256'}


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def authority(value, label):
    require(isinstance(value, dict) and set(value) == AUTHORITY_KEYS, label + ' authority shape refused')
    link_id, credential = value.get('link_id', ''), value.get('credential_sha256', '')
    certificate = value.get('certificate_sha256')
    require(re.fullmatch(r'[a-f0-9]{32}', link_id) is not None and link_id != '0' * 32 and
            re.fullmatch(r'[a-f0-9]{64}', credential) is not None and credential != '0' * 64 and
            type(value.get('certificate_generation')) is int and 1 <= value['certificate_generation'] <= 1000000 and
            isinstance(value.get('certificate_sha256'), list) and len(value['certificate_sha256']) == 4 and
            all(re.fullmatch(r'[a-f0-9]{64}', item) is not None and item != '0' * 64 for item in certificate),
            label + ' authority values refused')
    return value


def process_identity(pid, executable=EXECUTABLE):
    require(type(pid) is int and pid > 1, 'runtime process identifier refused')
    actual = os.stat('/proc/%d/exe' % pid)
    if executable is not None:
        expected = executable.stat()
        require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino),
                'runtime executable mismatch')
    fields = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'start_tick': int(fields[19]),
            'executable_device': actual.st_dev, 'executable_inode': actual.st_ino}


class Observer:
    def __init__(self, initial, reader, deadline):
        self.reader, self.deadline = reader, deadline
        self.source = authority(initial.get('serving'), 'source')
        self.configuration_sha256 = initial.get('configuration_sha256')
        require(re.fullmatch(r'[a-f0-9]{64}', self.configuration_sha256 or '') is not None,
                'configuration authority digest required')
        require(hashlib.sha256(reader(CONFIG, 0o640)).hexdigest() == self.configuration_sha256,
                'canonical proxy configuration changed')
        self.initial_staging_empty = self.staging(())
        self.source_process = self.running_subscription(self.source)
        self.proxy_process = self.running_proxy()

    @classmethod
    def for_recovery(cls, source, configuration_sha256, source_process, proxy_process,
                     reader, deadline):
        self = cls.__new__(cls)
        self.reader, self.deadline = reader, deadline
        self.source = authority(source, 'source')
        self.configuration_sha256 = configuration_sha256
        require(re.fullmatch(r'[a-f0-9]{64}', configuration_sha256 or '') is not None and
                hashlib.sha256(reader(CONFIG, 0o640)).hexdigest() == configuration_sha256,
                'recovery proxy configuration changed')
        require(isinstance(source_process, dict) and type(source_process.get('pid')) is int and
                type(source_process.get('start_tick')) is int, 'recorded source process refused')
        require(isinstance(proxy_process, dict), 'recorded proxy process refused')
        self.source_process, self.proxy_process = source_process, proxy_process
        self.unchanged_proxy()
        return self

    def command(self, argv, codes=(0,)):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'link runtime observation deadline')
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=min(15, remaining))
        require(result.returncode in codes and len(result.stdout) <= 65536 and len(result.stderr) <= 65536,
                'link runtime command refused')
        return result.stdout.decode('utf-8').strip()

    def property(self, unit, name):
        return self.command(['systemctl', 'show', '--property=' + name, '--value', unit])

    def running_proxy(self):
        require(self.property(PROXY_UNIT, 'ActiveState') == 'active', 'proxy is not active')
        pid = int(self.property(PROXY_UNIT, 'MainPID'))
        process = process_identity(pid, None)
        require('0::/system.slice/' + PROXY_UNIT in Path('/proc/%d/cgroup' % pid).read_text().splitlines(),
                'proxy process group mismatch')
        require(hashlib.sha256(self.reader(CONFIG, 0o640)).hexdigest() == self.configuration_sha256,
                'proxy configuration changed')
        return process

    def serving_state(self, selected):
        raw = self.reader(SERVING_STATE, 0o600)
        expected = serving_state_bytes(selected)
        require(raw == expected, 'subscription serving state authority mismatch')
        return hashlib.sha256(raw).hexdigest()

    def serving_token(self, selected):
        token = self.reader(SERVING_TOKEN, 0o600)
        require(len(token) == 44 and token[43:] == b'\n' and
                hashlib.sha256(token[:43]).hexdigest() == selected['credential_sha256'],
                'subscription credential digest mismatch')
        return selected['credential_sha256']

    def staging(self, expected):
        fd = os.open(TARGET_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            require(before.st_uid == 0 and (before.st_mode & 0o777) == 0o700,
                    'subscription staging protection refused')
            names = tuple(sorted(os.listdir(fd)))
            after = os.fstat(fd)
            require(names == tuple(sorted(expected)) and
                    (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
                    'subscription staging content mismatch')
            return True
        finally:
            os.close(fd)

    def running_subscription(self, selected):
        require(self.property(SUBSCRIPTION_UNIT, 'ActiveState') == 'active',
                'subscription service is not active')
        pid = int(self.property(SUBSCRIPTION_UNIT, 'MainPID'))
        process = process_identity(pid)
        cgroup = '/system.slice/' + SUBSCRIPTION_UNIT
        require('0::' + cgroup in Path('/proc/%d/cgroup' % pid).read_text().splitlines(),
                'subscription process group mismatch')
        listener = self.command(['ss', '-H', '-ltnp', 'sport', '=', ':8443'])
        require(len(listener.splitlines()) == 1 and 'pid=' + str(pid) + ',' in listener,
                'subscription listener identity mismatch')
        self.serving_token(selected)
        process.update({'cgroup': cgroup, 'serving_state_sha256': self.serving_state(selected)})
        return process

    def unchanged_proxy(self):
        require(self.running_proxy() == self.proxy_process, 'proxy process changed during link rotation')

    def target_staged(self, record):
        operation = record.get('subscription_rotation')
        require(isinstance(operation, dict) and operation.get('checkpoint') == 'target authorized' and
                operation.get('direction') == 'cleanup' and operation.get('source') == self.source and
                record.get('serving') == self.source, 'target-authorized source authority mismatch')
        target = authority(operation.get('target'), 'target')
        require(target['link_id'] != self.source['link_id'] and
                target['credential_sha256'] != self.source['credential_sha256'] and
                target['certificate_generation'] == self.source['certificate_generation'] and
                target['certificate_sha256'] == self.source['certificate_sha256'],
                'target changes more than subscription identity')
        prepared = self.prepared_files(target)
        require(self.running_subscription(self.source) == self.source_process,
                'source subscription changed before stop authority')
        self.unchanged_proxy()
        return target, {'source_process': self.source_process, **prepared,
                        'source_still_running': True, 'target_staged_only': True}

    def prepared_files(self, target):
        self.staging(('credential', 'serving.json'))
        token = self.reader(TARGET_TOKEN, 0o600)
        require(len(token) == 44 and token[43:] == b'\n' and
                hashlib.sha256(token[:43]).hexdigest() == target['credential_sha256'],
                'staged target credential digest mismatch')
        state = self.reader(TARGET_STATE, 0o600)
        require(state == serving_state_bytes(target),
                'staged target serving state mismatch')
        return {'target_state_sha256': hashlib.sha256(state).hexdigest(),
                'target_credential_sha256': target['credential_sha256']}

    def committed_unpublished(self, target):
        prepared = self.prepared_files(target)
        return {**prepared, 'target_staged_only': True, 'serving_material': 'source',
                'source_state_sha256': self.serving_state(self.source),
                'source_credential_sha256': self.serving_token(self.source)}

    def quiescent(self):
        require(self.property(SUBSCRIPTION_UNIT, 'ActiveState') == 'inactive' and
                self.property(SUBSCRIPTION_UNIT, 'MainPID') == '0',
                'subscription service not inactive')
        source_path = Path('/proc/%d/stat' % self.source_process['pid'])
        if source_path.exists():
            fields = source_path.read_text().rsplit(')', 1)[1].split()
            require(int(fields[19]) != self.source_process['start_tick'], 'source subscription process remains')
        require(self.command(['pgrep', '-f', '^/usr/local/bin/sbxr --subscription-serving$'], codes=(1,)) == '',
                'subscription process remains')
        listener = self.command(['ss', '-H', '-ltnp', 'sport', '=', ':8443'])
        sockets = self.command(['ss', '-H', '-tanp', 'sport', '=', ':8443'])
        require(listener == '', 'subscription listener remains')
        socket_lines = sockets.splitlines() if sockets else []
        require(all(line.split(maxsplit=1)[0] == 'TIME-WAIT' and 'users:' not in line
                    for line in socket_lines), 'subscription accepted socket remains')
        if GROUP.exists():
            require(not GROUP.is_symlink() and
                    'populated 0' in (GROUP / 'cgroup.events').read_text().splitlines() and
                    not (GROUP / 'cgroup.procs').read_text().strip(),
                    'subscription descendants remain')
            group_state = 'empty'
        else:
            require(not GROUP.is_symlink() and GROUP.parent.is_dir(), 'subscription cgroup absence unknown')
            group_state = 'absent'
        self.unchanged_proxy()
        return {'active_state': 'inactive', 'main_pid': 0, 'source_process_absent': True,
                'owned_processes_and_descendants_absent': True, 'cgroup_state': group_state,
                'listener_8443_absent': True, 'accepted_sockets_8443_absent': True,
                'unowned_kernel_time_wait_sockets': len(socket_lines),
                'proxy_process': self.proxy_process,
                'configuration_sha256': self.configuration_sha256}

    def final_running(self, selected):
        staging_empty = self.staging(())
        process = self.running_subscription(selected)
        self.unchanged_proxy()
        return {'subscription_process': process, 'proxy_process': self.proxy_process,
                'configuration_sha256': self.configuration_sha256,
                'selected_authority_sha256': hashlib.sha256(canonical(selected)).hexdigest(),
                'staging_empty': staging_empty}


def comparison(source, target, initial_selector, interrupted_selector, final_selector,
               configuration_unchanged=True):
    authority(source, 'source')
    authority(target, 'target')
    require(initial_selector == 'source' and interrupted_selector in ('source', 'target') and
            final_selector in ('source', 'target'), 'serving selector refused')
    return {
        'source_authority_sha256': hashlib.sha256(canonical(source)).hexdigest(),
        'target_authority_sha256': hashlib.sha256(canonical(target)).hexdigest(),
        'link_id_changed': source['link_id'] != target['link_id'],
        'credential_sha256_changed': source['credential_sha256'] != target['credential_sha256'],
        'certificate_generation_unchanged': source['certificate_generation'] == target['certificate_generation'],
        'certificate_sha256_unchanged': source['certificate_sha256'] == target['certificate_sha256'],
        'configuration_sha256_unchanged': configuration_unchanged,
        'initial_serving': initial_selector, 'interrupted_serving': interrupted_selector,
        'final_serving': final_selector,
    }


def serving_state_bytes(selected):
    authority(selected, 'serving state')
    ordered = {'link_id': selected['link_id'],
               'credential_sha256': selected['credential_sha256'],
               'certificate_generation': selected['certificate_generation'],
               'certificate_sha256': selected['certificate_sha256']}
    return (json.dumps({'schema': 1, 'serving': ordered}, separators=(',', ':')) + '\n').encode()
