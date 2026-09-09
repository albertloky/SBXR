#!/usr/bin/env python3
"""Interrupt and recover the four durable link/identity transition scenarios.

The interrupt command arms syscall-gate.py before starting the installed,
zero-argument SBXR UI in a unique transient service.  It holds the real process
before the next Ownership Record publication, verifies the already-durable
checkpoint, and kills the process.  The recover command requires that exact
interrupted record, selects the public Finish action, and verifies the result.

Only protected record hashes and non-secret checkpoint metadata are retained.
Outside link and proxy observations remain separate acceptance evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent
EXECUTABLE = Path('/usr/local/bin/sbxr')
RECORD = Path('/var/lib/sbxr/proxy-ownership.json')
NEXT = Path('/var/lib/sbxr/.proxy-ownership.json.next')
STATE_DIR = Path('/run/sbxr-qualification')
MAX_RECORD = 1024 * 1024
MAX_OUTPUT = 1024 * 1024

SPECS = {
    'link-precommit': {
        'phase': 'initial',
        'action': 'Rotate subscription link',
        'finish': 'Finish subscription change',
        'field': 'subscription_rotation.checkpoint',
        'checkpoint': 'stop authorized',
        'direction': 'cleanup',
        'result': 'PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-CLEANED-UP',
        'plan': 'restore the proved old generation and remove the unused replacement',
    },
    'link-postcommit': {
        'phase': 'initial',
        'action': 'Rotate subscription link',
        'finish': 'Finish subscription change',
        'field': 'subscription_rotation.checkpoint',
        'checkpoint': 'committed',
        'direction': 'forward',
        'result': 'PROXY-INSTALLATION-SUBSCRIPTION-LINK-ROTATED',
        'plan': 'complete only the durably selected replacement',
    },
    'identity-precommit': {
        'phase': 'after-snap-refresh',
        'action': 'Rotate Client Identity',
        'finish': 'Finish Client Identity rotation',
        'field': 'client_identity_rotation.checkpoint',
        'checkpoint': 'source quiescent',
        'direction': 'cleanup',
        'result': 'PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-CLEANED-UP',
        'plan': 'clean up the unused target and restore only the proved unchanged source',
    },
    'identity-postcommit': {
        'phase': 'after-snap-refresh',
        'action': 'Rotate Client Identity',
        'finish': 'Finish Client Identity rotation',
        'field': 'client_identity_rotation.checkpoint',
        'checkpoint': 'source revoked',
        'direction': 'forward',
        'result': 'PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-FINISHED',
        'plan': 'finish only the prepared target; the revoked source can never be restored',
    },
}


def unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate Ownership Record key')
        result[key] = value
    return result


def protected_record(path=RECORD):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or
                before.st_size > MAX_RECORD):
            raise ValueError('Ownership Record protection refused')
        raw = os.read(fd, MAX_RECORD + 1)
        after = os.fstat(fd)
        if (len(raw) != before.st_size or
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)):
            raise ValueError('Ownership Record changed while reading')
        current = os.lstat(path)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('Ownership Record replaced while reading')
        value = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(value, dict):
            raise ValueError('Ownership Record shape refused')
        return raw, value
    finally:
        os.close(fd)


def protected_bytes(path, mode):
    if not path.is_absolute():
        raise ValueError('protected authority path must be absolute')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or
                stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1 or
                before.st_size > MAX_RECORD):
            raise ValueError('protected authority metadata refused')
        raw = os.read(fd, MAX_RECORD + 1)
        after = os.fstat(fd)
        if (len(raw) != before.st_size or
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)):
            raise ValueError('protected authority changed while reading')
        current = os.lstat(path)
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('protected authority replaced while reading')
        return raw
    finally:
        os.close(fd)


def dotted(value, field):
    for part in field.split('.'):
        if not isinstance(value, dict) or part not in value:
            raise ValueError('expected transition checkpoint absent')
        value = value[part]
    return value


def validate_checkpoint(spec, record):
    if dotted(record, spec['field']) != spec['checkpoint']:
        raise ValueError('unexpected transition checkpoint')
    family = spec['field'].split('.', 1)[0]
    operation = record.get(family)
    if not isinstance(operation, dict) or operation.get('direction') != spec['direction']:
        raise ValueError('unexpected transition direction')
    if family == 'subscription_rotation':
        if spec['checkpoint'] == 'committed' and record.get('serving') != operation.get('target'):
            raise ValueError('committed subscription target is not authoritative')
        if spec['checkpoint'] == 'stop authorized' and record.get('serving') != operation.get('source'):
            raise ValueError('precommit subscription source is not authoritative')
    else:
        if record.get('configuration_sha256') != operation.get('source_configuration_sha256'):
            raise ValueError('source Client Identity is not authoritative at boundary')


def validate_final(spec, interrupted, final):
    family = spec['field'].split('.', 1)[0]
    operation = interrupted[family]
    if family == 'subscription_rotation':
        selected = operation['source' if spec['direction'] == 'cleanup' else 'target']
        if final.get('serving') != selected:
            raise ValueError('recovered Subscription Serving authority mismatch')
    else:
        key = 'source_configuration_sha256' if spec['direction'] == 'cleanup' else 'target_configuration_sha256'
        if final.get('configuration_sha256') != operation.get(key):
            raise ValueError('recovered Client Identity authority mismatch')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def held_process(pid, cgroup):
    if not isinstance(pid, int) or pid <= 1:
        raise ValueError('held process identifier refused')
    actual = os.stat('/proc/%d/exe' % pid)
    expected = EXECUTABLE.stat()
    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
        raise ValueError('held process executable mismatch')
    groups = Path('/proc/%d/cgroup' % pid).read_text().splitlines()
    if '0::' + cgroup not in groups:
        raise ValueError('held process cgroup mismatch')
    process = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'start_tick': int(process[19]),
            'executable_device': actual.st_dev, 'executable_inode': actual.st_ino,
            'cgroup': cgroup}


def state_path(scenario):
    return STATE_DIR / ('transition-' + scenario + '.json')


def write_state(path, value):
    if path.exists() or path.is_symlink():
        raise ValueError('transition state already exists')
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    if stat.S_IMODE(os.lstat(path).st_mode) != 0o600:
        raise ValueError('transition state protection refused')


def read_state(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 65536:
            raise ValueError('transition state protection refused')
        raw = os.read(fd, 65537)
        if len(raw) != info.st_size:
            raise ValueError('transition state changed')
        value = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(value, dict):
            raise ValueError('transition state shape refused')
        return value
    finally:
        os.close(fd)


def json_event(stream, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
        raise TimeoutError('gate event deadline')
    line = stream.readline()
    if not line:
        raise ValueError('gate closed before event')
    value = json.loads(line, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError('gate event shape refused')
    return value


class LineStream:
    """Deadline-aware line reader without TextIO read-ahead/select races."""
    def __init__(self, stream):
        self.stream = stream
        self.buffer = bytearray()
        self.consumed = 0

    def line(self, deadline):
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.stream], [], [], remaining)[0]:
                raise TimeoutError('SBXR UI output deadline')
            block = os.read(self.stream.fileno(), 4096)
            if not block:
                raise ValueError('SBXR UI exited before expected output')
            self.buffer.extend(block)
            self.consumed += len(block)
            if self.consumed > MAX_OUTPUT or len(self.buffer) > 16384:
                raise ValueError('SBXR UI output bound exceeded')
        raw, _, rest = self.buffer.partition(b'\n')
        self.buffer = bytearray(rest)
        try:
            return raw.rstrip(b'\r').decode('utf-8')
        except UnicodeDecodeError as error:
            raise ValueError('SBXR UI output encoding refused') from error


def choose(process, stream, action, deadline, plan=None):
    selection = None
    while True:
        line = stream.line(deadline)
        match = re.fullmatch(r'([1-9][0-9]*)\. (.+)', line)
        if match and match.group(2) == action:
            if selection is not None:
                raise ValueError('duplicate requested menu action')
            selection = match.group(1)
        if line == '0. Exit':
            if selection is None:
                raise ValueError('requested action is not legal')
            process.stdin.write((selection + '\n').encode())
            process.stdin.flush()
            break
    prompt = action + '? [y/N]'
    plan_seen = plan is None
    while True:
        line = stream.line(deadline)
        if plan and plan in line:
            plan_seen = True
        if line == prompt:
            if not plan_seen:
                raise ValueError('reviewed recovery direction absent')
            process.stdin.write(b'y\n')
            process.stdin.flush()
            return


def wait_code(process, stream, expected, deadline):
    found = False
    while not found:
        line = stream.line(deadline)
        if line.startswith('Code: '):
            code = line.removeprefix('Code: ')
            if code == expected:
                found = True
            elif code:
                raise ValueError('unexpected SBXR result code')
    # Execute returns to a fresh menu. Exit without invoking another action.
    while True:
        line = stream.line(deadline)
        if line == '0. Exit':
            process.stdin.write(b'0\n')
            process.stdin.flush()
            return


def launch_menu(unit):
    return subprocess.Popen([
        'systemd-run', '--quiet', '--pipe', '--wait', '--collect',
        '--service-type=exec', '--unit=' + unit, str(EXECUTABLE),
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=0)


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)


def stop_menu(process, unit):
    if process is None:
        return
    if process.poll() is None:
        # A systemd-run client is only the pipe client. Stop the unique
        # transient unit itself before terminating that client on error.
        subprocess.run(['systemctl', 'stop', unit], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=40)
    stop(process)


def qualification_preflight(scenario, timeout):
    if os.environ.get('SBXR_OPERATOR_REHEARSAL_HOOK') or os.environ.get('SBXR_OPERATOR_REHEARSAL'):
        raise ValueError('rehearsal overrides cannot control a qualification transition')
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    manifest_path = Path(os.environ['SBXR_QUALIFICATION_MANIFEST'])
    request = json.loads(protected_bytes(request_path, 0o600), object_pairs_hook=unique)
    manifest_raw = protected_bytes(manifest_path, 0o600)
    manifest = json.loads(manifest_raw, object_pairs_hook=unique)
    manifest_digest = digest(manifest_raw)
    if (request.get('scenario_id') != scenario or type(request.get('deadline_unix')) is not int or
            request['deadline_unix'] - time.time() < timeout):
        raise ValueError('wrong scenario or insufficient original deadline')
    if request.get('qualification_manifest_sha256') != manifest_digest:
        raise ValueError('collector manifest binding mismatch')
    attempt = manifest.get('v3_attempt')
    if not isinstance(attempt, dict) or attempt.get('evidence_policy') != 'repair-issuance-bounded-v4':
        raise ValueError('controller is scoped to V4 preparation')
    scenarios = attempt.get('required_scenarios')
    if (not isinstance(scenarios, list) or not all(isinstance(item, str) for item in scenarios) or
            len(scenarios) != len(set(scenarios)) or
            scenario not in scenarios or 'snap-refresh' not in scenarios):
        raise ValueError('signed scenario order refused')
    phase = 'after-snap-refresh' if scenarios.index(scenario) > scenarios.index('snap-refresh') else 'initial'
    if phase != SPECS[scenario]['phase']:
        raise ValueError('signed scenario package phase refused')
    subprocess.run([
        'bash', '-c',
        'source "$1"; operator_expect_scenario "$2"; preflight "$3"; operator_exact_candidate',
        'transition-preflight', str(HERE / 'operator-support.sh'), scenario, phase,
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(30, timeout))
    return request['deadline_unix'], manifest_digest


def common_preflight(scenario, timeout):
    if sys.platform != 'linux' or os.geteuid() != 0 or not 5 <= timeout <= 120:
        raise ValueError('Linux root and timeout 5..120 required')
    original_deadline, manifest_digest = qualification_preflight(scenario, timeout)
    STATE_DIR.mkdir(mode=0o700, parents=False, exist_ok=True)
    directory = STATE_DIR.stat()
    if directory.st_uid != 0 or stat.S_IMODE(directory.st_mode) & 0o077 or STATE_DIR.is_symlink():
        raise ValueError('operator state directory protection refused')
    executable = os.stat(EXECUTABLE, follow_symlinks=False)
    if not stat.S_ISREG(executable.st_mode) or executable.st_uid != 0 or executable.st_mode & 0o022:
        raise ValueError('installed executable protection refused')
    if NEXT.exists() or NEXT.is_symlink():
        raise ValueError('staged Ownership Record must initially be absent')
    return original_deadline, manifest_digest


def interrupt(scenario, timeout):
    original_deadline, manifest_digest = common_preflight(scenario, timeout)
    spec = SPECS[scenario]
    state = state_path(scenario)
    if state.exists() or state.is_symlink():
        raise ValueError('transition scenario already interrupted')
    initial_raw, initial = protected_record()
    if initial.get('subscription_rotation') is not None or initial.get('client_identity_rotation') is not None:
        raise ValueError('an unfinished transition already exists')
    unit = 'sbxr-v4-' + scenario + '-' + str(os.getpid()) + '.service'
    cgroup = '/system.slice/' + unit
    gate = menu = None
    deadline = time.monotonic() + min(timeout, original_deadline - time.time())
    try:
        gate = subprocess.Popen([
            sys.executable, str(HERE / 'syscall-gate.py'), str(EXECUTABLE), cgroup,
            'before-open', str(NEXT), '--record', str(RECORD), '--field', spec['field'],
            '--value', spec['checkpoint'], '--timeout', str(timeout),
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        armed = json_event(gate.stdout, deadline)
        if armed.get('state') != 'armed':
            raise ValueError('syscall gate did not arm')
        menu = launch_menu(unit)
        choose(menu, LineStream(menu.stdout), spec['action'], deadline)
        held = json_event(gate.stdout, deadline)
        if (held.get('state') != 'boundary-held' or held.get('boundary') != 'before-open' or
                held.get('path') != str(NEXT)):
            raise ValueError('unexpected syscall boundary')
        process_evidence = held_process(held.get('pid'), cgroup)
        interrupted_raw, interrupted = protected_record()
        validate_checkpoint(spec, interrupted)
        if held.get('record_sha256') != digest(interrupted_raw) or NEXT.exists() or NEXT.is_symlink():
            raise ValueError('held boundary does not match durable record')
        gate.stdin.write('kill\n')
        gate.stdin.flush()
        if json_event(gate.stdout, deadline).get('state') != 'interrupted':
            raise ValueError('syscall gate did not interrupt')
        gate.wait(timeout=max(1, deadline - time.monotonic()))
        if gate.returncode != 0:
            raise ValueError('syscall gate failed after interruption')
        menu.wait(timeout=max(1, deadline - time.monotonic()))
        final_raw, final = protected_record()
        validate_checkpoint(spec, final)
        if digest(final_raw) != digest(interrupted_raw) or NEXT.exists() or NEXT.is_symlink():
            raise ValueError('interrupted durable record changed')
        write_state(state, {
            'schema': 1, 'scenario': scenario, 'phase': 'interrupted',
            'initial_record_sha256': digest(initial_raw),
            'interrupted_record_sha256': digest(interrupted_raw),
            'field': spec['field'], 'checkpoint': spec['checkpoint'],
            'direction': spec['direction'], 'boundary_process': process_evidence,
            'qualification_manifest_sha256': manifest_digest,
        })
        print(json.dumps({'state': 'interrupted', 'scenario': scenario,
                          'record_sha256': digest(interrupted_raw),
                          'boundary_process': process_evidence}, sort_keys=True))
    finally:
        stop_menu(menu, unit)
        stop(gate)


def recover(scenario, timeout):
    original_deadline, manifest_digest = common_preflight(scenario, timeout)
    spec = SPECS[scenario]
    state_file = state_path(scenario)
    state = read_state(state_file)
    if (state.get('schema') != 1 or state.get('scenario') != scenario or
            state.get('phase') != 'interrupted' or state.get('field') != spec['field'] or
            state.get('checkpoint') != spec['checkpoint'] or state.get('direction') != spec['direction'] or
            state.get('qualification_manifest_sha256') != manifest_digest):
        raise ValueError('transition state does not match scenario')
    before_raw, before = protected_record()
    validate_checkpoint(spec, before)
    if digest(before_raw) != state.get('interrupted_record_sha256'):
        raise ValueError('Ownership Record drifted after interruption')
    unit = 'sbxr-v4-recover-' + scenario + '-' + str(os.getpid()) + '.service'
    menu = None
    deadline = time.monotonic() + min(timeout, original_deadline - time.time())
    try:
        menu = launch_menu(unit)
        stream = LineStream(menu.stdout)
        choose(menu, stream, spec['finish'], deadline, spec['plan'])
        wait_code(menu, stream, spec['result'], deadline)
        menu.wait(timeout=max(1, deadline - time.monotonic()))
        if menu.returncode != 0:
            raise ValueError('SBXR recovery UI failed')
        final_raw, final = protected_record()
        if final.get('subscription_rotation') is not None or final.get('client_identity_rotation') is not None:
            raise ValueError('transition authority remains after recovery')
        validate_final(spec, before, final)
        completed = dict(state)
        completed.update({'phase': 'recovered', 'final_record_sha256': digest(final_raw),
                          'result_code': spec['result']})
        replacement = state_file.with_name(state_file.name + '.next')
        write_state(replacement, completed)
        os.replace(replacement, state_file)
        directory_fd = os.open(STATE_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        print(json.dumps({'state': 'recovered', 'scenario': scenario,
                          'record_sha256': digest(final_raw), 'result_code': spec['result']}, sort_keys=True))
    finally:
        stop_menu(menu, unit)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['interrupt', 'recover'])
    parser.add_argument('scenario', choices=sorted(SPECS))
    parser.add_argument('--timeout', type=int, default=90)
    args = parser.parse_args()
    try:
        (interrupt if args.operation == 'interrupt' else recover)(args.scenario, args.timeout)
    except Exception as error:
        print(json.dumps({'state': 'refused', 'error_type': type(error).__name__,
                          'errno': getattr(error, 'errno', None)}, sort_keys=True))
        sys.exit(1)
