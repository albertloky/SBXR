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
import importlib.util
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
SERVING_TOKEN = Path('/var/lib/sbxr/subscription-token')
STATE_DIR = Path('/run/sbxr-qualification')
MAX_RECORD = 1024 * 1024
MAX_OUTPUT = 1024 * 1024
startup_spec = importlib.util.spec_from_file_location('identity_startup', HERE / 'identity-startup.py')
startup = importlib.util.module_from_spec(startup_spec)
startup_spec.loader.exec_module(startup)
link_spec = importlib.util.spec_from_file_location('link_runtime', HERE / 'link-runtime.py')
link = importlib.util.module_from_spec(link_spec)
link_spec.loader.exec_module(link)
identity_outside_spec = importlib.util.spec_from_file_location('identity_transition_outside', HERE / 'identity-transition-outside.py')
identity_outside = importlib.util.module_from_spec(identity_outside_spec)
identity_outside_spec.loader.exec_module(identity_outside)

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
ROTATION_SPECS = {
    'identity-absent': {'phase': 'initial', 'action': 'Rotate Client Identity',
                        'result': 'PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATED'},
    'identity-unavailable': {'phase': 'after-snap-refresh', 'action': 'Rotate Client Identity',
                             'result': 'PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATED'},
}
INTERRUPT_SCENARIOS = ('link-precommit', 'link-postcommit', 'identity-precommit', 'identity-postcommit')


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


def identity_entry(scenario, manifest_digest, request_raw):
    path = STATE_DIR / (scenario + '-entry.json')
    raw = protected_bytes(path, 0o600)
    value = json.loads(raw, object_pairs_hook=unique)
    required = {'schema', 'scenario_id', 'qualification_manifest_sha256', 'request_sha256',
                'started_at', 'entry_started_at'}
    if (not isinstance(value, dict) or not required.issubset(value) or
            value.get('schema') != 'sbxr-v4-identity-transition-entry-v1' or value.get('scenario_id') != scenario or
            value.get('qualification_manifest_sha256') != manifest_digest or
            value.get('request_sha256') != digest(request_raw)):
        raise ValueError('identity scenario entry binding differs')
    return value, raw


def identity_ready(scenario, manifest_digest, request_raw, entry):
    raw = protected_bytes(STATE_DIR / (scenario + '-outside-ready.json'), 0o600)
    value = json.loads(raw, object_pairs_hook=unique)
    manifest_raw = protected_bytes(Path(os.environ['SBXR_QUALIFICATION_MANIFEST']), 0o600)
    bound = identity_outside.binding(manifest_raw, request_raw, entry)
    identity_outside.check(value, bound, entry, ready=True)
    if value.get('qualification_manifest_sha256') != manifest_digest:
        raise ValueError('identity outside ready manifest differs')
    return value, raw


def publish_identity_trigger(scenario, request_raw, ready_raw, operation):
    trigger = {'schema': 'sbxr-v4-identity-transition-action-v1', 'scenario_id': scenario,
               'request_sha256': digest(request_raw), 'ready_sha256': digest(ready_raw),
               'source_configuration_sha256': operation['source_configuration_sha256'],
               'target_configuration_sha256': operation['target_configuration_sha256'],
               'published_at': startup.timestamp()}
    write_state(STATE_DIR / (scenario + '-action.json'), trigger)
    return trigger


def identity_closed(scenario, request_raw):
    ready_raw = protected_bytes(STATE_DIR / (scenario + '-outside-ready.json'), 0o600)
    closed_raw = protected_bytes(STATE_DIR / (scenario + '-outside-closed.json'), 0o600)
    ready = json.loads(ready_raw, object_pairs_hook=unique)
    closed = json.loads(closed_raw, object_pairs_hook=unique)
    if (closed.get('schema') != 'sbxr-v4-identity-transition-closed-v1' or
            closed.get('scenario_id') != scenario or closed.get('request_sha256') != digest(request_raw) or
            closed.get('ready_sha256') != digest(ready_raw) or
            closed.get('connection_id') != ready.get('connection_id') or
            closed.get('fresh_old_refused') is not True):
        raise ValueError('outside old-session termination/refusal receipt differs')
    return closed


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
    if phase != {**SPECS, **ROTATION_SPECS}[scenario]['phase']:
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


def identity_gate(unit, timeout, final_checkpoint):
    checkpoints = list(startup.CHECKPOINTS)
    if final_checkpoint != checkpoints[-1]:
        checkpoints.append(final_checkpoint)
    command = [sys.executable, str(HERE / 'syscall-gate.py'), str(EXECUTABLE),
               '/system.slice/' + unit, 'before-open', str(NEXT), '--record', str(RECORD),
               '--field', 'client_identity_rotation.checkpoint', '--value', checkpoints[0],
               '--timeout', str(timeout)]
    for checkpoint in checkpoints[1:]:
        command += ['--then-value', checkpoint]
    gate = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    return gate, LineStream(gate.stdout), checkpoints


def link_gate(unit, timeout, scenario):
    checkpoints = ['target authorized', 'stop authorized']
    if scenario == 'link-postcommit':
        checkpoints.append('committed')
    command = [sys.executable, str(HERE / 'syscall-gate.py'), str(EXECUTABLE),
               '/system.slice/' + unit, 'before-open', str(NEXT), '--record', str(RECORD),
               '--field', 'subscription_rotation.checkpoint', '--value', checkpoints[0],
               '--timeout', str(timeout)]
    paths = [NEXT, NEXT] + ([SERVING_TOKEN] if scenario == 'link-postcommit' else [])
    for checkpoint, path in zip(checkpoints[1:], paths[1:]):
        command += ['--then-value', checkpoint, '--then-path', str(path)]
    gate = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    return gate, LineStream(gate.stdout), checkpoints


def wait_protected(path, deadline):
    while time.monotonic() < deadline:
        if path.exists() or path.is_symlink():
            return protected_bytes(path, 0o600)
        time.sleep(.01)
    raise TimeoutError('outside link receipt deadline')


def check_outside(kind, scenario, request_path, manifest_path, deadline):
    receipt = STATE_DIR / ('link-' + scenario + '-' + kind + '.json')
    raw = wait_protected(receipt, deadline)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('outside link checker deadline')
    subprocess.run([sys.executable, str(HERE / 'link-outside.py'), 'check-' + kind,
                    '--manifest', str(manifest_path), '--request', str(request_path),
                    '--receipt', str(receipt)], check=True, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, timeout=min(15, remaining))
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError('outside link receipt shape refused')
    return raw, value


def link_handoff(scenario, held_record_sha256, request, request_raw, manifest_digest, deadline):
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    manifest_path = Path(os.environ['SBXR_QUALIFICATION_MANIFEST'])
    ready_raw, ready = check_outside('ready', scenario, request_path, manifest_path, deadline)
    if (ready.get('scenario_id') != scenario or ready.get('request_sha256') != digest(request_raw) or
            ready.get('qualification_manifest_sha256') != manifest_digest or
            ready.get('deadline_unix') != request.get('deadline_unix')):
        raise ValueError('outside ready binding mismatch')
    challenge = {
        'schema': 'sbxr-v4-link-outside-challenge-v1', 'scenario_id': scenario,
        'request_sha256': digest(request_raw), 'qualification_manifest_sha256': manifest_digest,
        'deadline_unix': request['deadline_unix'], 'nonce': os.urandom(32).hex(),
        'challenged_at': startup.timestamp(), 'ready_sha256': digest(ready_raw),
        'initial_disclosure_sha256': ready['initial_disclosure_sha256'],
        'transition_record_sha256': held_record_sha256,
    }
    challenge_path = STATE_DIR / ('link-' + scenario + '-challenge.json')
    write_state(challenge_path, challenge)
    challenge_raw = protected_bytes(challenge_path, 0o600)
    ack_raw, ack = check_outside('ack', scenario, request_path, manifest_path, deadline)
    if (ack.get('challenge_sha256') != digest(challenge_raw) or
            ack.get('pending_ready_at') is None or ack.get('connection_id') is None):
        raise ValueError('outside pending-request acknowledgement mismatch')
    return {'ready_sha256': digest(ready_raw), 'ready_at': ready['ready_at'],
            'challenge_sha256': digest(challenge_raw), 'challenged_at': challenge['challenged_at'],
            'ack_sha256': digest(ack_raw), 'pending_ready_at': ack['pending_ready_at'],
            'connection_id': ack['connection_id'], 'old_link_sha256': ack['old_link_sha256'],
            'configuration_sha256': ready['configuration_sha256'],
            'certificate_der_sha256': ready['certificate_der_sha256']}


def link_closed(scenario, handoff, deadline):
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    manifest_path = Path(os.environ['SBXR_QUALIFICATION_MANIFEST'])
    closed_raw, closed = check_outside('closed', scenario, request_path, manifest_path, deadline)
    if (closed.get('challenge_sha256') != handoff['challenge_sha256'] or
            closed.get('ack_sha256') != handoff['ack_sha256'] or
            closed.get('connection_id') != handoff['connection_id'] or
            closed.get('server_deadline_seconds') != 5 or
            type(closed.get('pending_elapsed_milliseconds')) is not int or
            not 0 <= closed['pending_elapsed_milliseconds'] < 5000 or
            closed.get('closure_kind') not in ('eof', 'reset', 'ssl-eof')):
        raise ValueError('outside held request closure mismatch')
    handoff.update({'closed_sha256': digest(closed_raw), 'closed_at': closed['closed_at'],
                    'closure_kind': closed['closure_kind'],
                    'pending_elapsed_milliseconds': closed['pending_elapsed_milliseconds']})
    return handoff


def gate_event(stream, deadline):
    value = json.loads(stream.line(deadline), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError('gate event shape refused')
    return value


def observe_identity_boundaries(gate, stream, checkpoints, observer, unit, deadline, on_target=None):
    observations = []
    process = None
    for index, checkpoint in enumerate(checkpoints):
        held = gate_event(stream, deadline)
        if (held.get('state') != 'boundary-held' or held.get('boundary_index') != index or
                held.get('boundary') != 'before-open' or held.get('path') != str(NEXT)):
            raise ValueError('unexpected identity syscall boundary')
        actual = held_process(held.get('pid'), '/system.slice/' + unit)
        if process is not None and actual != process:
            raise ValueError('identity action process changed between checkpoints')
        process = actual
        raw, record = protected_record()
        if (dotted(record, 'client_identity_rotation.checkpoint') != checkpoint or
                held.get('record_sha256') != digest(raw) or NEXT.exists() or NEXT.is_symlink()):
            raise ValueError('identity boundary durable record mismatch')
        if index < len(startup.CHECKPOINTS):
            observation = observer.observe(checkpoint, record, process)
            observation.update({'boundary_index': index, 'checkpoint': checkpoint,
                                'record_sha256': digest(raw), 'boundary_process': process})
            observations.append(observation)
            if index == 0 and on_target is not None:
                on_target(record['client_identity_rotation'])
        after, _ = protected_record()
        if after != raw or held_process(process['pid'], process['cgroup']) != process:
            raise ValueError('identity boundary changed during observation')
        if index + 1 < len(checkpoints):
            gate.stdin.write(b'continue\n')
            gate.stdin.flush()
    return raw, record, process, observations


def rotate(scenario, timeout):
    if scenario not in ('identity-absent', 'identity-unavailable'):
        raise ValueError('normal rotation scenario required')
    original_deadline, manifest_digest = common_preflight(scenario, timeout)
    state = state_path(scenario)
    if state.exists() or state.is_symlink():
        raise ValueError('identity observation state already exists')
    initial_raw, initial = protected_record()
    if initial.get('subscription_rotation') is not None or initial.get('client_identity_rotation') is not None:
        raise ValueError('an unfinished transition already exists')
    deadline = time.monotonic() + min(timeout, original_deadline - time.time())
    observer = startup.Observer(initial, protected_bytes, deadline)
    request_raw = protected_bytes(Path(os.environ['SBXR_QUALIFICATION_REQUEST']), 0o600)
    entry = ready = ready_raw = None
    if scenario == 'identity-unavailable':
        entry, _ = identity_entry(scenario, manifest_digest, request_raw)
        ready, ready_raw = identity_ready(scenario, manifest_digest, request_raw, entry)
    unit = 'sbxr-v4-' + scenario + '-' + str(os.getpid()) + '.service'
    gate = menu = None
    started = startup.timestamp()
    action_started = startup.timestamp()
    try:
        gate, stream, checkpoints = identity_gate(unit, timeout, startup.CHECKPOINTS[-1])
        if gate_event(stream, deadline).get('state') != 'armed':
            raise ValueError('identity syscall gate did not arm')
        menu = launch_menu(unit)
        output = LineStream(menu.stdout)
        choose(menu, output, ROTATION_SPECS[scenario]['action'], deadline)
        callback = (lambda operation: publish_identity_trigger(scenario, request_raw, ready_raw, operation)) if scenario == 'identity-unavailable' else None
        _, interrupted, process, observations = observe_identity_boundaries(
            gate, stream, checkpoints, observer, unit, deadline, callback)
        gate.stdin.write(b'release\n')
        gate.stdin.flush()
        if gate_event(stream, deadline).get('state') != 'released':
            raise ValueError('identity syscall gate did not release')
        gate.wait(timeout=max(1, deadline - time.monotonic()))
        if gate.returncode != 0:
            raise ValueError('identity gate failed after release')
        wait_code(menu, output, ROTATION_SPECS[scenario]['result'], deadline)
        menu.wait(timeout=max(1, deadline - time.monotonic()))
        final_raw, final = protected_record()
        if (menu.returncode != 0 or final.get('client_identity_rotation') is not None or
                final.get('subscription_rotation') is not None or
                final.get('configuration_sha256') != interrupted['client_identity_rotation']['target_configuration_sha256']):
            raise ValueError('identity rotation did not finish the prepared target')
        if protected_bytes(Path(os.environ['SBXR_QUALIFICATION_REQUEST']), 0o600) != request_raw:
            raise ValueError('collector request changed during identity action')
        action_completed = startup.timestamp()
        if scenario == 'identity-unavailable':
            receipt = {'schema': 'sbxr-v4-identity-transition-controller-v1', 'scenario': scenario, 'phase': 'rotated',
                           'entry_started_at': entry['entry_started_at'], 'started_at': started,
                           'action_started_at': action_started, 'action_completed_at': action_completed,
                           'completed_at': startup.timestamp(),
                           'qualification_manifest_sha256': manifest_digest,
                           'request_sha256': digest(request_raw), 'boundary_process': process,
                           'initial_record_sha256': digest(initial_raw),
                           'interrupted_record_sha256': digest(interrupted_raw), 'interrupted_at': observations[-1]['observed_at'],
                           'final_record_sha256': digest(final_raw), 'observations': observations,
                           'field': 'client_identity_rotation.checkpoint', 'checkpoint': 'source revoked', 'direction': 'forward',
                           'source_configuration_sha256': interrupted['client_identity_rotation']['source_configuration_sha256'],
                           'target_configuration_sha256': interrupted['client_identity_rotation']['target_configuration_sha256'],
                           'result_code': ROTATION_SPECS[scenario]['result']}
        else:
            receipt = {'schema': 1, 'scenario': scenario, 'phase': 'rotated', 'started_at': started,
                       'completed_at': startup.timestamp(), 'qualification_manifest_sha256': manifest_digest,
                       'request_sha256': digest(request_raw), 'boundary_process': process,
                       'initial_record_sha256': digest(initial_raw), 'final_record_sha256': digest(final_raw),
                       'observations': observations, 'result_code': ROTATION_SPECS[scenario]['result']}
        write_state(state, receipt)
        print(json.dumps({'state': 'rotated', 'scenario': scenario, 'startup_checks': len(observations)}))
    finally:
        stop_menu(menu, unit)
        stop(gate)


def interrupt(scenario, timeout):
    if scenario not in INTERRUPT_SCENARIOS:
        raise ValueError('interruption scenario required')
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
    identity = scenario.startswith('identity-')
    link_scenario = scenario.startswith('link-')
    observer = startup.Observer(initial, protected_bytes, deadline) if identity else None
    link_observer = link.Observer(initial, protected_bytes, deadline) if link_scenario else None
    observations = []
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    request_raw = protected_bytes(request_path, 0o600)
    request = json.loads(request_raw, object_pairs_hook=unique) if link_scenario else None
    started = startup.timestamp()
    action_started = startup.timestamp() if link_scenario else None
    identity_entry_value = identity_ready_raw = None
    if identity:
        identity_entry_value, _ = identity_entry(scenario, manifest_digest, request_raw)
        _, identity_ready_raw = identity_ready(scenario, manifest_digest, request_raw, identity_entry_value)
    try:
        if identity:
            gate, gate_stream, checkpoints = identity_gate(unit, timeout, spec['checkpoint'])
            armed = gate_event(gate_stream, deadline)
        elif link_scenario:
            gate, gate_stream, checkpoints = link_gate(unit, timeout, scenario)
            armed = gate_event(gate_stream, deadline)
        else:
            gate = subprocess.Popen([
            sys.executable, str(HERE / 'syscall-gate.py'), str(EXECUTABLE), cgroup,
            'before-open', str(NEXT), '--record', str(RECORD), '--field', spec['field'],
            '--value', spec['checkpoint'], '--timeout', str(timeout),
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
            armed = json_event(gate.stdout, deadline)
        if armed.get('state') != 'armed':
            raise ValueError('syscall gate did not arm')
        menu = launch_menu(unit)
        if identity:
            action_started = startup.timestamp()
        choose(menu, LineStream(menu.stdout), spec['action'], deadline)
        if identity:
            interrupted_raw, interrupted, process_evidence, observations = observe_identity_boundaries(
                gate, gate_stream, checkpoints, observer, unit, deadline,
                lambda operation: publish_identity_trigger(scenario, request_raw, identity_ready_raw, operation))
            held = {'state': 'boundary-held', 'boundary': 'before-open', 'path': str(NEXT),
                    'pid': process_evidence['pid'], 'record_sha256': digest(interrupted_raw)}
        elif not link_scenario:
            held = json_event(gate.stdout, deadline)
        else:
            held = gate_event(gate_stream, deadline)
            if (held.get('state') != 'boundary-held' or held.get('boundary_index') != 0 or
                    held.get('boundary') != 'before-open' or held.get('path') != str(NEXT)):
                raise ValueError('unexpected target-authorized syscall boundary')
            process_evidence = held_process(held.get('pid'), cgroup)
            target_raw, target_record = protected_record()
            if (dotted(target_record, spec['field']) != 'target authorized' or
                    held.get('record_sha256') != digest(target_raw) or NEXT.exists() or NEXT.is_symlink()):
                raise ValueError('target-authorized durable record mismatch')
            target, target_snapshot = link_observer.target_staged(target_record)
            target_prepared_at = startup.timestamp()
            outside_handoff = link_handoff(scenario, digest(target_raw), request, request_raw,
                                           manifest_digest, deadline)
            after_target_raw, _ = protected_record()
            if after_target_raw != target_raw or held_process(process_evidence['pid'], cgroup) != process_evidence:
                raise ValueError('target-authorized boundary changed during handoff')
            gate.stdin.write(b'continue\n')
            gate.stdin.flush()
            held = gate_event(gate_stream, deadline)
            if (held.get('state') != 'boundary-held' or held.get('boundary_index') != 1 or
                    held.get('boundary') != 'before-open' or held.get('path') != str(NEXT)):
                raise ValueError('unexpected stop-authorized syscall boundary')
            stopped_raw, stopped_record = protected_record()
            if (dotted(stopped_record, spec['field']) != 'stop authorized' or
                    stopped_record.get('subscription_rotation', {}).get('source') != link_observer.source or
                    stopped_record.get('subscription_rotation', {}).get('target') != target or
                    stopped_record.get('serving') != link_observer.source or
                    held.get('record_sha256') != digest(stopped_raw) or NEXT.exists() or NEXT.is_symlink()):
                raise ValueError('stop-authorized durable record mismatch')
            quiescent_snapshot = link_observer.quiescent()
            quiesced_at = startup.timestamp()
            outside_handoff = link_closed(scenario, outside_handoff, deadline)
            after_stop_raw, _ = protected_record()
            if (after_stop_raw != stopped_raw or
                    held_process(process_evidence['pid'], cgroup) != process_evidence):
                raise ValueError('stop-authorized boundary changed during observation')
            if scenario == 'link-precommit':
                interrupted_raw, interrupted = stopped_raw, stopped_record
            else:
                gate.stdin.write(b'continue\n')
                gate.stdin.flush()
                held = gate_event(gate_stream, deadline)
                if (held.get('state') != 'boundary-held' or held.get('boundary_index') != 2 or
                        held.get('boundary') != 'before-open' or held.get('path') != str(SERVING_TOKEN)):
                    raise ValueError('unexpected committed syscall boundary')
                interrupted_raw, interrupted = protected_record()
                validate_checkpoint(spec, interrupted)
                if (held.get('record_sha256') != digest(interrupted_raw) or
                        interrupted.get('subscription_rotation', {}).get('source') != link_observer.source or
                        interrupted.get('subscription_rotation', {}).get('target') != target or
                        NEXT.exists() or NEXT.is_symlink()):
                    raise ValueError('committed durable record mismatch')
                # Commitment still precedes target publication and activation.
                # Re-observe the same empty service boundary before interruption.
                committed_snapshot = link_observer.quiescent()
                committed_snapshot.update(link_observer.committed_unpublished(target))
                committed_snapshot['observed_at'] = startup.timestamp()
        expected_held_path = SERVING_TOKEN if scenario == 'link-postcommit' else NEXT
        if (held.get('state') != 'boundary-held' or held.get('boundary') != 'before-open' or
                held.get('path') != str(expected_held_path)):
            raise ValueError('unexpected syscall boundary')
        process_evidence = held_process(held.get('pid'), cgroup)
        if not link_scenario:
            interrupted_raw, interrupted = protected_record()
        validate_checkpoint(spec, interrupted)
        if held.get('record_sha256') != digest(interrupted_raw) or NEXT.exists() or NEXT.is_symlink():
            raise ValueError('held boundary does not match durable record')
        gate.stdin.write(b'kill\n' if identity or link_scenario else 'kill\n')
        gate.stdin.flush()
        outcome = gate_event(gate_stream, deadline) if identity or link_scenario else json_event(gate.stdout, deadline)
        if outcome.get('state') != 'interrupted':
            raise ValueError('syscall gate did not interrupt')
        gate.wait(timeout=max(1, deadline - time.monotonic()))
        if gate.returncode != 0:
            raise ValueError('syscall gate failed after interruption')
        menu.wait(timeout=max(1, deadline - time.monotonic()))
        interrupted_at = startup.timestamp()
        final_raw, final = protected_record()
        validate_checkpoint(spec, final)
        if digest(final_raw) != digest(interrupted_raw) or NEXT.exists() or NEXT.is_symlink():
            raise ValueError('interrupted durable record changed')
        if protected_bytes(request_path, 0o600) != request_raw:
            raise ValueError('collector request changed during transition action')
        saved = {
            'schema': 'sbxr-v4-link-transition-controller-v1' if link_scenario else 'sbxr-v4-identity-transition-controller-v1',
            'scenario': scenario, 'phase': 'interrupted',
            'initial_record_sha256': digest(initial_raw),
            'interrupted_record_sha256': digest(interrupted_raw),
            'field': spec['field'], 'checkpoint': spec['checkpoint'],
            'direction': spec['direction'], 'boundary_process': process_evidence,
            'qualification_manifest_sha256': manifest_digest,
            'started_at': started,
            **({'request_sha256': digest(request_raw), 'observations': observations} if identity else {}),
        }
        if identity:
            operation = interrupted['client_identity_rotation']
            saved.update({'entry_started_at': identity_entry_value['entry_started_at'],
                          'action_started_at': action_started, 'interrupted_at': interrupted_at,
                          'source_configuration_sha256': operation['source_configuration_sha256'],
                          'target_configuration_sha256': operation['target_configuration_sha256']})
        if link_scenario:
            operation = interrupted['subscription_rotation']
            interrupted_selector = 'source' if scenario == 'link-precommit' else 'target'
            saved.update({
                'request_sha256': digest(request_raw), 'source': operation['source'],
                'target': operation['target'], 'target_record_sha256': digest(target_raw),
                'action_started_at': action_started, 'interrupted_at': interrupted_at,
                'boundary_path': str(expected_held_path),
                'target_prepared_at': target_prepared_at,
                'quiesced_at': quiesced_at, 'outside_handoff': outside_handoff,
                'runtime': {'initial': {'source_process': link_observer.source_process,
                                        'proxy_process': link_observer.proxy_process,
                                        'configuration_sha256': link_observer.configuration_sha256,
                                        'staging_empty': link_observer.initial_staging_empty},
                            'target_prepared': target_snapshot,
                            'quiescent': quiescent_snapshot,
                            **({'committed': committed_snapshot} if scenario == 'link-postcommit' else {})},
                'source_target_comparison': link.comparison(
                    operation['source'], operation['target'], 'source', interrupted_selector,
                    'source' if scenario == 'link-precommit' else 'target'),
            })
        write_state(state, saved)
        print(json.dumps({'state': 'interrupted', 'scenario': scenario,
                          'record_sha256': digest(interrupted_raw),
                          'boundary_process': process_evidence}, sort_keys=True))
    finally:
        stop_menu(menu, unit)
        stop(gate)


def recover(scenario, timeout):
    if scenario not in INTERRUPT_SCENARIOS:
        raise ValueError('recovery scenario required')
    original_deadline, manifest_digest = common_preflight(scenario, timeout)
    spec = SPECS[scenario]
    state_file = state_path(scenario)
    state = read_state(state_file)
    link_scenario = scenario.startswith('link-')
    expected_schema = ('sbxr-v4-link-transition-controller-v1' if link_scenario else
                       'sbxr-v4-identity-transition-controller-v1')
    if (state.get('schema') != expected_schema or state.get('scenario') != scenario or
            state.get('phase') != 'interrupted' or state.get('field') != spec['field'] or
            state.get('checkpoint') != spec['checkpoint'] or state.get('direction') != spec['direction'] or
            state.get('qualification_manifest_sha256') != manifest_digest):
        raise ValueError('transition state does not match scenario')
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST']) if link_scenario else None
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    request_raw = protected_bytes(request_path, 0o600)
    if link_scenario and state.get('request_sha256') != digest(request_raw):
        raise ValueError('collector request drifted after interruption')
    before_raw, before = protected_record()
    validate_checkpoint(spec, before)
    if digest(before_raw) != state.get('interrupted_record_sha256'):
        raise ValueError('Ownership Record drifted after interruption')
    unit = 'sbxr-v4-recover-' + scenario + '-' + str(os.getpid()) + '.service'
    menu = None
    deadline = time.monotonic() + min(timeout, original_deadline - time.time())
    recovery_started = startup.timestamp() if link_scenario else None
    runtime_observer = None
    try:
        if not link_scenario:
            identity_closed(scenario, request_raw)
        if link_scenario:
            initial_runtime = state.get('runtime', {}).get('initial', {})
            runtime_observer = link.Observer.for_recovery(
                state.get('source'), initial_runtime.get('configuration_sha256'),
                initial_runtime.get('source_process'), initial_runtime.get('proxy_process'),
                protected_bytes, deadline)
            runtime_observer.quiescent()
            closed_raw, _ = check_outside(
                'closed', scenario, request_path, Path(os.environ['SBXR_QUALIFICATION_MANIFEST']), deadline)
            if digest(closed_raw) != state.get('outside_handoff', {}).get('closed_sha256'):
                raise ValueError('outside closure receipt drifted after interruption')
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
        if link_scenario and protected_bytes(request_path, 0o600) != request_raw:
            raise ValueError('collector request changed during transition recovery')
        completed = dict(state)
        completed.update({'phase': 'recovered', 'final_record_sha256': digest(final_raw),
                          'result_code': spec['result'],
                          })
        if link_scenario:
            completed['recovery_started_at'] = recovery_started
            selected = state['source'] if spec['direction'] == 'cleanup' else state['target']
            completed['runtime']['recovered'] = runtime_observer.final_running(selected)
            expected_selector = 'source' if spec['direction'] == 'cleanup' else 'target'
            if (completed.get('source_target_comparison', {}).get('final_serving') != expected_selector or
                    final.get('configuration_sha256') != initial_runtime.get('configuration_sha256')):
                raise ValueError('recovered link final comparison mismatch')
            completed['recovered_at'] = startup.timestamp()
        else:
            completed['action_completed_at'] = startup.timestamp()
            completed['completed_at'] = startup.timestamp()
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
    parser.add_argument('operation', choices=['interrupt', 'recover', 'rotate'])
    parser.add_argument('scenario', choices=sorted({**SPECS, **ROTATION_SPECS}))
    parser.add_argument('--timeout', type=int, default=90)
    args = parser.parse_args()
    try:
        {'interrupt': interrupt, 'recover': recover, 'rotate': rotate}[args.operation](args.scenario, args.timeout)
    except Exception as error:
        print(json.dumps({'state': 'refused', 'error_type': type(error).__name__,
                          'errno': getattr(error, 'errno', None)}, sort_keys=True))
        sys.exit(1)
