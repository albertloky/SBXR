#!/usr/bin/env python3
"""Hold the official managed-renewal child before its first instruction.

Requires the scenario preflight and a stopped official timer. Creates only an
external cgroup guard, starts only the existing official unit, and never edits
product authority. stdin: 'interrupt' kills the child; 'release' permits it with
network egress still denied until the unit finishes. Neither branch can issue a
certificate. EOF/error/timeout stops the service before removing the guard.

This operator integration is not qualified by kernel fixtures alone: its receipt
and unchanged packaged route must also be rehearsed against supported setup.
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
UNIT = 'snap.certbot.renew.service'
TIMER = 'snap.certbot.renew.timer'
GROUP = Path('/sys/fs/cgroup/system.slice', UNIT)
DROPIN = Path('/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf')
RECEIPT = Path('/var/lib/sbxr/renewal-attempts.json')
EXECUTABLE = Path('/usr/local/bin/sbxr')


def unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate protected key')
        result[key] = value
    return result


def protected_bytes(path, mode):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1 or info.st_size > 1048576:
            raise ValueError('protected file metadata refused')
        body = os.read(descriptor, 1048577)
        if len(body) != info.st_size or os.fstat(descriptor) != info:
            # Stat can include atime changes after read: compare the authority
            # fields explicitly below instead of treating atime as mutation.
            after = os.fstat(descriptor)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode, after.st_uid, after.st_gid, after.st_nlink) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid, info.st_nlink) or len(body) != info.st_size:
                raise ValueError('protected file changed')
        current = os.lstat(path)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('protected file replaced')
        return body
    finally:
        os.close(descriptor)


def receipt(path=RECEIPT):
    raw = protected_bytes(path, 0o600)
    value = json.loads(raw, object_pairs_hook=unique)
    if value.get('schema') != 1 or not isinstance(value.get('attempts'), list):
        raise ValueError('receipt shape refused')
    return value, hashlib.sha256(raw).hexdigest()


def show(unit, property):
    return subprocess.check_output(['systemctl', 'show', unit, '--property='+property, '--value'], text=True).strip()


def process(pid):
    values = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
    return int(values[1]), int(values[19])


def new_attempt(before, after, recorder_pid, tick, boot):
    previous = {item['attempt_id'] for item in before['attempts']}
    added = [item for item in after['attempts'] if item['attempt_id'] not in previous]
    if len(added) != 1 or before['recorder_id'] != after['recorder_id']:
        raise ValueError('expected one real recorder attempt')
    item = added[0]
    if item.get('invocation') != 'snap-certbot-renew-v1' or item.get('recorder_pid') != recorder_pid or item.get('process_tick') != tick or item.get('boot_id') != boot or item.get('completion') is not None:
        raise ValueError('receipt does not prove live recorder')
    if not re.fullmatch('[0-9a-f]{32}', item.get('attempt_id', '')):
        raise ValueError('attempt identifier refused')
    return item


def preflight(interpreter, digest, timeout, allowed=None):
    if sys.platform != 'linux' or os.geteuid() != 0 or not 5 <= timeout <= 120 or not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('Linux root, digest and bounded timeout required')
    if os.environ.get('SBXR_OPERATOR_REHEARSAL_HOOK') or os.environ.get('SBXR_OPERATOR_REHEARSAL'):
        raise ValueError('rehearsal overrides cannot control the official route')
    request = json.loads(protected_bytes(Path(os.environ['SBXR_QUALIFICATION_REQUEST']), 0o600), object_pairs_hook=unique)
    manifest_bytes = protected_bytes(Path(os.environ['SBXR_QUALIFICATION_MANIFEST']), 0o600)
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique)
    allowed = allowed or {'managed-renewal', 'recorder-live', 'recorder-locks', 'remove-certbot'}
    scenario = request.get('scenario_id')
    if scenario not in allowed or type(request.get('deadline_unix')) is not int or request['deadline_unix']-time.time() < timeout:
        raise ValueError('wrong scenario or insufficient original deadline')
    if request.get('qualification_manifest_sha256') != hashlib.sha256(manifest_bytes).hexdigest():
        raise ValueError('collector manifest binding mismatch')
    attempt = manifest['v3_attempt']
    if attempt.get('evidence_policy') != 'repair-issuance-bounded-v4':
        raise ValueError('controller is scoped to V4 preparation')
    scenarios = attempt['required_scenarios']
    phase = 'after-snap-refresh' if scenarios.index(scenario) > scenarios.index('snap-refresh') else 'initial'
    subprocess.run(['bash', '-c', 'source "$1"; operator_expect_scenario "$2"; preflight "$3"; operator_exact_candidate',
                    'managed-preflight', str(HERE/'operator-support.sh'), scenario, phase], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(30, timeout))
    interpreter = Path(interpreter)
    if not re.fullmatch(r'/snap/certbot/[1-9][0-9]*/usr/bin/python3\.[0-9]+', str(interpreter)) or interpreter.is_symlink():
        raise ValueError('expected resolved revision-specific Certbot interpreter')
    if hashlib.sha256(interpreter.read_bytes()).hexdigest() != digest:
        raise ValueError('interpreter digest changed')
    dropin = protected_bytes(DROPIN, 0o644)
    if dropin != b'[Service]\nExecStart=\nExecStart=/usr/local/bin/sbxr --certbot-recorder\n':
        raise ValueError('official managed route changed')
    route = show(UNIT, 'ExecStart')
    if 'path=/usr/local/bin/sbxr ;' not in route or 'argv[]=/usr/local/bin/sbxr --certbot-recorder ;' not in route or route.count('path=') != 1:
        raise ValueError('effective official route refused')
    if show(UNIT, 'ActiveState') != 'inactive' or show(TIMER, 'ActiveState') != 'inactive' or GROUP.exists():
        raise ValueError('unit/timer must be stopped with no existing cgroup')
    before, _ = receipt()
    installed = json.loads(protected_bytes(Path('/var/lib/sbxr/installed.json'), 0o600), object_pairs_hook=unique)
    executable_digest = hashlib.sha256(EXECUTABLE.read_bytes()).hexdigest()
    if installed.get('executable_sha256') != executable_digest:
        raise ValueError('installed candidate digest mismatch')
    return before, route, dropin, interpreter, request['deadline_unix']


def run(interpreter, digest, timeout):
    before, route, dropin, interpreter, original_deadline = preflight(interpreter, digest, timeout)
    spec = importlib.util.spec_from_file_location('egress_guard', HERE/'network-guard.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    guard = None
    controller = None
    GROUP.mkdir()
    group_identity = GROUP.stat()
    started = False
    try:
        guard = module.EgressGuard(str(GROUP), managed_renewal=True)
        controller = subprocess.Popen([sys.executable, str(HERE/'exec-gate.py'), str(interpreter), '/system.slice/'+UNIT, '--timeout', str(timeout)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        deadline = time.monotonic()+min(timeout, original_deadline-time.time())
        def event():
            remaining = deadline-time.monotonic()
            if remaining <= 0 or not select.select([controller.stdout], [], [], remaining)[0]:
                raise TimeoutError('hold event deadline')
            return json.loads(controller.stdout.readline(), object_pairs_hook=unique)
        if event().get('state') != 'armed':
            raise ValueError('gate not armed')
        guard.verify()
        if protected_bytes(DROPIN, 0o644) != dropin or show(UNIT, 'ExecStart') != route:
            raise ValueError('route changed before launch')
        subprocess.run(['systemctl', 'start', '--no-block', UNIT], check=True)
        started = True
        held = event()
        if held.get('state') != 'held' or held.get('boundary') != 'actual-image-exec-trap-before-target-code':
            raise ValueError('actual child boundary not observed')
        guard.verify()
        current = GROUP.stat()
        if (current.st_dev, current.st_ino) != (group_identity.st_dev, group_identity.st_ino):
            raise ValueError('guarded cgroup replaced')
        pid = held['pid']
        args = Path('/proc/%d/cmdline' % pid).read_bytes().rstrip(b'\0').split(b'\0')
        revision = interpreter.parts[3]
        if len(args) != 5 or args[1:] != [b'-s', ('/snap/certbot/'+revision+'/bin/certbot').encode(), b'-q', b'renew']:
            raise ValueError('actual Certbot invocation mismatch')
        main = int(show(UNIT, 'MainPID'))
        actual_recorder, expected_recorder = os.stat('/proc/%d/exe' % main), EXECUTABLE.stat()
        if (actual_recorder.st_dev, actual_recorder.st_ino) != (expected_recorder.st_dev, expected_recorder.st_ino):
            raise ValueError('actual recorder executable mismatch')
        ancestors = set()
        parent = pid
        while parent > 1 and parent not in ancestors and len(ancestors) < 32:
            ancestors.add(parent)
            parent, _ = process(parent)
        if main not in ancestors:
            raise ValueError('child is not a recorder descendant')
        _, tick = process(main)
        after, receipt_digest = receipt()
        attempt = new_attempt(before, after, main, tick, Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        environment = Path('/proc/%d/environ' % pid).read_bytes().split(b'\0')
        if ('SBXR_RENEWAL_ATTEMPT_ID='+attempt['attempt_id']).encode() not in environment:
            raise ValueError('child receipt binding mismatch')
        print(json.dumps({'state': 'held', 'child': held, 'recorder_pid': main, 'recorder_tick': tick,
                          'attempt_id': attempt['attempt_id'], 'receipt_sha256': receipt_digest,
                          'egress_denied': True}), flush=True)
        remaining = deadline-time.monotonic()
        if remaining <= 0 or not select.select([sys.stdin], [], [], remaining)[0]:
            raise TimeoutError('operator hold deadline')
        command = sys.stdin.readline()
        if command not in ('interrupt\n', 'release\n'):
            raise ValueError('explicit interrupt or release required')
        guard.verify()
        controller.stdin.write('deny\n' if command == 'interrupt\n' else 'release\n')
        controller.stdin.flush()
        outcome = event()
        if outcome.get('state') != ('denied' if command == 'interrupt\n' else 'released'):
            raise ValueError('child decision refused')
        if controller.wait(timeout=max(1, deadline-time.monotonic())) != 0:
            raise ValueError('exec controller failed')
        while show(UNIT, 'ActiveState') in ('active', 'activating', 'deactivating'):
            guard.verify()
            if time.monotonic() >= deadline:
                raise TimeoutError('managed completion deadline')
            time.sleep(.05)
        final, final_digest = receipt()
        matches = [item for item in final['attempts'] if item['attempt_id'] == attempt['attempt_id']]
        if len(matches) != 1:
            raise ValueError('final receipt lost')
        completion = matches[0].get('completion')
        if command == 'release\n' and (not completion or completion.get('exit_code') != 0):
            raise ValueError('guarded child did not complete successfully')
        if command == 'interrupt\n' and completion and completion.get('exit_code') == 0:
            raise ValueError('interruption incorrectly recorded success')
        print(json.dumps({'state': 'interrupted' if command == 'interrupt\n' else 'completed',
                          'receipt_sha256': final_digest, 'no_ca_egress': True}), flush=True)
    finally:
        # Stop the unit while egress remains denied; never drop the guard first.
        if started:
            subprocess.run(['systemctl', 'stop', UNIT], check=True, timeout=40)
        if controller:
            if controller.poll() is None:
                controller.kill()
            controller.wait(timeout=5)
        if guard:
            guard.close()
        if GROUP.exists():
            GROUP.rmdir()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('interpreter')
    parser.add_argument('sha256')
    parser.add_argument('--timeout', type=int, default=90)
    args = parser.parse_args()
    try:
        run(args.interpreter, args.sha256, args.timeout)
    except Exception as error:
        print(json.dumps({'state': 'refused', 'error_type': type(error).__name__}), flush=True)
        sys.exit(1)
