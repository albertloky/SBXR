#!/usr/bin/env python3
"""Retain actual helper stdout events with their current request and clock.

This preserves the helper's stdin/stdout control protocol. It neither interprets
its events as passes nor authorizes a product action. Scenario adapters validate
the retained records separately.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('capture_scenario_entry', HERE / 'scenario-entry.py')
entry = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = entry
spec.loader.exec_module(entry)
api = entry.api
HELPERS = {
    'managed-hold': 'managed-hold.py', 'recorder-boundary': 'recorder-boundary.py',
    'route-control': 'route-control.py', 'firewall-control': 'firewall-control.py',
    'hold-flock': 'hold-flock.py', 'directory-locks': 'directory-locks.py',
    'admission-race-operator': 'admission-race-operator.py',
    '19-lifecycle-menu.sh': '19-lifecycle-menu.sh', '24-secret-containment.sh': '24-secret-containment.sh',
    'removal-refusal': 'removal-refusal.py', 'karing-evidence': 'karing-evidence.py',
    'identity-private-observation': 'identity-private-observation.py',
    'identity-runtime-observation': 'identity-runtime-observation.py',
    'identity-unavailable-subscription': 'identity-unavailable-subscription.py',
    'identity-unavailable-repair': 'identity-unavailable-repair.py',
    'managed-evidence': 'managed-evidence.py', 'renewal-outside': 'renewal-outside.py',
    'connection-probe': 'connection-probe.py', 'observations': 'observations.py', 'syscall-gate': 'syscall-gate.py',
}


def event(line, at):
    if not line.endswith(b'\n'):
        raise api.Refusal('helper output: unterminated event')
    text = line[:-1].decode('utf-8')
    if text.lstrip().startswith('{'):
        record = json.loads(text, object_pairs_hook=api.unique)
        if not isinstance(record, dict):
            raise api.Refusal('helper output: object required')
    else:
        record = {'text': text}
    return {'observed_at': at, 'record': record}


def capture(command, helper, bound, request_path, request_raw, forward, stdin=None):
    started = entry.timestamp()
    if time.time() >= bound['deadline_unix']:
        raise api.Refusal('capture cannot start after original deadline')
    child = subprocess.Popen(command, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    events, pending, stderr, received = [], bytearray(), bytearray(), 0
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, 'stdout')
    selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
    try:
        while selector.get_map():
            remaining = bound['deadline_unix'] - time.time()
            if remaining <= 0:
                raise api.Refusal('helper exceeded original scenario deadline')
            if api.private_bytes(request_path, 'current request') != request_raw:
                raise api.Refusal('collector request changed during helper')
            for ready, _ in selector.select(min(.2, remaining)):
                block = os.read(ready.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(ready.fileobj)
                    continue
                received += len(block)
                if received > api.JSON_LIMIT // 2:
                    raise api.Refusal('helper output exceeded capture bound')
                if ready.data == 'stderr':
                    stderr.extend(block)
                    continue
                pending.extend(block)
                while b'\n' in pending:
                    line, _, rest = pending.partition(b'\n')
                    pending = bytearray(rest)
                    raw = bytes(line) + b'\n'
                    events.append(event(raw, entry.timestamp()))
                    if len(events) > 10000:
                        raise api.Refusal('helper event count exceeded capture bound')
                    forward(raw)
        code = child.wait(timeout=max(.01, bound['deadline_unix'] - time.time()))
        completed = entry.timestamp()
        if pending or not events or (code == 0 and stderr):
            raise api.Refusal('helper produced incomplete output or diagnostics')
        if time.time() > bound['deadline_unix'] or api.private_bytes(request_path, 'current request') != request_raw:
            raise api.Refusal('helper completed outside original request')
        return {'schema': 'sbxr-v4-captured-source-v1', 'scenario_id': bound['scenario_id'],
                'qualification_manifest_sha256': bound['qualification_manifest_sha256'],
                'request_sha256': api.digest(request_raw), 'helper': helper, 'started_at': started,
                'completed_at': completed, 'exit_code': code, 'events': events}
    finally:
        selector.close()
        if child.poll() is None:
            child.send_signal(signal.SIGINT)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', choices=HELPERS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise api.Refusal('Linux root required')
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    request = api.load(request_path, 'request', True)[0]
    _, _, request, request_raw, _, _ = entry.read_authority(request['scenario_id'])
    if request['scenario_id'] not in api.later.SCENARIOS:
        raise api.Refusal('unsupported captured scenario')
    path = HERE / HELPERS[args.helper]
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o022:
        raise api.Refusal('bundled helper unavailable')
    arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
    command = (['/bin/bash', '--noprofile', '--norc', str(path)] if path.suffix == '.sh' else [sys.executable, str(path)]) + arguments
    # Check the destination before starting the helper; never rerun an action to
    # replace a previously retained result.
    parent = args.output.parent.lstat()
    if not args.output.is_absolute() or args.output.exists() or args.output.is_symlink() or args.output.parent.is_symlink() or parent.st_mode & 0o777 != 0o700 or parent.st_uid != os.geteuid():
        raise api.Refusal('new private capture destination required')
    def forward(raw):
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
    value = capture(command, args.helper, request, request_path, request_raw, forward, sys.stdin.buffer)
    raw = api.canonical(value)
    if len(raw) > api.JSON_LIMIT:
        raise api.Refusal('retained source exceeded capture bound')
    api.identity.atomic_write_new(args.output, raw)
    return 0 if value['exit_code'] == 0 else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('{"source_capture_refused":true}', file=sys.stderr)
        sys.exit(1)
