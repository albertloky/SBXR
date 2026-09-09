#!/usr/bin/env python3
"""Coordinate actual writer/admission boundaries on the official managed route.

For admission, prepare the public removal review before running this helper.
After boundary-held, use the already reviewed public removal action and collect
its refusal/resource preservation. Send release only after those observations.
A persistent egress guard remains until the official unit is stopped. No private
product CLI or replacement recorder is used. Timer restoration belongs to the
outer operator procedure after the final state is checked.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE/file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

m = load('managed_hold', 'managed-hold.py')
g = load('egress_guard', 'network-guard.py')
o = load('observations', 'observations.py')


def run(mode, interpreter, digest, timeout):
    before, route, dropin, interpreter, original_deadline = m.preflight(interpreter, digest, timeout, {'remove-writer' if mode == 'writer' else 'remove-admission-race'})
    boundary = 'before-open' if mode == 'writer' else 'after-close'
    target = '/var/lib/sbxr/.renewal-attempts.json.next' if mode == 'writer' else '/run/lock/sbxr.lock'
    guard = None
    controller = None
    started = False
    deadline = time.monotonic()+min(timeout, original_deadline-time.time())
    try:
        m.GROUP.mkdir()
        group_identity = m.GROUP.stat()
        guard = g.EgressGuard(str(m.GROUP), managed_renewal=True)
        args = [sys.executable, str(HERE/'syscall-gate.py'), str(m.EXECUTABLE), '/system.slice/'+m.UNIT,
                boundary, target, '--record', str(m.RECEIPT), '--field', 'attempts.-1.recorder_pid',
                '--value', '@root-pid', '--timeout', str(timeout)]
        if mode == 'writer':
            args += ['--no-child', '--child-executable', str(interpreter)]
        controller = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        def event():
            remaining = deadline-time.monotonic()
            if remaining <= 0 or not select.select([controller.stdout], [], [], remaining)[0]:
                raise TimeoutError('recorder boundary deadline')
            return json.loads(controller.stdout.readline(), object_pairs_hook=m.unique)
        if event().get('state') != 'armed':
            raise ValueError('recorder gate not armed')
        guard.verify()
        if m.protected_bytes(m.DROPIN, 0o644) != dropin or m.show(m.UNIT, 'ExecStart') != route:
            raise ValueError('managed route changed')
        subprocess.run(['systemctl', 'start', '--no-block', m.UNIT], check=True)
        started = True
        held = event()
        if held.get('state') != 'boundary-held' or held.get('boundary') != boundary or held.get('path') != target:
            raise ValueError('actual recorder boundary not observed')
        guard.verify()
        current = m.GROUP.stat()
        if (current.st_dev, current.st_ino) != (group_identity.st_dev, group_identity.st_ino):
            raise ValueError('guarded cgroup replaced')
        pid = int(m.show(m.UNIT, 'MainPID'))
        if held.get('pid') != pid:
            raise ValueError('boundary belongs to another process')
        _, tick = m.process(pid)
        after, receipt_digest = m.receipt()
        attempt = m.new_attempt(before, after, pid, tick, Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        writer = o.observe_flock('/var/lib/sbxr/renewal-writer.lock')
        admission = o.observe_flock('/var/lib/sbxr/renewal-admission.lock')
        whole_host = o.observe_flock('/run/lock/sbxr.lock')
        if whole_host['lock_state'] != 'unlocked':
            raise ValueError('whole-host lock is not free')
        if mode == 'writer':
            if writer['lock_state'] != 'locked' or {'mode': 'WRITE', 'pid': pid} not in writer.get('holders', []):
                raise ValueError('actual recorder does not hold writer lock')
            if not held['children'] or any(child.get('exit_code') != 0 for child in held['children']):
                raise ValueError('actual Certbot child did not complete successfully')
        elif admission['lock_state'] != 'locked' or {'mode': 'READ', 'pid': pid} not in admission.get('holders', []) or writer['lock_state'] != 'unlocked':
            raise ValueError('actual shared admission boundary not proved')
        print(json.dumps({'state': 'boundary-held', 'mode': mode, 'recorder_pid': pid, 'process_tick': tick,
                          'attempt_id': attempt['attempt_id'], 'receipt_sha256': receipt_digest,
                          'whole_host': whole_host, 'writer': writer, 'admission': admission,
                          'actual_boundary': held}), flush=True)
        remaining = deadline-time.monotonic()
        if remaining <= 0 or not select.select([sys.stdin], [], [], remaining)[0] or sys.stdin.readline() != 'release\n':
            raise ValueError('explicit release after reviewed refusal required')
        guard.verify()
        controller.stdin.write('release\n')
        controller.stdin.flush()
        if event().get('state') != 'released':
            raise ValueError('recorder release refused')
        if controller.wait(timeout=max(1, deadline-time.monotonic())) != 0:
            raise ValueError('recorder gate failed')
        while m.show(m.UNIT, 'ActiveState') in ('active', 'activating', 'deactivating'):
            if time.monotonic() >= deadline:
                raise TimeoutError('recorder completion deadline')
            time.sleep(.05)
        final, final_digest = m.receipt()
        matches = [item for item in final['attempts'] if item['attempt_id'] == attempt['attempt_id']]
        if len(matches) != 1 or matches[0].get('completion', {}).get('exit_code') != 0:
            raise ValueError('recorder did not complete successfully')
        print(json.dumps({'state': 'completed', 'receipt_sha256': final_digest, 'no_ca_egress': True}), flush=True)
    finally:
        if started:
            subprocess.run(['systemctl', 'stop', m.UNIT], check=True, timeout=40)
        if controller:
            if controller.poll() is None:
                controller.kill()
            controller.wait(timeout=5)
        if guard:
            guard.close()
        if m.GROUP.exists():
            m.GROUP.rmdir()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['writer', 'admission'])
    parser.add_argument('interpreter')
    parser.add_argument('sha256')
    parser.add_argument('--timeout', type=int, default=90)
    args = parser.parse_args()
    try:
        run(args.mode, args.interpreter, args.sha256, args.timeout)
    except Exception as error:
        print(json.dumps({'state': 'refused', 'error_type': type(error).__name__}), flush=True)
        sys.exit(1)
