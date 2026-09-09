#!/usr/bin/env python3
"""Exercise the controller's real coordination/cleanup with an isolated OS model.

Kernel exec/BPF/systemd mechanics are tested separately on Linux. These tests
cover the ordering and refusal paths joining those mechanics to actual-shaped
recorder receipts; they are never acceptance evidence.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('managed', Path(__file__).with_name('managed-hold.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Coordinator(unittest.TestCase):
    def exercise(self, decision='interrupt', fault=None):
        order = []
        attempt = {'attempt_id': 'a'*32, 'invocation': 'snap-certbot-renew-v1', 'recorder_pid': 21, 'process_tick': 123, 'boot_id': 'boot'}
        before = {'recorder_id': 'r', 'attempts': []}
        after = {'recorder_id': 'r', 'attempts': [dict(attempt)]}
        final = {'recorder_id': 'r', 'attempts': [dict(attempt, completion={'exit_code': 0 if decision == 'release' else 125})]}
        if fault == 'wrong-tick':
            after['attempts'][0]['process_tick'] += 1
        if fault == 'false-success':
            final['attempts'][0]['completion']['exit_code'] = 0
        replies = iter([after, final])
        states = iter(['armed', 'held', 'released' if decision == 'release' else 'denied'])
        class Reader:
            def readline(self):
                state = next(states)
                return json.dumps({'state': state, 'pid': 42, 'boundary': 'actual-image-exec-trap-before-target-code'})+'\n'
        class Writer:
            def write(self, value):
                order.append('child:'+value.strip())
            def flush(self):
                pass
        class Controller:
            stdout, stdin = Reader(), Writer()
            def wait(self, **kwargs):
                order.append('controller-wait')
                return 1 if fault == 'controller-failure' else 0
            def poll(self):
                return 0
        class Guard:
            def __init__(self, *args, **kwargs):
                order.append('guard-attach')
            def verify(self):
                order.append('guard-verify')
                if fault == 'guard-failure':
                    raise ValueError('fixture guard refused')
            def close(self):
                order.append('guard-detach')
        fake_spec = types.SimpleNamespace(loader=types.SimpleNamespace(exec_module=lambda module: setattr(module, 'EgressGuard', Guard)))
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            group = Path(directory, 'group')
            executable = Path(directory, 'sbxr')
            executable.write_bytes(b'fixture')
            actual_stat = os.stat
            actual_readbytes = Path.read_bytes
            actual_readtext = Path.read_text
            def stat(path, *args, **kwargs):
                return actual_stat(executable if str(path) == '/proc/21/exe' else path, *args, **kwargs)
            def readbytes(path):
                if str(path) == '/proc/42/cmdline':
                    return b'python\0-s\0/snap/certbot/5893/bin/certbot\0-q\0renew\0' if fault != 'wrong-child' else b'python\0other\0'
                if str(path) == '/proc/42/environ':
                    return ('SBXR_RENEWAL_ATTEMPT_ID='+attempt['attempt_id']).encode()+b'\0'
                return actual_readbytes(path)
            def readtext(path, *args, **kwargs):
                if str(path) == '/proc/sys/kernel/random/boot_id':
                    return 'boot\n'
                return actual_readtext(path, *args, **kwargs)
            def show(unit, key):
                return {'ExecStart': 'route', 'MainPID': '21', 'ActiveState': 'inactive'}[key]
            def run(command, **kwargs):
                operation = command[1]
                order.append('unit:'+operation)
                if operation == 'stop' and fault == 'stop-failure':
                    raise RuntimeError('fixture stop refused')
            for target, name, value in [
                (m, 'GROUP', group), (m, 'EXECUTABLE', executable),
                (m, 'preflight', lambda *a: (before, 'route', b'dropin', Path('/snap/certbot/5893/usr/bin/python3.12'), time.time()+1800)),
                (m, 'protected_bytes', lambda *a: b'dropin'), (m, 'show', show),
                (m, 'process', lambda pid: (21, 456) if pid == 42 else (1, 123)),
                (m, 'receipt', lambda: (next(replies), 'b'*64)),
                (m.os, 'stat', stat), (Path, 'read_bytes', readbytes), (Path, 'read_text', readtext),
                (m.subprocess, 'Popen', lambda *a, **kw: Controller()), (m.subprocess, 'run', run),
                (m.select, 'select', lambda readers, *a: (readers, [], [])),
                (m.importlib.util, 'spec_from_file_location', lambda *a: fake_spec),
                (m.importlib.util, 'module_from_spec', lambda *a: types.SimpleNamespace()),
                (m.sys, 'stdin', io.StringIO('' if fault == 'eof' else decision+'\n')),
            ]:
                stack.enter_context(patch.object(target, name, value))
            output = io.StringIO()
            error = None
            with contextlib.redirect_stdout(output):
                try:
                    m.run('unused', 'c'*64, 90)
                except Exception as caught:
                    error = caught
            events = [json.loads(line) for line in output.getvalue().splitlines()]
            if group.exists():
                group.rmdir()  # failed-stop fixture keeps the guard intentionally
            return order, events, error

    def test_interrupt_stops_before_unprotecting(self):
        order, events, error = self.exercise()
        self.assertIsNone(error)
        self.assertEqual([event['state'] for event in events], ['held', 'interrupted'])
        self.assertLess(order.index('guard-attach'), order.index('unit:start'))
        self.assertLess(order.index('unit:stop'), order.index('guard-detach'))
        self.assertIn('child:deny', order)

    def test_release_keeps_guard_until_success(self):
        order, events, error = self.exercise('release')
        self.assertIsNone(error)
        self.assertEqual(events[-1]['state'], 'completed')
        self.assertLess(order.index('child:release'), order.index('unit:stop'))
        self.assertLess(order.index('unit:stop'), order.index('guard-detach'))

    def test_refusals_never_release_child(self):
        for fault in ['wrong-tick', 'wrong-child', 'eof', 'guard-failure']:
            with self.subTest(fault=fault):
                order, events, error = self.exercise(fault=fault)
                self.assertIsNotNone(error)
                self.assertNotIn('child:release', order)
                self.assertNotIn('child:deny', order)
                if fault == 'guard-failure':
                    self.assertNotIn('unit:start', order)
                else:
                    self.assertLess(order.index('unit:stop'), order.index('guard-detach'))

    def test_false_success_is_not_interruption(self):
        _, events, error = self.exercise(fault='false-success')
        self.assertIsNotNone(error)
        self.assertNotIn('interrupted', [event['state'] for event in events])

    def test_controller_failure_is_not_success(self):
        order, events, error = self.exercise('release', 'controller-failure')
        self.assertIsNotNone(error)
        self.assertNotIn('completed', [event['state'] for event in events])
        self.assertLess(order.index('unit:stop'), order.index('guard-detach'))

    def test_stop_failure_retains_network_guard(self):
        order, _, error = self.exercise(fault='stop-failure')
        self.assertIsNotNone(error)
        self.assertNotIn('guard-detach', order)


if __name__ == '__main__':
    unittest.main()
