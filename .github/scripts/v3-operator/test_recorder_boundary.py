#!/usr/bin/env python3
"""Coordinator refusal/cleanup checks; kernel fixtures are separate evidence."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('boundary', Path(__file__).with_name('recorder-boundary.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

class Boundary(unittest.TestCase):
    def exercise(self, mode='writer', fault=None):
        order = []
        boundary = 'before-open' if mode == 'writer' else 'after-close'
        target = '/var/lib/sbxr/.renewal-attempts.json.next' if mode == 'writer' else '/run/lock/sbxr.lock'
        held = dict(state='boundary-held', boundary=boundary, path=target, pid=21,
                    children=[{'exit_code': 0}])
        if fault == 'wrong-pid': held['pid'] = 22
        if fault == 'child-failure': held['children'][0]['exit_code'] = 1
        events = iter([{'state':'armed'}, held, {'state':'released'}])
        class Reader:
            def readline(self): return json.dumps(next(events))+'\n'
        class Writer:
            def write(self, value): order.append(value.strip())
            def flush(self): pass
        class Controller:
            stdout, stdin = Reader(), Writer()
            def poll(self): return 0
            def wait(self, **kwargs): return 1 if fault == 'controller-failure' else 0
        class Guard:
            def __init__(self, *a, **kw): order.append('guard')
            def verify(self):
                if fault == 'guard-failure': raise ValueError('guard')
            def close(self): order.append('unguard')
        def run(args, **kw):
            order.append(args[1])
            if args[1] == 'stop' and fault == 'stop-failure': raise ValueError('stop')
        def lock(path):
            active = ('writer' in path and mode == 'writer') or ('admission' in path and mode == 'admission')
            if fault == 'wrong-lock': active = False
            return {'lock_state':'locked' if active else 'unlocked',
                    'holders':[{'mode':'WRITE' if mode == 'writer' else 'READ', 'pid':21}] if active else []}
        receipts = iter([({'attempts':[]}, 'a'*64),
                         ({'attempts':[{'attempt_id':'attempt', 'completion':{'exit_code':1 if fault == 'completion-failure' else 0}}]}, 'b'*64)])
        with tempfile.TemporaryDirectory() as root, contextlib.ExitStack() as stack:
            values = [(b.m,'GROUP',Path(root,'group')), (b.m,'preflight',lambda *a: ({},'route',b'dropin',Path('/fixture'),time.time()+90)),
                      (b.g,'EgressGuard',Guard), (b.subprocess,'Popen',lambda *a,**kw:Controller()),
                      (b.subprocess,'run',run), (b.select,'select',lambda readers,*a:(readers,[],[])),
                      (b.m,'protected_bytes',lambda *a:b'dropin'),
                      (b.m,'show',lambda unit,key:{'ExecStart':'route','MainPID':'21','ActiveState':'inactive'}[key]),
                      (b.m,'process',lambda pid:(1,123)), (b.m,'receipt',lambda:next(receipts)),
                      (b.m,'new_attempt',lambda *a:{'attempt_id':'attempt'}), (b.o,'observe_flock',lock),
                      (b.sys,'stdin',io.StringIO('' if fault == 'eof' else 'release\n'))]
            original = Path.read_text
            def read(path,*a,**kw):
                return 'boot' if str(path) == '/proc/sys/kernel/random/boot_id' else original(path,*a,**kw)
            values.append((Path,'read_text',read))
            for obj,key,value in values: stack.enter_context(patch.object(obj,key,value))
            output,error = io.StringIO(),None
            with contextlib.redirect_stdout(output):
                try: b.run(mode,'/fixture','c'*64,90)
                except Exception as caught: error=caught
            return order,[json.loads(line) for line in output.getvalue().splitlines()],error

    def test_success_both_boundaries(self):
        for mode in ['writer','admission']:
            with self.subTest(mode=mode):
                order,events,error=self.exercise(mode)
                self.assertIsNone(error)
                self.assertEqual([e['state'] for e in events],['boundary-held','completed'])
                self.assertLess(order.index('guard'),order.index('start'))
                self.assertLess(order.index('release'),order.index('stop'))
                self.assertLess(order.index('stop'),order.index('unguard'))

    def test_refusal_never_releases_recorder(self):
        for fault in ['wrong-pid','child-failure','wrong-lock','guard-failure','eof']:
            with self.subTest(fault=fault):
                order,events,error=self.exercise(fault=fault)
                self.assertIsNotNone(error)
                self.assertNotIn('release',order)
                self.assertNotIn('completed',[e['state'] for e in events])

    def test_failed_completion_is_not_success(self):
        for fault in ['controller-failure','completion-failure']:
            with self.subTest(fault=fault):
                _,events,error=self.exercise(fault=fault)
                self.assertIsNotNone(error)
                self.assertNotIn('completed',[e['state'] for e in events])

    def test_failed_stop_keeps_guard(self):
        order,_,error=self.exercise(fault='stop-failure')
        self.assertIsNotNone(error)
        self.assertNotIn('unguard',order)

if __name__ == '__main__': unittest.main()
