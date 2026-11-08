"""Offline containment contracts; fixtures never access SSH/systemd/Karing."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('containment', HERE / 'mvp-retained-containment.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SHA = 'a' * 64
UNITS = ('sbxr-subscription.service', 'sing-box.service')


class Clock:
    def __init__(self): self.wall = 1000.; self.mono = 10.
    def __call__(self): return self.wall, self.mono
    def advance(self, n): self.wall += n; self.mono += n


class Fixture:
    """An explicit injected host/client boundary, never a native observer."""
    def __init__(self, root, clock):
        self.root, self.clock = root, clock
        self.calls = []
        self.mutate = {}
        self.children = []
        self.files = {'config': b'private test config', 'failure': b'original failed action'}
        for name, raw in self.files.items(): (root / name).write_bytes(raw)
        self.digests = self.snapshot()
        self.scope = {
            'binding': {'run_id': 215001, 'source': '78e26e7ae5c4d23335ffecf79f02a1da5c0453a8', 'manifest_sha256': SHA,
                        'request_sha256': SHA, 'failure_sha256': self.digests['failure'],
                        'host': '107.175.53.219', 'tag': 'v3.1.141', 'sequence': 215},
            'original_cutoff': 5000., 'signed_finish': 5000., 'runtime_finish': 5000.,
            'final_cutoff': 6800., 'http_state_possible': True,
            'confirmation': {'status': 'missing', 'notified_at': 900., 'response_cap': 60},
            'expected_units': {u: {'fragment_sha256': SHA, 'dropins': {}} for u in UNITS},
            'retained_files': self.digests, 'outside_client_ids': ['outside-1'],
            'candidate_profile': 'SBXR-q215-v141',
        }

    def snapshot(self):
        return {n: hashlib.sha256((self.root / n).read_bytes()).hexdigest() for n in self.files}

    def run(self, action, deadline, commands=()):
        self.calls.append((action, deadline, commands))
        self.clock.advance(1)
        base = {'binding': self.scope['binding'], 'observed_at': self.clock.wall,
                'current_cutoff': self.scope['original_cutoff'], 'outcome': 'complete'}
        owned = {u: {'fragment_sha256': SHA, 'dropins': {}, 'exec_stop': [],
                     'exec_stop_post': [], 'kill_mode': 'control-group',
                     'timeout_stop_seconds': 90} for u in UNITS}
        facts = {
            'clock': {'clock_consistent': True},
            'ownership': {'owned_units': owned, 'absent_units': [], 'prior_uncertain': False,
                          'foreign_processes': [], 'retained_files': self.snapshot()},
            'stop-services': {'stopped_units': list(UNITS)},
            'verify-host': {'inactive_disabled_units': list(UNITS), 'absent_units': [],
                            'candidate_pids': [], 'open_test_ports': [], 'ssh_preserved': True,
                            'unrelated_state_preserved': True, 'retained_files': self.snapshot()},
            'stop-outside': {'stopped_client_ids': ['outside-1'], 'public_ports_closed': [443, 8443]},
            'restore-client': {'original_restored': True, 'candidate_selected': False,
                               'test_data_deleted': False},
            'verify-retained': {'retained_files': self.snapshot(), 'original_client_preserved': True,
                                'candidate_selected': False, 'test_data_deleted': False},
            'record-failure': {'failure_sha256': self.scope['binding']['failure_sha256'],
                               'failure_recorded': True, 'qualification_passed': False},
            'verify-transport': {'gateway_stopped': True, 'test_ca_absent': True,
                                 'test_hosts_entry_absent': True, 'test_redirect_absent': True,
                                 'ssh_preserved': True, 'unrelated_state_preserved': True},
        }[action]
        if action == 'stop-services' and self.children:
            # Actual bounded subprocess, fixed test-owned waitable children only.
            for child in self.children:
                subprocess.run([sys.executable, '-c', 'import os,signal,sys; os.kill(int(sys.argv[1]),signal.SIGTERM)', str(child.pid)], check=True, timeout=2)
                child.wait(timeout=2)
        out = {**base, **facts}
        change = self.mutate.get(action)
        if callable(change): change(out)
        elif change: out.update(change)
        return out


class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='retained-containment-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.clock = Clock()
        self.backend = Fixture(self.root, self.clock)
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir(mode=0o700)

    def run_case(self):
        return m.contain(self.backend.scope, self.backend, self.evidence, clocks=self.clock)

    def test_missing_reply_contains_but_never_claims_cleanup_or_pass(self):
        before = self.backend.snapshot()
        result = self.run_case()
        self.assertTrue(result['product_contained'])
        self.assertFalse(result['cleanup_complete'])
        self.assertFalse(result['qualification_passed'])
        self.assertEqual(result['transport_status'], 'pending')
        self.assertEqual(self.backend.snapshot(), before)
        self.assertEqual([x[0] for x in self.backend.calls], list(m.HTTP_PHASES))
        commands = next(x[2] for x in self.backend.calls if x[0] == 'stop-services')
        self.assertEqual(commands, tuple(('/usr/bin/systemctl', 'disable', '--now', u) for u in UNITS))
        self.assertTrue(all('remove' not in ' '.join(c) for c in commands))

    def test_partial_install_absence_skips_only_proved_absent_unit(self):
        self.backend.mutate['ownership'] = lambda x: (x['owned_units'].pop(UNITS[0]), x['absent_units'].append(UNITS[0]))
        self.backend.mutate['stop-services'] = {'stopped_units': [UNITS[1]]}
        self.backend.mutate['verify-host'] = {'inactive_disabled_units': [UNITS[1]], 'absent_units': [UNITS[0]]}
        self.assertTrue(self.run_case()['product_contained'])
        commands = next(x[2] for x in self.backend.calls if x[0] == 'stop-services')
        self.assertEqual(len(commands), 1)

    def test_installed_only_no_service_still_verifies_all_rows(self):
        self.backend.mutate['ownership'] = {'owned_units': {}, 'absent_units': list(UNITS)}
        self.backend.mutate['stop-services'] = {'stopped_units': []}
        self.backend.mutate['verify-host'] = {'inactive_disabled_units': [], 'absent_units': list(UNITS)}
        self.assertTrue(self.run_case()['product_contained'])

    def test_m1_omits_native_effect_only_when_http_certainly_absent(self):
        self.backend.scope['http_state_possible'] = False
        self.assertTrue(self.run_case()['product_contained'])
        self.assertNotIn('restore-client', [x[0] for x in self.backend.calls])

    def test_declined_confirmation_also_never_deletes(self):
        self.backend.scope['confirmation']['status'] = 'declined'
        self.assertTrue(self.run_case()['product_contained'])

    def test_early_or_granted_or_unknown_reply_refuses(self):
        for status in ('granted', 'unknown', 'pending'):
            with self.subTest(status=status):
                scope = copy.deepcopy(self.backend.scope); scope['confirmation']['status'] = status
                with self.assertRaises(m.Refusal): m.contain(scope, self.backend, self.evidence, clocks=self.clock)
        self.backend.scope['confirmation']['notified_at'] = 999
        with self.assertRaises(m.Refusal): self.run_case()
        self.assertEqual(self.backend.calls, [])

    def test_equal_budget_boundary_refuses_before_effects(self):
        self.backend.scope['original_cutoff'] = self.clock.wall + 1200
        with self.assertRaises(m.Refusal): self.run_case()
        self.assertEqual(self.backend.calls, [])

    def test_nonfinite_and_boolean_cutoffs_refuse(self):
        for value in (float('inf'), float('nan'), True):
            scope=copy.deepcopy(self.backend.scope); scope['original_cutoff']=value
            with self.assertRaises(m.Refusal): m.contain(scope,self.backend,self.evidence,clocks=self.clock)
        self.assertEqual(self.backend.calls, [])

    def test_identity_changed_refuses_before_stop(self):
        self.backend.mutate['ownership'] = {'binding': {**self.backend.scope['binding'], 'run_id': 7}}
        result=self.run_case(); self.assertFalse(result['product_contained'])
        self.assertNotIn('stop-services',[x[0] for x in self.backend.calls])

    def test_foreign_fragment_hooks_dropins_process_or_uncertainty_refuse(self):
        for change in ('fragment','hook','dropin','process','uncertain','missing'):
            with self.subTest(change=change), tempfile.TemporaryDirectory(dir=self.root) as d:
                backend=Fixture(Path(d),self.clock)
                def mutate(x):
                    if change=='fragment': x['owned_units'][UNITS[0]]['fragment_sha256']='b'*64
                    if change=='hook': x['owned_units'][UNITS[0]]['exec_stop_post']=['rm important']
                    if change=='dropin': x['owned_units'][UNITS[0]]['dropins']={'foreign':'b'*64}
                    if change=='process': x['foreign_processes']=[9]
                    if change=='uncertain': x['prior_uncertain']=True
                    if change=='missing': x['owned_units'].pop(UNITS[0])
                backend.mutate['ownership']=mutate
                out=Path(d)/'evidence';out.mkdir(mode=0o700)
                result=m.contain(backend.scope,backend,out,clocks=self.clock)
                self.assertFalse(result['product_contained'])
                self.assertNotIn('stop-services',[x[0] for x in backend.calls])

    def test_stop_timeout_is_uncertain_and_not_retried(self):
        self.backend.mutate['stop-services']={'outcome':'timeout'}
        result=self.run_case()
        self.assertEqual(result['status'],'uncertain')
        self.assertFalse(result['product_contained'])
        self.assertEqual([x[0] for x in self.backend.calls].count('stop-services'),1)
        with self.assertRaises(m.Refusal): self.run_case()

    def test_silent_success_with_remaining_listener_refuses(self):
        self.backend.mutate['verify-host']={'open_test_ports':[443]}
        self.assertFalse(self.run_case()['product_contained'])

    def test_ssh_or_unrelated_changes_refuse_success(self):
        self.backend.mutate['verify-host']={'ssh_preserved':False}
        self.assertFalse(self.run_case()['product_contained'])

    def test_removed_or_changed_secret_is_not_retention(self):
        self.backend.mutate['verify-retained']={'retained_files':{}}
        result = self.run_case()
        self.assertFalse(result['product_contained'])
        self.assertFalse(result['retained_data_verified'])

    def test_native_restore_failure_is_incomplete(self):
        self.backend.mutate['restore-client']={'candidate_selected':True}
        self.assertFalse(self.run_case()['product_contained'])

    def test_failure_record_cannot_be_relabelled(self):
        self.backend.mutate['record-failure']={'qualification_passed':True}
        self.assertFalse(self.run_case()['product_contained'])

    def test_clock_rollback_and_overrun_are_uncertain(self):
        def overrun(x): self.clock.advance(401)
        self.backend.mutate['stop-services']=overrun
        self.assertEqual(self.run_case()['status'],'uncertain')

    def test_cutoff_tightens_without_extension(self):
        self.backend.mutate['clock']={'current_cutoff':2100.}
        self.assertFalse(self.run_case()['product_contained'])
        self.assertNotIn('ownership',[x[0] for x in self.backend.calls])

    def test_receipts_exclusive_and_original_failure_preserved(self):
        before=(self.root/'failure').read_bytes(); self.run_case()
        with self.assertRaises(m.Refusal): self.run_case()
        self.assertEqual((self.root/'failure').read_bytes(),before)
        self.assertTrue(all((p.stat().st_mode & 0o777)==0o600 for p in self.evidence.iterdir()))

    def test_symlinked_evidence_directory_refuses_before_any_action(self):
        linked = self.root / 'linked-evidence'
        linked.symlink_to(self.evidence, target_is_directory=True)
        with self.assertRaises((m.Refusal, OSError)):
            m.contain(self.backend.scope, self.backend, linked, clocks=self.clock)
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_real_owned_processes_stop_and_data_survives(self):
        try:
            for _ in UNITS:
                child=subprocess.Popen([sys.executable,'-c','import signal,time; signal.alarm(15); time.sleep(30)'])
                self.backend.children.append(child)
            self.assertTrue(self.run_case()['product_contained'])
            self.assertTrue(all(p.poll() is not None for p in self.backend.children))
            self.assertEqual(self.backend.snapshot(),self.backend.digests)
        finally:
            for child in self.backend.children:
                if child.poll() is None: child.kill()
                child.wait(timeout=3)

    def test_transport_verified_separately_and_no_deletion_is_executed(self):
        result=self.run_case()
        complete=m.verify_transport(self.backend.scope,result,self.backend,self.evidence,clocks=self.clock)
        self.assertEqual(complete['transport_status'],'restored')
        self.assertFalse(complete['cleanup_complete'])
        self.assertFalse(complete['qualification_passed'])
        self.assertEqual(self.backend.calls[-1][0],'verify-transport')
        self.assertEqual(self.backend.calls[-1][2],())

    def test_unrestored_transport_does_not_claim_safety(self):
        result=self.run_case(); self.backend.mutate['verify-transport']={'test_redirect_absent':False}
        self.assertEqual(m.verify_transport(self.backend.scope,result,self.backend,self.evidence,clocks=self.clock)['transport_status'],'unproved')

    def test_wall_clock_rollback_preserves_uncertain_observation(self):
        def rollback(x): self.clock.wall -= 2
        self.backend.mutate['stop-services'] = rollback
        result = self.run_case()
        self.assertEqual(result['status'], 'uncertain')
        self.assertTrue((self.evidence / 'stop-services-observation.json').exists())

    def test_final_cutoff_tightening_records_refusal(self):
        self.backend.mutate['record-failure'] = lambda x: x.update(current_cutoff=self.clock.wall + 1)
        result = self.run_case()
        self.assertFalse(result['product_contained'])
        self.assertTrue((self.evidence / 'containment-outcome.json').exists())

    def test_late_grant_does_not_change_retention_sequence(self):
        # A reply cannot be spliced into an already started, fixed scope.
        def late(x): self.backend.scope['confirmation']['status'] = 'granted'
        self.backend.mutate['stop-services'] = late
        result = self.run_case()
        self.assertFalse(result['cleanup_complete'])
        self.assertEqual(self.backend.snapshot(), self.backend.digests)

    def test_real_operator_timeout_is_uncertain_without_replay(self):
        original = self.backend.run
        pidfile = self.root / 'timeout-child.pid'
        runner_dir = self.root / 'runner'; runner_dir.mkdir(mode=0o700)
        def bounded(action, deadline, commands=()):
            if action != 'stop-services': return original(action, deadline, commands)
            self.backend.calls.append((action, deadline, commands))
            fixture = "import os,pathlib,signal,time; signal.alarm(12); pathlib.Path(" + repr(str(pidfile)) + ").write_text(str(os.getpid())); time.sleep(30)"
            result = subprocess.run([sys.executable, '-B', str(HERE / 'mvp-operator-run.py'),
                '--run-directory', str(runner_dir), '--label', 'containment-timeout',
                '--cutoff-unix', str(time.time() + 20), '--timeout', '0.2', '--reserve', '0',
                '--', sys.executable, '-c', fixture], capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertTrue(pidfile.exists())
            with self.assertRaises(ProcessLookupError): os.kill(int(pidfile.read_text()), 0)
            return {'binding': self.backend.scope['binding'], 'outcome': 'timeout'}
        self.backend.run = bounded
        result = self.run_case()
        self.assertEqual(result['status'], 'uncertain')
        self.assertEqual([x[0] for x in self.backend.calls].count('stop-services'), 1)
        self.assertEqual(self.backend.snapshot(), self.backend.digests)

    def test_native_cli_refuses_and_cannot_start_action(self):
        p=subprocess.run([sys.executable,str(HERE/'mvp-retained-containment.py'),'--execute'],capture_output=True,timeout=3)
        self.assertNotEqual(p.returncode,0)
        self.assertIn(b'no actual producer-bound scope',p.stderr)


if __name__=='__main__': unittest.main()
