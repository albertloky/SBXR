"""Inert watchdog orchestration tests: no processes, signals, namespaces or mounts."""
import importlib.util
from pathlib import Path
import signal
import stat
import types
import unittest
from unittest.mock import Mock, patch

spec=importlib.util.spec_from_file_location('watchdog',Path(__file__).with_name('dns-child-session-watchdog.py'))
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)


class WatchdogTests(unittest.TestCase):
    def test_durable_record_handles_partial_write_and_fsync(self):
        chunks=[]
        def write(fd,data):
            n=min(3,len(data));chunks.append(bytes(data[:n]));return n
        with patch.object(w.os,'write',side_effect=write),patch.object(w.os,'fsync') as sync:
            w.durable_record(9,{'state':'OWNER_ARMED'})
            sync.assert_called_once_with(9)
        self.assertEqual(w.json.loads(b''.join(chunks)),{'state':'OWNER_ARMED'})

    def test_durable_record_bound_refuses_before_write(self):
        with patch.object(w.os,'write') as write:
            with self.assertRaises(ValueError):w.durable_record(9,{'bad':'x'*32768})
            write.assert_not_called()

    def owner_scenario(self, failures=(), write_failure=False, hold=False):
        class Refusal(Exception):pass
        class EndObservation(Exception):pass
        now=[0];records=[];pauses=[]
        child=Mock(pid=123)
        child.poll.side_effect=lambda:None if now[0]<2 or hold else 0
        owned=types.SimpleNamespace(items={123:(9,77)})
        def discover(o):
            if now[0] in failures:raise Refusal()
        api=types.SimpleNamespace(discover=discover,reap_adopted=lambda p:[],Refusal=Refusal)
        def evidence(r):
            records.append(r)
            if write_failure:raise OSError('disk full')
        def pause(n):
            pauses.append(n);now[0]+=n
            if hold and now[0]>65:raise EndObservation()
        with patch.object(w.signal,'signal'),patch.object(w.os,'close') as close, \
             patch.object(w.select,'select',side_effect=lambda *a: ([],[],[]) if hold or now[0]<2 else ([9],[],[])):
            if hold:
                with self.assertRaises(EndObservation):
                    w.owner_finish(api,{'owned':owned,'procs':{'supervisor':child}},
                                   {'failure':'deadline'},evidence,lambda:now[0],pause)
                result=None
            else:
                result=w.owner_finish(api,{'owned':owned,'procs':{'supervisor':child}},
                                      {'failure':'deadline'},evidence,lambda:now[0],pause)
            close.assert_not_called()
        return result,records,pauses

    def test_owner_retains_custody_until_actual_reap(self):
        result,records,pauses=self.owner_scenario()
        self.assertTrue(result)
        self.assertEqual([r['state'] for r in records],['OWNER_CUSTODY','FAILED_CLEANUP_HOLD','OWNER_RELEASED'])
        self.assertEqual(records[1]['residual_ownership'],[{'pid':123,'starttime':77,'pidfd':9}])

    def test_owner_observation_error_does_not_release(self):
        result,records,pauses=self.owner_scenario(failures=(0,1,2))
        self.assertGreaterEqual(len(pauses),3)
        self.assertTrue(records[1]['observation_uncertain'])

    def test_owner_disk_failure_remains_failure(self):
        result,records,pauses=self.owner_scenario(write_failure=True)
        self.assertFalse(result)
        self.assertEqual(records[-1]['state'],'OWNER_RELEASED')

    def test_owner_after60_seconds_is_quiescent_not_abandoned(self):
        _,records,pauses=self.owner_scenario(hold=True)
        self.assertEqual(records[-1]['state'],'FAILED_CLEANUP_HOLD')
        self.assertIn(5,pauses)
    def test_host_namespace_refused(self):
        with self.assertRaisesRegex(ValueError,'host-mount'):w.private_mounts('mnt:[1]','mnt:[1]','')

    def test_all_propagation_links_refused(self):
        for field in ('shared:1','master:2','propagate_from:3'):
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'propagation'):
                w.private_mounts('mnt:[1]','mnt:[2]',f'1 0 8:1 / / rw {field} - ext4 /dev/a rw')

    def test_private_view_accepted(self):
        w.private_mounts('mnt:[1]','mnt:[2]','1 0 8:1 / / rw - ext4 /dev/a rw')

    def test_empty_inventory_refused(self):
        with self.assertRaises(ValueError):w.private_mounts('a','b','')

    def test_supervisor_file_on_other_mount_refused(self):
        with patch.object(w.os,'fstat',return_value=types.SimpleNamespace(st_mode=stat.S_IFREG)), \
             patch.object(w.Path,'read_text',side_effect=['mnt_id: 1','mnt_id: 2']):
            with self.assertRaisesRegex(ValueError,'bootstrap-file-mount'):w.same_image_file(3,4)

    def scenario(self, *, stalled=False, discover_error=False, spawn_error=False, cleanup_error=False, launch_jump=0, permanent=False, select_error=False, registration_error=False, custody=None):
        now=[0.0];signals=[];child=Mock(pid=123)
        child.poll.side_effect=lambda:None if permanent or (stalled and now[0]<108) else 0
        class Refusal(Exception):pass
        owned=types.SimpleNamespace(items={})
        def cleanup(o,s,p):
            signals.append((now[0],s));return ['denied'] if cleanup_error else []
        def spawn(*a,**kw):
            if spawn_error:raise OSError()
            now[0]+=launch_jump
            return child
        def identity(p):
            if registration_error:raise OSError()
            return (w.os.getpid(),77)
        api=types.SimpleNamespace(runtime_setup=Mock(),Ownership=lambda p:owned,
            proc_identity=identity,Refusal=Refusal,
            discover=Mock(side_effect=Refusal() if discover_error else None),
            reap_adopted=lambda p:[],cleanup_tick=cleanup)
        def pause(n):now[0]+=1
        def ready(*args):
            if select_error:raise OSError()
            return ([],[],[]) if permanent or (stalled and now[0]<108) else ([9],[],[])
        with patch.object(w.subprocess,'Popen',side_effect=spawn), \
             patch.object(w.os,'pidfd_open',return_value=9),patch.object(w.os,'close'), \
             patch.object(w.signal,'signal') as handlers,patch.object(w.select,'select',side_effect=ready):
            report=w.supervise(api,['fixed'],clock=lambda:now[0],pause=pause,custody=custody)
            if custody is not None:
                self.assertEqual(handlers.call_count,2) # Install only; no restoration gap.
                self.assertEqual(set(custody['previous_handlers']),{signal.SIGINT,signal.SIGTERM})
        return report,signals

    def test_clean_supervisor_exit(self):
        report,signals=self.scenario()
        self.assertTrue(report['processes_reaped']);self.assertIsNone(report['failure'])
        self.assertEqual(signals,[]);self.assertEqual(report['kernel_cleanup'],'UNVERIFIED')

    def test_stalled_supervisor_outer_deadline(self):
        report,signals=self.scenario(stalled=True)
        self.assertEqual(report['failure'],'deadline')
        self.assertEqual(signals[0],(105,signal.SIGTERM))
        self.assertIn((107,signal.SIGKILL),signals)
        self.assertLessEqual(report['elapsed_seconds'],110)

    def test_discovery_error_enters_cleanup(self):
        report,signals=self.scenario(stalled=True,discover_error=True)
        self.assertEqual(report['failure'],'discovery-unproved')
        self.assertTrue(signals);self.assertFalse(report['processes_reaped'])
        self.assertLessEqual(report['elapsed_seconds'],6)

    def test_spawn_failure_not_success(self):
        report,signals=self.scenario(spawn_error=True)
        self.assertEqual(report['failure'],'watchdog-adapter-failure')
        self.assertFalse(report['processes_reaped'])

    def test_cleanup_failure_is_retained(self):
        report,signals=self.scenario(stalled=True,cleanup_error=True)
        self.assertEqual(report['failure'],'cleanup-unproved');self.assertTrue(signals)

    def test_late_launch_uses_absolute_kill_deadline(self):
        for late in (108,111):
            report,signals=self.scenario(permanent=True,launch_jump=late)
            self.assertEqual(signals[0],(late,signal.SIGKILL))
            self.assertFalse(report['processes_reaped'])

    def test_permanent_residual_identity_is_reported(self):
        report,signals=self.scenario(permanent=True)
        self.assertEqual(report['residual_ownership'],[{'pid':123,'starttime':77}])
        self.assertFalse(report['processes_reaped'])

    def test_persistent_observation_failure_keeps_ledger(self):
        report,signals=self.scenario(select_error=True,permanent=True)
        self.assertEqual(report['failure'],'ownership-observation-unproved')
        self.assertFalse(report['discovery_complete'])
        self.assertEqual(report['residual_ownership'],[{'pid':123,'starttime':77}])
        self.assertFalse(report['processes_reaped'])

    def test_late_registration_failure_still_attempts_cleanup(self):
        report,signals=self.scenario(launch_jump=111,registration_error=True,permanent=True)
        self.assertEqual(signals,[(111,signal.SIGKILL)])
        self.assertFalse(report['processes_reaped'])

    def test_handoff_retains_handlers_and_live_objects(self):
        custody={}
        report,_=self.scenario(permanent=True,custody=custody)
        self.assertFalse(report['processes_reaped'])
        self.assertEqual(custody['owned'].items,{123:(9,77)})
        self.assertEqual(custody['procs']['supervisor'].pid,123)


if __name__=='__main__':unittest.main()
