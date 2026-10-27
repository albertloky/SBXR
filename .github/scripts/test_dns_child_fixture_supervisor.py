"""Inert tests: no subprocess, signal, pidfd, prctl, wrapper or fixture execution."""
import argparse
import importlib.util
from pathlib import Path
import sys
import hashlib
import tempfile
import io
import json
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec=importlib.util.spec_from_file_location('supervisor',Path(__file__).with_name('dns-child-fixture-supervisor.py'))
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)

class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.guards=[]
        for module,name in [(s.subprocess,'Popen'),(s.signal,'pidfd_send_signal'),(s.os,'pidfd_open'),(s.ctypes,'CDLL')]:
            guard=patch.object(module,name,side_effect=AssertionError('runtime operation forbidden in inert tests'))
            guard.start();self.guards.append(guard)
    def tearDown(self):
        for guard in self.guards:guard.stop()
    def test_runtime_entry_refuses_without_flag_before_any_side_effect(self):
        with self.assertRaisesRegex(s.Refusal,'runtime-approval'):
            s.run(argparse.Namespace(execute_approved=False))
    def test_exact_post_attachment_gate_in_both_receipt_orders(self):
        for order in [0,1]:
            g=s.Gate(100,True,'immediate','none')
            rows=[('fixture','GATED 100'),('wrapper','SBXR_DNS_OBSERVER_ATTACHED 100')]
            if order:rows.reverse()
            g.line(*rows[0],0);self.assertEqual(g.input(0),b'')
            g.line(*rows[1],1);self.assertEqual(g.input(1),b'G');self.assertEqual(g.input(2),b'')
    def test_early_wrong_duplicate_or_unknown_receipts_refuse(self):
        for source,line in [('wrapper','STARTING 100 1'),('wrapper','SBXR_DNS_OBSERVER_ATTACHED 101'),('fixture','GATED 101'),('fixture','CHILD 123'),('fixture','COMPLETE')]:
            with self.subTest(line=line),self.assertRaises(s.Refusal):s.Gate(100,True,'immediate','none').line(source,line,0)
        g=s.Gate(100,True,'immediate','none');g.line('wrapper','SBXR_DNS_OBSERVER_ATTACHED 100',0)
        with self.assertRaises(s.Refusal):g.line('wrapper','SBXR_DNS_OBSERVER_ATTACHED 100',1)
    def test_pipe_close_only_after_child_and_hold_budget(self):
        g=s.Gate(100,False,'pipe-wait','none');g.line('fixture','GATED 100',0)
        self.assertEqual(g.input(0),b'G');g.line('fixture','CHILD 200',1)
        self.assertEqual(g.input(1.049),b'');self.assertEqual(g.input(1.051),b'C');self.assertEqual(g.input(2),b'')
    def test_unrelated_child_must_be_distinct_and_precede_selected(self):
        g=s.Gate(100,False,'unrelated','none');g.line('fixture','GATED 100',0);g.input(0)
        with self.assertRaises(s.Refusal):g.line('fixture','CHILD 200',1)
        g.line('fixture','UNRELATED 201',1)
        with self.assertRaises(s.Refusal):g.line('fixture','CHILD 201',1)
        g.line('fixture','CHILD 200',1);g.line('fixture','COMPLETE',2);self.assertTrue(g.complete)
    def test_withheld_gate_never_releases_even_with_valid_attachment(self):
        g=s.Gate(100,True,'immediate','withhold');g.line('fixture','GATED 100',0);g.line('wrapper','SBXR_DNS_OBSERVER_ATTACHED 100',0)
        self.assertEqual(g.input(1000),b'');self.assertFalse(g.sent)
    def test_split_lines_and_byte_limit(self):
        c=s.Capture(8);self.assertEqual(c.feed(b'ABC'),[]);self.assertEqual(c.feed(b'\nDEF\n'),['ABC','DEF'])
        with self.assertRaisesRegex(s.Refusal,'output-overflow'):c.feed(b'X')
        self.assertEqual(len(c.data),8)
    def test_line_and_non_ascii_refusal(self):
        for blob in [b'X'*257,b'X'*257+b'\n']:
            with self.assertRaisesRegex(s.Refusal,'line-overflow'):s.Capture(1000).feed(blob)
        with self.assertRaises(UnicodeDecodeError):s.Capture(10).feed(b'\xff\n')
    def test_pid_starttime_and_parent_must_both_stay_exact(self):
        o=s.Ownership(100)
        self.assertTrue(o.eligible(200,(100,77),(100,77),{100}))
        for pid,before,after in [(100,(100,77),(100,77)),(1,(100,77),(100,77)),(200,(100,77),(100,78)),(200,(999,77),(999,77)),(200,(100,77),(101,77))]:
            self.assertFalse(o.eligible(pid,before,after,{100}))
        o.items[200]=(9,77);self.assertFalse(o.eligible(200,(100,77),(100,77),{100}))
    def test_cleanup_uses_only_owned_pidfds_and_tolerates_already_exited(self):
        o=s.Ownership(100);o.items={200:(9,77),201:(10,78)}
        sender=Mock(side_effect=[ProcessLookupError(),None]);o.signal_owned(sender,15)
        self.assertEqual(sender.call_args_list,[unittest.mock.call(9,15,None,0),unittest.mock.call(10,15,None,0)])
    def test_signal_permission_failure_is_not_hidden(self):
        o=s.Ownership(100);o.items={200:(9,77)}
        with self.assertRaises(PermissionError):o.signal_owned(Mock(side_effect=PermissionError()),15)
    def test_cleanup_escalation_and_absolute_stop(self):
        self.assertEqual(s.cleanup_decision(0),'TERM');self.assertEqual(s.cleanup_decision(1.999),'TERM')
        self.assertEqual(s.cleanup_decision(2),'KILL');self.assertEqual(s.cleanup_decision(4.999),'KILL')
        self.assertEqual(s.cleanup_decision(5),'deadline');self.assertEqual(s.cleanup_decision(110),'deadline')
    def test_proc_stat_parser_handles_spaces_and_parentheses_in_comm(self):
        fields=['S','100']+['0']*17+['777']+['0']*5
        self.assertEqual(s.stat_identity('200 (name ) with spaces) '+' '.join(fields)),(100,777))
    def test_discovery_refuses_recycled_parent_without_opening_any_child(self):
        o=s.Ownership(100);o.items={200:(9,77)}
        class FakePath:
            def __init__(self,path):self.path=path;self.name=path.rsplit('/',1)[-1]
            def iterdir(self):return [FakePath(self.path+'/200')]
            def __truediv__(self,name):return FakePath(self.path+'/'+name)
            def read_text(self):return '200'
            def open(self):return io.StringIO('200')
        with patch.object(s,'Path',FakePath),patch.object(s,'proc_identity',return_value=(100,999)),patch.object(s.select,'select',return_value=([],[],[])):
            with self.assertRaisesRegex(s.Refusal,'pid-reuse'):s.discover(o)
    def test_pinned_file_refuses_wrong_bytes_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture';path.write_bytes(b'fixed inert bytes')
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(s.pin(path,digest),(path.stat().st_dev,path.stat().st_ino))
            with self.assertRaisesRegex(s.Refusal,'file-identity'):s.pin(path,'0'*64)
            link=Path(directory)/'link';link.symlink_to(path)
            with self.assertRaises(OSError):s.pin(link,digest)

    def test_cleanup_summary_never_claims_kernel_cleanup(self):
        report=s.result('immediate','none',None,{'fixture':0},[],.1)
        self.assertEqual(report['outcome'],'process-checks-passed')
        self.assertIn('UNVERIFIED',report['kernel_cleanup'])
        for failure,statuses,residual in [('output-overflow',{'fixture':0},[]),(None,{'fixture':None},[]),(None,{'fixture':0},[200])]:
            self.assertEqual(s.result('immediate','none',failure,statuses,residual,110)['outcome'],'refused')

    def test_discovery_failure_does_not_skip_existing_pidfd_cleanup(self):
        owned=s.Ownership(100);owned.items={200:(9,77)}
        sender=Mock()
        with patch.object(s,'discover',side_effect=s.Refusal('inventory-bound')),patch.object(s.signal,'pidfd_send_signal',sender):
            errors=s.cleanup_tick(owned,15)
        sender.assert_called_once_with(9,15,None,0)
        self.assertEqual(errors,['discovery-unproved'])

    def test_readonly_bind_view_of_writable_superblock_refuses(self):
        texts={'/proc/self/fdinfo/9':'mnt_id: 12\n','/proc/self/mountinfo':'12 1 0:1 / /safe ro - ext4 /dev/sda rw\n'}
        class FakePath:
            def __init__(self,path):self.path=path
            def read_text(self):return texts[self.path]
        with patch.object(s,'Path',FakePath),patch.object(s.os,'fstatvfs',return_value=SimpleNamespace(f_flag=s.os.ST_RDONLY)):
            with self.assertRaisesRegex(s.Refusal,'superblock-writable'):s.readonly_superblock(9)
            texts['/proc/self/mountinfo']='12 1 0:1 / /safe ro - ext4 /dev/sda ro\n'
            s.readonly_superblock(9)
            texts['/proc/self/mountinfo']='12 1 0:1 / /safe ro - nfs server ro\n'
            with self.assertRaisesRegex(s.Refusal,'filesystem-unreviewed'):s.readonly_superblock(9)

    def test_any_existing_bytecode_cache_refuses_even_when_source_is_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            checker=Path(directory)/'dns-child-observer.py';checker.write_text('pass')
            s.reject_bytecode_cache(checker)
            cache=Path(directory)/'__pycache__';cache.mkdir()
            with self.assertRaisesRegex(s.Refusal,'unchecked-python-bytecode'):s.reject_bytecode_cache(checker)
            cache.rmdir();checker.with_suffix('.pyc').write_bytes(b'inert cache')
            with self.assertRaisesRegex(s.Refusal,'unchecked-python-bytecode'):s.reject_bytecode_cache(checker)

    def orchestration(self, scenario):
        # Exercise execute() itself with inert process, clock, selector and fd
        # adapters. No actual process, descriptor, signal or Linux setup call.
        class Stream:
            def __init__(self,fd):self.fd=fd;self.closed=False
            def fileno(self):return self.fd
            def close(self):self.closed=True
        class Process:
            def __init__(self,pid):
                self.pid=pid;self.rc=None
                self.stdin=Stream(pid*10);self.stdout=Stream(pid*10+1);self.stderr=Stream(pid*10+2)
            def poll(self):return self.rc
        clock=SimpleNamespace(now=0)
        processes=[];writes=[];sends=[];reads={};timestamps=[]
        class Selector:
            def __init__(self):self.keys={};self.first=True
            def register(self,stream,event,data):self.keys[stream.fd]=SimpleNamespace(fd=stream.fd,fileobj=stream,data=data)
            def unregister(self,stream):self.keys.pop(stream.fd)
            def get_map(self):return self.keys
            def close(self):pass
            def select(self,timeout):
                clock.now += 106 if scenario=='late-readiness' and self.first else .02
                if self.first:
                    self.first=False
                    return [(key,None) for key in self.keys.values() if key.data.endswith('-out')]
                return [(key,None) for key in self.keys.values()]
        selector=Selector()
        def popen(*a,**kw):
            if processes and scenario=='spawn-failure':raise OSError('inert spawn refusal')
            p=Process(200+len(processes));processes.append(p)
            if len(processes)==1:reads[p.stdout.fd]=[b'GATED 200\n']
            else:reads[p.stdout.fd]=[b'SBXR_DNS_OBSERVER_ATTACHED 200\n']
            return p
        def monotonic():clock.now+=.01;return clock.now
        def sender(fd,sig,*rest):
            sends.append((fd,sig))
            for p in processes:
                if fd==1000+p.pid:p.rc=0
        def reader(fd,count):
            queue=reads.get(fd,[])
            return queue.pop(0) if queue else b''
        original_line=s.Gate.line
        def receipt(g,source,line,now):
            timestamps.append(now);return original_line(g,source,line,now)
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            args=SimpleNamespace(output=Path(directory)/'result',case='immediate',baseline=False,fault='none',symbol='exact')
            paths={k:'/inert/'+k for k in ['fixture','python','wrapper','tracer']}
            spec={'tracer':{'sha256':'0'*64}}
            patches=[(s.subprocess,'Popen',popen),(s.selectors,'DefaultSelector',lambda:selector),
                     (s.os,'pidfd_open',lambda pid,flags:1000+pid),(s,'proc_identity',lambda pid:(s.os.getpid(),pid*100)),
                     (s.os,'set_blocking',lambda *a:None),(s.os,'close',lambda *a:None),
                     (s.os,'read',reader),(s.os,'write',lambda fd,data:writes.append((fd,data)) or len(data)),
                     (s.signal,'signal',lambda *a:None),(s.signal,'pidfd_send_signal',sender),
                     (s.time,'monotonic',monotonic),(s.time,'sleep',lambda n:setattr(clock,'now',clock.now+n)),
                     (s,'reap_adopted',lambda direct:[]),(s,'live_fixture',lambda *a:None),(s.Gate,'line',receipt)]
            for obj,name,value in patches:stack.enter_context(patch.object(obj,name,value))
            if scenario in ('spawn-failure','discovery-failure'):
                stack.enter_context(patch.object(s,'discover',side_effect=s.Refusal('inert-discovery-failure')))
            else:stack.enter_context(patch.object(s,'discover',lambda owned:None))
            code=s.execute(args,spec,paths,{'fixture':(1,2)})
            report=json.loads((args.output/'result.json').read_text())
        return code,report,writes,sends,timestamps

    def test_event_loop_refuses_late_ready_before_gate_write(self):
        code,report,writes,sends,timestamps=self.orchestration('late-readiness')
        self.assertEqual(code,1);self.assertEqual(writes,[])
        self.assertEqual(report['failure'],'watchdog-expired');self.assertTrue(sends)
        self.assertTrue(all(t>106 for t in timestamps))

    def test_spawn_failure_and_persistent_discovery_error_still_clean_known_child(self):
        code,report,writes,sends,_=self.orchestration('spawn-failure')
        self.assertEqual(code,1);self.assertEqual(writes,[])
        self.assertIn((1200,s.signal.SIGKILL),sends)
        self.assertTrue(report['processes_reaped']);self.assertEqual(report['failure'],'discovery-unproved')

    def test_running_discovery_failure_still_signals_both_owned_children(self):
        code,report,writes,sends,_=self.orchestration('discovery-failure')
        self.assertEqual(code,1);self.assertEqual(writes,[])
        self.assertEqual({fd for fd,sig in sends},{1200,1201})
        self.assertEqual(report['outcome'],'refused')

    def test_one_signal_error_does_not_starve_later_owned_handles(self):
        owned=s.Ownership(100);owned.items={200:(9,1),201:(10,2)}
        sender=Mock(side_effect=[PermissionError('inert denied'),None])
        with self.assertRaises(PermissionError):owned.signal_owned(sender,15)
        self.assertEqual([c.args[0] for c in sender.call_args_list],[9,10])

    def test_oversized_inventory_reaps_zombies_before_discovering_next_batch(self):
        model={pid:'alive' for pid in range(200,240)};signaled=[];owned=s.Ownership(100)
        class FakePath:
            def __init__(self,path):self.path=path;self.name=path.rsplit('/',1)[-1]
            def __truediv__(self,name):return FakePath(self.path+'/'+name)
            def iterdir(self):return [FakePath(self.path+'/'+self.path.split('/')[2])]
            def read_text(self):return ' '.join(map(str,model))+' ' if self.path.split('/')[2] in ('100','self') else ''
            def open(self):return io.StringIO(self.read_text())
        def sender(fd,sig,*rest):
            pid=fd-1000
            if pid not in model:raise ProcessLookupError()
            signaled.append(pid);model[pid]='zombie'
        def wait(pid,flags):
            if model[pid]=='zombie':del model[pid];return pid,0
            return 0,0
        def ready(fds,*rest):return ([fd for fd in fds if model.get(fd-1000)!='alive'],[],[])
        with patch.object(s,'Path',FakePath),patch.object(s.os,'getpid',return_value=100),\
             patch.object(s,'proc_identity',side_effect=lambda pid:(100,pid*10)),\
             patch.object(s.os,'pidfd_open',side_effect=lambda pid,flags:1000+pid),\
             patch.object(s.os,'waitpid',side_effect=wait),patch.object(s.os,'close'),\
             patch.object(s.select,'select',side_effect=ready),patch.object(s.signal,'pidfd_send_signal',side_effect=sender):
            self.assertIn('discovery-unproved',s.cleanup_tick(owned,15,{}))
            self.assertEqual(len(model),8)
            s.cleanup_tick(owned,15,{})
        self.assertEqual(model,{})
        self.assertEqual(set(signaled),set(range(200,240)))

if __name__=='__main__':unittest.main()
