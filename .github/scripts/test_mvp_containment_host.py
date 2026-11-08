import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('host',HERE/'mvp-containment-host.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)

class HostTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='containment-host-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.calls=[];self.clock=1000.;self.states={}
        def write(name,raw):
            p=self.root/name.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o600);return h.sha(raw)
        self.write=write
        machine=write('/etc/machine-id',b'fixture-machine');boot=write('/proc/sys/kernel/random/boot_id',b'fixture-boot')
        manifest=write('/root/sbxr-qualification-v3/qualification-manifest.json',b'fixture-manifest')
        write('/root/sbxr-qualification-v3/staging-owned',b'215001-1\n')
        executable=write('/usr/local/bin/sbxr',b'fixture-executable')
        write('/run/lock/sbxr.lock',b'')
        authority={x:write(x,b'fixture-authority') for x in h.AUTHORITY}
        retained={'/etc/sing-box/config.json':write('/etc/sing-box/config.json',b'disposable secrets retained')}
        units={}
        for unit in h.UNITS:
            path='/etc/systemd/system/'+unit
            digest=write(path,b'[Service]\nExecStart=fixture\n')
            units[unit]={'fragment_paths':[path],'fragment_sha256':digest,'dropins':{}}
            self.states[unit]=dict(zip(h.PROPS,('loaded','inactive','enabled',path,'','0','0','/system.slice/'+unit,'control-group','90s','','','yes','','','multi-user.target')))
        self.scope={'binding':{'run_id':215001,'manifest_sha256':manifest},'machine_sha256':machine,'boot_sha256':boot,
                    'authority_files':authority,'executable_sha256':executable,'retained_files':retained,'expected_units':units,
                    'unrelated_files':{},'effective_deadline':2000.,'reviewed_at':1000.,'prior_processes':[{'pid':999999,'pgid':999999,'start_ticks':1,'remote_deadline':999.,'boot_sha256':boot}]}
        self.host=h.Host(self.scope,root=self.root,command=self.command,now=lambda:self.clock)
    def command(self,argv,timeout):
        self.calls.append((argv,timeout))
        self.assertGreater(timeout,0)
        if argv[:2]==['/usr/bin/systemctl','show']:
            return '\n'.join(k+'='+v for k,v in self.states[argv[2]].items())+'\n'
        if argv[:3]==['/usr/bin/systemctl','disable','--now']:
            self.states[argv[3]].update(ActiveState='inactive',UnitFileState='disabled',MainPID='0',ControlPID='0',WantedBy='')
            return ''
        if argv[0]=='/usr/bin/ss':return ''
        if argv[0] in ('/usr/bin/dpkg-query','/usr/bin/apt-mark','/usr/bin/getent','/usr/sbin/iptables-save','/usr/sbin/ip6tables-save'):return 'fixture unchanged observation'
        self.fail(str(argv))
    def stops(self):return [x for x in self.calls if x[0][1:3]==['disable','--now']]
    def test_review_stop_verify_concrete_commands_preserve_files(self):
        before=self.host.files(self.scope['retained_files'])
        review=self.host.review(1400);self.assertEqual(set(review['owned_units']),set(h.UNITS))
        commands=[('/usr/bin/systemctl','disable','--now',u) for u in h.UNITS]
        self.assertEqual(self.host.stop(1400,commands)['stopped_units'],list(h.UNITS))
        result=self.host.verify(1500)
        self.assertEqual(result['candidate_pids'],[]);self.assertEqual(result['retained_files'],before)
        self.assertEqual(len(self.stops()),2)
    def test_stale_review_refuses_before_stop(self):
        self.clock=1121
        with self.assertRaises(ValueError):self.host.stop(1500,[])
        self.assertEqual(self.stops(),[])
    def test_native_constructor_cannot_fall_back_to_fixture(self):
        with self.assertRaises(ValueError):h.Host(self.scope,root=Path('/'),command=self.command)
    def test_foreign_unit_or_stop_hook_refuses(self):
        for field,value in [('ExecStopPost','rm secret'),('KillMode','process'),('TimeoutStopUSec','infinity'),('SendSIGKILL','no')]:
            old=self.states[h.UNITS[0]][field];self.states[h.UNITS[0]][field]=value
            with self.assertRaises(ValueError):self.host.stop(1400,[])
            self.states[h.UNITS[0]][field]=old
        self.assertEqual(self.stops(),[])
    def test_unknown_unloaded_dropin_refuses(self):
        self.write('/etc/systemd/system/'+h.UNITS[0]+'.d/foreign.conf',b'foreign')
        with self.assertRaises(ValueError):self.host.review(1400)
    def test_changed_authority_or_secret_refuses_before_stop(self):
        self.write('/etc/sing-box/config.json',b'changed')
        with self.assertRaises(ValueError):self.host.stop(1400,[])
        self.assertEqual(self.stops(),[])
    def test_absent_service_with_unloaded_fragment_refuses(self):
        self.states[h.UNITS[0]].update(LoadState='not-found',ActiveState='inactive',MainPID='0',ControlPID='0',FragmentPath='',DropInPaths='')
        with self.assertRaises(ValueError):self.host.review(1400)
        self.assertEqual(self.stops(),[])
    def test_partial_install_skips_only_independently_absent_service(self):
        (self.root/self.scope['expected_units'][h.UNITS[0]]['fragment_paths'][0].lstrip('/')).unlink()
        self.states[h.UNITS[0]].update(LoadState='not-found',ActiveState='inactive',MainPID='0',ControlPID='0',FragmentPath='',DropInPaths='')
        commands=[('/usr/bin/systemctl','disable','--now',h.UNITS[1])]
        self.assertEqual(self.host.stop(1400,commands)['stopped_units'],[h.UNITS[1]])
        self.assertEqual(self.host.verify(1500)['absent_units'],[h.UNITS[0]])
    def test_old_review_time_not_rewritten_after_long_stop(self):
        original=self.host.command
        def slow(argv,timeout):
            result=original(argv,timeout)
            if argv[1:3]==['disable','--now']:self.clock+=90
            return result
        self.host.command=slow
        self.host.stop(1400,[('/usr/bin/systemctl','disable','--now',u) for u in h.UNITS])
        self.host.verify(1500)
        self.assertEqual(self.scope['reviewed_at'],1000.)
    def test_timeout_never_repeats_stop(self):
        def fail(argv,timeout):
            if argv[1:3]==['disable','--now']:
                self.calls.append((argv,timeout));raise TimeoutError('fixture stop uncertain')
            return self.command(argv,timeout)
        self.host.command=fail
        with self.assertRaises(TimeoutError):self.host.stop(1400,[('/usr/bin/systemctl','disable','--now',u) for u in h.UNITS])
        self.assertEqual(len(self.stops()),1)
    def test_populated_cgroup_refuses_closed_port_only_success(self):
        self.host.stop(1400,[('/usr/bin/systemctl','disable','--now',u) for u in h.UNITS])
        self.write('/sys/fs/cgroup/system.slice/'+h.UNITS[0]+'/cgroup.procs',b'123\n')
        with self.assertRaises(ValueError):self.host.verify(1500)
    def test_deadline_or_boot_change_refuses(self):
        with self.assertRaises(ValueError):self.host.review(2001)
        self.write('/proc/sys/kernel/random/boot_id',b'changed')
        with self.assertRaises(ValueError):self.host.review(1400)
    def test_preserved_directory_and_symlink_metadata(self):
        base='/root/sbxr-qualification-evidence-q212-41958829811'
        self.write(base+'/proof',b'original evidence')
        (self.root/(base+'/alias').lstrip('/')).symlink_to('proof')
        self.scope['unrelated_files']={x:{} for x in (base,base+'/proof',base+'/alias')}
        self.host.guard(1400);snap=self.host.preservation()
        self.assertEqual(snap['files'][base]['kind'],'directory')
        self.assertEqual(snap['files'][base+'/alias']['target'],'proof')
        self.assertEqual(snap['archive_members'][base],sorted(self.scope['unrelated_files']))
        self.write(base+'/unexpected',b'new')
        self.assertNotEqual(snap['archive_members'],self.host.preservation()['archive_members'])
    def test_requested_command_set_cannot_expand(self):
        with self.assertRaises(ValueError):self.host.stop(1400,[('/bin/rm','-rf','/')])
        self.assertEqual(self.stops(),[])

if __name__=='__main__':unittest.main()
