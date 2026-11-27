"""Offline protocol composition. Every OS, network, client and workflow input is synthetic."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent


def module(name):
    return runpy.run_path(str(HERE/(name+'.py')))


def write(path, doc):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    raw=doc if isinstance(doc,bytes) else json.dumps(doc,sort_keys=True,separators=(',',':')).encode()
    path.write_bytes(raw)
    path.chmod(0o600)
    return hashlib.sha256(raw).hexdigest()


def respond(base):
    from test_mvp_containment_host import h
    root=base/'host'
    if root.resolve()==Path('/'):
        raise ValueError('requires a disposable fixture')
    live=base/'live'
    states=json.loads((base/'units').read_bytes())
    def command(argv, timeout):
        if argv==['fixture-prove-not-installed']:
            from test_prepare_mvp_containment import ABSENCE_PROBE
            p=subprocess.run(['bash','-c',ABSENCE_PROBE,'fixture',str(HERE/'v3-packaged-live.sh'),str(root)],
                             capture_output=True,timeout=3)
            return 'absent' if p.returncode==0 else 'remaining'
        if argv[1:2]==['show']:
            if argv[2]=='sbxr-qualification-v3.service':
                return 'LoadState=not-found\nActiveState=inactive\nMainPID=0\nControlPID=0'
            return '\n'.join(k+'='+v for k,v in states[argv[2]].items())
        if argv[1:3]==['disable','--now']:
            states[argv[3]].update(ActiveState='inactive',UnitFileState='disabled',WantedBy='',MainPID='0')
            write(base/'units',states)
            return ''
        if argv[0]=='/usr/bin/ss':
            return ''
        if argv==['/usr/sbin/iptables-save','-t','filter']:
            rule=(base/'fixture-filter-rule')
            return '*filter\n'+(rule.read_text() if rule.exists() else '')+'COMMIT'
        if argv[0] in ('/usr/sbin/iptables-save','/usr/sbin/ip6tables-save'):
            return '*nat\nCOMMIT'
        if argv[0] in ('/usr/bin/getent','/usr/bin/apt-mark','/usr/bin/dpkg-query'):
            return 'fixture baseline'
        raise ValueError('unexpected fixture host command')
    host=h.Host({},root=root,command=command)
    assets={name:(base/'prepared/operator-source'/name).read_bytes() for name in module('remote')['ASSETS']}
    endpoint=module('mvp-recovery-endpoint')
    req=json.loads(sys.stdin.buffer.readline())
    owner=124 if req['phase']=='remove' else 123
    if req['phase']=='remove':
        write(root/'proc/124/stat',('124 (fixture) S 1 124 124 '+'0 '*15+'55').encode())
        write(root/'proc/124/environ',b'')
    def acknowledge(row):
        print(json.dumps({'receipt':row}),flush=True)
        return sys.stdin.buffer.readline(66).strip().decode('ascii')
    def effect(operation, deadline):
        # The fake host receives the effect only after the actual transport has
        # durably retained this particular owner on the operator side.
        copies=module('remote')['copies'](live)
        if not any(r['intent']==req['intent'] for r in copies):
            raise ValueError('local receipt was not present before effect')
        if operation=='complete-removal':
            if (base/'interrupt-removal').exists():
                raise ConnectionError('fixture removal channel interrupted')
            # Drive the real fixed menu and cleanup clock on a synthetic executable.
            fixture=base/'menu-fixture'
            shell=b'#!/bin/sh\nset -eu\nprintf "%s\\n" "SBXR V3" "1. Complete removal" "0. Exit"\nread -r n; test "$n" = 1\necho "Type REMOVE SBXR to confirm Complete removal. Any other input cancels."\nread -r answer; test "$answer" = "REMOVE SBXR"\necho "Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"\n'
            write(fixture,shell)
            fixture.chmod(0o700)
            rec=base/'prepared/operator-source/mvp-observe.py'
            env={**os.environ,'SBXR_QUALIFICATION_REQUEST':str(root/'root/sbxr-qualification-evidence/request.json'),
                 'SBXR_QUALIFICATION_CLOCK':str(rec),'SBXR_QUALIFICATION_CLOCK_SHA256':hashlib.sha256(rec.read_bytes()).hexdigest(),
                 'SBXR_QUALIFICATION_DRAFT':str(root/'root/mvp-observation-draft.json')}
            subprocess.run([sys.executable,'-B',str(HERE/'v3-menu-session.py'),'safety-cleanup','Complete removal',
                            'SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED','--confirmation','remove','--timeout','360',
                            '--cleanup-cutoff',str(req['reviewed']['cutoff']),'--cleanup-reserve','660',
                            '--runtime-deadline',str(root/'root/sbxr-qualification-v3/runtime-deadline'),
                            '--executable',str(fixture)],env=env,stdout=subprocess.DEVNULL,check=True,timeout=4)
            for name in ('usr/local/bin/sbxr','var/lib/sbxr','etc/sing-box','etc/systemd/system/sbxr-subscription.service'):
                (root/name).rename(base/('retired-'+name.replace('/','-')))
            for state in states.values():
                state.update(LoadState='not-found',FragmentPath='',UnitFileState='',ActiveState='inactive',MainPID='0',ControlPID='0',WantedBy='',ControlGroup='')
            write(base/'units',states)
            return 0
        write(base/'effect',{'operation':operation})
        raise ConnectionError('fixture channel severed after first effect')
    def drain():
        pass
    try:
        result=endpoint['dispatch'](req,assets,host,acknowledge=acknowledge,owner=(owner,effect,drain))
    finally:
        if req['phase']=='remove':
            (root/'proc/124').rename(base/'retired-removal-owner')
        if req['phase']=='launch' and (base/'effect').exists() and not (base/'leave-alive').exists():
            (root/'proc/123').rename(base/'exited-launch-owner')
    print(json.dumps(result))


class Journey(unittest.TestCase):
    def setUp(self):
        from test_prepare_mvp_containment import ClockPreparation
        from test_mvp_containment_readbacks import NativeTests
        f=ClockPreparation()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.f=f
        self.base=f.base
        self.root=f.host
        self.root.rename(self.base/'host')
        self.root=self.base/'host'
        f.host=self.root
        f.staging=self.root/'root/sbxr-qualification-v3'
        f.request=self.root/'root/sbxr-qualification-evidence/request.json'
        f.draft=self.root/'root/mvp-observation-draft.json'
        f.staging.chmod(0o700)
        self.live=self.base/'live'
        self.live.mkdir(mode=0o700)
        self.native=NativeTests()
        self.native.setUp()
        self.addCleanup(self.native.doCleanups)
        f.release['release_identity']={'tag':f.release['tag'],'commit':f.release['commit'],
                'repository':'albertloky/SBXR','release_index_sha256':'c'*64}
        f.manifest['v3_attempt']['vps_id']='vps-fixture'
        f.pin=write(self.base/'manifest.json',f.manifest)
        f.cmd[f.cmd.index('--manifest-sha256')+1]=f.pin
        write(f.staging/'qualification-manifest.json',f.manifest)
        f.window['window']['manifest_sha256']=f.pin
        f.prepare()
        f.window_pin=write(f.staging/'fresh-window-decision.json',f.window)
        write(self.root/'proc/sys/kernel/random/boot_id',b'fixture boot')
        write(self.root/'proc/123/stat',('123 (fixture) S 1 123 123 '+'0 '*15+'45').encode())
        write(self.root/'proc/123/environ',b'')
        write(f.staging/'journey-custody.jsonl',('88-1 '+f.pin+'\n').encode())
        executable=write(self.root/'usr/local/bin/sbxr',b'fixture signed executable')
        write(self.root/'var/lib/sbxr/installed.json',{**f.release['release_identity'],'sequence':f.release['sequence'],
                'executable_sha256':executable,'architecture':'amd64'})
        write(self.root/'run/lock/sbxr.lock',b'')
        self.secret=self.root/'etc/sing-box/config.json'
        write(self.secret,b'fixture retained candidate credential')
        write(self.root/'etc/hosts',b'original fixture hosts')
        write(self.root/'etc/ssl/certs/ca-certificates.crt',b'original fixture trust')
        host=module('mvp-containment-host')
        self.baseline={'files':{path:host['Host']({},root=self.root,command=self.fail).preserved_metadata(path)
                          for path in ('/etc/hosts','/etc/ssl/certs/ca-certificates.crt')},
                       'checks':{k:{'exit':0} for k in ('packages','holds','accounts','groups','firewall','ip6firewall')}}
        bfile=self.live/'host-baseline.operator.stdout'
        bpin=write(bfile,self.baseline)
        helper=f.prepared/'operator-source/native-receipts.py'
        inputs={**self.native.inputs,'source_commit':f.cfg['source'],'candidate':{k:f.cfg[k] for k in ('tag','sequence')},
                'canonical_helper':{'source_file':str(helper),'size':helper.stat().st_size,'sha256':hashlib.sha256(helper.read_bytes()).hexdigest()}}
        write(f.prepared/'native-inputs.json',inputs)
        proposal=module('mvp-containment-bindings')['proposal'](HERE.parents[1],f.prepared)
        self.assertFalse(proposal['ready_for_live'])
        unit='sbxr-subscription.service'
        unit_path=proposal['source_unit_pins'][unit]['fragment_paths'][0]
        unit_bytes=module('mvp-containment-bindings')['rust_string'](HERE.parents[1]/'src/runtime_handoff.rs','SERVING_UNIT')
        write(self.root/unit_path.lstrip('/'),unit_bytes)
        states={}
        for name in host['UNITS']:
            values=('loaded','inactive','enabled',unit_path,'','0','0','/system.slice/'+unit,'control-group','10s','','','yes','','','multi-user.target')
            states[name]=dict(zip(host['PROPS'],values))
            if name!=unit:
                states[name].update(LoadState='not-found',FragmentPath='',UnitFileState='',WantedBy='',ControlGroup='')
        write(self.base/'units',states)
        self.remote=types.ModuleType('fixture_remote')
        self.remote.__dict__.update(module('remote'))
        # run_path returns a copy; keep function globals tied to the prepared provider.
        self.remote.call.__globals__['HERE']=f.prepared
        self.remote.call.__globals__['ssh']=lambda cfg,assets:[sys.executable,'-B',str(Path(__file__).resolve()),'serve',str(self.base)]
        self.proof={'manifest_sha256':f.pin,'window_sha256':f.window_pin,'job_id':8881}
        self.remote.bound_candidate=lambda **kwargs:(f.cfg,88,self.proof)
        approval={'host':f.cfg['host'],'source':f.cfg['source'],'run_id':88,'run_attempt':1,'job_id':8881,
                  'window_sha256':f.window_pin,'automatic_transport_disposal_approved':True,'outside_program':{'fixture':True},
                  'proposal_sha256':self.remote.sha(self.remote.canonical(proposal)),
                  'baseline':{'source_file':str(bfile),'size':bfile.stat().st_size,'sha256':bpin}}
        write(self.live/'operator-approval.json',approval)
        operator=module('mvp-recovery')['Operator']
        components=operator.__init__.__globals__['component']
        def boundary(name):
            obj=components(name)
            if name=='outside-run':
                obj['program_pids']=lambda r:set()
            if name=='mvp-containment-entry':
                obj['load']=lambda *args:self.remote
            return obj
        with patch.dict(operator.__init__.__globals__,component=boundary,verify_revision=lambda *a:None):
            self.op=operator(f.prepared)
            self.op.initialize()

    def interrupt(self,scenario='mvp-subscription',operation='enable-subscription'):
        from test_prepare_mvp_containment import SCENARIOS
        self.scenario,self.operation=scenario,operation
        f=self.f
        f.request_for(scenario)
        f.request.parent.chmod(0o700)
        f.window_pin=write(f.staging/'fresh-window-decision.json',f.window)
        f.document['qualification_window_sha256']=f.window_pin
        f.document['deadline_unix']=min(f.now-1+f.document['scenario_limit_seconds'],f.plan['test_until_unix'])
        f.request_pin=write(f.request,f.document)
        f.draft.rename(self.base/'old-disposable-draft')
        start=subprocess.run([sys.executable,'-B',str(HERE/'mvp-observe.py'),'start','--request',str(f.request),
                              '--draft',str(f.draft)],capture_output=True)
        self.assertEqual(start.returncode,0,start.stderr.decode())
        with self.assertRaisesRegex(ValueError,'uncertain'):
            self.op.launch(self.scenario,self.operation,self.f.request_pin)
        self.assertEqual(json.loads((self.base/'effect').read_bytes()),{'operation':self.operation})
        self.assertEqual(len(self.remote.copies(self.live)),1)
        failure={'actual_result':'unexpected-failure','scenario_id':self.scenario,'operation_id':'operation-'+str(SCENARIOS.index(scenario)+1),
                 'attempt_id':'run-88-attempt-1','candidate':self.f.release,'vps_id':'vps-fixture'}
        original=self.live/'original-failure.json'
        pin=write(original,failure)
        binding=dict(run_id=88,source=self.f.cfg['source'],host=self.f.cfg['host'],tag=self.f.cfg['tag'],sequence=self.f.cfg['sequence'],
                     manifest_sha256=self.f.pin,request_sha256=self.f.request_pin,failure_sha256=pin)
        write(self.live/'recovery-decision.json',{'binding':binding,'local_retained':[str(original)],'http_state_possible':scenario!='mvp-install',
                    'confirmation':{'status':'declined','notified_at':time.time()-1,'response_cap':60}})
        return failure

    def approve_removal(self):
        copies=self.remote.copies(self.live)
        intent=copies[0]['intent']
        observed=self.op.send('ownership',intent,time.time()+30,copies=copies)
        write(self.live/'removal-decision.json',{'interrupted':intent,'choice':'complete-removal','job_id':8881,
              'status':'approved','observed_at':time.time(),'http_state_possible':True,
              'executable_sha256':observed['executable_sha256'],'authority_snapshot':observed['authority_snapshot']})

    def test_freeze_retains_both_captures_after_interrupted_supported_removal(self):
        original=self.interrupt()
        self.approve_removal()
        write(self.base/'interrupt-removal',b'')
        with self.assertRaisesRegex(ValueError,'uncertain'):
            self.op.remove(self.scenario,self.operation,self.f.request_pin,'complete-removal')
        scope=self.op.freeze(self.scenario,self.operation,self.f.request_pin)
        for phase, message in (('launch','severed after first effect'),('remove','removal channel interrupted')):
            capture,=self.live.glob(phase+'-*.stderr')
            self.assertIn(message,capture.read_text())
            self.assertEqual(scope['retained_files']['local:'+str(capture)],hashlib.sha256(capture.read_bytes()).hexdigest())
        self.assertEqual(self.op.document('original-failure.json'),original)
        self.assertFalse((self.live/'product-absence.json').exists())

    def test_supported_removal_requires_independent_absence_and_never_replays(self):
        self.interrupt()
        self.approve_removal()
        dangling=self.root/'etc/apt/keyrings/sagernet.asc'
        dangling.parent.mkdir(parents=True)
        dangling.symlink_to('missing-key')
        with self.assertRaisesRegex(ValueError,'uncertain'):
            self.op.remove(self.scenario,self.operation,self.f.request_pin,'complete-removal')
        self.assertFalse((self.live/'product-absence.json').exists())
        self.assertFalse(self.secret.exists())
        with self.assertRaises((ValueError,FileExistsError)):
            self.op.remove(self.scenario,self.operation,self.f.request_pin,'complete-removal')
        dangling.rename(self.base/'retained-fixture-link')
        unit=self.root/'etc/systemd/system/sbxr-subscription-firewall.service'
        write(unit,b'fixture owned firewall service')
        verify=lambda: self.op.remove(self.scenario,self.operation,self.f.request_pin,'complete-removal',observe_only=True)
        with self.assertRaisesRegex(ValueError,'uncertain'):
            verify()
        unit.rename(self.base/'retired-firewall-unit')
        rule=self.base/'fixture-filter-rule'
        write(rule,b'-A INPUT -p tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT\n')
        with self.assertRaisesRegex(ValueError,'uncertain'):
            verify()
        self.assertFalse((self.live/'product-absence.json').exists())
        rule.rename(self.base/'retired-firewall-rule')
        process=self.root/'proc/237'
        process.mkdir()
        (process/'exe').symlink_to('/usr/bin/sing-box (deleted)')
        with self.assertRaisesRegex(ValueError,'uncertain'):
            verify()
        self.assertFalse((self.live/'product-absence.json').exists())
        process.rename(self.base/'exited-fixture-service')
        write(rule,b'-A INPUT -p tcp --dport 8443 -m comment --comment "unrelated-sbxr-subscription" -j ACCEPT\n')
        proof=verify()
        self.assertTrue(proof['product_absent'])
        self.assertEqual(proof['candidate_pids'],[])
        self.assertEqual(len(self.remote.copies(self.live)),2)

    def test_independent_scan_blocks_a_surviving_group(self):
        write(self.base/'leave-alive',b'')
        self.interrupt()
        with self.assertRaisesRegex(ValueError,'uncertain'):
            self.op.freeze(self.scenario,self.operation,self.f.request_pin)
        self.assertFalse((self.live/'retained-scope.json').exists())
        self.assertTrue((self.root/'proc/123/stat').exists())

    def test_install_interruption(self):
        self.verify_interruption('mvp-install','setup')

    def test_subscription_interruption(self):
        self.verify_interruption('mvp-subscription','enable-subscription')

    def test_credentials_interruption(self):
        self.verify_interruption('mvp-credentials','rotate-identity')

    def test_serving_interruption(self):
        self.verify_interruption('mvp-serving','restart-serving')

    def test_removal_interruption(self):
        self.verify_interruption('mvp-removal','restart-access')

    def verify_interruption(self,scenario,operation):
        from concurrent.futures import ThreadPoolExecutor
        original=self.interrupt(scenario,operation)
        scope=self.op.freeze(self.scenario,self.operation,self.f.request_pin)
        process=self.remote.copies(self.live)[0]['process']
        self.assertEqual(self.op.document('containment-host-scope.json')['prior_processes'],[process])
        evidence=self.live/'outcomes'
        evidence.mkdir(mode=0o700)
        coordinator=module('mvp-retained-containment')
        entry=module('mvp-containment-entry')['Entry']
        loader=entry.__init__.__globals__['load']
        def load(name,path,pins):
            if name=='remote':
                return self.remote
            if name=='containment_native_receipts':
                return self.native.n
            if name=='containment_outside':
                actual=loader(name,path,pins)
                actual.program_pids=lambda record:set()
                return actual
            if name=='containment_direct':
                direct=loader(name,path,pins)
                def observe(host,deadline):
                    class Control:
                        def __enter__(self):return self
                        def __exit__(self,*a):pass
                        def settimeout(self,t):pass
                        def connect(self,peer):self.peer=peer
                        def getpeername(self):return self.peer
                        def recv(self,n):return b'SSH-2.0-synthetic'
                    return direct.observe(host,deadline,socket_for=lambda _:Control())
                return types.SimpleNamespace(observe=observe)
            return loader(name,path,pins)
        outside=entry.run.__globals__['outside']
        def reject(port):
            self.assertIn(port,(443,8443))
            raise ConnectionRefusedError()
        def fake_ui(request,path,deadline):
            value={'origin':'fixture','binding':scope['binding'],'observed_at':time.time(),'connected':True,'tun_enabled':True}
            write(path,value)
            return value
        def execute(action,deadline,commands):
            with patch.dict(entry.__init__.__globals__,load=load,await_ui=fake_ui,
                            outside=lambda *a:outside(*a,connect=reject)):
                phase=entry({'scope':scope,'origin':'native','action':action,'deadline':deadline,'commands':commands,
                             'dependencies':self.op.pins})
                phase.origin='fixture'
                return phase.run()
        backend=types.SimpleNamespace(run=execute)
        def receive():
            result=self.f.request.parent/'result.json'
            end=time.monotonic()+10
            while not result.exists() and time.monotonic()<end:
                time.sleep(.01)
            notice=json.loads(result.read_bytes())
            fresh={'workflow':self.f.window['window']['workflow'],'run_attempt':1,'window_decision':self.f.window}
            facts=module('finalize-failure')['assemble'](notice,self.f.request.read_bytes(),
                   (self.f.staging/'qualification-manifest.json').read_bytes(),{},fresh)
            (self.f.request.parent/('recorded-'+hashlib.sha256(result.read_bytes()).hexdigest())).mkdir(mode=0o700)
            return facts
        with ThreadPoolExecutor(max_workers=1) as worker:
            got=worker.submit(receive)
            result=coordinator['contain'](scope,backend,evidence)
            if not result['product_contained']:
                if got.done():got.result()
                self.fail(str(result)+'\n'+str([(p.name,p.read_text()[-900:]) for p in self.live.glob('*.stderr')]))
            facts=got.result()
        self.assertEqual(facts['failure'],original)
        self.assertEqual(facts['safety_cleanup']['status'],'incomplete')
        self.assertFalse(result['cleanup_complete'])
        self.assertFalse(result['qualification_passed'])
        self.assertEqual(self.secret.read_bytes(),b'fixture retained candidate credential')
        self.assertEqual(json.loads((self.base/'units').read_bytes())['sbxr-subscription.service']['UnitFileState'],'disabled')
        self.assertFalse((self.root/'proc/123').exists())
        self.f.staging.rename(self.base/'fixture-staging-taken-down')
        terminal=coordinator['verify_transport'](scope,result,backend,evidence)
        self.assertEqual(terminal['transport_status'],'restored',terminal)
        self.assertTrue(self.secret.exists())


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='serve':
        respond(Path(sys.argv[2]))
    else:
        unittest.main()
