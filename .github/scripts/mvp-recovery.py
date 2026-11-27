#!/usr/bin/env python3
"""Operate the reviewed fresh-window launch and retained-failure recovery path."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import runpy
import time

HERE=Path(__file__).resolve().parent


def require(value, why):
    if not value:
        raise ValueError(why)


def component(name):
    return runpy.run_path(str(HERE/(name+'.py')))


def outside_identity(cfg,run,proof):
    return dict(run_id=run,manifest_sha256=proof['manifest_sha256'],window_sha256=proof['window_sha256'],host=cfg['host'])


def verify_revision(cfg, approval, proposal):
    repo=HERE.parents[1]
    commit=approval['operator_commit']
    require(re.fullmatch('[0-9a-f]{40}',commit),'workflow revision')
    paths={Path(p) for p in proposal['callers']['clock']['dependencies'] if Path(p).is_relative_to(HERE)}
    paths.update(HERE/Path(name).name for name in cfg['provider_pins'])
    paths.update((repo/'.github/workflows/candidate.yml',HERE/'v3-recurring-evidence.sh'))
    for path in paths:
        rel=path.relative_to(repo)
        blob=subprocess.check_output(['git','-C',str(repo),'show',commit+':'+str(rel)],timeout=3)
        require(blob==path.read_bytes(),'reviewed operator differs from protected workflow: '+str(rel))
    constants={'src/runtime_handoff.rs':'SERVING_UNIT','src/client_identity.rs':'STARTUP_DROP_IN',
               'src/host/owner_runtime/testdata/sing-box.service':None}
    rust_value=component('mvp-containment-bindings')['rust_value']
    for name,constant in constants.items():
        signed=subprocess.check_output(['git','-C',str(repo),'show',cfg['source']+':'+name],timeout=3)
        current=(repo/name).read_bytes()
        if constant:
            signed,current=(rust_value(body.decode(),constant) for body in (signed,current))
        require(signed==current,'reviewed unit definition differs from the signed candidate')


class Operator:
    def __init__(self,prepared,*,post_transport=False):
        self.proposal=component('mvp-containment-bindings')['proposal'](HERE.parents[1],prepared)
        self.prepared=Path(self.proposal['runtime_static']['prepared'])
        self.live=self.prepared.parent/'live'
        entry=component('mvp-containment-entry')
        self.remote=entry['load']('fresh_recovery_remote',self.prepared/'remote.py',self.pins)
        self.cfg,self.run,self.proof=self.remote.bound_candidate(post_transport=post_transport)
        self.approval=self.document('operator-approval.json')
        require(self.remote.sha(self.remote.canonical(self.proposal))==self.approval['proposal_sha256'],
                'actual caller, source, native baseline or destination differs from approval')
        require(self.approval['automatic_transport_disposal_approved'] is True and self.approval['job_id']==self.proof['job_id']
                and self.approval['run_id']==self.run and self.approval['run_attempt']==1
                and self.approval['window_sha256']==self.proof['window_sha256'],'terminal disposition authority unavailable')
        verify_revision(self.cfg,self.approval,self.proposal)
        self.outside_binding=outside_identity(self.cfg,self.run,self.proof)
        self.native=json.loads(self.remote.private(self.prepared/'native-inputs.json'))
        self.baseline,self.baseline_record=component('mvp-host-baseline')['baseline_input'](
            self.prepared.parent,self.approval,self.cfg,self.remote.private,
            ('/etc/hosts','/etc/ssl/certs/ca-certificates.crt'))
        self.registry=self.live/'outside'

    @property
    def pins(self):
        return self.proposal['callers']['clock']['dependencies']

    def document(self,name):
        return json.loads(self.remote.private(self.live/name))

    def initialize(self):
        require(not component('outside-run')['program_pids'](self.approval['outside_program']),
                'outside client already present before custody')
        self.registry.mkdir(mode=0o700)
        component('outside-run')['initialize'](self.registry,self.outside_binding)

    def outside_client(self,label):
        manifest=self.document('outside-'+label+'-binding.json')
        record=self.approval['outside_program']
        require(manifest['executable_sha256']==record['sha256'] and manifest['binding']==self.outside_binding
                and manifest['label']==label,'outside client authorization differs')
        req=self.document('outside-'+label+'-intent.json')
        observation=self.send('clock',req,time.time()+10)
        cutoff=observation['effective_deadline_unix']
        reserve=1170 if req['scenario']=='mvp-install' else 1470
        end=manifest['deadline']
        require(time.time()<end and end+10+reserve<cutoff,'outside client expiry exceeds available window')
        with (self.live/('outside-'+label+'.log')).open('xb') as log:
            os.fchmod(log.fileno(),0o600)
            component('outside-run')['run_client'](self.registry,self.outside_binding,label,end,
                Path(record['source_file']),self.live/('outside-'+label+'.json'),manifest,log=log)

    def send(self,phase,intent,deadline,**values):
        return self.remote.call(self.cfg,self.run,self.proof,dict(phase=phase,intent=intent,deadline=deadline,**values))

    def launch(self,scenario,operation,request_pin):
        require(component('outside-run')['read'](self.registry/'registry.json')==self.outside_binding,'outside owner unavailable')
        require(not os.path.lexists(self.registry/'closed.json'),'outside recovery already started')
        custody=component('mvp-journey-custody')
        cap=custody['CAPS'].get(scenario,{}).get(operation)
        require(cap is not None,'operation outside this journey')
        # Include the existing 30s remote start/connection allocation and 10s local stop.
        expiry=int(time.time())+cap+15
        intent=dict(run_id=self.run,run_attempt=1,manifest_sha256=self.proof['manifest_sha256'],
                    request_sha256=request_pin,window_sha256=self.proof['window_sha256'],machine_sha256=self.cfg['machine_sha256'],
                    scenario=scenario,operation=operation,remote_deadline=expiry)
        custody['validate'](intent)
        return self.send('launch',intent,expiry+15,units=self.proposal['source_unit_pins'],
                         startup_sha256=self.proposal['startup_dropin_sha256'])

    def remove(self,scenario,operation,request_pin,choice,*,observe_only=False):
        custody=component('mvp-journey-custody')
        records=self.remote.copies(self.live)
        key=choice if observe_only else operation
        matching=[r['intent'] for r in records if (r['intent']['operation'],r['intent']['request_sha256'],r['intent']['scenario'])
                  ==(key,request_pin,scenario)]
        require(len(matching)==1 and choice in custody['REMOVALS'],'supported removal binding differs')
        prior,=matching
        phase_end=self.cfg['cleanup_finish_unix']-60 if scenario=='mvp-removal' else self.cfg['test_finish_unix']
        if not observe_only:
            require(operation not in custody['REMOVALS'],'removal cannot retry a removal')
            decision=self.document('removal-decision.json')
            require(decision['interrupted']==prior and decision['choice']==choice and decision['job_id']==self.proof['job_id']
                    and decision['status']=='approved' and 0<=time.time()-decision['observed_at']<=120
                    and type(decision['http_state_possible']) is bool and (decision['http_state_possible'] or scenario=='mvp-install'),
                    'current supported-removal decision differs')
            review=self.send('ownership',prior,min(time.time()+80,phase_end),copies=records)
            require(review['executable_sha256']==decision['executable_sha256'] and review['authority_snapshot']==decision['authority_snapshot'],
                    'supported removal ownership differs from reviewed state')
            cutoff=min(review['current_E'],phase_end)
            reserve=620 if decision['http_state_possible'] else 320
            require(time.time()+390+10+reserve<cutoff,'full supported-removal budget does not fit')
            intent={**prior,'operation':choice,'remote_deadline':int(time.time())+375}
            checked=dict(interrupted=prior,copies=records,ownership=review,cutoff=cutoff,http_state_possible=decision['http_state_possible'])
            result=self.send('remove',intent,intent['remote_deadline']+15,units=self.proposal['source_unit_pins'],
                             startup_sha256=self.proposal['startup_dropin_sha256'],reviewed=checked)
            require(result['exit']==0,'supported removal uncertain; inspect without replay')
            prior=intent
        proof=self.send('absence',prior,min(time.time()+80,phase_end),units=self.proposal['source_unit_pins'],
                        copies=self.remote.copies(self.live))
        self.remote.save(self.live/'product-absence.json',proof)
        return proof

    def freeze(self,scenario,operation,request_pin):
        records=self.remote.copies(self.live)
        candidates=[r['intent'] for r in records if (r['intent']['scenario'],r['intent']['operation'],r['intent']['request_sha256'])
                    ==(scenario,operation,request_pin)]
        require(len(candidates)==1,'interrupted launch identity unavailable')
        intent,=candidates
        original_path=self.live/'original-failure.json'
        original=self.remote.private(original_path)
        binding=dict(run_id=self.run,source=self.cfg['source'],host=self.cfg['host'],tag=self.cfg['tag'],sequence=self.cfg['sequence'],
                     manifest_sha256=self.proof['manifest_sha256'],request_sha256=request_pin,failure_sha256=self.remote.sha(original))
        component('finalize-failure')['notice'](original,binding,scenario,self.proof['window_sha256'])
        phase_end=self.cfg['cleanup_finish_unix']-60 if scenario=='mvp-removal' else self.cfg['test_finish_unix']
        observation=self.send('clock',intent,min(time.time()+80,phase_end))
        cutoff=min(phase_end,observation['effective_deadline_unix'])
        opts=self.document('recovery-decision.json')
        require(opts['binding']==binding and set(opts['local_retained'])>= {str(original_path)}
                and all(Path(p).is_relative_to(self.live) for p in opts['local_retained']), 'retention decision differs')
        http=opts['http_state_possible']
        require(type(http) is bool and (http or scenario=='mvp-install'),'HTTP retention reserve missing')
        require(time.time()+80+(1200 if http else 900)<cutoff,'full recovery and review do not fit')
        policy=dict(machine_sha256=intent['machine_sha256'],boot_sha256=records[0]['process']['boot_sha256'],
                    expected_units=self.proposal['source_unit_pins'],startup_dropin_sha256=self.proposal['startup_dropin_sha256'],
                    original_cutoff=cutoff,final_cutoff=self.cfg['cleanup_finish_unix'],unrelated_files=list(self.baseline['files']),
                    original_ca_bundle_sha256=self.baseline['files']['/etc/ssl/certs/ca-certificates.crt']['sha256'])
        frozen=self.send('freeze',intent,min(time.time()+80,cutoff),copies=records,binding=binding,policy=policy)
        host=frozen['scope']
        self.remote.save(self.live/'containment-host-scope.json',host)
        self.remote.save(self.live/'ownership-review.json',frozen['review'])
        owned_local=set(opts['local_retained'])
        custody=component('mvp-journey-custody')
        for record in records:
            name=custody['filename'](record['intent'])
            phase='remove' if record['intent']['operation'] in custody['REMOVALS'] else 'launch'
            owned_local.update(str(self.live/n) for n in (name,'intent-'+name,phase+'-'+name+'.stderr'))
        for path in self.registry.glob('intent-*.json'):
            label=path.name[7:-5]
            owned_local.update(str(self.live/('outside-'+label+suffix)) for suffix in
                               ('.json','-binding.json','-intent.json','.log'))
        retained={'host:'+k:v for k,v in host['retained_files'].items() if v is not None}
        for path in sorted(owned_local):
            retained['local:'+path]=self.remote.sha(self.remote.private(path))
        labels=sorted(p.name[7:-5] for p in self.registry.glob('intent-*.json'))
        runtime={**self.proposal['runtime_static'],**self.proposal['late_bound_paths'],'scenario':scenario,
                 'ownership_review':str(self.live/'ownership-review.json'),'interrupted_intent':intent,
                 'local_retained':sorted(owned_local),'outside_binding':self.outside_binding,'outside_program':self.approval['outside_program'],
                 'original_host_baseline':self.baseline_record,'failure_notice':str(self.live/'retained-failure-notice.json'),
                 'transport_disposal_confirmation':self.approval}
        scope=dict(binding=binding,original_cutoff=cutoff,signed_finish=phase_end,
                   runtime_finish=cutoff,final_cutoff=self.cfg['cleanup_finish_unix'],expected_units={
                   k:{'fragment_sha256':v['fragment_sha256'],'dropins':v['dropins']} for k,v in host['expected_units'].items()},
                   confirmation=opts['confirmation'],http_state_possible=http,candidate_profile=self.native['profile_remark'],
                   retained_files=retained,outside_client_ids=labels,runtime=runtime)
        component('mvp-retained-containment')['validate_scope'](scope,time.time())
        self.remote.save(self.live/'retained-scope.json',scope)
        return scope

    def containment(self,post=False):
        scope=self.document('retained-scope.json')
        directory=self.live/'containment'
        if not post:
            directory.mkdir(mode=0o700)
        backend=component('mvp-containment-process')['Callers'](scope,{**self.proposal,'binding':scope['binding']},
                                                               directory,self.proposal['runner'])
        coordinator=component('mvp-retained-containment')
        if post:
            original=json.loads(self.remote.private(directory/'containment-outcome.json'))
            return coordinator['verify_transport'](scope,original,backend,directory)
        return coordinator['contain'](scope,backend,directory)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prepared',type=Path)
    sub=parser.add_subparsers(dest='action',required=True)
    for action in ('initialize','launch','outside-client','supported-removal','verify-absence','freeze','contain','verify-transport'):
        command=sub.add_parser(action)
        if action=='outside-client':
            command.add_argument('label',choices=sorted(component('outside-run')['LABELS']))
        if action in ('launch','freeze','supported-removal','verify-absence'):
            command.add_argument('scenario')
            command.add_argument('operation')
            command.add_argument('request_sha256')
            if action in ('supported-removal','verify-absence'):
                command.add_argument('choice',choices=('complete-removal','finish-removal'))
    args=parser.parse_args()
    op=Operator(args.prepared,post_transport=args.action=='verify-transport')
    if args.action=='initialize':
        op.initialize()
        return
    if args.action=='outside-client':
        op.outside_client(args.label)
        return
    if args.action=='launch':
        value=op.launch(args.scenario,args.operation,args.request_sha256)
        require(value['exit']==0,'journey operation failed; inspect without replay')
    elif args.action in ('supported-removal','verify-absence'):
        value=op.remove(args.scenario,args.operation,args.request_sha256,args.choice,observe_only=args.action=='verify-absence')
    elif args.action=='freeze':
        op.freeze(args.scenario,args.operation,args.request_sha256)
        return
    else:
        value=op.containment(args.action=='verify-transport')
    print(json.dumps(value,sort_keys=True))
    if args.action=='contain' and value['status']!='contained-with-retained-data':
        raise SystemExit(1)
    if args.action=='verify-transport' and value['transport_status']!='restored':
        raise SystemExit(1)


if __name__=='__main__':
    main()
