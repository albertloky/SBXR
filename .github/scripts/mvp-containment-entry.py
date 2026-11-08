#!/usr/bin/env python3
"""Concrete phase entry for the q215 retained-data fallback; import is inert.

Invoked only by the pinned process adapter. Native execution authenticates the
existing signed candidate through the prepared producer. A fixture invocation
uses explicitly injected files/transports and is tagged fixture throughout.
"""
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import socket
import stat
import sys
import time
import types


def require(v,why):
    if not v:raise ValueError(why)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def private(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno());require(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and not s.st_mode & 0o077,'private binding/input')
        raw=f.read(16*1024*1024+1)
    require(len(raw)<=16*1024*1024,'input too large');return raw


def save(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())


def load(name,path,pins):
    path=Path(path);raw=path.read_bytes();require(sha(raw)==pins[str(path)],'dependency changed: '+path.name)
    module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


def await_ui(request,reply_path,deadline,*,clock=time.time):
    """A direct CUA work item, not a credited Owner-response handoff."""
    while clock()<deadline:
        if os.path.lexists(reply_path):
            value=json.loads(private(reply_path))
            require(value['binding']==request['binding'] and value['origin']==request['origin'],'UI reply identity/origin')
            require(request['created_at']<=value['observed_at']<=clock() and clock()-value['observed_at']<=30,'UI reply stale')
            return value
        time.sleep(min(.1,max(0,deadline-clock())))
    raise TimeoutError('CUA restoration acknowledgement absent; no deletion or retry')


def outside(o,control,labels,target,deadline,*,connect=None):
    require(time.time()+12<deadline,'outside complete stop/probe budget')
    result=o.stop_clients(labels)
    require(result['all_owned_children_reaped'] is True and result['stopped_labels']==labels,'owned outside stop unproved')
    require(control()['passed'] is True,'physical outside control unproved')
    def native_connect(port):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as stream:
            stream.settimeout(min(3,deadline-time.time()-1));index=socket.if_nametoindex('en0')
            stream.setsockopt(socket.IPPROTO_IP,25,index)
            require(stream.getsockopt(socket.IPPROTO_IP,25)==index,'physical interface binding')
            stream.connect((target,port))
    probe=connect or native_connect
    for port in (443,8443):
        require(time.time()+4<deadline,'outside probe deadline')
        try:probe(port)
        except (ConnectionRefusedError,ConnectionResetError,TimeoutError):pass
        else:raise ValueError('test endpoint still accessible')
    return {'stopped_client_ids':labels,'public_ports_closed':[443,8443]}


class Entry:
    def __init__(self,payload):
        self.payload=payload;self.scope=payload['scope'];self.runtime=self.scope['runtime'];self.pins=payload['dependencies']
        self.action=payload['action'];self.deadline=payload['deadline'];self.origin=payload['origin'];self.binding=self.scope['binding']
        require(self.origin=='native','native entry refuses fixture transport; use the explicit rehearsal entry')
        require(time.time()<self.deadline,'phase deadline before import')
        self.prepared=Path(self.runtime['prepared'])
        self.remote=load('remote',self.prepared/'remote.py',self.pins)
        cfg,run,proof=self.remote.bound_candidate()
        require(self.binding['run_id']==run and self.binding['source']==cfg['source'] and self.binding['manifest_sha256']==proof['manifest_sha256'] and self.binding['tag']==cfg['tag'] and self.binding['sequence']==cfg['sequence'],'actual signed candidate differs')
        require(self.scope['signed_finish']==cfg['test_finish_unix'] and self.scope['final_cutoff']==cfg['cleanup_finish_unix'],'original approved window changed')
        require(sha(private(self.runtime['original_failure']))==self.binding['failure_sha256'],'original failure changed')
        self.cfg=cfg;self.proof=proof
        original_remote=self.remote.remote
        def bounded(label,argv,source,*,timeout,reserve,cutoff):
            remaining=self.deadline-time.time()
            require(remaining>12,'remote phase budget exhausted')
            # Absolute phase end already protects every later row; do not count
            # the global downstream reserve twice inside this nested supervisor.
            return original_remote(label,argv,source,timeout=min(timeout,remaining-1),reserve=0,
                                   cutoff=min(cutoff,self.deadline+10))
        self.remote.remote=bounded
        self.host_scope=json.loads(private(self.runtime['host_scope']))
        review=load('containment_ownership_producer',self.prepared/'review-cleanup.py',self.pins)
        budget=json.loads(private(self.runtime['ownership_budget']))
        actual=review.validate_retained_review(Path(self.runtime['ownership_review']),budget)
        require(actual['run_id']==self.binding['run_id'] and actual['request_sha256']==self.binding['request_sha256']
                and actual['uncertain_action_reconciled'] is True and actual['process_cleanup_verified'] is True,'authenticated ownership review differs')
        require(actual['exact_installed_identity_verified'] is True or actual['installed_executable_present'] is False,'installed candidate authentication absent')
        require(self.host_scope['authority_files']=={k:None if v is None else v['sha256'] for k,v in actual['authority_snapshot'].items()}
                and self.host_scope['executable_sha256']==actual['executable_sha256'],'frozen authority differs from producer')
        require(self.host_scope['binding']==self.binding and self.host_scope['effective_deadline']<=self.scope['original_cutoff'],'host scope binding')

    def retained(self,host):
        value={'host:'+name:digest for name,digest in host.items() if digest is not None}
        for name in self.runtime['local_retained']:
            value['local:'+name]=sha(private(name))
        require(value==self.scope['retained_files'],'retained host/local data changed')
        return value

    def host(self,method,**values):
        hostfile=Path(self.runtime['host_module']);source=hostfile.read_bytes()
        require(sha(source)==self.pins[str(hostfile)],'host payload changed')
        scope=dict(self.host_scope)
        preservation_path=Path(self.runtime['host_review_record'])
        if method!='review':
            review=json.loads(private(preservation_path));require(review['binding']==self.binding,'host review record binding')
            scope['reviewed_at']=review['observed_at'] # actual independent observation, never now
        # Native remote supervisor supplies another independent absolute limit.
        body=('SCOPE='+repr(scope)+'\nVALUES='+repr(values)+'\n'+source.decode()+
              '\nhost=Host(SCOPE)\ndeadline=min('+repr(self.deadline)+',float(os.environ["SBXR_Q215_OPERATOR_DEADLINE_UNIX"]))\n'+
              ('result=host.stop(deadline,VALUES["commands"])' if method=='stop' else ('while time.time()<deadline-90 and os.path.lexists("/root/sbxr-qualification-v3"):\n time.sleep(min(2,max(0,deadline-90-time.time())))\nresult=host.transport(deadline)' if method=='transport' else 'result=host.'+method+'(deadline)'))+
              '\nresult["observed_at"]=time.time()\n'+
              ('result["preservation"]=host.preservation()\n' if method=='verify' else '')+
              'print(json.dumps(result,sort_keys=True))\n').encode()
        code,out,err=self.remote.remote('containment-'+self.action+'-'+method,['python3','-B','-'],body,timeout=max(11,self.deadline-time.time()-1),reserve=0,cutoff=self.deadline+10)
        require(code==0,'remote '+method+' failed/uncertain; inspect without replay')
        result=json.loads(out)
        if method=='review':save(preservation_path,{'binding':self.binding,**result})
        if method=='verify':
            before=json.loads(private(preservation_path));require(result['preservation']==before['preservation'],'unrelated host state changed')
            result.update(ssh_preserved=True,unrelated_state_preserved=True)
        if 'retained_files' in result:result['retained_files']=self.retained(result['retained_files'])
        return result

    def native(self,prepare=False):
        inputs=json.loads(private(self.runtime['native_inputs']))
        n=load('containment_native_receipts',inputs['canonical_helper']['source_file'],self.pins)
        require(inputs['source_commit']==self.binding['source'] and inputs['candidate']=={'tag':self.binding['tag'],'sequence':self.binding['sequence']},'native inputs candidate changed')
        frozen=Path(self.runtime['native_retention_inputs'])
        if prepare:
            raw,_=n._native_bytes(n.NATIVE_SUBSCRIPTION_SOURCE);store=json.loads(raw,object_pairs_hook=n.unique)
            inputs['retained_candidate_profiles']=sorted(sha(n._canonical(p)) for p in store['items'] if p.get('remark')==inputs['profile_remark'])
            save(frozen,inputs)
            connection=json.loads(n.source_file(inputs['selected_connection_baseline']))['connection']
            request={'binding':self.binding,'origin':'native','created_at':time.time(),'deadline':self.deadline,
                     'operation':'Restore original selected profile, node, connection and TUN using CUA; retain candidate profile and data. Do not delete.', 'original_connection':connection}
            if not self.scope['http_state_possible']:
                request['operation']='Observe original Karing selection, connection and TUN through CUA; do not change or delete anything.'
            save(self.runtime['cua_request'],request)
            ui_end=self.deadline-15 if self.scope['http_state_possible'] else min(self.deadline-50,time.time()+20)
            ui=await_ui(request,Path(self.runtime['cua_reply']),ui_end)
        else:
            inputs=json.loads(private(frozen));ui=json.loads(private(self.runtime['cua_reply']))
        verifier=load('retained_native_verifier',self.runtime['native_verifier'],self.pins)
        return verifier.verify(n,inputs,ui,authority=self.binding,source='native',deadline=self.deadline)

    def run(self):
        action=self.action
        if action=='clock':
            c=load('containment_clock',self.prepared/'read-current-clock.py',self.pins)
            value=c.read_current_clock('containment-clock',self.runtime['scenario'],mode='cleanup',reserve=0)
            require(value['request_sha256']==self.binding['request_sha256'],'current request changed')
            save(self.runtime['clock_record'],value)
            result={'clock_consistent':True,'current_cutoff':min(self.scope['original_cutoff'],value['effective_deadline_unix'])}
        elif action=='ownership':result=self.host('review')
        elif action=='stop-services':result=self.host('stop',commands=self.payload['commands'])
        elif action=='verify-host':result=self.host('verify')
        elif action=='stop-outside':
            o=load('containment_outside',self.prepared/'outside-run.py',self.pins)
            d=load('containment_direct',self.prepared/'direct-control.py',self.pins)
            result=outside(o,lambda:d.observe('m5-containment-control'),self.scope['outside_client_ids'],self.binding['host'],self.deadline)
        elif action=='restore-client':result=self.native(prepare=True)
        elif action=='verify-retained':
            result=self.native(prepare=not self.scope['http_state_possible'])
            result['retained_files']=self.host('verify')['retained_files']
            f=load('containment_failure',self.prepared/'finalize-failure.py',self.pins)
            proof=f.prepare_after_cleanup(Path(self.runtime['clock_record']),None,None,deadline_monotonic=time.monotonic()+max(0,self.deadline-time.time()-1))
            require(proof['safety_cleanup']['status']=='incomplete','retained data cannot mean completed cleanup')
        elif action=='record-failure':
            require(self.runtime['transport_disposal_confirmation']['run_id']==self.binding['run_id'],'actual live-job disposal confirmation missing')
            f=load('containment_failure_publish',self.prepared/'finalize-failure.py',self.pins)
            # The prepared finalizer otherwise loads a fresh remote module. Bind
            # its existing operation to this same independently bounded phase.
            f.n.invoke=lambda label,argv,body,cap,downstream,e: self.remote.remote(label,argv,body,timeout=cap,reserve=downstream,cutoff=e)
            f.submit()
            result={'failure_sha256':self.binding['failure_sha256'],'failure_recorded':True,'qualification_passed':False}
        elif action=='verify-transport':
            # Observe once after the already approved automatic teardown. No down,
            # delete or retry is executed by this retained-data caller.
            result=self.host('transport');result.update(ssh_preserved=True,unrelated_state_preserved=False)
            # Full original preservation comparison must use its retained actual
            # pre-run proof; never mark it true merely because transport is absent.
            checker=load('containment_preservation',self.runtime['transport_preservation_verifier'],self.pins)
            require(checker.verify_retained_transport(result,self.runtime,self.binding),'transport preservation unproved')
            result['unrelated_state_preserved']=True
        else:raise ValueError('unknown containment operation')
        require(time.time()<self.deadline,'phase completion past deadline')
        result.update(binding=self.binding,origin='native',observed_at=time.time(),outcome='complete')
        result.setdefault('current_cutoff',self.scope['original_cutoff'])
        return result


def main():
    payload=json.loads(private(sys.argv[1]));print(json.dumps(Entry(payload).run(),sort_keys=True))

if __name__=='__main__':main()
