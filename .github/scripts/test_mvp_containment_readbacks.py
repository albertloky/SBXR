import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import time
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name,file):
 s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
S=load('settings_fixture','test_native_settings.py')
P=load('profiles_fixture','test_native_profiles.py')
V=load('retained_native','mvp-containment-native-readback.py')
T=load('retained_transport','mvp-containment-transport-preservation.py')
E=load('concrete_entry','mvp-containment-entry.py')

class NativeTests(unittest.TestCase):
 def setUp(self):
  self.f=S.NativeSettingsFixture();self.f.setUp();self.addCleanup(self.f.doCleanups)
  self.p=P.OriginalProfilesV3Tests();self.p.setUp();self.addCleanup(self.p.doCleanups)
  self.n=S.RECEIPTS;self.root=self.f.root
  self.store=self.root/'karing_subscribe.json';self.use=self.root/'karing_subscribe_use.json'
  zone=self.root/'zoneinfo/Asia/Hong_Kong';zone.parent.mkdir(parents=True);self.f.write(zone,self.p.zone_path.read_bytes(),0o644)
  for key,value in [('NATIVE_SUBSCRIPTION_SOURCE',self.store),('NATIVE_TIMEZONE_SOURCE',zone)]:
   p=patch.object(self.n,key,value);p.start();self.addCleanup(p.stop)
  self.candidate={'groupid':'test215','remark':'SBXR-q215-v141','servers':[{'tag':'test node'}]}
  self.base={'items':copy.deepcopy(self.p.before),'version':1}
  self.current=copy.deepcopy(self.base);self.current['items'].append(self.candidate)
  self.f.write(self.store,S.canonical(self.current));self.f.write(self.use,S.canonical({'select_default':'Existing node'}))
  original=self.f.write(self.root/'original.json',S.canonical(self.base));selected=self.f.write(self.root/'selected.json',self.use.read_bytes())
  settings=self.f.write(self.root/'baseline-settings.json',S.canonical(self.n.settings_readback(self.n.settings_binding())))
  connection=self.f.write(self.root/'connection.json',S.canonical({'connection':{'configuration':'Existing original','node':'Existing node','connected':True,'tun_enabled':True}}))
  self.inputs={'original_store_baseline':S.record(original),'selected_use_baseline':S.record(selected),'settings_baseline':S.record(settings),
   'selected_connection_baseline':S.record(connection),'settings_binding':self.n.settings_binding(),'native_timezone':self.n.native_timezone_binding(),
   'native_tzif':S.record(self.p.zone_path),'original_store_observed_at':'2026-10-20T01:39:48Z','profile_remark':'SBXR-q215-v141',
   'retained_candidate_profiles':[hashlib.sha256(self.n._canonical(self.candidate)).hexdigest()]}
  self.binding={'run_id':215001};self.ui={'binding':self.binding,'origin':'fixture','observed_at':time.time(),'connected':True,'tun_enabled':True}
 def verify(self):return V.verify(self.n,self.inputs,self.ui,authority=self.binding,source='fixture',deadline=time.time()+30)
 def test_candidate_is_retained_and_original_state_verified(self):
  before=self.store.read_bytes();r=self.verify();self.assertEqual(r['candidate_profiles_retained'],1);self.assertEqual(self.store.read_bytes(),before)
 def test_candidate_deletion_or_change_refuses(self):
  self.f.write(self.store,S.canonical(self.base))
  with self.assertRaises(ValueError):self.verify()
 def test_selected_candidate_refuses(self):
  self.f.write(self.use,S.canonical({'select_default':'test node'}))
  with self.assertRaises(ValueError):self.verify()
 def test_foreign_profile_and_original_change_refuse(self):
  self.current['items'][1]['remark']='changed original';self.f.write(self.store,S.canonical(self.current))
  with self.assertRaises(ValueError):self.verify()
 def test_stale_or_wrong_origin_ui_refuses(self):
  self.ui['origin']='native'
  with self.assertRaises(ValueError):self.verify()
  self.ui['origin']='fixture';self.ui['observed_at']-=31
  with self.assertRaises(ValueError):self.verify()
 def test_wrong_ui_connection_state_refuses(self):
  self.ui['connected']=False
  with self.assertRaises(ValueError):self.verify()

class EntryBindingTests(unittest.TestCase):
 def test_distinct_verifications_have_distinct_no_replay_labels(self):
  with tempfile.TemporaryDirectory(prefix='containment-entry-') as tmp:
   root=Path(tmp);root.chmod(0o700);record=root/'host-review.json'
   binding={'run_id':215001};preservation={'fixture':'unchanged'}
   record.write_text(json.dumps({'binding':binding,'observed_at':time.time(),'preservation':preservation}));record.chmod(0o600)
   entry=E.Entry.__new__(E.Entry);entry.binding=binding;entry.deadline=time.time()+60;entry.host_scope={'binding':binding}
   entry.runtime={'host_module':str(HERE/'mvp-containment-host.py'),'host_review_record':str(record),'local_retained':[]}
   entry.pins={entry.runtime['host_module']:E.sha(Path(entry.runtime['host_module']).read_bytes())}
   entry.scope={'retained_files':{'host:/fixture':'a'*64}};labels=set()
   def remote(label,argv,body,**kwargs):
    self.assertNotIn(label,labels);labels.add(label);compile(body,'generated-remote-source','exec')
    return 0,json.dumps({'preservation':preservation,'retained_files':{'/fixture':'a'*64}}).encode(),b''
   entry.remote=types.SimpleNamespace(remote=remote)
   for action in ('verify-host','verify-retained'):
    entry.action=action;self.assertTrue(entry.host('verify')['unrelated_state_preserved'])
   self.assertEqual(labels,{'containment-verify-host-verify','containment-verify-retained-verify'})
 def test_native_entry_refuses_fixture_origin_before_import(self):
  with self.assertRaises(ValueError):E.Entry({'scope':{'runtime':{},'binding':{}},'dependencies':{},'action':'clock','deadline':time.time()+60,'origin':'fixture'})

class OtherReadbackTests(unittest.TestCase):
 def snapshots(self):
  before={'packages':'same','holds':'same','accounts':'same','groups':'same','files':{'/etc/hosts':{'sha256':'during','kind':'regular'}}}
  before['firewall_normalized']='*nat\n'+T.REDIRECT+'\nCOMMIT';before['ip6firewall_normalized']='*filter\nCOMMIT'
  after=copy.deepcopy(before);after['firewall_normalized']='*nat\nCOMMIT';after['files']['/etc/hosts']={'sha256':'original','kind':'regular'}
  for obj in (before,after):
   for key in ('firewall','ip6firewall'):obj[key]=hashlib.sha256(obj[key+'_normalized'].encode()).hexdigest()
  return before,after,{'/etc/hosts':{'sha256':'original'}}
 def test_only_exact_transport_rollback_is_allowed(self):
  before,after,original=self.snapshots();self.assertTrue(T.compare(before,after,original))
  after['accounts']='changed'
  with self.assertRaises(ValueError):T.compare(before,after,original)
 def test_legacy_baseline_type_metadata_is_compatible_and_other_fields_remain_strict(self):
  before,after,original=self.snapshots()
  original['/etc/hosts'].update(mode='0o644',ino=1,size=100)
  before['files']['/etc/hosts'].update(mode='0o644',ino=1,size=200)
  after['files']['/etc/hosts'].update(mode='0o644',ino=2,size=100)
  self.assertTrue(T.compare(before,after,original))
  for key,bad in (('mode','0o666'),('size',101),('sha256','changed'),('kind','symlink')):
   old=after['files']['/etc/hosts'][key];after['files']['/etc/hosts'][key]=bad
   with self.assertRaises(ValueError):T.compare(before,after,original)
   after['files']['/etc/hosts'][key]=old
 def ca_snapshots(self):
  before,after,original=self.snapshots();path='/etc/ssl/certs/ca-certificates.crt'
  original[path]={'sha256':'original-ca','dev':1,'ino':10,'uid':0,'gid':0,'mode':'0o644','nlink':1,'size':100}
  before['files'][path]={**original[path],'sha256':'temporary-ca','kind':'regular'}
  after['files'][path]={**original[path],'ino':11,'kind':'regular'}
  return before,after,original,path
 def test_ca_restore_allows_only_inode_replacement(self):
  before,after,original,path=self.ca_snapshots()
  self.assertTrue(T.compare(before,after,original))
  for key,bad in (('sha256','changed'),('dev',2),('uid',1),('gid',1),('mode','0o666'),('nlink',2),('size',101),('kind','symlink'),('target','elsewhere')):
   with self.subTest(key=key):
    changed=copy.deepcopy(after);changed['files'][path][key]=bad
    with self.assertRaises(ValueError):T.compare(before,changed,original)
 def test_ca_restore_requires_complete_metadata(self):
  before,after,original,path=self.ca_snapshots()
  for key in ('sha256','dev','ino','uid','gid','mode','nlink','size'):
   with self.subTest(key=key):
    missing=copy.deepcopy(original);del missing[path][key]
    with self.assertRaises(ValueError):T.compare(before,after,missing)
    missing=copy.deepcopy(after);del missing['files'][path][key]
    with self.assertRaises(ValueError):T.compare(before,missing,original)
 def test_ca_restore_requires_current_type_and_single_link_even_when_equal(self):
  before,after,original,path=self.ca_snapshots()
  del after['files'][path]['kind']
  with self.assertRaises(ValueError):T.compare(before,after,original)
  before,after,original,path=self.ca_snapshots()
  original[path]['nlink']=2;after['files'][path]['nlink']=2
  with self.assertRaises(ValueError):T.compare(before,after,original)
 def test_unrelated_file_inode_still_exact(self):
  before,after,original,path=self.ca_snapshots()
  before['files']['/unrelated']={'ino':1};after['files']['/unrelated']={'ino':2}
  with self.assertRaises(ValueError):T.compare(before,after,original)
 def test_remaining_or_foreign_redirect_refuses(self):
  before,after,original=self.snapshots();after['firewall_normalized']+='\n'+T.REDIRECT
  with self.assertRaises(ValueError):T.compare(before,after,original)
 def test_outside_control_failure_cannot_be_port_closure(self):
  class Outside:
   def stop_clients(self,labels):return {'all_owned_children_reaped':True,'stopped_labels':labels}
  with self.assertRaises(ValueError):E.outside(Outside(),lambda:{'passed':False},[],'fixture',time.time()+30,connect=lambda p:None)
 def test_outside_exact_rejection_and_stop(self):
  class Outside:
   def stop_clients(self,labels):return {'all_owned_children_reaped':True,'stopped_labels':labels}
  def reject(port):raise ConnectionRefusedError()
  self.assertEqual(E.outside(Outside(),lambda:{'passed':True},['owned'],'fixture',time.time()+30,connect=reject)['public_ports_closed'],[443,8443])
 def test_ui_missing_reply_expires_without_creating_files(self):
  import tempfile
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'reply'
   with self.assertRaises(TimeoutError):E.await_ui({'binding':{},'origin':'fixture','created_at':time.time()},p,time.time()+.05)
   self.assertFalse(p.exists())

if __name__=='__main__':unittest.main()
