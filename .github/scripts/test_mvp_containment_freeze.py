import copy
import datetime
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent

def load(name,file):
 s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
H=load('freeze_host_tests','test_mvp_containment_host.py')
F=load('freeze','mvp-containment-freeze.py')
B=load('bindings','mvp-containment-bindings.py')

class FreezeTests(unittest.TestCase):
 def setUp(self):
  self.fixture=H.HostTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups);h=self.fixture
  for path in H.h.AUTHORITY:h.scope['authority_files'][path]=h.write(path,b'{}')
  self.binding={**h.scope['binding'],'source':'a'*40,'request_sha256':'b'*64}
  self.review={'run_id':215001,'source':'a'*40,'manifest_sha256':self.binding['manifest_sha256'],'request_sha256':'b'*64,'observed_at':datetime.datetime.fromtimestamp(1000,datetime.timezone.utc).isoformat(),'uncertain_action_reconciled':True,'process_cleanup_verified':True,'exact_installed_identity_verified':True,'installed_executable_present':True,'authority_snapshot':{k:{'sha256':v} for k,v in h.scope['authority_files'].items()},'executable_sha256':h.scope['executable_sha256'],'current_E':2000}
  self.policy={**h.scope,'original_cutoff':2000,'final_cutoff':3800,'original_ca_bundle_sha256':'c'*64,'startup_dropin_sha256':'d'*64}
 def freeze(self):
  h=self.fixture
  return F.freeze(H.h.Host,self.review,self.binding,self.policy,root=h.root,command=h.command,now=lambda:h.clock,deadline=1100)
 def test_real_files_frozen_without_mutation(self):
  got=self.freeze();self.assertEqual(got['retained_files']['/etc/sing-box/config.json'],self.fixture.scope['retained_files']['/etc/sing-box/config.json']);self.assertEqual(got['reviewed_at'],1000);self.assertEqual(self.fixture.stops(),[])
 def test_stale_or_unreconciled_review_refuses(self):
  self.fixture.clock=1121
  with self.assertRaises(ValueError):self.freeze()
  self.fixture.clock=1000;self.review['uncertain_action_reconciled']=False
  with self.assertRaises(ValueError):self.freeze()
 def test_candidate_and_authority_change_refuses(self):
  self.binding['source']='e'*40
  with self.assertRaises(ValueError):self.freeze()
  self.binding['source']='a'*40;self.fixture.write('/var/lib/sbxr/installed.json',b'changed')
  with self.assertRaises(ValueError):self.freeze()
 def test_unknown_dropin_refuses(self):
  self.fixture.write('/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf',b'foreign')
  with self.assertRaises(ValueError):self.freeze()
 def test_owned_inventory_symlink_refuses(self):
  (self.fixture.root/'etc/sing-box/alias').symlink_to('config.json')
  with self.assertRaises(ValueError):self.freeze()
 def test_empty_installation_does_not_require_or_create_lock(self):
  h=self.fixture
  for path in H.h.AUTHORITY+('/usr/local/bin/sbxr','/run/lock/sbxr.lock'):(h.root/path.lstrip('/')).unlink()
  for unit in H.h.UNITS:(h.root/h.scope['expected_units'][unit]['fragment_paths'][0].lstrip('/')).unlink()
  for state in h.states.values():state.update(LoadState='not-found',ActiveState='inactive',MainPID='0',ControlPID='0',FragmentPath='',DropInPaths='')
  self.review.update(authority_snapshot={k:None for k in H.h.AUTHORITY},executable_sha256=None,installed_executable_present=False,exact_installed_identity_verified=False)
  scope=self.freeze();host=H.h.Host(scope,root=h.root,command=h.command,now=lambda:h.clock)
  self.assertEqual(host.stop(1100,[])['stopped_units'],[]);self.assertFalse((h.root/'run/lock/sbxr.lock').exists())
 def test_source_unit_strings_are_exact(self):
  repo=HERE.parents[1]
  self.assertIn(b'ExecStart=/usr/local/bin/sbxr --subscription-serving\n',B.rust_string(repo/'src/runtime_handoff.rs','SERVING_UNIT'))
  self.assertEqual(B.rust_string(repo/'src/client_identity.rs','STARTUP_DROP_IN'),b'[Service]\nExecCondition=+/usr/local/bin/sbxr --proxy-start-authorize\n')

if __name__=='__main__':unittest.main()
