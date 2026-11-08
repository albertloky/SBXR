import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('baseline',HERE/'mvp-host-baseline.py');B=importlib.util.module_from_spec(s);s.loader.exec_module(B)

class BaselineTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='host-baseline-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  (self.root/'live').mkdir();self.path=self.root/'live/host-baseline.operator.stdout'
  self.baseline={'files':{'/etc/hosts':{'sha256':'a'*64}},'checks':{k:{'exit':0} for k in ('packages','holds','accounts','groups','firewall','ip6firewall')}}
  self.cfg={'source':'b'*40,'host':'fixture-host'};self.write()
 def write(self):
  raw=json.dumps(self.baseline).encode();self.path.write_bytes(raw);self.path.chmod(0o600)
  self.binding={**self.cfg,'baseline':{'source_file':str(self.path),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}}
 def read(self):return B.baseline_input(self.root,self.binding,self.cfg,lambda p:p.read_bytes(),('/etc/hosts',))
 def test_accepts_actual_live_capture_without_moving_or_rewriting(self):
  before=self.path.read_bytes();got,record=self.read();self.assertEqual(got,self.baseline);self.assertEqual(record,self.binding['baseline']);self.assertEqual(self.path.read_bytes(),before);self.assertFalse((self.root/'readiness').exists())
 def test_wrong_path_refuses_even_when_bytes_match(self):
  self.binding['baseline']['source_file']=str(self.root/'other/host-baseline.operator.stdout')
  with self.assertRaisesRegex(ValueError,'path differs'):self.read()
 def test_wrong_source_or_host_refuses(self):
  for key in ('source','host'):
   old=self.binding[key];self.binding[key]='changed'
   with self.assertRaisesRegex(ValueError,'source/host differs'):self.read()
   self.binding[key]=old
 def test_changed_bytes_refuse(self):
  self.path.write_bytes(b'changed')
  with self.assertRaisesRegex(ValueError,'bytes differ'):self.read()
 def test_failed_snapshot_or_missing_required_path_refuses(self):
  self.baseline['checks']['firewall']['exit']=1;self.write()
  with self.assertRaisesRegex(ValueError,'inspection failed'):self.read()
  self.baseline['checks']['firewall']['exit']=0;self.baseline['files']={};self.write()
  with self.assertRaisesRegex(ValueError,'paths missing'):self.read()
 def test_old_unpreserved_attempt_location_refuses(self):
  self.baseline['files']['/root/sbxr-qualification-evidence']={};self.write()
  with self.assertRaisesRegex(ValueError,'previous evidence'):self.read()

if __name__=='__main__':unittest.main()
