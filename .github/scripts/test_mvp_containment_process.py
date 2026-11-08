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

HERE=Path(__file__).resolve().parent

def load(name,file):
 s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=load('phase_process','mvp-containment-process.py')
C=load('containment_core','mvp-retained-containment.py')
H=load('host_fixture','test_mvp_containment_host.py')
N=load('native_fixture','test_mvp_containment_readbacks.py')


class ProcessTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='containment-process-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.evidence=self.root/'process';self.evidence.mkdir(mode=0o700)
  self.source=self.root/'caller.py';self.source.write_text("import json,sys,time; from pathlib import Path; p=json.loads(Path(sys.argv[1]).read_text()); print(json.dumps({'binding':p['scope']['binding'],'origin':p['origin'],'outcome':'complete','observed_at':time.time(),'current_cutoff':p['scope']['original_cutoff']}))")
  self.runner=HERE/'mvp-operator-run.py';self.scope={'binding':{'run_id':215001},'original_cutoff':time.time()+2000,'signed_finish':time.time()+2000,'runtime_finish':time.time()+2000,'final_cutoff':time.time()+3800}
  self.pins={}
 def adapter(self):
  caller={'path':str(self.source),'sha256':hashlib.sha256(self.source.read_bytes()).hexdigest(),'dependencies':self.pins}
  self.manifest={'binding':self.scope['binding'],'origin':'fixture','runner_sha256':hashlib.sha256(self.runner.read_bytes()).hexdigest(),'callers':{x:caller for x in P.PHASES}}
  return P.Callers(self.scope,self.manifest,self.evidence,self.runner)
 def test_pinned_real_subprocess_and_no_replay(self):
  adapter=self.adapter();r=adapter.run('clock',time.time()+5);self.assertEqual(r['origin'],'fixture')
  with self.assertRaises(ValueError):adapter.run('clock',time.time()+5)
 def test_changed_caller_refuses_before_launch(self):
  adapter=self.adapter();self.source.write_text('raise Exception()')
  with self.assertRaises(ValueError):adapter.run('clock',time.time()+5)
  self.assertEqual(list(self.evidence.iterdir()),[])
 def test_expired_phase_cannot_be_reset(self):
  with self.assertRaises(ValueError):self.adapter().run('clock',time.time()-.1)
 def test_fixture_cannot_claim_native_origin(self):
  self.source.write_text("import json,sys;from pathlib import Path;p=json.loads(Path(sys.argv[1]).read_text());print(json.dumps({'binding':p['scope']['binding'],'origin':'native'}))")
  with self.assertRaises(ValueError):self.adapter().run('clock',time.time()+5)
 def test_process_timeout_is_not_success(self):
  self.source.write_text('import time; time.sleep(30)')
  with self.assertRaises(ValueError):self.adapter().run('clock',time.time()+1)
  receipt=json.loads((self.evidence/'clock-supervisor.json').read_text());self.assertEqual(receipt['exit'],124)
 def test_interruption_reaches_supervisor_and_child(self):
  ready=self.root/'child.pid'
  self.source.write_text("import os,time;from pathlib import Path;Path("+repr(str(ready))+").write_text(str(os.getpid()));time.sleep(30)")
  self.adapter();config=self.root/'config.json';config.write_text(json.dumps({'scope':self.scope,'manifest':self.manifest}))
  program="import importlib.util,json,sys,time;from pathlib import Path;s=importlib.util.spec_from_file_location('p',sys.argv[1]);p=importlib.util.module_from_spec(s);s.loader.exec_module(p);c=json.loads(Path(sys.argv[2]).read_text());p.Callers(c['scope'],c['manifest'],sys.argv[3],sys.argv[4]).run('clock',time.time()+20)"
  proc=subprocess.Popen([sys.executable,'-B','-c',program,str(HERE/'mvp-containment-process.py'),str(config),str(self.evidence),str(self.runner)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:
   end=time.monotonic()+5
   while not ready.exists() and time.monotonic()<end:time.sleep(.01)
   self.assertTrue(ready.exists());proc.send_signal(signal.SIGTERM);proc.communicate(timeout=12)
   self.assertNotEqual(proc.returncode,0)
   with self.assertRaises(ProcessLookupError):os.kill(int(ready.read_text()),0)
   self.assertEqual(json.loads((self.evidence/'clock-supervisor.json').read_text())['signals'],[signal.SIGTERM])
  finally:
   if proc.poll() is None:proc.kill();proc.communicate(timeout=3)

if __name__=='__main__':unittest.main()
