import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import unittest

HERE=Path(__file__).resolve().parent


class OutsideCustody(unittest.TestCase):
    def test_parent_reaps_only_its_registered_client_and_rejects_untracked_or_foreign_rows(self):
        api=runpy.run_path(str(HERE/'outside-run.py'))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            binding={'run_id':88,'manifest_sha256':'a'*64,'host':'192.0.2.10','window_sha256':'b'*64}
            api['initialize'](root,binding)
            with self.assertRaises(ValueError):
                api['stop_clients'](root,binding,['foreign'],time.time()+3)
            with self.assertRaises(ValueError):
                api['stop_clients'](root,{**binding,'run_id':89},[],time.time()+3)
            proc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(6)'],start_new_session=True)
            try:
                def stop_order(label,row):
                    api['write'](root/('stop-'+label+'.json'),row)
                api['supervise'](root,binding,'initial',lambda:proc,time.time()+4,on_registered=stop_order)
                self.assertIsNotNone(proc.returncode)
                self.assertTrue(api['stop_clients'](root,binding,['initial'],time.time()+3)['all_owned_children_reaped'])
                self.assertFalse(api['visible_group'](proc.pid))
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
