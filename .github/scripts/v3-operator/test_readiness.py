import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('readiness',Path(__file__).with_name('check-readiness.py'))
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class Readiness(unittest.TestCase):
    def report(self):
        return {'schema':'sbxr-v4-linux-rehearsal-v1','live_evidence':False,
                'completed_unix':100,'source_sha256':r.linux.source_hashes(),
                'tests':[{'name':name,'exit_code':0} for name in r.linux.TESTS]}
    def test_complete_exact_report(self): self.assertTrue(r.validate(self.report(),101))
    def test_missing_failed_stale_or_changed_report_refused(self):
        for fault in ['missing','failed','stale','future','changed','live','duplicate']:
            with self.subTest(fault=fault):
                report=self.report()
                if fault == 'missing': report['tests'].pop()
                if fault == 'failed': report['tests'][0]['exit_code']=1
                if fault == 'stale': report['completed_unix']=-90000
                if fault == 'future': report['completed_unix']=102
                if fault == 'changed': report['source_sha256']['exec-gate.py']='0'*64
                if fault == 'live': report['live_evidence']=True
                if fault == 'duplicate': report['tests'][1]=report['tests'][0]
                with self.assertRaises(ValueError): r.validate(report,101)

    def test_main_refuses_report_replacement_during_rehearsal(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root,'report.json')
            path.write_text(json.dumps(self.report(),separators=(',',':')))
            path.chmod(0o600)
            replacement=Path(root,'replacement.json')
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            def replace(*args,**kwargs):
                replacement.replace(path)
            output=io.StringIO()
            with patch.dict(os.environ,{'SBXR_OPERATOR_REHEARSAL_REPORT':str(path)}), \
                 patch.object(r.subprocess,'run',replace), \
                 patch.object(r.time,'time',return_value=101), \
                 contextlib.redirect_stdout(output):
                with self.assertRaises(ValueError): r.main()
            self.assertEqual(output.getvalue(),'')

if __name__ == '__main__': unittest.main()
