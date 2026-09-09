import contextlib
import importlib.util
import io
import hashlib
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
                'runtime':{'system':'Linux','machine':'x86_64','uid':0},
                'platform':'Linux-6.8.0-x86_64-with-glibc2.39',
                'interpreter':'/snap/certbot/5893/usr/bin/python3.12',
                'interpreter_sha256':'a'*64,'fixture_sha256':'b'*64,
                'tests':[{'name':name,'exit_code':0} for name in r.linux.TESTS]}
    def test_complete_exact_report(self): self.assertTrue(r.validate(self.report(),101))
    def test_missing_failed_stale_or_changed_report_refused(self):
        for fault in ['missing','failed','stale','future','changed','live','duplicate','runtime','interpreter','fixture','platform']:
            with self.subTest(fault=fault):
                report=self.report()
                if fault == 'missing': report['tests'].pop()
                if fault == 'failed': report['tests'][0]['exit_code']=1
                if fault == 'stale': report['completed_unix']=-90000
                if fault == 'future': report['completed_unix']=102
                if fault == 'changed': report['source_sha256']['exec-gate.py']='0'*64
                if fault == 'live': report['live_evidence']=True
                if fault == 'duplicate': report['tests'][1]=report['tests'][0]
                if fault == 'runtime': report['runtime']['uid']=1000
                if fault == 'interpreter': report['interpreter']='/usr/bin/python3'
                if fault == 'fixture': report['fixture_sha256']='invalid'
                if fault == 'platform': report['platform']='Darwin-test'
                with self.assertRaises(ValueError): r.validate(report,101)

    def write_logs(self, report, path):
        for test in report['tests']:
            log=path.with_name(path.name+'.'+test['name']+'.log')
            log.write_bytes(b'fixture passed\n')
            log.chmod(0o600)
            test.update(output_file=log.name,output_sha256=hashlib.sha256(log.read_bytes()).hexdigest())

    def test_logs_are_required_protected_and_digest_bound(self):
        for fault in [None,'missing','tampered','symlink','mode','traversal']:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as root:
                path=Path(root,'report.json'); report=self.report()
                self.write_logs(report,path)
                first=path.with_name(report['tests'][0]['output_file'])
                if fault == 'missing': first.unlink()
                if fault == 'tampered': first.write_bytes(b'changed\n')
                if fault == 'symlink':
                    target=path.with_name('other.log'); first.rename(target); first.symlink_to(target)
                if fault == 'mode': first.chmod(0o644)
                if fault == 'traversal': report['tests'][0]['output_file']='../other.log'
                if fault is None: r.validate_logs(report,path)
                else:
                    with self.assertRaises((ValueError,OSError)): r.validate_logs(report,path)

    def test_bundle_includes_procedures_module_and_dispatch(self):
        hashes=r.linux.source_hashes()
        for name in ['README.md','../../../docs/acceptance/v4-operator-procedures.md','../v3-packaged-live.sh','../v3-candidate-dispatch.sh','../v3-recurring-evidence.sh']:
            self.assertIn(name,hashes)

    def test_main_refuses_report_replacement_during_rehearsal(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root,'report.json')
            report=self.report()
            self.write_logs(report,path)
            path.write_text(json.dumps(report,separators=(',',':')))
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
