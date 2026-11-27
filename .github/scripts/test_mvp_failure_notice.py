import hashlib
import json
from pathlib import Path
import runpy
import unittest

HERE = Path(__file__).resolve().parent


class FailureNotice(unittest.TestCase):
    def test_hosted_collector_supplies_its_own_admission_and_preserves_failure(self):
        api = runpy.run_path(str(HERE/'finalize-failure.py'))
        encode = api['canonical']
        sha = lambda b: hashlib.sha256(b).hexdigest()
        m = {'workflow': {'run_id':'77'}, 'releases':[{'tag':'v1.2.3'}], 'v3_attempt':{'vps_id':'fixture'}}
        fresh = {'window_decision': {'window':{'workflow':{'run_id':'88'}}}, 'workflow':{'run_id':'88'},
                 'admitted_at':'known-only-to-collector', 'run_attempt':1}
        req = encode({'qualification_manifest_sha256':sha(encode(m)), 'scenario_id':'mvp-install',
                      'qualification_window_sha256':sha(encode(fresh['window_decision']))})
        failure = {'scenario_id':'mvp-install','operation_id':'operation-1','attempt_id':'run-88-attempt-1',
                   'actual_result':'timeout','candidate':m['releases'][0],'vps_id':'fixture'}
        original = encode(failure)
        binding = {'failure_sha256':sha(original),'manifest_sha256':sha(encode(m)),
                   'request_sha256':sha(req),'run_id':88}
        msg = api['notice'](original, binding, 'mvp-install', sha(encode(fresh['window_decision'])))
        facts = api['assemble'](msg, req, encode(m), {'protected':True}, fresh)
        self.assertEqual(facts['safety_cleanup'], {'status':'incomplete','host_state':'Unknown'})
        self.assertEqual(facts['failure'],failure)
        self.assertEqual(facts['fresh_window'],fresh)
        for key, bad in [('run_id',99), ('run_attempt',2), ('request_sha256','0'*64),
                         ('window_sha256','1'*64), ('manifest_sha256','2'*64),
                         ('original_failure_sha256','3'*64), ('safety_cleanup',{'status':'completed'})]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                api['assemble']({**msg,key:bad}, req, encode(m), {}, fresh)
