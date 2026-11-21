"""Exercise real bash/jq/filesystem; substitute only the network verifier command."""
import json, os, pathlib, subprocess, tempfile, unittest
SCRIPT = pathlib.Path(__file__).with_name('signing-latest-recheck.sh').resolve()
SECRET = 'must-not-appear-private-token?sig=secret'
IDENTITY = {'tag':'v3.1.118','commit':'a'*40,'release_index_sha256':'b'*64}
ACCEPTED = json.dumps({'outcome':'accepted','release_identity':IDENTITY,'private':SECRET})
HTTP_RECEIPTS = {
    'quota': {'stage':'latest_metadata','destination':'github_api','redirect_count':0,
              'http_status':403,'rate_limit_exhausted':True,'retry_after_present':False},
    'cdn-refused': {'stage':'release_archive','destination':'github_release_cdn','redirect_count':1,
                    'http_status':403,'rate_limit_exhausted':None,'retry_after_present':False},
    'invalid-evidence': {'stage':'latest_metadata','destination':'github_api','redirect_count':0,
                         'http_status':200,'rate_limit_exhausted':False,'retry_after_present':False},
}
class SigningDiagnostics(unittest.TestCase):
    def test_shell_outcomes(self):
        cases = [
            ('accepted', ACCEPTED, 0, 0, 'accepted', 'matched'),
            ('mismatch', ACCEPTED, 0, 1, 'accepted', 'not-completed'),
            ('refused', '{"outcome":"refused"}', 0, 1, 'refused', 'not-completed'),
            *[(name, json.dumps({'outcome':'refused','private':SECRET}), 0, 1, 'refused', 'not-completed')
              for name in HTTP_RECEIPTS],
            ('unavailable', '{"outcome":"unavailable"}', 0, 1, 'unavailable', 'not-completed'),
            ('process', '', 42, 42, 'empty', 'not-started'),
            ('process-result', ACCEPTED, 42, 42, 'accepted', 'not-started'),
            ('terminated', '{"outcome":', 143, 143, 'invalid', 'not-started'),
            ('invalid', '{"outcome":', 0, 2, 'invalid', 'not-completed'),
            ('empty', '', 0, 1, 'empty', 'not-completed'),
            ('missing', '', 0, 2, 'missing', 'not-completed'),
            ('untrusted', json.dumps({'outcome':SECRET}), 0, 1, 'invalid', 'not-completed'),
            ('multiple', ACCEPTED+'\n'+ACCEPTED, 0, 0, 'invalid', 'matched'),
            ('write-failure', '{"outcome":"refused"}', 0, 1, None, 'not-completed'),
            ('write-failure-success', ACCEPTED, 0, 0, None, 'matched'),
        ]
        for name, result, verifier_status, status, outcome, comparison in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                cargo = root/'cargo'
                cargo.write_text('''#!/bin/bash
set -eu
test "$#" -eq 10
test "${*:1:8}" = 'run --locked --offline --release --manifest-path tooling/rust-package/Cargo.toml -- verify-public-latest'
test "$9" = --http-diagnostics
test "${10}" = "${RUNNER_TEMP:-.}/signing-latest-http.json"
if test -n "$HTTP_RECEIPT"; then printf '%s' "$HTTP_RECEIPT" > "${10}"; fi
if test "$CASE" = missing; then rm current-source-verification.json; else printf '%s' "$RESULT"; fi
if test "$CASE" = terminated; then kill -TERM "$$"; fi
exit "$VERIFIER_STATUS"
''')
                cargo.chmod(0o700)
                facts={'latest_tag': 'changed' if name=='mismatch' else IDENTITY['tag'], 'releases':[{'tag':IDENTITY['tag'],'commit':IDENTITY['commit'],'index':{'sha256':IDENTITY['release_index_sha256']}}]}
                (root/'candidate-preflight-facts.json').write_text(json.dumps(facts))
                runner_temp = root/'runner temp'
                runner_temp.mkdir()
                diagnostic_dir = root if name == 'accepted' else runner_temp
                if name.startswith('write-failure'):
                    (diagnostic_dir/'signing-latest-diagnostics.json').mkdir()
                expected_receipt = HTTP_RECEIPTS.get(name)
                env=dict(
                    os.environ, PATH=directory+os.pathsep+os.environ['PATH'], CASE=name, RESULT=result,
                    VERIFIER_STATUS=str(verifier_status), GH_TOKEN=SECRET, V3_ATTEMPT=SECRET,
                    RUNNER_TEMP=str(runner_temp),
                    HTTP_RECEIPT=json.dumps(expected_receipt) if expected_receipt is not None else '',
                )
                if name == 'accepted':
                    env.pop('RUNNER_TEMP')
                run=subprocess.run(['bash',str(SCRIPT)],cwd=root,env=env,capture_output=True,text=True)
                self.assertEqual(run.returncode,status,run.stderr)
                self.assertNotIn(SECRET,run.stdout+run.stderr)
                receipt = diagnostic_dir/'signing-latest-http.json'
                if expected_receipt is None:
                    self.assertFalse(receipt.exists())
                else:
                    raw_receipt = receipt.read_text()
                    self.assertNotIn(SECRET,raw_receipt)
                    self.assertEqual(json.loads(raw_receipt),expected_receipt)
                if outcome is not None:
                    raw=(diagnostic_dir/'signing-latest-diagnostics.json').read_text()
                    self.assertNotIn(SECRET,raw)
                    self.assertEqual(json.loads(raw),{'schema':'sbxr-signing-latest-diagnostics-v1','verifier_exit':verifier_status,'verifier_outcome':outcome,'baseline_comparison':comparison,'exit_status':status})
if __name__=='__main__': unittest.main()
