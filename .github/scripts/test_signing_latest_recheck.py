"""Exercise real bash/jq/filesystem; substitute only the network verifier command."""
import json, os, pathlib, subprocess, tempfile, unittest
SCRIPT = pathlib.Path(__file__).with_name('signing-latest-recheck.sh').resolve()
SECRET = 'must-not-appear-private-token?sig=secret'
IDENTITY = {'tag':'v3.1.118','commit':'a'*40,'release_index_sha256':'b'*64}
ACCEPTED = json.dumps({'outcome':'accepted','release_identity':IDENTITY,'private':SECRET})
class SigningDiagnostics(unittest.TestCase):
    def test_shell_outcomes(self):
        cases = [
            ('accepted', ACCEPTED, 0, 0, 'accepted', 'matched'),
            ('mismatch', ACCEPTED, 0, 1, 'accepted', 'not-completed'),
            ('refused', '{"outcome":"refused"}', 0, 1, 'refused', 'not-completed'),
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
test "$*" = 'run --locked --offline --release --manifest-path tooling/rust-package/Cargo.toml -- verify-public-latest'
if test "$CASE" = missing; then rm current-source-verification.json; else printf '%s' "$RESULT"; fi
if test "$CASE" = terminated; then kill -TERM "$$"; fi
exit "$VERIFIER_STATUS"
''')
                cargo.chmod(0o700)
                facts={'latest_tag': 'changed' if name=='mismatch' else IDENTITY['tag'], 'releases':[{'tag':IDENTITY['tag'],'commit':IDENTITY['commit'],'index':{'sha256':IDENTITY['release_index_sha256']}}]}
                (root/'candidate-preflight-facts.json').write_text(json.dumps(facts))
                if name.startswith('write-failure'):
                    (root/'signing-latest-diagnostics.json').mkdir()
                env=dict(os.environ, PATH=directory+os.pathsep+os.environ['PATH'], CASE=name, RESULT=result, VERIFIER_STATUS=str(verifier_status), GH_TOKEN=SECRET, V3_ATTEMPT=SECRET)
                run=subprocess.run(['bash',str(SCRIPT)],cwd=root,env=env,capture_output=True,text=True)
                self.assertEqual(run.returncode,status,run.stderr)
                self.assertNotIn(SECRET,run.stdout+run.stderr)
                if outcome is not None:
                    raw=(root/'signing-latest-diagnostics.json').read_text()
                    self.assertNotIn(SECRET,raw)
                    self.assertEqual(json.loads(raw),{'schema':'sbxr-signing-latest-diagnostics-v1','verifier_exit':verifier_status,'verifier_outcome':outcome,'baseline_comparison':comparison,'exit_status':status})
if __name__=='__main__': unittest.main()
