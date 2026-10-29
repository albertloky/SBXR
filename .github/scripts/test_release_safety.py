"""Inert workflow regressions: fake gh, files and process adapters only."""
import ast
import io
from contextlib import redirect_stderr
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
WORKFLOW = HERE.parent / 'workflows/candidate.yml'

def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class BoundaryTests(unittest.TestCase):
    def test_unverifiable_manifest_never_authorizes_unsigned_cleanup(self):
        text = WORKFLOW.read_text()
        start = text.index('          signed=')
        end = text.index('          mkdir -m 0700 boundary/burned', start)
        shell = '\n'.join(line[10:] for line in text[start:end].splitlines())
        for failure in ('authentication', 'network', 'server'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                gh = root / 'gh'
                gh.write_text("#!/bin/sh\ncase \"$1 $2\" in\n 'api '*) echo 17;;\n 'run download') exit 0;;\n 'attestation verify') exit 1;;\n *) exit 99;;\nesac\n")
                gh.chmod(0o700)
                output = root / 'output'
                env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'], GITHUB_OUTPUT=str(output), GITHUB_REPOSITORY='fixture/repo', GITHUB_RUN_ID='17', GITHUB_SHA='a'*40, GITHUB_RUN_ATTEMPT='1', SIGN_RESULT='failure')
                result = subprocess.run(['bash', '-c', 'set -euo pipefail\n'+shell], cwd=root, env=env, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('recorded=true', output.read_text())

    def test_boundary_requires_positive_unsigned_proof_and_preserves_signed_path(self):
        text=WORKFLOW.read_text();start=text.index('          signed=');end=text.index('          mkdir -m 0700 boundary/burned', start)
        shell='\n'.join(line[10:] for line in text[start:end].splitlines())
        for case, permitted, signed in [('job-skipped',True,False),('step-skipped',True,False),('signed',True,True),('step-success',False,False),('step-cancelled',False,False),('missing-job',False,False),('api-error',False,False),('wrong-manifest',False,False),('rerun',False,False)]:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);gh=root/'gh'
                gh.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
case=os.environ['FIXTURE_CASE'];args=sys.argv[1:]
if args[0]=='api':
    if case=='api-error':sys.exit(1)
    if 'artifacts?' in args[1]:
        print('17' if case in ('signed','wrong-manifest') else '')
    else:
        steps=[dict(name='Attest qualification manifest',conclusion={'step-skipped':'skipped','step-success':'success','step-cancelled':'cancelled'}.get(case,'unknown'))]
        print(json.dumps([dict(jobs=[] if case=='missing-job' else [dict(name='sign',status='completed',steps=steps)])]))
elif args[:2]==['attestation','verify']:sys.exit(0)
elif args[:2]==['run','download']:
    if args[args.index('--name')+1]=='signed-qualification-manifest':
        value=dict(schema='sbxr-qualification-manifest-v3',repository=os.environ['GITHUB_REPOSITORY'],workflow=dict(path='.github/workflows/candidate.yml',ref='albertloky/SBXR/.github/workflows/candidate.yml@refs/heads/main',commit=os.environ['GITHUB_SHA'],run_id='17',run_url='https://github.com/fixture/repo/actions/runs/17'))
        if case=='wrong-manifest':value['workflow']['commit']='b'*40
        pathlib.Path('boundary/qualification-manifest.json').write_text(json.dumps(value))
else:sys.exit(99)
""")
                gh.chmod(0o700);output=root/'output'
                env=dict(os.environ,PATH=str(root)+os.pathsep+os.environ['PATH'],GITHUB_OUTPUT=str(output),GITHUB_REPOSITORY='fixture/repo',GITHUB_RUN_ID='17',GITHUB_SHA='a'*40,GITHUB_RUN_ATTEMPT='2' if case=='rerun' else '1',GITHUB_SERVER_URL='https://github.com',SIGN_RESULT='skipped' if case=='job-skipped' else 'failure',FIXTURE_CASE=case)
                result=subprocess.run(['bash','-c','set -euo pipefail\n'+shell],cwd=root,env=env,capture_output=True)
                self.assertEqual(result.returncode==0,permitted,result.stderr)
                outputs=output.read_text()
                self.assertEqual('recorded=true' in outputs,permitted and not signed)
                self.assertEqual('signed=true' in outputs,signed)

class FailureDecisionTests(unittest.TestCase):
    def test_candidate_has_no_automatic_failure_mutations(self):
        text = WORKFLOW.read_text()
        for forbidden in ('gh api --method DELETE', 'prepare-burn-tag.sh',
                          'git push', '--draft=false', 'subject-path: boundary/burned'):
            self.assertNotIn(forbidden, text)
        failure = text.split('\n  cleanup-unqualified:', 1)[1]
        self.assertIn('contents: read', failure)
        self.assertIn('attestations: read', failure)
        self.assertNotIn('id-token:', failure)
        self.assertNotIn('continue-on-error:', failure)
        self.assertIn('candidate-failure-finalization', failure)
        self.assertIn('all(.actions[];', failure)

    def test_partial_construction_trap_retains_draft_and_original_failure(self):
        text = WORKFLOW.read_text()
        start = text.index('          retain_unsigned_drafts() {')
        end = text.index("          printf '[]' > built-releases.json", start)
        shell = '\n'.join(line[10:] for line in text[start:end].splitlines())
        for status in (0, 37):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                scripts = root/'.github/scripts'
                scripts.mkdir(parents=True)
                # Substitute external observation and decision producers only;
                # execute the actual trap, jq bindings and filesystem retention.
                recheck = scripts/'recheck-qualified-release.sh'
                recheck.write_text('#!/bin/sh\ncp release.json "$3"\n')
                recheck.chmod(0o700)
                (scripts/'observe-github-resource.py').write_text("print('{\"state\":\"absent\"}')\n")
                go = root/'go'
                go.write_text("""#!/usr/bin/env python3
import hashlib,json,sys
raw=sys.stdin.buffer.read();facts=json.loads(raw);digest=hashlib.sha256(raw).hexdigest()
action=dict(type='cleanup-draft',tag='v2.0.0',release_id=71,commit='a'*40,delete_release=True,delete_tag=False,facts_sha256=digest,prior_decision_sha256=facts['prior_decision_sha256'])
print(json.dumps(dict(schema='sbxr-release-qualification-decision-v1',stage='candidate-failure-finalization',outcome='cleanup',facts_sha256=digest,prior_decision_sha256=facts['prior_decision_sha256'],actions=[action])))
""")
                go.chmod(0o700)
                gh = root/'gh'
                gh.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> attempted-mutation\nexit 99\n')
                gh.chmod(0o700)
                entry = dict(tag='v2.0.0',sequence=17,commit='a'*40,release_id=71,
                             assets=[],release_identity={'repository':'fixture/repo'})
                (root/'drafts.json').write_text(json.dumps([entry]))
                (root/'release.json').write_text(json.dumps(dict(id=71,tag_name='v2.0.0',target_commitish='a'*40,draft=True,prerelease=False,assets=[],body='')))
                (root/'candidate-draft-construction-facts.json').write_text(json.dumps({'preflight_facts':{'burned_identities':[]}}))
                (root/'candidate-draft-construction-decision.json').write_text('{}')
                env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'],
                           GITHUB_WORKSPACE=str(root), GITHUB_SHA='a'*40, GITHUB_REPOSITORY='fixture/repo',
                           GITHUB_WORKFLOW_REF='fixture/ref', GITHUB_RUN_ID='17', GITHUB_SERVER_URL='https://github.com',
                           BUILD_RELEASES=json.dumps([entry]))
                result = subprocess.run(['bash','-c','set -euo pipefail\ncurrent_tag=\n'+shell+'\nexit '+str(status)],
                                        cwd=root,env=env,capture_output=True)
                self.assertFalse((root/'attempted-mutation').exists(), 'automatic failure mutation attempted')
                self.assertEqual(result.returncode,status,result.stderr)
                self.assertEqual(json.loads((root/'drafts.json').read_text()),[entry])
                self.assertEqual((root/'candidate-failure-decision.json').exists(),status != 0)

    def test_pending_draft_gate_is_read_only_and_fails_closed(self):
        text = WORKFLOW.read_text()
        start = text.index("          preflight_operation='require resolved candidate drafts'")
        end = text.index("          preflight_operation='fetch source tags'", start)
        shell = '\n'.join(line[10:] for line in text[start:end].splitlines())
        cases = [('empty', [[]], 0, True), ('published', [[{'draft': False}]], 0, True),
                 ('retained', [[{'draft': True}]], 0, False),
                 ('later-page', [[{'draft': False}], [{'draft': True}]], 0, False),
                 ('missing-field', [[{}]], 0, False), ('wrong-type', [[{'draft': 'false'}]], 0, False),
                 ('missing-page', [], 0, False), ('bad-page', [{}], 0, False),
                 ('unavailable', [[]], 1, False)]
        for name, pages, status, accepted in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                gh = root/'gh'
                gh.write_text('#!/bin/sh\n' +
                              'test "$*" = "api repos/fixture/repo/releases?per_page=100 --paginate --slurp" || exit 99\n' +
                              'printf "%s" "$FIXTURE_PAGES"\nexit "$FIXTURE_STATUS"\n')
                gh.chmod(0o700)
                env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'],
                           GITHUB_REPOSITORY='fixture/repo', FIXTURE_PAGES=json.dumps(pages),
                           FIXTURE_STATUS=str(status))
                result = subprocess.run(['bash', '-c', 'set -euo pipefail\n'+shell],
                                        cwd=root, env=env, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_failure_stop_remains_failed_with_or_without_proposal(self):
        text = WORKFLOW.read_text()
        start = text.index('      - name: Stop for an explicit candidate failure decision')
        end = text.index('      - name:', start+10)
        step = text[start:end]
        self.assertIn('if: always()', step)
        shell = '\n'.join(line[10:] for line in step.split('        run: |\n', 1)[1].splitlines())
        for proposal in (None, 'cleanup', 'failed-prerelease'):
            with self.subTest(proposal=proposal), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                if proposal:
                    (root/'candidate-failure-decision.json').write_text(json.dumps({'outcome': proposal}))
                summary = root/'summary'
                result = subprocess.run(['bash', '-c', shell], cwd=root,
                                        env=dict(os.environ, GITHUB_STEP_SUMMARY=str(summary)), capture_output=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn('pending Owner decision', summary.read_text())
                if proposal:
                    self.assertEqual(json.loads((root/'candidate-failure-decision.json').read_text()),
                                     {'outcome': proposal})

class FixtureAdmissionTests(unittest.TestCase):
    def test_optimized_fixture_refuses_before_any_host_access(self):
        for filename in ('test_mvp_startup_cleanup.py', 'test_mvp_protected_menu.py'):
            with self.subTest(filename=filename):
                tree = ast.parse((HERE / filename).read_text())
                function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
                module = ast.Module(body=[function], type_ignores=[])
                system = Mock(platform='linux', flags=Mock(optimize=1))
                environ = Mock()
                environ.geteuid.return_value = 0
                paths = Mock(side_effect=AssertionError('host access before refusal'))
                namespace = dict(sys=system, os=environ, Path=paths)
                exec(compile(module, filename, 'exec', optimize=1), namespace)
                with self.assertRaisesRegex(RuntimeError, 'enabled-assertions'):
                    namespace['run']()
                paths.assert_not_called()

class EvidenceTests(unittest.TestCase):
    def test_failed_workflow_preserves_only_screened_staging(self):
        text = WORKFLOW.read_text()
        for job, end in [('drafts', 'sign'), ('acceptance-vps', 'owner-exception'), ('cleanup-unqualified', None)]:
            body = text.split('\n  '+job+':', 1)[1]
            if end:
                body = body.split('\n  '+end+':', 1)[0]
            self.assertIn('if: always()\n        run: python3 .github/scripts/candidate-evidence.py', body)
            self.assertIn("if: always() && steps.retained_evidence.outcome == 'success'", body)
            self.assertIn('path: retained-candidate-evidence/', body)
        module = load('candidate-evidence')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = dict(schema='sbxr-release-qualification-facts-v1', stage='v3-scenario-failure', failure={'actual_result':'timeout'})
            path = root / 'handoff/failure-evidence/failure.json'
            path.parent.mkdir(parents=True)
            raw = json.dumps(data).encode()
            path.write_bytes(raw)
            # Private unrelated material is neither traversed nor uploaded.
            (root / 'handoff/ssh.key').write_text('PRIVATE KEY')
            prefix = root / 'handoff/v3-scenarios/1-facts.json'
            prefix.parent.mkdir()
            prefix.write_text(json.dumps(dict(data, stage='v3-scenario-result')))
            self.assertEqual(module.stage(root, root/'retained'), 2)
            self.assertEqual((root/'retained/handoff/failure-evidence/failure.json').read_bytes(), raw)
            self.assertFalse((root/'retained/handoff/ssh.key').exists())

    def test_valid_facts_survive_empty_malformed_secret_and_linked_records(self):
        module = load('candidate-evidence')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'boundary').mkdir()
            facts = json.dumps(dict(schema='sbxr-release-qualification-facts-v1', stage='candidate-failure-finalization')).encode()
            (root/'boundary/candidate-failure-facts.json').write_bytes(facts)
            (root/'candidate-failure-facts.json').write_bytes(facts)
            (root/'boundary/candidate-failure-decision.json').write_bytes(b'')
            with redirect_stderr(io.StringIO()):
                self.assertEqual(module.stage(root, root/'retained'), 2)
            self.assertEqual((root/'retained/candidate-failure-facts.json').read_bytes(), facts)
            self.assertEqual((root/'retained/boundary/candidate-failure-facts.json').read_bytes(), facts)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe = json.dumps(dict(schema='sbxr-release-qualification-facts-v1',
                                   stage='candidate-failure-finalization')).encode()
            files = {
                'boundary/candidate-failure-facts.json': safe,
                'boundary/candidate-failure-decision.json': b'',
                'boundary/candidate-failure-verification-facts.json': b'{malformed SECRET-SENTINEL',
                'boundary/candidate-failure-verification-decision.json': json.dumps(dict(
                    schema='sbxr-release-qualification-decision-v1', stage='candidate-failure-verification',
                    secret='Authorization: Bearer SECRET-SENTINEL')).encode(),
                'handoff/v3-scenarios/1-facts.json': json.dumps(dict(
                    schema='sbxr-release-qualification-facts-v1', stage='v3-scenario-result')).encode(),
            }
            for name, raw in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            linked = root/'handoff/v3-scenarios/1-decision.json'
            linked.symlink_to(root/'boundary/candidate-failure-facts.json')
            diagnostics = io.StringIO()
            with redirect_stderr(diagnostics):
                self.assertEqual(module.stage(root, root/'retained'), 2)
            retained = {str(path.relative_to(root/'retained')): path.read_bytes()
                        for path in (root/'retained').rglob('*') if path.is_file()}
            self.assertEqual(retained, {name: files[name] for name in (
                'boundary/candidate-failure-facts.json', 'handoff/v3-scenarios/1-facts.json')})
            self.assertEqual(diagnostics.getvalue(), 'Candidate evidence: omitted 4 unsafe or incomplete records.\n')
            self.assertEqual((root/'boundary/candidate-failure-facts.json').read_bytes(), safe)
            self.assertTrue(linked.is_symlink())

    def test_malformed_field_types_are_omitted_independently(self):
        module = load('candidate-evidence')
        valid = dict(schema='sbxr-release-qualification-facts-v1', stage='candidate-failure-finalization')
        invalid = [dict(valid, **{field: value}) for field in ('schema', 'stage')
                   for value in ([], {}, None, True, 1, 1.5, 'SECRET-SENTINEL')]
        invalid += [[], None, True, 1, 1.5, 'SECRET-SENTINEL']
        for index, record in enumerate(invalid):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/'boundary').mkdir()
                raw = json.dumps(valid).encode()
                (root/'boundary/candidate-failure-facts.json').write_bytes(raw)
                (root/'boundary/candidate-failure-decision.json').write_text(json.dumps(record))
                diagnostics = io.StringIO()
                with redirect_stderr(diagnostics):
                    self.assertEqual(module.stage(root, root/'retained'), 1)
                files = [path for path in (root/'retained').rglob('*') if path.is_file()]
                self.assertEqual(files, [root/'retained/boundary/candidate-failure-facts.json'])
                self.assertEqual(files[0].read_bytes(), raw)
                self.assertEqual(diagnostics.getvalue(), 'Candidate evidence: omitted 1 unsafe or incomplete records.\n')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'handoff/v3-scenarios'
            source.mkdir(parents=True)
            for index, record in enumerate(invalid, 1):
                (source/(str(index)+'-facts.json')).write_text(json.dumps(record))
            diagnostics = io.StringIO()
            with redirect_stderr(diagnostics):
                self.assertEqual(module.stage(root, root/'retained'), 0)
            self.assertEqual(list((root/'retained').iterdir()), [])
            self.assertEqual(diagnostics.getvalue(), f'Candidate evidence: omitted {len(invalid)} unsafe or incomplete records.\n')

    def test_unsafe_or_secret_evidence_is_never_staged(self):
        module = load('candidate-evidence')
        for fault in ('secret', 'escaped-secret', 'duplicate', 'symlink', 'hardlink', 'oversize', 'schema', 'total'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root/'handoff/failure-evidence/failure.json'
                path.parent.mkdir(parents=True)
                data = dict(schema='sbxr-release-qualification-facts-v1', stage='v3-scenario-failure')
                if fault in ('secret', 'escaped-secret'):
                    data['failure'] = 'http://fixture.invalid:8443/s/private-link'
                if fault == 'schema':
                    data['schema'] = 'raw-log'
                raw = json.dumps(data).encode()
                if fault == 'escaped-secret':
                    raw = raw.replace(b'/', b'\\u002f')
                if fault == 'duplicate':
                    raw = b'{"stage":1,"stage":2}'
                path.write_bytes(raw)
                if fault == 'symlink':
                    original=path.with_suffix('.original');path.rename(original);path.symlink_to(original)
                if fault == 'hardlink':
                    os.link(path, path.with_suffix('.link'))
                with patch.object(module, 'MAX_FILE', 1 if fault == 'oversize' else 16 << 20), patch.object(module, 'MAX_TOTAL', 1 if fault == 'total' else 64 << 20):
                    diagnostics = io.StringIO()
                    with redirect_stderr(diagnostics):
                        self.assertEqual(module.stage(root, root/'retained'), 0)
                self.assertEqual(list((root/'retained').iterdir()), [])
                self.assertEqual(diagnostics.getvalue(), 'Candidate evidence: omitted 1 unsafe or incomplete records.\n')

class SSHDeadlineTests(unittest.TestCase):
    def test_collection_and_cleanup_have_distinct_bounded_adapters(self):
        source = (HERE/'v3-recurring-evidence.sh').read_text()
        self.assertIn('remote=(python3 "$(dirname "${BASH_SOURCE[0]}")/bounded-ssh.py" 30 -i', source)
        self.assertIn('submit_remote=(python3 "$(dirname "${BASH_SOURCE[0]}")/bounded-ssh.py" 30 -T', source)
        cleanup = source.split('stop_attempt() {',1)[1].split('trap stop_attempt EXIT',1)[0]
        self.assertIn('remote[2]=10', cleanup)
        self.assertLess(cleanup.index('remote[2]=10'),cleanup.index('cleanup_mvp_observation'))
        self.assertIn('if python3 .github/scripts/bounded-ssh.py 90', WORKFLOW.read_text())

    def test_stalled_transport_is_killed_and_reaped_without_retry(self):
        module=load('bounded-ssh')
        process=Mock(pid=123, returncode=None)
        process.wait.side_effect=[subprocess.TimeoutExpired('ssh',30), -9]
        with patch.object(module.subprocess,'Popen',return_value=process) as spawn, patch.object(module.os,'killpg') as kill:
            self.assertEqual(module.run(30,['-n','fixture.invalid','read-only-fixture']),124)
            spawn.assert_called_once_with(['ssh','-n','fixture.invalid','read-only-fixture'],start_new_session=True)
            kill.assert_called_once_with(123,module.signal.SIGKILL)
            self.assertEqual([call.kwargs for call in process.wait.call_args_list],[{'timeout':30},{'timeout':5}])
            process.poll.assert_not_called()

    def test_completed_transport_status_is_preserved_and_never_signalled(self):
        module=load('bounded-ssh')
        for status in (0,1,255):
            process=Mock(pid=123,returncode=status)
            process.wait.return_value=status
            with patch.object(module.subprocess,'Popen',return_value=process), patch.object(module.os,'killpg') as kill:
                self.assertEqual(module.run(10,['fixture.invalid']),status)
                kill.assert_not_called()

    def test_interruption_cleans_owned_transport_and_propagates(self):
        module=load('bounded-ssh')
        process=Mock(pid=123, returncode=None)
        process.wait.side_effect=[KeyboardInterrupt(),-9]
        with patch.object(module.subprocess,'Popen',return_value=process),patch.object(module.os,'killpg') as kill:
            with self.assertRaises(KeyboardInterrupt):
                module.run(10,['fixture.invalid'])
            kill.assert_called_once_with(123,module.signal.SIGKILL)

if __name__ == '__main__':
    unittest.main()
