import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


capture = load('test_capture_source', 'capture-source.py')
entry = capture.entry
api = capture.api


class ScenarioSourcesTests(unittest.TestCase):
    def test_phase_records_keep_start_and_require_previous_current_phase(self):
        request = {'not_before': '2030-01-01T00:00:00Z', 'deadline_unix': 1893457800}
        state = None
        for index, phase in enumerate(entry.PHASES):
            state = entry.advance(state, phase, 'recorder-live', 'a' * 64, 'b' * 64, request,
                                  '2030-01-01T00:00:00Z', f'2030-01-01T00:00:0{index + 2}Z')
        self.assertEqual(state['started_at'], '2030-01-01T00:00:00Z')
        self.assertEqual(state['completed_at'], '2030-01-01T00:00:05Z')
        with self.assertRaisesRegex(api.Refusal, 'original collector start'):
            entry.advance(None, 'begin', 'recorder-live', 'a'*64, 'b'*64, request,
                          '2030-01-01T00:00:01Z', '2030-01-01T00:00:02Z')
        with self.assertRaises(api.Refusal):
            entry.advance(None, 'action-complete', 'recorder-live', 'a' * 64, 'b' * 64, request,
                          '2030-01-01T00:00:01Z', '2030-01-01T00:00:03Z')
        with self.assertRaises(api.Refusal):
            entry.advance(state, 'finish', 'recorder-live', 'a' * 64, 'c' * 64, request,
                          '2030-01-01T00:00:01Z', '2030-01-01T00:00:06Z')

    def test_capture_preserves_interactive_helper_protocol_and_real_output(self):
        with tempfile.TemporaryDirectory() as directory:
            request_path = Path(directory) / 'request'
            request_path.write_bytes(b'current')
            request_path.chmod(0o600)
            control = Path(directory) / 'control'
            control.write_text('release\n')
            bound = {'scenario_id': 'recorder-live', 'qualification_manifest_sha256': 'a' * 64,
                     'deadline_unix': int(time.time()) + 30}
            output = []
            script = 'import json,sys; print(json.dumps({"state":"held"}),flush=True); assert input()=="release"; print(json.dumps({"state":"completed"}),flush=True)'
            with control.open('rb') as stdin:
                result = capture.capture([sys.executable, '-c', script], 'managed-hold', bound,
                                         request_path, b'current', output.append, stdin)
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual([row['record']['state'] for row in result['events']], ['held', 'completed'])
            self.assertEqual([json.loads(line) for line in output], [row['record'] for row in result['events']])
            self.assertTrue(api.before(result['started_at'], result['events'][0]['observed_at']))
            self.assertTrue(api.before(result['events'][-1]['observed_at'], result['completed_at']))
            state = {'entry_started_at': result['started_at'], 'completed_at': result['completed_at']}
            path = Path(directory) / 'managed.json'
            path.write_bytes(api.canonical(result)); path.chmod(0o600)
            ctx = api.later.Context(api, 'recorder-live', {}, b'', 'a' * 64, bound, b'current', api.digest(b'current'), state, Path(directory))
            self.assertEqual(ctx.capture('managed.json', 'managed-hold')[0], result)
            for change in ({'request_sha256': 'c' * 64}, {'exit_code': 1}, {'helper': 'different-helper'}):
                altered = dict(result, **change)
                path.write_bytes(api.canonical(altered))
                with self.assertRaises(api.Refusal):
                    ctx.capture('managed.json', 'managed-hold')

    def test_capture_refuses_duplicate_output_keys_and_current_request_drift(self):
        with self.assertRaises(api.Refusal):
            capture.event(b'{"state":"held","state":"completed"}\n', entry.timestamp())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'request'
            path.write_bytes(b'current'); path.chmod(0o600)
            bound = {'scenario_id': 'recorder-live', 'qualification_manifest_sha256': 'a' * 64,
                     'deadline_unix': int(time.time()) + 30}
            script = 'import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b"changed"); print("{}",flush=True)'
            with self.assertRaisesRegex(api.Refusal, 'request'):
                capture.capture([sys.executable, '-c', script, str(path)], 'managed-hold', bound, path, b'current', lambda raw: None)

    def test_capture_expired_request_does_not_start_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'marker'
            with self.assertRaisesRegex(api.Refusal, 'deadline'):
                capture.capture([sys.executable, '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).touch()', str(marker)],
                                'managed-hold', {'deadline_unix': int(time.time()) - 1}, Path(directory) / 'request', b'', lambda raw: None)
            self.assertFalse(marker.exists())

    def test_identity_disclosure_uses_public_process_output_and_original_request(self):
        identity_entry = load('test_public_identity_entry', 'identity-entry.py')
        configuration = {'inbounds': [{'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 2080}],
                         'outbounds': [{'type': 'vless', 'uuid': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'}], 'log': {}}
        raw = api.canonical(configuration)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'request'
            path.write_bytes(api.canonical({'scenario_id': 'identity-postcommit', 'deadline_unix': int(time.time())+60}))
            path.chmod(0o600)
            with mock.patch.dict('os.environ', {'SBXR_QUALIFICATION_REQUEST': str(path), 'BASH_ENV': '/untrusted'}), \
                    mock.patch.object(identity_entry.subprocess, 'run', return_value=SimpleNamespace(stdout=raw, stderr=b'')) as run:
                self.assertEqual(identity_entry.public_disclosure('identity-postcommit'), raw)
                command, options = run.call_args.args[0], run.call_args.kwargs
                self.assertIn('remote_outside_disclose', command[4])
                self.assertEqual(options['stdin'], identity_entry.subprocess.DEVNULL)
                self.assertNotIn('BASH_ENV', options['env'])
                with self.assertRaises(identity_entry.api.Refusal):
                    identity_entry.public_disclosure('identity-precommit')


if __name__ == '__main__':
    unittest.main()
