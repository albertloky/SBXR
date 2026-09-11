import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('link_entry', ROOT / 'link-entry.py')
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)


class LinkEntryTests(unittest.TestCase):
    def request(self):
        return {'scenario_id': 'link-precommit', 'not_before': '2026-09-11T00:00:00Z',
                'deadline_unix': 2_000_000_000, 'qualification_manifest_sha256': 'a' * 64,
                'scenario_limit_seconds': 90}

    def test_prepare_preserves_original_clock_and_publishes_bound_trigger(self):
        request = self.request()
        with mock.patch.dict(os.environ, {'SCENARIO_START': '2026-09-11T00:00:01Z'}):
            state, trigger = entry.prepare_documents(
                'link-precommit', 'a' * 64, 'b' * 64, request, b'private',
                '2026-09-11T00:00:01Z', '2026-09-11T00:00:02Z')
            self.assertEqual(state['started_at'], os.environ['SCENARIO_START'])
            self.assertEqual(trigger, {
                'schema': 'sbxr-v4-link-outside-request-v1', 'scenario_id': 'link-precommit',
                'deadline_unix': request['deadline_unix'], 'qualification_manifest_sha256': 'a' * 64,
                'operator_directory': '/run/sbxr-qualification',
                'state_directory': '/run/sbxr-qualification'})

            with self.assertRaisesRegex(entry.evidence.Refusal, 'original scenario start'):
                entry.prepare_documents('link-precommit', 'a' * 64, 'b' * 64, request,
                                        b'private', '2026-09-11T00:00:03Z',
                                        '2026-09-11T00:00:04Z')

    def test_finalize_binds_actual_controller_and_handoff_bytes(self):
        document = entry.finalize_document(
            'link-postcommit', 'a' * 64, 'b' * 64, self.request(), b'final',
            {'recovered_at': '2026-09-11T00:00:06Z'}, b'controller',
            b'challenge', b'closed', '2026-09-11T00:00:07Z')
        self.assertEqual(document['recovered_transition_sha256'], entry.evidence.digest(b'controller'))
        self.assertEqual(document['challenge_sha256'], entry.evidence.digest(b'challenge'))
        self.assertEqual(document['closed_sha256'], entry.evidence.digest(b'closed'))
        self.assertEqual(document['final_disclosure_sha256'], entry.evidence.digest(b'final'))

    def test_finalize_refuses_malformed_or_rebound_entry_state_before_disclosure(self):
        request = self.request()
        state = {
            'schema': 'sbxr-v4-link-entry-v1', 'scenario_id': 'link-precommit',
            'qualification_manifest_sha256': 'a' * 64, 'request_sha256': 'b' * 64,
            'started_at': '2026-09-11T00:00:01Z',
            'entry_started_at': '2026-09-11T00:00:02Z',
            'initial_disclosure_sha256': 'c' * 64}
        self.assertIs(entry.validate_entry_state(
            state, 'link-precommit', 'a' * 64, 'b' * 64, request), state)
        with self.assertRaisesRegex(entry.evidence.Refusal, 'exact object shape'):
            entry.validate_entry_state(dict(state, extra=True), 'link-precommit',
                                       'a' * 64, 'b' * 64, request)
        with self.assertRaisesRegex(entry.evidence.Refusal, 'original request or clock'):
            entry.validate_entry_state(dict(state, request_sha256='d' * 64),
                                       'link-precommit', 'a' * 64, 'b' * 64, request)

    def test_result_wait_refuses_deadline_and_request_drift_even_after_visibility(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / 'result.json'
            request = Path(directory) / 'request.json'
            result.write_text('{}')
            with mock.patch.object(entry.time, 'time', return_value=101), \
                    mock.patch.object(entry.evidence, 'private_bytes', return_value=b'current'):
                with self.assertRaisesRegex(entry.evidence.Refusal, 'exceeded'):
                    entry.wait_result(result, request, b'current', 100, 0)
            with mock.patch.object(entry.time, 'time', return_value=99), \
                    mock.patch.object(entry.evidence, 'private_bytes', return_value=b'changed'):
                with self.assertRaisesRegex(entry.evidence.Refusal, 'changed'):
                    entry.wait_result(result, request, b'current', 100, 0)


if __name__ == '__main__':
    unittest.main()
