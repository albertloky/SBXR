import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_link_collector import COLLECTOR, function


class TransitionCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.source = COLLECTOR.read_text()

    def test_trigger_rejects_replay_unknown_fields_and_wrong_scenario(self):
        code = function(self.source, 'transition_request_matches')
        value = {'deadline_unix': 123, 'operator_directory': '/run/sbxr-qualification',
                 'qualification_manifest_sha256': 'a'*64, 'request_id': 'identity-identity-postcommit',
                 'request_sha256': 'b'*64, 'scenario_id': 'identity-postcommit',
                 'schema': 'sbxr-v4-identity-transition-outside-request-v1',
                 'source_configuration_sha256': 'c'*64, 'state_directory': '/run/sbxr-qualification'}
        for change in ({}, {'request_sha256': 'd'*64}, {'extra': True}, {'scenario_id': 'identity-absent'},
                       {'state_directory': '/tmp'}, {'source_configuration_sha256': 'invalid'}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                request = Path(directory) / 'request'
                request.write_text(json.dumps(dict(value, **change), sort_keys=True, separators=(',', ':')))
                result = subprocess.run(['bash', '-eu', '-c', code + '\ntransition_request_matches "$1" 123 "$2" identity-postcommit "$3"',
                                         'test', str(request), 'a'*64, 'b'*64], capture_output=True)
                self.assertEqual(result.returncode == 0, not change, result.stderr)

    def test_failed_driver_never_marks_complete(self):
        code = function(self.source, 'collect_transition_driver')
        script = code + '''
outside_transition_done=false
(exit 42) & transition_pid=$!
if collect_transition_driver; then exit 90; fi
test "$outside_transition_done" = false
test -z "$transition_pid"
test "$reason" = evidence-refused
'''
        self.assertEqual(subprocess.run(['bash', '-eu', '-c', script]).returncode, 0)

    def test_cleanup_failure_is_propagated_without_erasing_retry_path(self):
        code = function(self.source, 'cleanup_transition_trigger')
        script = code + '''
remote_failure() { return 42; }
remote=(remote_failure)
transition_request_remote=/root/sbxr-qualification-evidence/identity-transition-outside-request.json
if cleanup_transition_trigger; then exit 90; fi
test -n "$transition_request_remote"
'''
        self.assertEqual(subprocess.run(['bash', '-eu', '-c', script]).returncode, 0)


if __name__ == '__main__': unittest.main()
