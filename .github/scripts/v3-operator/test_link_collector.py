from pathlib import Path
import subprocess
import tempfile
import unittest


COLLECTOR = Path(__file__).parent.parent / 'v3-recurring-evidence.sh'


def function(source, name):
    return name + '() {' + source.split(name + '() {', 1)[1].split('\n}\n', 1)[0] + '\n}\n'


class LinkCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = COLLECTOR.read_text()

    def test_link_request_requires_exact_bytes_and_scenario(self):
        code = function(self.source, 'link_request_matches')
        valid = (b'{"deadline_unix":123,"operator_directory":"/run/sbxr-qualification",'
                 b'"qualification_manifest_sha256":"' + b'a' * 64 +
                 b'","scenario_id":"link-precommit","schema":"sbxr-v4-link-outside-request-v1",'
                 b'"state_directory":"/run/sbxr-qualification"}')
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / 'request.json'
            request.write_bytes(valid)
            accepted = subprocess.run(['bash', '-c', code + '\nlink_request_matches "$1" 123 "' +
                                       'a' * 64 + '" link-precommit', 'link-request', str(request)])
            self.assertEqual(accepted.returncode, 0)
            request.write_bytes(valid[:-1] + b',"extra":true}')
            refused = subprocess.run(['bash', '-c', code + '\nlink_request_matches "$1" 123 "' +
                                      'a' * 64 + '" link-precommit', 'link-request', str(request)])
            self.assertNotEqual(refused.returncode, 0)

    def test_failure_cleanup_removes_only_non_symlink_link_trigger(self):
        code = function(self.source, 'cleanup_link_trigger')
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'remote.log'
            script = code + '''
fixture_remote() { printf '%s' "$2" > "$1"; }
remote=(fixture_remote "''' + str(log) + '''")
link_request_remote=/root/sbxr-qualification-evidence/link-outside-request.json
cleanup_link_trigger
test -z "$link_request_remote"
'''
            result = subprocess.run(['bash', '-c', script])
            self.assertEqual(result.returncode, 0)
            self.assertIn("test ! -L '/root/sbxr-qualification-evidence/link-outside-request.json'",
                          log.read_text())

    def test_failed_remote_cleanup_is_reported_and_keeps_trigger_for_retry(self):
        code = function(self.source, 'cleanup_link_trigger')
        script = code + '''
fixture_remote() { return 42; }
remote=(fixture_remote)
link_request_remote=/root/sbxr-qualification-evidence/link-outside-request.json
if cleanup_link_trigger; then exit 90; fi
test "$link_request_remote" = /root/sbxr-qualification-evidence/link-outside-request.json
'''
        result = subprocess.run(['bash', '-c', script])
        self.assertEqual(result.returncode, 0)

    def test_remote_source_set_contains_every_link_runtime_and_entry_dependency(self):
        for name in ('link-outside.py', 'link-runtime.py', 'transition-operator.py',
                     'syscall-gate.py', 'exec-gate.py', 'link-entry.py',
                     'link-subscription-input.sh', '09-10-link-start.sh',
                     '09-10-link-finish.sh', 'effective-route.py', 'operator-support.sh',
                     'assemble-evidence.py', 'link-evidence.py', 'evidence-timing.py',
                     'identity-outside.py', 'check-connection-observation.py',
                     'identity-startup.py', 'subscription-observation.py'):
            self.assertIn(' ' + name, self.source)
        self.assertLess(self.source.index('link_request_remote=/root/sbxr-qualification-evidence'),
                        self.source.index('fetch_identity_file /root/sbxr-qualification-evidence/link-outside-request.json'))


if __name__ == '__main__':
    unittest.main()
