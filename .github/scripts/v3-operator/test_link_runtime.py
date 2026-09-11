import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('link_runtime', ROOT / 'link-runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def authority(link_id='1', credential='2'):
    return {'link_id': link_id * 32, 'credential_sha256': credential * 64,
            'certificate_generation': 3, 'certificate_sha256': ['4' * 64] * 4}


class LinkRuntimeTests(unittest.TestCase):
    def test_runtime_process_identity_binds_executable_inode_and_start_tick(self):
        executable = mock.Mock()
        executable.stat.return_value = SimpleNamespace(st_dev=1, st_ino=2)
        proc_path = mock.Mock()
        proc_path.read_text.return_value = '77 (sbxr) ' + ' '.join(['S'] + ['0'] * 18 + ['99'])
        with mock.patch.object(runtime.os, 'stat', return_value=SimpleNamespace(st_dev=1, st_ino=2)), \
                mock.patch.object(runtime, 'Path', return_value=proc_path):
            self.assertEqual(runtime.process_identity(77, executable)['start_tick'], 99)
        with mock.patch.object(runtime.os, 'stat', return_value=SimpleNamespace(st_dev=1, st_ino=3)):
            with self.assertRaisesRegex(ValueError, 'executable mismatch'):
                runtime.process_identity(77, executable)

    def test_target_staging_changes_only_link_identity_and_retains_source_process(self):
        source, target = authority(), authority('5', '6')
        token = b'x' * 43 + b'\n'
        target['credential_sha256'] = hashlib.sha256(token[:43]).hexdigest()
        state = runtime.serving_state_bytes(target)
        observer = runtime.Observer.__new__(runtime.Observer)
        observer.source = source
        observer.source_process = {'pid': 10, 'start_tick': 20}
        observer.reader = lambda path, mode: token if path == runtime.TARGET_TOKEN else state
        observer.running_subscription = mock.Mock(return_value=observer.source_process)
        observer.unchanged_proxy = mock.Mock()
        observer.staging = mock.Mock()
        record = {'serving': source, 'subscription_rotation': {
            'checkpoint': 'target authorized', 'direction': 'cleanup',
            'source': source, 'target': target}}

        selected, snapshot = observer.target_staged(record)

        self.assertEqual(selected, target)
        self.assertTrue(snapshot['target_staged_only'])
        observer.running_subscription.assert_called_once_with(source)

        changed = json.loads(json.dumps(record))
        changed['subscription_rotation']['target']['certificate_generation'] = 4
        with self.assertRaisesRegex(ValueError, 'more than subscription identity'):
            observer.target_staged(changed)

    def test_quiescence_requires_no_listener_accepted_socket_or_cgroup_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            group = Path(directory) / 'sbxr-subscription.service'
            group.mkdir()
            (group / 'cgroup.events').write_text('populated 0\n')
            (group / 'cgroup.procs').write_text('')
            observer = runtime.Observer.__new__(runtime.Observer)
            observer.deadline = time.monotonic() + 10
            observer.source_process = {'pid': 99999999, 'start_tick': 7}
            observer.proxy_process = {'pid': 22, 'start_tick': 8}
            observer.configuration_sha256 = 'a' * 64
            observer.property = mock.Mock(side_effect=lambda unit, name: 'inactive' if name == 'ActiveState' else '0')
            observer.unchanged_proxy = mock.Mock()
            outputs = {('pgrep', '-f', '^/usr/local/bin/sbxr --subscription-serving$'): '',
                       ('ss', '-H', '-ltnp', 'sport', '=', ':8443'): '',
                       ('ss', '-H', '-tanp', 'sport', '=', ':8443'): ''}
            observer.command = mock.Mock(side_effect=lambda argv, codes=(0,): outputs[tuple(argv)])
            with mock.patch.object(runtime, 'GROUP', group):
                result = observer.quiescent()
                self.assertTrue(result['accepted_sockets_8443_absent'])

                outputs[('ss', '-H', '-tanp', 'sport', '=', ':8443')] = 'ESTAB source socket'
                with self.assertRaisesRegex(ValueError, 'accepted socket remains'):
                    observer.quiescent()

                outputs[('ss', '-H', '-tanp', 'sport', '=', ':8443')] = 'TIME-WAIT 0 0 host:8443 peer:1'
                self.assertEqual(observer.quiescent()['unowned_kernel_time_wait_sockets'], 1)
                outputs[('ss', '-H', '-tanp', 'sport', '=', ':8443')] = ''
                (group / 'cgroup.procs').write_text('123\n')
                with self.assertRaisesRegex(ValueError, 'descendants remain'):
                    observer.quiescent()

    def test_source_target_comparison_is_digest_only_and_exact(self):
        source, target = authority(), authority('5', '6')
        value = runtime.comparison(source, target, 'source', 'target', 'target')
        self.assertEqual(set(value), {
            'source_authority_sha256', 'target_authority_sha256', 'link_id_changed',
            'credential_sha256_changed', 'certificate_generation_unchanged',
            'certificate_sha256_unchanged', 'configuration_sha256_unchanged',
            'initial_serving', 'interrupted_serving', 'final_serving'})
        self.assertTrue(value['link_id_changed'])
        self.assertNotIn(source['link_id'], json.dumps(value))

    def test_committed_hold_retains_source_material_and_staged_target(self):
        source, target = authority(), authority('5', '6')
        observer = runtime.Observer.__new__(runtime.Observer)
        observer.source = source
        observer.prepared_files = mock.Mock(return_value={
            'target_state_sha256': '7' * 64,
            'target_credential_sha256': target['credential_sha256']})
        observer.serving_state = mock.Mock(return_value='8' * 64)
        observer.serving_token = mock.Mock(return_value=source['credential_sha256'])

        result = observer.committed_unpublished(target)

        self.assertEqual(result['serving_material'], 'source')
        self.assertTrue(result['target_staged_only'])
        observer.prepared_files.assert_called_once_with(target)
        observer.serving_state.assert_called_once_with(source)
        observer.serving_token.assert_called_once_with(source)


if __name__ == '__main__':
    unittest.main()
