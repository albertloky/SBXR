"""Exercise the offline proposal and its first consumer with synthetic inputs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
CALLERS = ('remote.py', 'review-cleanup.py', 'read-current-clock.py', 'outside-run.py',
           'direct-control.py', 'finalize-failure.py')


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


factory = module('mvp-containment-bindings')
process = module('mvp-containment-process')
entry = module('mvp-containment-entry')


class ProposalTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.prepared = self.root / 'prepared'
        self.prepared.mkdir(mode=0o700)
        sources = self.prepared / 'operator-source'
        sources.mkdir()
        (sources / 'native-receipts.py').write_bytes((HERE / 'native-receipts.py').read_bytes())
        self.config = dict(source='a' * 40, host='fixture.invalid', tag='v1.2.3', sequence=7,
                           approved_window_start=900, dispatch_guard_by=950, attended_finish_by=3000,
                           security_cutoff=4800, test_finish_unix=3000, cleanup_finish_unix=4800)
        (self.prepared / 'preparation.json').write_text(json.dumps(self.config))
        (self.prepared / 'preparation.json').chmod(0o600)
        helper = sources / 'native-receipts.py'
        self.native = dict(source_commit=self.config['source'], candidate={'tag': 'v1.2.3', 'sequence': 7},
                           canonical_helper={'source_file': str(helper), 'size': helper.stat().st_size,
                                             'sha256': hashlib.sha256(helper.read_bytes()).hexdigest()})
        (self.prepared / 'native-inputs.json').write_text(json.dumps(self.native))
        (self.prepared / 'native-inputs.json').chmod(0o600)
        for name in CALLERS:
            (self.prepared / name).write_text('raise AssertionError("proposal executed a caller")\n')

    def proposal(self):
        return factory.proposal(HERE.parents[1], self.prepared)

    def test_cli_freezes_synthetic_inputs_without_running_them(self):
        output = subprocess.check_output([sys.executable, '-B', str(HERE / 'mvp-containment-bindings.py'),
                                          str(self.prepared)])
        self.assertTrue(output, 'command did not produce a proposal')
        proposal = json.loads(output)
        self.assertFalse(proposal['ready_for_live'])
        self.assertEqual(proposal, self.proposal())
        self.assertEqual(len(proposal['callers']), 9)
        pins = proposal['callers']['clock']['dependencies']
        for name in (*CALLERS, 'preparation.json', 'native-inputs.json', 'operator-source/native-receipts.py'):
            path = self.prepared / name
            self.assertEqual(pins[str(path)], hashlib.sha256(path.read_bytes()).hexdigest())
        proposal['binding'] = {'run_id': 100}
        process.Callers({'binding': proposal['binding']}, proposal, self.root, proposal['runner'])

    def test_each_required_member_must_exist(self):
        for name in (*CALLERS, 'preparation.json', 'native-inputs.json', 'operator-source/native-receipts.py'):
            with self.subTest(name=name):
                path = self.prepared / name
                path.rename(self.root / 'saved')
                try:
                    with self.assertRaisesRegex((OSError, ValueError), name):
                        self.proposal()
                finally:
                    (self.root / 'saved').rename(path)

    def test_empty_preparation_lists_missing_inputs_without_emitting_json(self):
        empty = self.root / 'empty'
        empty.mkdir()
        result = subprocess.run([sys.executable, '-B', str(HERE / 'mvp-containment-bindings.py'),
                                 str(empty)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        for name in ('preparation.json', *CALLERS):
            self.assertIn(name, result.stderr.decode())

    def test_out_of_scope_links_refused(self):
        for name in ('remote.py', 'operator-source', 'extra.py'):
            with self.subTest(name=name):
                path = self.prepared / name
                target = self.root / name
                if path.exists():
                    path.rename(target)
                else:
                    target.touch()
                path.symlink_to(target)
                try:
                    with self.assertRaises((ValueError, OSError)):
                        self.proposal()
                finally:
                    path.unlink()
                    target.rename(path)

    def test_changed_canonical_helper_refused_before_freeze(self):
        (self.prepared / 'operator-source/native-receipts.py').write_text('# changed\n')
        with self.assertRaisesRegex(ValueError, 'native-receipts'):
            self.proposal()

    def test_native_input_must_select_the_same_candidate_and_local_helper(self):
        for target, key, wrong in ((self.native, 'source_commit', 'b'*40),
                                   (self.native['candidate'], 'sequence', 8),
                                   (self.native['canonical_helper'], 'source_file', str(HERE / 'native-receipts.py')),
                                   (self.native['canonical_helper'], 'sha256', 'c'*64)):
            with self.subTest(key=key), patch.dict(target, {key: wrong}):
                (self.prepared / 'native-inputs.json').write_text(json.dumps(self.native))
                with self.assertRaises(ValueError):
                    self.proposal()

    def test_consumer_refuses_changed_preparation_before_launch(self):
        for name in ('remote.py', 'preparation.json', 'native-inputs.json'):
            with self.subTest(name=name):
                proposal = self.proposal()
                proposal['binding'] = {'run_id': 100}
                path = self.prepared / name
                original = path.read_bytes()
                path.write_bytes(original + b' ')
                try:
                    with self.assertRaisesRegex(ValueError, 'dependency changed'):
                        process.Callers({'binding': proposal['binding']}, proposal, self.root, proposal['runner'])
                finally:
                    path.write_bytes(original)

    def test_native_read_uses_the_frozen_input_path_and_bytes(self):
        proposal = self.proposal()
        phase = entry.Entry.__new__(entry.Entry)
        phase.prepared = self.prepared
        phase.runtime = dict(proposal['runtime_static'])
        phase.pins = proposal['callers']['verify-retained']['dependencies']
        path = self.prepared / 'native-inputs.json'
        copy = self.root / 'elsewhere.json'
        copy.write_bytes(path.read_bytes())
        copy.chmod(0o600)
        with patch.dict(phase.runtime, {'native_inputs': str(copy)}), self.assertRaisesRegex(ValueError, 'native input'):
            phase.native()
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'native input'):
            phase.native()

    def test_publicly_readable_input_cannot_be_frozen_for_private_reader(self):
        (self.prepared / 'native-inputs.json').chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'private'):
            self.proposal()

    def test_entry_rejects_different_destination_run_and_deadline_before_review(self):
        # Synthetic signed-candidate reader. No transport, review, or host access.
        (self.prepared / 'remote.py').write_text(
            'def bound_candidate():\n    return ' + repr((self.config, 100, {'manifest_sha256': 'b'*64})) + '\n')
        proposal = self.proposal()
        binding = {**proposal['candidate'], 'run_id': 100, 'manifest_sha256': 'b'*64}
        scope = {'binding': binding, 'runtime': proposal['runtime_static'], 'signed_finish': 3000,
                 'final_cutoff': 4800}
        payload = {'origin': 'native', 'action': 'clock', 'dependencies': proposal['callers']['clock']['dependencies'],
                   'deadline': 1500, 'scope': scope}
        self.addCleanup(sys.modules.pop, 'remote', None)
        with patch.object(entry.time, 'time', return_value=1000):
            for target, key, wrong in ((binding, 'host', 'other.invalid'), (binding, 'run_id', 99),
                                       (scope, 'signed_finish', 3100), (payload, 'deadline', 1000)):
                with self.subTest(key=key), patch.dict(target, {key: wrong}), self.assertRaises(ValueError):
                    entry.Entry(payload)


if __name__ == '__main__':
    unittest.main()
