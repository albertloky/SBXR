import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('transition_operator', ROOT / 'transition-operator.py')
transition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transition)


def record_for(name):
    selected = transition.SPECS[name]
    family = selected['field'].split('.', 1)[0]
    operation = {'checkpoint': selected['checkpoint'], 'direction': selected['direction']}
    value = {family: operation}
    if family == 'subscription_rotation':
        source = {'link_id': '1' * 32, 'credential_sha256': '2' * 64,
                  'certificate_generation': 3, 'certificate_sha256': ['4' * 64] * 4}
        target = dict(source, link_id='5' * 32, credential_sha256='6' * 64)
        operation.update({'source': source, 'target': target})
        value['serving'] = operation['target' if selected['direction'] == 'forward' else 'source']
    else:
        operation.update({'source_configuration_sha256': 'a' * 64,
                          'target_configuration_sha256': 'b' * 64})
        value['configuration_sha256'] = operation['source_configuration_sha256']
    return value


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class FakeProcess:
    def __init__(self, output, text=False):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, output.encode() if isinstance(output, str) else output)
        os.close(write_fd)
        self.stdout = os.fdopen(read_fd, 'r' if text else 'rb', buffering=1 if text else 0)
        self.stdin = io.StringIO() if text else io.BytesIO()
        self.returncode = None
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = 0
        if not self.stdout.closed:
            self.stdout.close()
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


class TransitionSpecificationTests(unittest.TestCase):
    def test_all_scenarios_validate_only_the_exact_checkpoint(self):
        for name, selected in transition.SPECS.items():
            with self.subTest(name=name):
                value = record_for(name)
                transition.validate_checkpoint(selected, value)
                value[selected['field'].split('.', 1)[0]]['checkpoint'] = 'wrong'
                with self.assertRaisesRegex(ValueError, 'unexpected transition checkpoint'):
                    transition.validate_checkpoint(selected, value)

    def test_committed_link_requires_target_authority(self):
        value = record_for('link-postcommit')
        value['serving'] = value['subscription_rotation']['source']
        with self.assertRaisesRegex(ValueError, 'target is not authoritative'):
            transition.validate_checkpoint(transition.SPECS['link-postcommit'], value)

    def test_identity_boundaries_retain_source_authority(self):
        for name in ('identity-precommit', 'identity-postcommit'):
            value = record_for(name)
            value['configuration_sha256'] = value['client_identity_rotation']['target_configuration_sha256']
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'source Client Identity'):
                transition.validate_checkpoint(transition.SPECS[name], value)

    def test_final_authority_follows_cleanup_or_forward_direction(self):
        for name, selected in transition.SPECS.items():
            interrupted = record_for(name)
            family = selected['field'].split('.', 1)[0]
            operation = interrupted[family]
            if family == 'subscription_rotation':
                final = {'serving': operation['source' if selected['direction'] == 'cleanup' else 'target']}
                wrong = {'serving': operation['target' if selected['direction'] == 'cleanup' else 'source']}
            else:
                correct_key = 'source_configuration_sha256' if selected['direction'] == 'cleanup' else 'target_configuration_sha256'
                wrong_key = 'target_configuration_sha256' if selected['direction'] == 'cleanup' else 'source_configuration_sha256'
                final = {'configuration_sha256': operation[correct_key]}
                wrong = {'configuration_sha256': operation[wrong_key]}
            with self.subTest(name=name):
                transition.validate_final(selected, interrupted, final)
                with self.assertRaisesRegex(ValueError, 'authority mismatch'):
                    transition.validate_final(selected, interrupted, wrong)

    def test_duplicate_json_keys_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate Ownership Record key'):
            json.loads('{"schema":1,"schema":2}', object_pairs_hook=transition.unique)

    def test_state_is_exclusive_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            transition.write_state(path, {'schema': 1})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaisesRegex(ValueError, 'already exists'):
                transition.write_state(path, {'schema': 1})

    def test_scenario_contract_uses_exact_public_names_and_codes(self):
        self.assertEqual(transition.SPECS['identity-precommit']['field'], 'client_identity_rotation.checkpoint')
        self.assertEqual(transition.SPECS['identity-precommit']['checkpoint'], 'source quiescent')
        self.assertEqual(transition.SPECS['identity-postcommit']['checkpoint'], 'source revoked')
        self.assertEqual(transition.SPECS['link-precommit']['checkpoint'], 'stop authorized')
        self.assertEqual(transition.SPECS['link-postcommit']['checkpoint'], 'committed')
        for selected in transition.SPECS.values():
            self.assertRegex(selected['result'], r'^PROXY-INSTALLATION-[A-Z-]+$')

    def test_link_gate_uses_ordered_durable_boundaries(self):
        fake = FakeProcess(b'')
        with mock.patch.object(transition.subprocess, 'Popen', return_value=fake) as popen:
            transition.link_gate('fixture.service', 90, 'link-postcommit')
        command = popen.call_args.args[0]
        self.assertEqual(command[command.index('--value') + 1], 'target authorized')
        self.assertEqual([command[index + 1] for index, value in enumerate(command)
                          if value == '--then-value'], ['stop authorized', 'committed'])
        self.assertEqual([command[index + 1] for index, value in enumerate(command)
                          if value == '--then-path'], [str(transition.NEXT), str(transition.SERVING_TOKEN)])
        fake.stdout.close()

    def test_link_closure_rejects_server_deadline_as_termination_proof(self):
        handoff = {'challenge_sha256': '1' * 64, 'ack_sha256': '2' * 64,
                   'connection_id': 'connection-1'}
        closed = {'challenge_sha256': '1' * 64, 'ack_sha256': '2' * 64,
                  'connection_id': 'connection-1', 'server_deadline_seconds': 5,
                  'pending_elapsed_milliseconds': 5000, 'closure_kind': 'eof',
                  'closed_at': '2026-09-11T00:00:05Z'}
        with mock.patch.dict(os.environ, {'SBXR_QUALIFICATION_REQUEST': '/request',
                                          'SBXR_QUALIFICATION_MANIFEST': '/manifest'}), \
                mock.patch.object(transition, 'check_outside', return_value=(b'closed', closed)):
            with self.assertRaisesRegex(ValueError, 'closure mismatch'):
                transition.link_closed('link-precommit', handoff, time.monotonic() + 5)

    def test_menu_parser_handles_buffered_frame_and_checks_recovery_plan(self):
        read_fd, write_fd = os.pipe()
        selected = transition.SPECS['identity-postcommit']
        transcript = (
            'SBXR V3\n1. Finish Client Identity rotation\n0. Exit\n'
            'Action: Finish Client Identity rotation\n'
            'Selected direction: ' + selected['plan'] + '.\n'
            'Finish Client Identity rotation? [y/N]\n'
            'Code: ' + selected['result'] + '\nSBXR V3\n0. Exit\n'
        ).encode()
        os.write(write_fd, transcript)
        os.close(write_fd)
        output = os.fdopen(read_fd, 'rb', buffering=0)
        process = type('Process', (), {'stdout': output, 'stdin': io.BytesIO()})()
        stream = transition.LineStream(output)
        deadline = time.monotonic() + 5
        transition.choose(process, stream, selected['finish'], deadline, selected['plan'])
        transition.wait_code(process, stream, selected['result'], deadline)
        self.assertEqual(process.stdin.getvalue(), b'1\ny\n0\n')
        output.close()

    def test_product_refusal_read_ahead_by_menu_parser_ends_boundary_wait(self):
        gate_read, gate_write = os.pipe()
        menu = FakeProcess(
            '1. Rotate Client Identity\n0. Exit\nRotate Client Identity? [y/N]\n'
            'Failed safety check: Old-session quiescence\n'
            'Code: PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-INCOMPLETE\n')
        with os.fdopen(gate_read, 'rb', buffering=0) as gate_output:
            try:
                output = transition.LineStream(menu.stdout)
                deadline = time.monotonic() + 1
                transition.choose(menu, output, 'Rotate Client Identity', deadline)
                gate = type('Gate', (), {'stdin': io.BytesIO()})()
                with self.assertRaises(transition.ActionEndedBeforeBoundary) as error:
                    transition.observe_identity_boundaries(
                        gate, transition.LineStream(gate_output), ['target prepared'],
                        None, 'fixture.service', deadline, menu_output=output)
                self.assertEqual(error.exception.result_code,
                                 'PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-INCOMPLETE')
                self.assertEqual(gate.stdin.getvalue(), b'')
                self.assertEqual(menu.stdin.getvalue(), b'1\ny\n')
            finally:
                os.close(gate_write)
                menu.stdout.close()

    def test_boundary_wait_reads_refusal_from_live_menu_pipe(self):
        gate_read, gate_write = os.pipe()
        menu_read, menu_write = os.pipe()
        with os.fdopen(gate_read, 'rb', buffering=0) as gate, \
                os.fdopen(menu_read, 'rb', buffering=0) as menu:
            try:
                os.write(menu_write, b'Progress: Stopping source\nCode: PROXY-INSTALLATION-ACTION-REFUSED\n')
                with self.assertRaises(transition.ActionEndedBeforeBoundary) as error:
                    transition.gate_event(transition.LineStream(gate), time.monotonic() + 1,
                                          transition.LineStream(menu))
                self.assertEqual(error.exception.result_code, 'PROXY-INSTALLATION-ACTION-REFUSED')
                self.assertEqual(transition.ActionEndedBeforeBoundary(
                    'PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-INCOMPLETE').result_code,
                    'PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-INCOMPLETE')
            finally:
                os.close(gate_write)
                os.close(menu_write)

    def test_partial_menu_line_does_not_block_ready_kernel_event(self):
        gate_read, gate_write = os.pipe()
        menu_read, menu_write = os.pipe()
        with os.fdopen(gate_read, 'rb', buffering=0) as gate, \
                os.fdopen(menu_read, 'rb', buffering=0) as menu:
            try:
                output = transition.LineStream(menu)
                output.buffer.extend(b'Progress: partial')
                os.write(gate_write, b'{"state":"boundary-held"}\n')
                self.assertEqual(transition.gate_event(transition.LineStream(gate),
                                 time.monotonic() + 1, output), {'state': 'boundary-held'})
                self.assertEqual(output.buffer, b'Progress: partial')
            finally:
                os.close(gate_write)
                os.close(menu_write)

    def test_boundary_wait_refuses_menu_eof_and_does_not_expose_unknown_results(self):
        gate_read, gate_write = os.pipe()
        menu = FakeProcess(b'')
        with os.fdopen(gate_read, 'rb', buffering=0) as gate:
            try:
                with self.assertRaisesRegex(ValueError, 'UI exited'):
                    transition.gate_event(transition.LineStream(gate), time.monotonic() + 1,
                                          transition.LineStream(menu.stdout))
                error = transition.ActionEndedBeforeBoundary('private unrecognized output')
                self.assertIsNone(error.result_code)
                self.assertNotIn('private', str(error))
            finally:
                os.close(gate_write)
                menu.stdout.close()

    def test_qualification_preflight_binds_scenario_manifest_phase_and_deadline(self):
        manifest = json.dumps({'v3_attempt': {
            'evidence_policy': 'repair-issuance-bounded-v4',
            'required_scenarios': ['link-precommit', 'link-postcommit', 'snap-refresh',
                                   'identity-precommit', 'identity-postcommit'],
        }}, separators=(',', ':')).encode()
        manifest_hash = transition.digest(manifest)
        current = 2_000_000_000

        def authority(path, mode):
            self.assertEqual(mode, 0o600)
            if str(path) == '/manifest':
                return manifest
            return json.dumps({'scenario_id': self.scenario,
                               'deadline_unix': current + 100,
                               'qualification_manifest_sha256': manifest_hash}).encode()

        environment = {'SBXR_QUALIFICATION_REQUEST': '/request',
                       'SBXR_QUALIFICATION_MANIFEST': '/manifest'}
        for scenario, phase in (('link-precommit', 'initial'),
                                ('identity-postcommit', 'after-snap-refresh')):
            self.scenario = scenario
            with self.subTest(scenario=scenario), \
                    mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(transition, 'protected_bytes', side_effect=authority), \
                    mock.patch.object(transition.time, 'time', return_value=current), \
                    mock.patch.object(transition.subprocess, 'run') as run:
                deadline, observed_hash = transition.qualification_preflight(scenario, 90)
                self.assertEqual((deadline, observed_hash), (current + 100, manifest_hash))
                self.assertEqual(run.call_args.args[0][-2:], [scenario, phase])

        self.scenario = 'link-postcommit'
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(transition, 'protected_bytes', side_effect=authority), \
                mock.patch.object(transition.time, 'time', return_value=current):
            with self.assertRaisesRegex(ValueError, 'wrong scenario'):
                transition.qualification_preflight('link-precommit', 90)

    def test_interrupt_and_recover_coordinator_sequences_all_four_boundaries(self):
        manifest_hash = 'c' * 64
        for scenario, selected in transition.SPECS.items():
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                interrupted = record_for(scenario)
                initial = {'schema': 2, 'configuration_sha256': 'a' * 64}
                if scenario.startswith('link-'):
                    initial['serving'] = interrupted['subscription_rotation']['source']
                initial_raw, interrupted_raw = encoded(initial), encoded(interrupted)
                identity = scenario.startswith('identity-')
                link_case = scenario.startswith('link-')
                target_record = record_for(scenario)
                if link_case:
                    target_record['subscription_rotation']['checkpoint'] = 'target authorized'
                    target_record['subscription_rotation']['direction'] = 'cleanup'
                    target_record['serving'] = target_record['subscription_rotation']['source']
                stopped_record = record_for('link-precommit') if link_case else None
                target_raw = encoded(target_record) if link_case else b''
                stopped_raw = encoded(stopped_record) if link_case else b''
                events = [json.dumps({'state': 'armed'})]
                if link_case:
                    for index, raw_value in enumerate([target_raw, stopped_raw] +
                                                       ([interrupted_raw] if scenario == 'link-postcommit' else [])):
                        path = transition.SERVING_TOKEN if index == 2 else root / 'next'
                        events.append(json.dumps({'state': 'boundary-held', 'pid': 123,
                            'boundary_index': index, 'boundary': 'before-open',
                            'path': str(path), 'record_sha256': transition.digest(raw_value)}))
                elif not identity:
                    events.append(json.dumps({'state': 'boundary-held', 'pid': 123, 'boundary': 'before-open',
                                  'path': str(root / 'next'), 'record_sha256': transition.digest(interrupted_raw)}))
                events.append(json.dumps({'state': 'interrupted'}))
                gate = FakeProcess('\n'.join(events) + '\n', text=not (identity or link_case))
                menu = FakeProcess(
                    '1. ' + selected['action'] + '\n0. Exit\n' +
                    selected['action'] + '? [y/N]\n')
                state_file = root / ('transition-' + scenario + '.json')
                with mock.patch.object(transition, 'STATE_DIR', root), \
                        mock.patch.object(transition, 'NEXT', root / 'next'), \
                        mock.patch.object(transition, 'common_preflight', return_value=(time.time() + 100, manifest_hash)), \
                        mock.patch.object(transition.startup, 'Observer'), \
                        mock.patch.object(transition.link, 'Observer') as link_observer_type, \
                        mock.patch.dict(os.environ, {'SBXR_QUALIFICATION_REQUEST': '/request'}), \
                        mock.patch.object(transition, 'protected_bytes', return_value=b'{}'), \
                        mock.patch.object(transition, 'observe_identity_boundaries', return_value=(
                            interrupted_raw, interrupted, {'pid': 123}, [{'check': 'fixture'}])), \
                        mock.patch.multiple(transition,
                            identity_entry=mock.Mock(return_value=({'entry_started_at': '2026-09-11T00:00:00Z'}, b'entry')),
                            identity_ready=mock.Mock(return_value=({}, b'ready')),
                            publish_identity_trigger=mock.Mock()), \
                        mock.patch.object(transition, 'link_handoff', return_value={'challenge_sha256': '7' * 64, 'ack_sha256': '8' * 64, 'connection_id': 'c'}), \
                        mock.patch.object(transition, 'link_closed', side_effect=lambda s, h, d: dict(h, closed_sha256='9' * 64)), \
                        mock.patch.object(transition, 'protected_record', side_effect=(
                            [(initial_raw, initial), (target_raw, target_record), (target_raw, target_record),
                             (stopped_raw, stopped_record), (stopped_raw, stopped_record)] +
                            ([(interrupted_raw, interrupted)] if scenario == 'link-postcommit' else []) +
                            [(interrupted_raw, interrupted)] if link_case else
                            [(initial_raw, initial), (interrupted_raw, interrupted), (interrupted_raw, interrupted)])), \
                        mock.patch.object(transition, 'held_process', return_value={
                            'pid': 123, 'start_tick': 456, 'executable_device': 1,
                            'executable_inode': 2, 'cgroup': '/fixture'}), \
                        mock.patch.object(transition.subprocess, 'Popen', return_value=gate), \
                        mock.patch.object(transition, 'launch_menu', return_value=menu), \
                        mock.patch('builtins.print'):
                    if link_case:
                        link_observer = link_observer_type.return_value
                        link_observer.source = interrupted['subscription_rotation']['source']
                        link_observer.source_process = {'pid': 44, 'start_tick': 55}
                        link_observer.proxy_process = {'pid': 66, 'start_tick': 77}
                        link_observer.configuration_sha256 = 'a' * 64
                        link_observer.initial_staging_empty = True
                        link_observer.target_staged.return_value = (interrupted['subscription_rotation']['target'], {'target_staged_only': True})
                        link_observer.quiescent.return_value = {'owned_processes_and_descendants_absent': True}
                        link_observer.committed_unpublished.return_value = {'serving_material': 'source'}
                    transition.interrupt(scenario, 90)
                expected_gate = (b'continue\n' + (b'continue\n' if scenario == 'link-postcommit' else b'') + b'kill\n') if link_case else (b'kill\n' if identity else 'kill\n')
                self.assertEqual(gate.stdin.getvalue(), expected_gate)
                self.assertEqual(menu.stdin.getvalue(), b'1\ny\n')
                saved = json.loads(state_file.read_text())
                self.assertEqual(saved['checkpoint'], selected['checkpoint'])
                self.assertEqual(saved['direction'], selected['direction'])
                if link_case:
                    self.assertEqual(saved['target_record_sha256'], transition.digest(target_raw))
                    self.assertEqual(saved['boundary_path'], str(
                        transition.SERVING_TOKEN if scenario == 'link-postcommit' else root / 'next'))

                family = selected['field'].split('.', 1)[0]
                operation = interrupted[family]
                if family == 'subscription_rotation':
                    final = {'serving': operation['source' if selected['direction'] == 'cleanup' else 'target']}
                    final['configuration_sha256'] = 'a' * 64
                else:
                    key = 'source_configuration_sha256' if selected['direction'] == 'cleanup' else 'target_configuration_sha256'
                    final = {'configuration_sha256': operation[key]}
                final_raw = encoded(final)
                recovery = FakeProcess(
                    '1. ' + selected['finish'] + '\n0. Exit\n' +
                    'Selected direction: ' + selected['plan'] + '.\n' +
                    selected['finish'] + '? [y/N]\n' +
                    'Code: ' + selected['result'] + '\nSBXR V3\n0. Exit\n')
                with mock.patch.object(transition, 'STATE_DIR', root), \
                        mock.patch.object(transition, 'NEXT', root / 'next'), \
                        mock.patch.object(transition, 'common_preflight', return_value=(time.time() + 100, manifest_hash)), \
                        mock.patch.object(transition, 'read_state', return_value=saved), \
                        mock.patch.object(transition, 'protected_record', side_effect=[
                            (interrupted_raw, interrupted), (final_raw, final)]), \
                        mock.patch.dict(os.environ, {'SBXR_QUALIFICATION_REQUEST': '/request',
                                                     'SBXR_QUALIFICATION_MANIFEST': '/manifest'}), \
                        mock.patch.object(transition, 'protected_bytes', return_value=b'{}'), \
                        mock.patch.object(transition, 'check_outside', return_value=(b'closed', {})), \
                        mock.patch.object(transition, 'identity_closed', return_value={}), \
                        mock.patch.object(transition.link.Observer, 'for_recovery') as recovery_observer, \
                        mock.patch.object(transition, 'launch_menu', return_value=recovery), \
                        mock.patch('builtins.print'):
                    if link_case:
                        saved['outside_handoff']['closed_sha256'] = transition.digest(b'closed')
                        recovery_observer.return_value.final_running.return_value = {'selected': True, 'staging_empty': True}
                    transition.recover(scenario, 90)
                self.assertEqual(recovery.stdin.getvalue(), b'1\ny\n0\n')
                completed = json.loads(state_file.read_text())
                self.assertEqual(completed['phase'], 'recovered')
                self.assertEqual(completed['result_code'], selected['result'])

    def test_recovery_refuses_record_drift_before_starting_ui(self):
        selected = transition.SPECS['link-precommit']
        interrupted = record_for('link-precommit')
        raw = encoded(interrupted)
        state = {'schema': 'sbxr-v4-link-transition-controller-v1', 'scenario': 'link-precommit', 'phase': 'interrupted',
                 'field': selected['field'], 'checkpoint': selected['checkpoint'],
                 'direction': selected['direction'], 'qualification_manifest_sha256': 'd' * 64,
                 'interrupted_record_sha256': '0' * 64}
        with mock.patch.object(transition, 'common_preflight', return_value=(time.time() + 100, 'd' * 64)), \
                mock.patch.dict(os.environ, {'SBXR_QUALIFICATION_REQUEST': '/request'}), \
                mock.patch.object(transition, 'protected_bytes', return_value=b'{}'), \
                mock.patch.object(transition, 'read_state', return_value=state), \
                mock.patch.object(transition, 'protected_record', return_value=(raw, interrupted)), \
                mock.patch.object(transition, 'launch_menu') as launch:
            with self.assertRaisesRegex(ValueError, 'drifted'):
                transition.recover('link-precommit', 90)
        launch.assert_not_called()

    def test_gate_controller_failure_is_killed_and_leaves_no_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initial, raw = {'schema': 2}, encoded({'schema': 2})
            gate = FakeProcess(json.dumps({'state': 'refused'}) + '\n', text=True)
            with mock.patch.object(transition, 'STATE_DIR', root), \
                    mock.patch.object(transition, 'NEXT', root / 'next'), \
                    mock.patch.object(transition, 'common_preflight', return_value=(time.time() + 100, 'e' * 64)), \
                    mock.patch.object(transition, 'protected_record', return_value=(raw, initial)), \
                    mock.patch.object(transition.link, 'Observer'), \
                    mock.patch.dict(os.environ, {'SBXR_QUALIFICATION_REQUEST': '/request'}), \
                    mock.patch.object(transition, 'protected_bytes', return_value=b'{}'), \
                    mock.patch.object(transition.subprocess, 'Popen', return_value=gate):
                with self.assertRaisesRegex(ValueError, 'did not arm'):
                    transition.interrupt('link-precommit', 90)
            self.assertTrue(gate.killed)
            self.assertFalse((root / 'transition-link-precommit.json').exists())


if __name__ == '__main__':
    unittest.main()
