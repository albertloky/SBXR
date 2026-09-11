import importlib.util
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('transition', HERE / 'transition-operator.py')
transition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transition)
startup = transition.startup

CONDITION = ('{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --proxy-start-authorize ; '
             'ignore_errors=no ; start_time=[fixture] ; stop_time=[fixture] ; pid=123 ; code=exited ; status=1 }')


class StartupObservationTests(unittest.TestCase):
    def test_effective_condition_requires_one_exact_nonignored_guard_and_actual_denial(self):
        startup.exact_condition(CONDITION, denied=True)
        for bad in (CONDITION.replace('status=1', 'status=0'),
                    CONDITION.replace('pid=123', 'pid=0'),
                    CONDITION.replace('ignore_errors=no', 'ignore_errors=yes'),
                    CONDITION.replace('--proxy-start-authorize', '--other-role'),
                    CONDITION + CONDITION,
                    CONDITION.replace('path=/usr/local/bin/sbxr', 'path=/usr/local/bin/sbxr ; path=/usr/local/bin/sbxr')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                startup.exact_condition(bad, denied=True)

    def observer(self):
        with mock.patch.object(startup.Observer, 'running_source', return_value={'pid': 2147483000, 'start_tick': 10}):
            return startup.Observer({'configuration_sha256': transition.digest(b'source')}, self.reader,
                                    time.monotonic() + 10)

    def reader(self, path, mode):
        if path == startup.CONFIG:
            self.assertEqual(mode, 0o640)
            return b'source'
        if path == startup.TARGET:
            self.assertEqual(mode, 0o600)
            return b'target'
        self.assertEqual(path, startup.DROP_IN)
        self.assertEqual(mode, 0o644)
        return startup.DROP_IN_BYTES

    def record(self, checkpoint):
        return {'configuration_sha256': transition.digest(b'source'),
                'proxy_startup': {'drop_in_sha256': transition.digest(startup.DROP_IN_BYTES)},
                'client_identity_rotation': {'source_configuration_sha256': transition.digest(b'source'),
                    'target_configuration_sha256': transition.digest(b'target'),
                    'direction': 'cleanup', 'checkpoint': checkpoint}}

    def test_observes_effects_in_order_and_records_active_start_only_as_noop(self):
        observer = self.observer()
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(startup, 'TOKEN', Path(temporary) / 'absent'), \
                mock.patch.object(startup, 'DROP_IN') as drop_in, \
                mock.patch.object(observer, 'running_source', return_value=observer.source_process), \
                mock.patch.object(observer, 'property', side_effect=lambda name: CONDITION if name == 'ExecCondition' else 'no'), \
                mock.patch.object(observer, 'quiescent') as quiet, \
                mock.patch.object(observer, 'command') as command, \
                mock.patch.object(startup.observations, 'observe_flock', return_value={
                    'lock_state': 'locked', 'holders': [{'mode': 'WRITE', 'pid': 123}]}):
            drop_in.stat.return_value.st_gid = 0
            values = [observer.observe(checkpoint, self.record(checkpoint), {'pid': 123})
                      for checkpoint in startup.CHECKPOINTS]
        self.assertEqual([item['check'] for item in values], list(startup.CHECKS))
        self.assertEqual(values[3]['details']['ordinary_active_start'], 'no-op')
        self.assertEqual(values[4]['details']['ordinary_requests_denied'], ['start', 'restart'])
        self.assertEqual(quiet.call_count, 3)
        self.assertEqual([call.args[0] for call in command.call_args_list], [
            ['systemctl', 'start', 'sing-box.service'], ['systemctl', 'start', 'sing-box.service'],
            ['systemctl', 'restart', 'sing-box.service']])

    def test_missing_phase_wrong_source_target_or_published_bytes_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'order'):
            self.observer().observe('startup route verified', self.record('startup route verified'), {'pid': 123})
        for mutate in (
                lambda row: row.update(configuration_sha256='b' * 64),
                lambda row: row['client_identity_rotation'].update(direction='forward'),
                lambda row: row['client_identity_rotation'].update(target_configuration_sha256='c' * 64)):
            row = self.record('target prepared')
            mutate(row)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.observer().observe('target prepared', row, {'pid': 123})

    def test_quiescence_refuses_listener_even_when_service_says_stopped(self):
        observer = self.observer()
        with mock.patch.object(observer, 'property', side_effect=lambda name: '0' if name == 'MainPID' else 'inactive'), \
                mock.patch.object(observer, 'command', side_effect=['', 'LISTEN fixture']):
            with self.assertRaisesRegex(ValueError, 'listener remains'):
                observer.quiescent()

    def test_no_pid_is_insufficient_when_descendants_remain(self):
        observer = self.observer()
        with tempfile.TemporaryDirectory() as temporary:
            group = Path(temporary)
            (group / 'cgroup.events').write_text('populated 1\n')
            (group / 'cgroup.procs').write_text('456\n')
            with mock.patch.object(startup, 'GROUP', group), \
                    mock.patch.object(observer, 'property', side_effect=lambda name: '0' if name == 'MainPID' else 'inactive'), \
                    mock.patch.object(observer, 'command', return_value=''):
                with self.assertRaisesRegex(ValueError, 'descendants remain'):
                    observer.quiescent()


class OrderedActionTests(unittest.TestCase):
    def run_boundaries(self, altered=None):
        with tempfile.TemporaryDirectory() as temporary:
            next_path = Path(temporary) / 'next'
            checkpoints = list(startup.CHECKPOINTS)
            records = [StartupObservationTests().record(checkpoint) for checkpoint in checkpoints]
            raw = [json.dumps(row, sort_keys=True).encode() for row in records]
            events = [{'state': 'boundary-held', 'boundary': 'before-open', 'boundary_index': index,
                       'path': str(next_path), 'pid': 123, 'record_sha256': transition.digest(body)}
                      for index, body in enumerate(raw)]
            processes = [{'pid': 123, 'start_tick': 7, 'executable_device': 1, 'executable_inode': 2,
                          'cgroup': '/system.slice/fixture.service'} for _ in range(10)]
            if altered:
                altered(events, processes)
            gate = mock.Mock(stdin=io.BytesIO())
            stream = mock.Mock()
            observer = mock.Mock()
            observer.observe.side_effect = [
                {'check': name, 'observed_at': '2026-09-11T00:00:01.000001Z', 'details': {}}
                for name in startup.CHECKS]
            record_reads = [pair for pair in zip(raw, records) for _ in range(2)]
            with mock.patch.object(transition, 'NEXT', next_path), \
                    mock.patch.object(transition, 'gate_event', side_effect=events), \
                    mock.patch.object(transition, 'held_process', side_effect=processes), \
                    mock.patch.object(transition, 'protected_record', side_effect=record_reads):
                result = transition.observe_identity_boundaries(gate, stream, checkpoints, observer,
                                                                'fixture.service', time.monotonic() + 10)
            self.assertEqual(gate.stdin.getvalue(), b'continue\n' * 4)
            self.assertEqual([row['checkpoint'] for row in result[3]], checkpoints)
            self.assertEqual([row['boundary_index'] for row in result[3]], list(range(5)))

    def test_one_action_reaches_all_required_startup_observations(self):
        self.run_boundaries()

    def test_skipped_boundary_wrong_record_or_reused_pid_are_not_proof(self):
        for alter in (
                lambda events, processes: events[2].update(boundary_index=3),
                lambda events, processes: events[2].update(record_sha256='0' * 64),
                lambda events, processes: processes[4].update(start_tick=8)):
            with self.subTest(alter=alter), self.assertRaises(ValueError):
                self.run_boundaries(alter)


if __name__ == '__main__':
    unittest.main()
