import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('identity_transition_outside_tested', HERE / 'identity-transition-outside.py')
outside = importlib.util.module_from_spec(spec); spec.loader.exec_module(outside)


def raw(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class IdentityTransitionOutsideTests(unittest.TestCase):
    def fixture(self, scenario='identity-postcommit'):
        manifest = {'schema': 'sbxr-qualification-manifest-v3', 'mode': 'v3',
                    'v3_attempt': {'evidence_policy': 'repair-issuance-bounded-v4', 'outside_runner_id': 'runner-1'}}
        manifest_raw = raw(manifest)
        request = {'scenario_id': scenario, 'qualification_manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
                   'scenario_limit_seconds': 1800, 'not_before': '2026-09-11T00:00:00Z', 'deadline_unix': 1789086600}
        request_raw = raw(request)
        state = {'schema': 'sbxr-v4-identity-transition-entry-v1', 'scenario_id': scenario,
                 'qualification_manifest_sha256': request['qualification_manifest_sha256'],
                 'request_sha256': hashlib.sha256(request_raw).hexdigest(), 'started_at': request['not_before'],
                 'entry_started_at': '2026-09-11T00:00:02Z'}
        state_raw = raw(state); bound = outside.binding(manifest_raw, request_raw, state)
        process = {'pid': 21, 'start_tick': 210, 'listener_owned': True, 'confirmed_disclosure': True}
        ready = dict(bound, connection_id='1' * 32, source_configuration_sha256='2' * 64,
                     noncredential_sha256='3' * 64, link_sha256='4' * 64, old_client=process,
                     old_established_at='2026-09-11T00:00:03Z', ready_at='2026-09-11T00:00:04Z')
        if scenario == 'identity-unavailable': ready['subscription_outside_failed_at'] = '2026-09-11T00:00:03Z'
        ready_raw = raw(ready)
        pre = scenario == 'identity-precommit'
        closed = {'schema': 'sbxr-v4-identity-transition-closed-v1', 'scenario_id': scenario,
                  'qualification_manifest_sha256': bound['qualification_manifest_sha256'],
                  'request_sha256': bound['request_sha256'], 'ready_sha256': hashlib.sha256(ready_raw).hexdigest(),
                  'connection_id': ready['connection_id'], 'old_terminated_at': '2026-09-11T00:00:05Z',
                  'fresh_old_checked_at': '2026-09-11T00:00:06Z', 'target_healthy_at': '2026-09-11T00:00:07Z',
                  'fresh_old_refused': True}
        closed_raw = raw(closed)
        result = dict(ready, ready_sha256=hashlib.sha256(ready_raw).hexdigest(), closed_sha256=hashlib.sha256(closed_raw).hexdigest(),
                      old_terminated_at='2026-09-11T00:00:05Z', fresh_old_checked_at='2026-09-11T00:00:06Z',
                      target_healthy_at='2026-09-11T00:00:07Z', selected_configuration_sha256=('2' if pre else '5') * 64,
                      selected_client=None if pre else dict(process, pid=22), final_traffic_at='2026-09-11T00:00:08Z',
                      cleanup_at='2026-09-11T00:00:09Z', facts={
                        'established_old_session_terminated': True, 'outside_target_healthy': True,
                        'fresh_old_refused': True, 'source_restored': pre, 'replacement_traffic': not pre,
                        'unchanged_link_and_noncredential_fields': True, 'runner_cleanup_complete': True})
        return manifest_raw, request_raw, state_raw, ready_raw, closed_raw, raw(result)

    def test_current_request_chain_accepts_cleanup_and_forward_results(self):
        for scenario in outside.SCENARIOS:
            with self.subTest(scenario=scenario):
                result = outside.check_chain(*self.fixture(scenario))
                self.assertTrue(result['facts']['established_old_session_terminated'])

    def test_successful_old_connection_after_revocation_is_refused(self):
        values = list(self.fixture('identity-postcommit'))
        result = json.loads(values[-1]); result['facts']['fresh_old_refused'] = False; values[-1] = raw(result)
        with self.assertRaisesRegex(ValueError, 'refused'):
            outside.check_chain(*values)

    def test_changed_noncredential_fields_are_refused(self):
        values = list(self.fixture('identity-precommit'))
        result = json.loads(values[-1]); result['facts']['unchanged_link_and_noncredential_fields'] = False; values[-1] = raw(result)
        with self.assertRaisesRegex(ValueError, 'refused'):
            outside.check_chain(*values)

    def test_cleanup_after_original_deadline_and_reset_start_are_refused(self):
        values = list(self.fixture())
        result = json.loads(values[-1]); result['cleanup_at'] = '2026-09-11T00:30:01Z'
        values[-1] = raw(result)
        with self.assertRaisesRegex(ValueError, 'refused'):
            outside.check_chain(*values)
        values = list(self.fixture())
        state = json.loads(values[2]); state['started_at'] = '2026-09-11T00:00:01Z'
        values[2] = raw(state)
        with self.assertRaisesRegex(ValueError, 'refused'):
            outside.check_chain(*values)

    def test_result_cannot_replace_the_ready_connection_identity(self):
        for change in ({'connection_id': 'f'*32}, {'noncredential_sha256': 'f'*64},
                       {'link_sha256': 'f'*64}, {'old_established_at': '2026-09-11T00:00:04Z'}):
            with self.subTest(change=change):
                values = list(self.fixture())
                result = json.loads(values[-1]); result.update(change); values[-1] = raw(result)
                with self.assertRaisesRegex(ValueError, 'refused'):
                    outside.check_chain(*values)

    def test_repaired_link_producer_checks_actual_probe_current_request_and_same_link(self):
        spec = importlib.util.spec_from_file_location('tested_identity_repair', HERE / 'identity-repair-outside.py')
        repair = importlib.util.module_from_spec(spec); spec.loader.exec_module(repair)
        bound = {'scenario_id': 'identity-unavailable', 'qualification_manifest_sha256': 'a'*64,
                 'request_sha256': 'b'*64, 'outside_runner_id': 'runner-1',
                 'not_before': '2030-01-01T00:00:00Z', 'deadline_unix': 1893457800}
        value = {'link': 'https://203.0.113.7:8443/s/' + 'A'*43, 'certificate_der_sha256': 'c'*64,
                 'configuration': {'outbounds': []}, 'binding': {k: v for k, v in bound.items() if k != 'outside_runner_id'}}
        expected = repair.link.hashes(value)['link']
        probe = mock.Mock()
        with mock.patch.object(repair.time, 'time', return_value=1893456010), \
                mock.patch.object(repair.link, 'now', side_effect=('2030-01-01T00:00:10Z', '2030-01-01T00:00:11Z')):
            result = repair.produce(raw(value), bound, expected, probe)
        probe.complete.assert_called_once_with(value, 200, 12)
        self.assertEqual(result['link_sha256'], expected)
        self.assertEqual(result['outside_runner_id'], bound['outside_runner_id'])
        self.assertNotIn('/s/', json.dumps(result))
        for altered, wanted, moment in ((dict(value, binding=dict(value['binding'], request_sha256='d'*64)), expected, 1893456010),
                                        (value, 'e'*64, 1893456010), (value, expected, 1893457801)):
            probe = mock.Mock()
            with mock.patch.object(repair.time, 'time', return_value=moment), self.assertRaises(repair.link.Refused):
                repair.produce(raw(altered), bound, wanted, probe)
            probe.complete.assert_not_called()

    def test_real_producer_emits_the_controller_and_collector_filenames(self):
        for scenario in outside.SCENARIOS:
            with self.subTest(scenario=scenario):
                values = self.fixture(scenario)
                state = json.loads(values[2])
                state.update(source_configuration_sha256='2'*64, noncredential_sha256='3'*64, link_sha256='4'*64)
                bound = outside.binding(values[0], values[1], state)
                published = {}

                class Connection:
                    def __init__(self, kind): self.kind, self.requests = kind, 0
                    def request(self):
                        self.requests += 1
                        if self.kind == 1 and self.requests > 1: raise outside.base.ClosedTransport()
                        if self.kind == 2: raise ConnectionRefusedError()
                    def close(self): pass

                class Backend:
                    second = 1789084810
                    connections = 0
                    cleaned = False
                    def prepare(self): pass
                    def start_client(self, replacement=False):
                        return {'pid': 22 if replacement else 21, 'start_tick': 210,
                                'listener_owned': True, 'confirmed_disclosure': True}
                    def stop_client(self): pass
                    def client_alive(self): pass
                    def routes(self): pass
                    def connect(self, proxy=True):
                        self.connections += 1
                        return Connection(self.connections)
                    def clock(self):
                        self.second += 1
                        return datetime.fromtimestamp(self.second, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                    def subscription_unavailable(self): return self.clock()
                    def publish(self, name, document): published[name] = document
                    def trigger(self):
                        ready = published[scenario + '-outside-ready.json']
                        return {'schema': 'sbxr-v4-identity-transition-action-v1', 'scenario_id': scenario,
                                'request_sha256': bound['request_sha256'], 'ready_sha256': outside.sha(raw(ready)),
                                'source_configuration_sha256': '2'*64, 'target_configuration_sha256': '5'*64}
                    def final_controller(self):
                        assert scenario + '-outside-closed.json' in published
                        return {'phase': 'recovered'}
                    def state(self): return state
                    def cleanup(self): self.cleaned = True
                    def repair_subscription(self):
                        assert self.cleaned and scenario + '-outside-result.json' in published
                    def pause(self): raise AssertionError('fixture unexpectedly waited')

                backend = Backend()
                result = outside.produce(backend, bound, state)
                self.assertTrue(backend.cleaned)
                self.assertEqual(set(published), {scenario + '-outside-' + suffix + '.json'
                                                 for suffix in ('ready', 'closed', 'result')})
                self.assertEqual(outside.check_chain(values[0], values[1], raw(state),
                    raw(published[scenario + '-outside-ready.json']), raw(published[scenario + '-outside-closed.json']), raw(result)), result)

    def test_live_transport_reads_the_same_paths_that_entry_and_controller_write(self):
        options = {'remote_state_dir': '/run/sbxr-qualification', 'ssh_key': '/fixture/key',
                   'known_hosts': '/fixture/known', 'host': 'example.test'}
        backend = outside.LiveBackend(options, {}, 'identity-postcommit')
        with mock.patch.object(backend, 'remote_read', return_value=b'{}') as read:
            for name, actual in (('07-state.json', 'identity-postcommit-entry.json'),
                                 ('07-source-client.json', 'identity-postcommit-source-client.json'),
                                 ('07-replacement-client.json', 'identity-postcommit-selected-client.json')):
                backend.fetch(name)
                read.assert_called_with('/run/sbxr-qualification/' + actual)
            backend.trigger()
            read.assert_called_with('/run/sbxr-qualification/identity-postcommit-action.json')


if __name__ == '__main__': unittest.main()
