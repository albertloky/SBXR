import importlib.util
from pathlib import Path
import sys
from datetime import datetime, timezone
import hashlib
import json
import os
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module); return module

timing = load('identity_evidence_timing', 'evidence-timing.py')
evidence = load('identity_evidence_tested', 'identity-evidence.py')
private_helper = load('identity_private_helper_tested', 'identity-private-observation.py')
runtime_helper = load('identity_runtime_helper_tested', 'identity-runtime-observation.py')
unavailable_helper = load('identity_unavailable_helper_tested', 'identity-unavailable-subscription.py')


def populate_fixture(ctx):
    """Write a complete positive family source set for the real assembler fixture."""
    api, scenario, state = ctx.api, ctx.scenario, ctx.state
    def instant(value): return api.instant(value, 'identity fixture').epoch_second
    def stamp(second): return datetime.fromtimestamp(second, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    begin, action, finish = instant(state['entry_started_at']), instant(state['action_started_at']), instant(state['action_completed_at'])
    slots = [stamp(action + (finish - action) * n // 12) for n in range(1, 12)]
    source_sha, target_sha = '1' * 64, '2' * 64
    process = {'pid': 301, 'start_tick': 3001, 'executable_device': 11, 'executable_inode': 21,
               'cgroup': '/system.slice/sbxr-v4-' + scenario + '-301.service'}
    checks = ('startup-publication', 'reload', 'effective-route', 'source-only-before-gate', 'ordinary-start-denied-after-gate')
    checkpoints = ('target prepared', 'startup integration published', 'systemd reloaded', 'startup route verified', 'source quiescent')
    observations = []
    for index, (check, checkpoint) in enumerate(zip(checks, checkpoints)):
        details = {'drop_in_sha256': '5'*64}
        if index >= 1: details['loaded_condition_exact'] = True
        if index == 3:
            details.update(ordinary_active_start='no-op', source_process={'pid': 200, 'start_tick': 100},
                           target_staged_only=True, whole_host_owner=process['pid'])
        if index == 4:
            details.update(owned_processes_and_descendants_absent=True, main_pid=0,
                           ordinary_requests_denied=['start', 'restart'])
        observations.append({'boundary_index': index, 'boundary_process': process, 'check': check,
            'checkpoint': checkpoint, 'details': details, 'observed_at': slots[index + 1], 'record_sha256': str(index + 3) * 64})
    pre = scenario == 'identity-precommit'
    controller = {'schema': 'sbxr-v4-identity-transition-controller-v1', 'scenario': scenario,
        'phase': 'recovered' if scenario != 'identity-unavailable' else 'rotated',
        'qualification_manifest_sha256': ctx.manifest_sha, 'request_sha256': ctx.request_sha,
        'entry_started_at': state['entry_started_at'], 'started_at': stamp(action - 1), 'action_started_at': state['action_started_at'],
        'interrupted_at': slots[7], 'action_completed_at': state['action_completed_at'], 'completed_at': state['completed_at'],
        'initial_record_sha256': 'a' * 64, 'interrupted_record_sha256': 'b' * 64, 'final_record_sha256': 'c' * 64,
        'field': 'client_identity_rotation.checkpoint', 'checkpoint': 'source quiescent' if pre else 'source revoked',
        'direction': 'cleanup' if pre else 'forward', 'boundary_process': process,
        'source_configuration_sha256': source_sha, 'target_configuration_sha256': target_sha,
        'observations': observations,
        'result_code': ('PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-CLEANED-UP' if pre else
            'PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-FINISHED' if scenario == 'identity-postcommit' else
            'PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATED')}
    bound = {'schema': 'sbxr-v4-identity-transition-outside-v1', 'scenario_id': scenario,
        'qualification_manifest_sha256': ctx.manifest_sha, 'request_sha256': ctx.request_sha,
        'outside_runner_id': ctx.manifest['v3_attempt']['outside_runner_id'],
        'deadline_unix': ctx.request['deadline_unix'], 'started_at': state['started_at']}
    old = {'pid': 41, 'start_tick': 410, 'listener_owned': True, 'confirmed_disclosure': True}
    ready = dict(bound, connection_id='d' * 32, source_configuration_sha256=source_sha,
        noncredential_sha256='e' * 64, link_sha256='f' * 64, old_client=old,
        old_established_at=stamp(begin + 10), ready_at=stamp(begin + 11))
    if scenario == 'identity-unavailable': ready['subscription_outside_failed_at'] = stamp(begin + 9)
    ready_raw = api.canonical(ready)
    selected = None if pre else dict(old, pid=42)
    closed = {'schema': 'sbxr-v4-identity-transition-closed-v1', 'scenario_id': scenario,
        'qualification_manifest_sha256': ctx.manifest_sha, 'request_sha256': ctx.request_sha,
        'ready_sha256': api.digest(ready_raw), 'connection_id': ready['connection_id'],
        'old_terminated_at': slots[7], 'fresh_old_checked_at': slots[8], 'target_healthy_at': slots[9],
        'fresh_old_refused': True}
    closed_raw = api.canonical(closed)
    result = dict(ready, ready_sha256=api.digest(ready_raw), closed_sha256=api.digest(closed_raw), old_terminated_at=slots[7],
        fresh_old_checked_at=slots[8], target_healthy_at=slots[9],
        selected_configuration_sha256=source_sha if pre else target_sha, selected_client=selected,
        final_traffic_at=slots[10], cleanup_at=stamp(instant(state['completed_at']) - 1), facts={
            'established_old_session_terminated': True, 'outside_target_healthy': True,
            'fresh_old_refused': True, 'source_restored': pre, 'replacement_traffic': not pre,
            'unchanged_link_and_noncredential_fields': True, 'runner_cleanup_complete': True})
    def write(name, value):
        path = ctx.directory / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream: stream.write(api.canonical(value))
    write('identity-controller.json', controller); write('identity-outside-ready.json', ready)
    write('identity-outside-closed.json', closed)
    write('identity-outside-result.json', result)
    if scenario == 'identity-unavailable':
        write('identity-private-baseline.json', {'schema': 'sbxr-v4-identity-private-baseline-v1',
            'scenario_id': scenario, 'qualification_manifest_sha256': ctx.manifest_sha,
            'request_sha256': ctx.request_sha, 'source_configuration_sha256': source_sha,
            'noncredential_sha256': 'e'*64, 'serving_sha256': '9'*64, 'observed_at': stamp(begin+5),
            'local_public_https_failed_at': stamp(begin+8), 'issuance_lines': 0})
    def capture(name, helper, rows, start=slots[7], end=stamp(instant(state['completed_at']) - 1)):
        write(name, {'schema': 'sbxr-v4-captured-source-v1', 'scenario_id': scenario,
            'qualification_manifest_sha256': ctx.manifest_sha, 'request_sha256': ctx.request_sha,
            'helper': helper, 'started_at': start, 'completed_at': end, 'exit_code': 0,
            'events': [{'observed_at': at, 'record': {'event': event, 'result': 'observed', 'facts': facts}}
                       for at, event, facts in rows]})
    capture('identity-private.json', 'identity-private-observation', [(slots[10], 'unchanged_at',
        {'link_unchanged': True, 'noncredential_fields_unchanged': True, 'source_target_credentials_distinct': True})])
    runtime_event = ('unused_target_absent_at', {'unused_target_absent': True, 'source_authoritative': True}) if pre else (
        'one_target_at', {'exactly_one_target_published': True, 'staged_target_absent': True, 'source_not_restored': True})
    capture('identity-runtime.json', 'identity-runtime-observation', [(slots[10], *runtime_event)])
    if scenario == 'identity-unavailable':
        capture('identity-subscription.json', 'identity-unavailable-subscription', [
            (slots[8], 'fault_reported_at', {'outside_link_failed': True, 'local_public_https_failed': True,
                'proxy_443_healthy': True, 'certificate_unchanged': True}),
            (slots[9], 'fallback_disclosed_at', {'show_client_configuration_confirmed': True,
                'configuration_file_not_used': True})], start=stamp(action - 2))
        capture('identity-repair.json', 'identity-unavailable-repair', [(slots[10], 'same_link_restored_at',
            {'runtime_only_plan': True, 'no_certbot_child': True, 'no_issuance': True,
             'certificate_lineage_unchanged': True, 'same_link_restored': True, 'proxy_healthy': True,
             'firewall_exactly_restored': True})])


class IdentityEvidenceTests(unittest.TestCase):
    def test_actual_helpers_derive_scenario_from_current_request(self):
        for helper in (private_helper, runtime_helper):
            with self.subTest(helper=helper.__name__), tempfile.TemporaryDirectory() as folder:
                request = Path(folder) / 'request.json'
                request.write_text('{"scenario_id":"identity-postcommit","qualification_manifest_sha256":"' + '1'*64 + '"}')
                request.chmod(0o600)
                with mock.patch.dict(os.environ, {'SBXR_QUALIFICATION_REQUEST': str(request)}, clear=False):
                    self.assertEqual(helper.request_context()[2]['scenario_id'], 'identity-postcommit')
                    request.write_text('{"scenario_id":"identity-absent","qualification_manifest_sha256":"' + '1'*64 + '"}')
                    with self.assertRaises(ValueError):
                        helper.request_context()

    def test_private_producer_accepts_current_binding_and_refuses_stale_baseline(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            request = root/'request.json'
            request.write_text('{"scenario_id":"identity-postcommit","qualification_manifest_sha256":"' + '1'*64 + '"}')
            request.chmod(0o600)
            request_sha = hashlib.sha256(request.read_bytes()).hexdigest()
            source = {'inbounds':[], 'outbounds':[{'uuid':'11111111-1111-1111-1111-111111111111'}], 'log':{}}
            selected = {'inbounds':[], 'outbounds':[{'uuid':'22222222-2222-2222-2222-222222222222'}], 'log':{}}
            public = {'inbounds':[], 'outbounds':[{}], 'log':{}}
            serving = {'link_id':'3'*32}
            controller = {'scenario':'identity-postcommit', 'qualification_manifest_sha256':'1'*64,
                'request_sha256':request_sha,
                'source_configuration_sha256':'4'*64, 'target_configuration_sha256':'5'*64}
            baseline = {'scenario_id':'identity-postcommit', 'qualification_manifest_sha256':'1'*64,
                'request_sha256':request_sha, 'source_configuration_sha256':controller['source_configuration_sha256'],
                'noncredential_sha256':private_helper.api.digest(private_helper.api.canonical(public)),
                'serving_sha256':private_helper.api.digest(private_helper.api.canonical(serving))}
            ownership = {'serving':serving, 'configuration_sha256':controller['target_configuration_sha256']}
            values = {'identity private baseline':baseline, 'identity controller':controller,
                      'Ownership Record':ownership, 'source client':source, 'selected client':selected}
            with mock.patch.object(private_helper, 'ROOT', root), \
                    mock.patch.object(private_helper, 'read', side_effect=lambda path, label: values[label]), \
                    mock.patch.object(private_helper.os, 'geteuid', return_value=0), \
                    mock.patch.dict(os.environ, {'SBXR_QUALIFICATION_REQUEST':str(request)}, clear=False), \
                    mock.patch('builtins.print') as output:
                private_helper.main()
                self.assertEqual(output.call_count, 1)
                baseline['request_sha256'] = '0'*64
                with self.assertRaisesRegex(ValueError, 'stale'):
                    private_helper.main()

    def test_runtime_producer_checks_current_controller_and_every_transient_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            request = root/'request.json'
            request.write_text('{"scenario_id":"identity-postcommit","qualification_manifest_sha256":"' + '1'*64 + '"}')
            request.chmod(0o600)
            configuration = root/'config.json'; configuration.write_bytes(b'target'); configuration.chmod(0o640)
            request_sha = hashlib.sha256(request.read_bytes()).hexdigest()
            target_sha = hashlib.sha256(b'target').hexdigest()
            controller = {'scenario':'identity-postcommit', 'qualification_manifest_sha256':'1'*64,
                'request_sha256':request_sha, 'target_configuration_sha256':target_sha}
            ownership = {'configuration_sha256':target_sha, 'client_identity_rotation':None, 'proxy_startup':None}
            values = {'identity controller':controller, 'Ownership Record':ownership}
            transient = tuple(root/f'absent-{index}' for index in range(len(runtime_helper.TRANSIENT_PATHS)))
            with mock.patch.object(runtime_helper, 'ROOT', root), \
                    mock.patch.object(runtime_helper, 'CONFIGURATION', configuration), \
                    mock.patch.object(runtime_helper, 'TRANSIENT_PATHS', transient), \
                    mock.patch.object(runtime_helper, 'read', side_effect=lambda path, label, mode=0o600: values[label]), \
                    mock.patch.object(runtime_helper.os, 'geteuid', return_value=0), \
                    mock.patch.dict(os.environ, {'SBXR_QUALIFICATION_REQUEST':str(request)}, clear=False), \
                    mock.patch('builtins.print') as output:
                runtime_helper.main()
                self.assertEqual(output.call_count, 1)
                controller['request_sha256'] = '0'*64
                with self.assertRaisesRegex(ValueError, 'stale'):
                    runtime_helper.main()

    def test_unavailable_producer_reads_certificate_proxy_and_outside_facts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            request = root/'request.json'
            request.write_text('{"scenario_id":"identity-unavailable","qualification_manifest_sha256":"' + '1'*64 + '"}')
            request.chmod(0o600)
            request_sha = hashlib.sha256(request.read_bytes()).hexdigest()
            binding = {'scenario_id':'identity-unavailable', 'qualification_manifest_sha256':'1'*64,
                       'request_sha256':request_sha}
            serving = {'certificate_sha256':['1'*64]*4, 'link_id':'2'*32}
            source = {'inbounds':[], 'outbounds':[{'uuid':'11111111-1111-1111-1111-111111111111'}], 'log':{}}
            selected = {'inbounds':[], 'outbounds':[{'uuid':'22222222-2222-2222-2222-222222222222'}], 'log':{}}
            public = {'inbounds':[], 'outbounds':[{}], 'log':{}}
            documents = {
                'firewall.json': {'ipv4':'203.0.113.7'},
                'transition-identity-unavailable.json': {**binding, 'scenario':'identity-unavailable',
                    'target_configuration_sha256':'4'*64},
                'identity-unavailable-private-baseline.json': {**binding,
                'serving_sha256': hashlib.sha256(json.dumps(serving,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                    'noncredential_sha256':unavailable_helper.api.digest(unavailable_helper.api.canonical(public)),
                    'local_public_https_failed_at':'2030-01-01T00:00:01Z'},
                'identity-unavailable-outside-ready.json': {**binding,
                    'subscription_outside_failed_at':'2030-01-01T00:00:02Z'},
                'identity-unavailable-outside-result.json': {**binding,
                    'facts':{'outside_target_healthy':True,'replacement_traffic':True}},
                'identity-unavailable-selected-client.json': selected,
                'identity-unavailable-source-client.json': source,
            }
            for name, document in documents.items():
                (root/name).write_text(json.dumps(document)); (root/name).chmod(0o600)
            ownership=root/'ownership.json'
            ownership.write_text(json.dumps({'serving':serving,
                'configuration_sha256':documents['transition-identity-unavailable.json']['target_configuration_sha256']}))
            ownership.chmod(0o600)
            def command(argv, **kwargs):
                if argv[:2]==['systemctl','is-active']: return types.SimpleNamespace(returncode=0,stdout=b'')
                if argv[:2]==['systemctl','show']: return types.SimpleNamespace(returncode=0,stdout='44\n')
                if argv[0]=='ss': return types.SimpleNamespace(returncode=0,stdout='users:(("sing-box",pid=44,fd=7))')
                return types.SimpleNamespace(returncode=0,stdout=b'Proxy status: Running\nSubscription status: Problem detected\n',stderr=b'')
            with mock.patch.object(unavailable_helper,'ROOT',root), mock.patch.object(unavailable_helper,'OWNERSHIP',ownership), \
                    mock.patch.object(unavailable_helper.firewall,'STATE',root/'firewall.json'), \
                    mock.patch.object(unavailable_helper.firewall,'rules',return_value='rules'), \
                    mock.patch.object(unavailable_helper.firewall,'qualification_rules',return_value=[['expected']]), \
                    mock.patch.object(unavailable_helper.firewall,'expected_saved_rule',return_value=['expected']), \
                    mock.patch.object(unavailable_helper.subprocess,'run',side_effect=command), \
                    mock.patch.object(unavailable_helper.os,'geteuid',return_value=0), \
                    mock.patch.dict(os.environ,{'SBXR_QUALIFICATION_REQUEST':str(request)},clear=False), \
                    mock.patch('builtins.print') as output:
                unavailable_helper.main()
                self.assertEqual(output.call_count,2)
                stale = documents['identity-unavailable-outside-result.json'] | {'request_sha256':'0'*64}
                (root/'identity-unavailable-outside-result.json').write_text(json.dumps(stale))
                with self.assertRaisesRegex(ValueError, 'stale'):
                    unavailable_helper.main()

    def test_populate_fixture_passes_real_context_adapter(self):
        assembler = load('identity_fixture_assembler', 'assemble-evidence.py')
        later = load('identity_fixture_context', 'scenario-sources.py')
        for scenario in evidence.SCENARIOS:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as folder:
                directory = Path(folder); directory.chmod(0o700)
                manifest = {'schema': 'sbxr-qualification-manifest-v3', 'mode': 'v3',
                    'v3_attempt': {'evidence_policy': 'repair-issuance-bounded-v4',
                                   'outside_runner_id': 'runner-1'}}
                manifest_raw = assembler.canonical(manifest); manifest_sha = assembler.digest(manifest_raw)
                request = {'scenario_id': scenario, 'qualification_manifest_sha256': manifest_sha,
                    'scenario_limit_seconds': 1800, 'not_before': '2030-01-01T00:00:00Z',
                    'deadline_unix': 1893457800}
                request_raw = assembler.canonical(request) + b'\n'; request_sha = assembler.digest(request_raw)
                state = {'schema': 'sbxr-v4-scenario-entry-v1', 'scenario_id': scenario,
                    'qualification_manifest_sha256': manifest_sha, 'request_sha256': request_sha,
                    'started_at': request['not_before'], 'entry_started_at': '2030-01-01T00:00:02Z',
                    'action_started_at': '2030-01-01T00:02:00Z', 'action_completed_at': '2030-01-01T00:08:00Z',
                    'completed_at': '2030-01-01T00:10:00Z'}
                context = later.Context(assembler, scenario, manifest, manifest_raw, manifest_sha,
                    request, request_raw, request_sha, state, directory)
                populate_fixture(context)
                expected = {'controller', 'outside', 'private', 'runtime'}
                if scenario == 'identity-unavailable': expected.update(('baseline', 'subscription', 'repair'))
                self.assertEqual(set(evidence.sources(context)), expected)

    def test_rules_are_full_ordered_procedure_checks(self):
        for scenario in evidence.SCENARIOS:
            checks = [item.check for item in evidence.rules(timing, scenario)]
            self.assertEqual(checks[:10], [item.check for item in timing.later_common_rules()])
            self.assertEqual(checks[10:18], list(evidence.PREFIX))
            self.assertEqual(checks[18:], list(evidence.SUFFIX[scenario]))
            self.assertEqual(len(checks), len(set(checks)))

    def test_unknown_scenario_refuses_instead_of_borrowing_rules(self):
        with self.assertRaisesRegex(timing.EvidenceTimingRefusal, 'unsupported'):
            evidence.rules(timing, 'identity-absent')

    def test_unavailable_fallback_requires_outside_subscription_and_repair_sources(self):
        selected = {rule.check: rule for rule in evidence.rules(timing, 'identity-unavailable')}
        fallback = selected['unavailable-subscription-fallback']
        self.assertEqual(fallback.required_sources, ('outside', 'subscription', 'repair'))
        self.assertEqual({anchor.event for anchor in fallback.not_before},
                         {'final_traffic_at', 'fallback_disclosed_at', 'same_link_restored_at'})


if __name__ == '__main__': unittest.main()
