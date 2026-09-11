"""Synthetic retained inputs for cross-language 11–25 assembly tests only."""
import copy
import datetime
import math
import json
from pathlib import Path
import tempfile
import unittest

from test_link_evidence import LinkFixture, assembler, canon, sha, stamp, HERE


class LaterFixture(LinkFixture):
    def build(self, authority=None, validator=None):
        # Reuse only test authority/preparation boilerplate; never run a helper.
        seed_root = self.root / 'seed'
        seed_root.mkdir(mode=0o700)
        seed = LinkFixture(seed_root, 'link-precommit', self.now - 2000)
        seed.build()
        manifest = copy.deepcopy(authority['manifest'] if authority else seed.documents['manifest'])
        attempt = manifest['v3_attempt']
        if not authority:
            attempt['required_scenarios'] += list(assembler.later.SCENARIOS)
            attempt['karing_limit_seconds'] = 7200
            attempt['started_at'] = stamp(self.now - 7000)
            attempt['packages'] = {name: {'name': name, 'sha256': digit * 64} for name, digit in
                                   (('snap', '1'), ('certbot', '2'), ('karing', '3'))}
            attempt['after_snap_refresh'] = copy.deepcopy(attempt['packages'])
            attempt['after_snap_refresh']['certbot']['sha256'] = '4' * 64
        manifest_raw = canon(manifest)
        self.manifest_sha = sha(manifest_raw)
        request = {'deadline_unix': self.now + 30, 'not_before': stamp(self.now - 1300),
                   'qualification_manifest_sha256': self.manifest_sha, 'scenario_id': self.scenario,
                   'scenario_limit_seconds': 7200 if self.scenario == 'karing-final' else 1800}
        request_raw = canon(request)
        self.request_sha = sha(request_raw)
        state = {'schema': 'sbxr-v4-scenario-entry-v1', 'scenario_id': self.scenario,
                 'qualification_manifest_sha256': self.manifest_sha, 'request_sha256': self.request_sha}
        state.update({key: stamp(self.now + offset) for key, offset in
                      (('started_at', -1300), ('entry_started_at', -1200), ('action_started_at', -1100),
                       ('action_completed_at', -100), ('completed_at', -50))})
        prefix = copy.deepcopy(authority['prefix']) if authority else []
        if not authority:
            previous = self.manifest_sha
            for index, scenario in enumerate(attempt['required_scenarios'][:assembler.SCENARIO_INDEX[self.scenario]]):
                before = attempt['packages'] if index <= 13 else attempt['after_snap_refresh']
                after = attempt['packages'] if index < 13 else attempt['after_snap_refresh']
                item = {'attempt_id': attempt['attempt_id'], 'candidate': manifest['releases'][0],
                        'completed_at': stamp(self.now - 5000 + index * 35), 'operation_id': f'operation-{index+1}',
                        'packages_before': before, 'packages_after': after, 'prior_scenario_sha256': previous,
                        'scenario_id': scenario, 'schema': 'sbxr-v3-scenario-evidence-v3',
                        'started_at': stamp(self.now - 5010 + index * 35),
                        'validated_at': stamp(self.now - 4990 + index * 35),
                        'vps_id': attempt['vps_id'], 'vps_identity_sha256': attempt['vps_identity_sha256']}
                prefix.append(item); previous = sha(canon(item))
        prefix_raw = canon(prefix)
        boundary = copy.deepcopy(authority['boundary'] if authority else seed.documents['boundary'])
        validator_path = Path(validator) if validator else seed.paths['validator']
        validator_sha = sha(validator_path.read_bytes())
        preparation = {'accepted_prior_prefix_sha256': sha(prefix_raw), 'prepared_at': stamp(self.now - 1270),
            'qualification_boundary_facts_sha256': sha(canon(boundary)), 'qualification_manifest_sha256': self.manifest_sha,
            'request_sha256': self.request_sha, 'scenario_id': self.scenario, 'schema': assembler.PREPARATION_SCHEMA,
            'validator_sha256': validator_sha, 'verifications': [
                {'artifact_sha256': digest, 'check': check, 'observed_at': stamp(self.now - 1280), 'result': 'verified'}
                for check, digest in (('fresh-signed-manifest', self.manifest_sha), ('qualification-boundary', sha(canon(boundary))),
                                      ('pinned-validator', validator_sha))]}
        sources_dir = self.root / 'sources'; sources_dir.mkdir(mode=0o700)
        ctx = assembler.later.Context(assembler, self.scenario, manifest, manifest_raw, self.manifest_sha,
                                      request, request_raw, self.request_sha, state, sources_dir)
        family = assembler.later.family(self.scenario)
        fixture_module = assembler.import_sibling('fixture_' + family.replace('-', '_'), 'test_' + family.replace('-', '_'))
        fixture_module.populate_fixture(ctx)
        sources = assembler.later.adapter(assembler, self.scenario).sources(ctx)
        sources['state'] = assembler.later.state_source(assembler, state, canon(state), self.scenario,
                                                       self.manifest_sha, self.request_sha, request)
        route = {'check': 'supported-effective-route-inspected', 'completed_at': stamp(self.now - 1110),
            'effective_exec_verified': True, 'owned_artifacts_sha256': {'/a': 'a'*64, '/b': 'b'*64, '/c': 'c'*64},
            'qualification_manifest_sha256': self.manifest_sha, 'record_sha256': '6'*64, 'request_sha256': self.request_sha,
            'route': 'owned-recorder', 'scenario_id': self.scenario, 'schema': 'sbxr-v4-effective-route-v1',
            'started_at': stamp(self.now - 1190), 'timer_calendar_verified': True}
        sources['route'] = assembler.route_source(route, canon(route), self.scenario, self.manifest_sha, self.request_sha)
        rules = assembler.rules_for(self.scenario)
        capture = b'synthetic retained test capture\n'
        entry_events, operator_rows = {}, []
        def epoch(value): return datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
        def anchor_time(anchor):
            if anchor.source == assembler.timing.PROOF_SOURCE: return self.now - 30
            return epoch(sources[anchor.source].events[anchor.event])
        # Select an entry event inside every rule's real source bounds.
        for rule in rules:
            lower = [anchor_time(a) for a in rule.not_before if a.source != 'entry']
            upper = [anchor_time(a) for a in rule.not_after if a.source != 'entry']
            for anchor in rule.not_before:
                if anchor.source == 'entry':
                    observed = math.ceil(max([self.now - 1200] + lower))
                    if upper and observed > min(upper): raise AssertionError((rule.check, lower, upper))
                    entry_events[anchor.event] = stamp(observed)
        for rule in rules:
            for anchor in rule.not_before:
                if anchor.source == 'entry':
                    operator_rows.append({'capture_sha256': sha(capture), 'check': rule.check, 'event': anchor.event,
                                          'observed_at': entry_events[anchor.event], 'result': 'observed'})
        operator = {'capture_sha256': sha(capture), 'observations': operator_rows,
            'qualification_manifest_sha256': self.manifest_sha, 'request_sha256': self.request_sha,
            'scenario_id': self.scenario, 'schema': assembler.OPERATOR_SCHEMA}
        sources['entry'] = assembler.operator_source(operator, canon(operator), capture, self.scenario,
                                                     self.manifest_sha, self.request_sha, rules)
        observations = []
        for rule in rules:
            at = stamp(math.ceil(max(anchor_time(a) for a in rule.not_before)))
            observations.append({'check': rule.check, 'observed_at': at, 'result': 'observed'})
        proof = {'schema': assembler.LATER_PROOF_SCHEMA, 'scenario_id': self.scenario,
                 'operation_id': f'operation-{assembler.SCENARIO_INDEX[self.scenario]+1}', 'link_id': '',
                 'completed_at': stamp(self.now - 30), 'observations': observations}
        for name, value in (('manifest', manifest), ('request', request), ('prefix', prefix), ('boundary', boundary),
                            ('preparation', preparation), ('state', state), ('route', route), ('operator', operator), ('proof', proof)):
            self.document(name, value)
        self.write('capture', capture)
        self.output = self.root / 'output'
        self.command = [__import__('sys').executable, str(HERE / 'assemble-evidence.py'), self.scenario]
        for flag, name in (('manifest', 'manifest'), ('boundary', 'boundary'), ('request', 'request'),
                           ('accepted-prior-prefix', 'prefix'), ('preparation-receipt', 'preparation'),
                           ('operator-observations', 'operator'), ('operator-capture', 'capture'),
                           ('effective-route', 'route'), ('state', 'state'), ('proof', 'proof')):
            self.command += ['--' + flag, str(self.paths[name])]
        self.command += ['--validator', str(validator_path), '--validator-sha256', validator_sha,
                         '--sources-directory', str(sources_dir), '--output', str(self.output)]


class LaterEvidenceTests(unittest.TestCase):
    def test_all_families_assemble_with_complete_retained_sources(self):
        for scenario in assembler.later.SCENARIOS:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as folder:
                fixture = LaterFixture(Path(folder), scenario)
                fixture.build()
                result = fixture.run()
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_source_or_changed_request_never_produces_evidence(self):
        for change in ('missing', 'request'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                fixture = LaterFixture(Path(folder), 'lifecycle-menu'); fixture.build()
                if change == 'missing': (fixture.root / 'sources/19-lifecycle-menu.json').unlink()
                else: fixture.replace('request', lambda d: d.update(deadline_unix=d['deadline_unix'] - 1))
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(fixture.output.exists())

    def test_route_detection_must_be_observed_while_injected_route_is_present(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = LaterFixture(Path(folder), 'unsupported-route'); fixture.build()
            # A human review before the injection cannot prove route detection.
            def before_fault(doc):
                next(row for row in doc['observations'] if row['check'] == 'problem-detected')['observed_at'] = stamp(fixture.now - 1200)
            fixture.replace('operator', before_fault)
            # Also backdate the corresponding wire record. Neither source
            # timestamps nor the proof may claim detection before the fault.
            fixture.replace('proof', before_fault)
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(fixture.output.exists())

    def test_identity_startup_labels_cannot_replace_actual_denial_details(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = LaterFixture(Path(folder), 'identity-postcommit'); fixture.build()
            path = fixture.root / 'sources/identity-controller.json'
            controller = json.loads(path.read_bytes())
            controller['observations'][-1]['details']['ordinary_requests_denied'] = []
            path.write_bytes(canon(controller))
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('ordinary startup denial differs', result.stderr)


if __name__ == '__main__': unittest.main()
