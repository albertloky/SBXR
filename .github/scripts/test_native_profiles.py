"""Future profile-policy regressions; all stores and zone files are public fixtures."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'native_receipts', Path(__file__).with_name('native-receipts.py'))
RECEIPTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECEIPTS)


class OriginalProfilesV3Tests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.zone_path = self.root / 'timezone.private.tzif'
        self.use_zone('Asia/Hong_Kong')
        self.before = [
            {'groupid': 'custom', 'remark': 'custom', 'urlOrPath': '', 'enable': True,
             'type': 'singbox', 'updateDurationMinutes': None, 'updateTime': '', 'servers': []},
            {'groupid': 'PUBLIC-original', 'remark': 'Existing original', 'enable': True,
             'urlOrPath': 'https://example.invalid/existing', 'type': 'v2ray',
             'updateDurationMinutes': 720, 'testLatencyAfterProfileUpdate': True,
             'updateTime': '2026-10-19 22:52:38.762764',
             'servers': [{'groupid': 'PUBLIC-original', 'tag': 'Existing node',
                          'latency': '111', 'type': 'vless', 'server': '198.51.100.10',
                          'server_port': 443, 'uuid': 'PUBLIC-original-identity',
                          'flow': 'xtls-rprx-vision',
                          'tls': {'enabled': True, 'server_name': 'example.invalid',
                                  'reality': {'enabled': True, 'public_key': 'PUBLIC_KEY'}},
                          'route': {'rules': ['PUBLIC-route'], 'updateTime': 'unchanged'}}]},
        ]
        self.start = '2026-10-20T01:39:48Z'
        self.end = '2026-10-20T03:00:00.000001+00:00'

    def use_zone(self, name):
        # A fixed public rules file, not the Mac's /etc/localtime or app state.
        raw = (Path('/usr/share/zoneinfo') / name).read_bytes()
        self.zone_path.write_bytes(raw)
        self.zone_path.chmod(0o600)
        self.tzif = {'source_file': str(self.zone_path),
                     'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
        self.timezone = {'name': name, 'resolved_source_path': '/PUBLIC/zoneinfo/' + name,
                         'sha256': self.tzif['sha256']}

    def audit(self, after=None, **kwargs):
        values = dict(timezone=self.timezone, tzif_record=self.tzif,
                      window_start=self.start, window_end=self.end)
        values.update(kwargs)
        return RECEIPTS.original_profiles_audit_v3(
            self.before, copy.deepcopy(self.before) if after is None else after, **values)

    def changed(self, key, value):
        after = copy.deepcopy(self.before)
        after[1][key] = value
        return after

    def test_identical_profiles_need_no_timestamp_exception(self):
        audit = self.audit()
        self.assertTrue(audit['passed'])
        self.assertEqual(audit['changes'], [])
        self.assertEqual(audit['policy'], 'original-profiles-refresh-cache-v3')
        self.assertEqual(audit['window'], {'not_before': self.start, 'observed_at': self.end})

    def test_only_two_approved_cache_paths_pass_with_complete_private_diff(self):
        after = self.changed('updateTime', '2026-10-20 10:52:38.926923')
        after[1]['servers'][0]['latency'] = '222'
        audit = self.audit(after)
        self.assertTrue(audit['passed'])
        self.assertEqual([item['path'] for item in audit['changes']],
                         [[1, 'servers', 0, 'latency'], [1, 'updateTime']])
        self.assertTrue(all(item['allowed'] for item in audit['changes']))
        self.assertEqual(audit['changes'][0]['before'], {'present': True, 'value': '111'})
        self.assertEqual(audit['changes'][0]['after'], {'present': True, 'value': '222'})
        self.assertNotEqual(audit['baseline_profiles_canonical_sha256'],
                            audit['current_profiles_canonical_sha256'])

    def test_window_boundaries_are_inclusive_but_timestamp_must_advance(self):
        for value in ('2026-10-20 09:39:48', '2026-10-20 11:00:00.000001'):
            with self.subTest(value=value):
                self.assertTrue(self.audit(self.changed('updateTime', value))['passed'])
        for value in ('2026-10-20 09:39:47.999999', '2026-10-20 11:00:00.000002',
                      '2026-10-19 22:52:38.762763'):
            with self.subTest(value=value):
                self.assertFalse(self.audit(self.changed('updateTime', value))['passed'])

    def test_changed_timestamp_requires_both_valid_native_values(self):
        for value in ('', None, 123, '2026-10-20T10:52:38Z',
                      '2026-10-20 10:52:38+08:00', '2026-02-30 10:52:38',
                      '2026-10-20 10:52:38.1234567', '２０２６-10-20 10:52:38'):
            with self.subTest(value=value):
                self.assertFalse(self.audit(self.changed('updateTime', value))['passed'])
        self.before[1]['updateTime'] = ''
        self.assertFalse(self.audit(self.changed('updateTime', '2026-10-20 10:52:38'))['passed'])

    def test_changed_timestamp_cannot_overflow_utc_or_avoid_advancement(self):
        for zone, old, new in (
            ('Asia/Hong_Kong', '0001-01-01 00:00:00', '2026-10-20 10:52:38'),
            ('Asia/Hong_Kong', '2026-10-19 22:52:38', '0001-01-01 00:00:00'),
            ('America/New_York', '9999-12-31 23:59:59', '2026-10-19 22:52:38'),
            ('America/New_York', '2026-10-19 22:52:38', '9999-12-31 23:59:59')):
            with self.subTest(zone=zone, old=old, new=new):
                self.use_zone(zone)
                self.before[1]['updateTime'] = old
                audit = self.audit(self.changed('updateTime', new))
                self.assertFalse(audit['passed'])
                self.assertTrue(audit['changes'])
        self.use_zone('Asia/Hong_Kong')
        self.before[1]['updateTime'] = '2026-10-20 10:52:38.000000'
        self.assertFalse(self.audit(self.changed('updateTime', '2026-10-20 10:52:38'))['passed'])

    def test_changed_latency_requires_both_positive_ascii_decimal_strings(self):
        for value in ('0', '000', '-2', '+2', '2.0', ' 2', '2\n', '２', '٢', 2, True, None):
            with self.subTest(value=value):
                after = copy.deepcopy(self.before)
                after[1]['servers'][0]['latency'] = value
                self.assertFalse(self.audit(after)['passed'])
        for value in ('1', '0002', '12345678901234567890'):
            with self.subTest(value=value):
                after = copy.deepcopy(self.before)
                after[1]['servers'][0]['latency'] = value
                self.assertTrue(self.audit(after)['passed'])
        self.before[1]['servers'][0]['latency'] = '0'
        after = copy.deepcopy(self.before)
        after[1]['servers'][0]['latency'] = '2'
        self.assertFalse(self.audit(after)['passed'])

    def test_custom_and_nested_lookalike_keys_remain_exact(self):
        for change in ('custom-time', 'custom-latency', 'nested-time'):
            with self.subTest(change=change):
                after = copy.deepcopy(self.before)
                if change == 'custom-time':
                    after[0]['updateTime'] = '2026-10-20 10:52:38'
                elif change == 'custom-latency':
                    self.before[0]['servers'] = [{'latency': '1'}]
                    after[0]['servers'] = [{'latency': '2'}]
                else:
                    after[1]['servers'][0]['route']['updateTime'] = '2026-10-20 10:52:38'
                self.assertFalse(self.audit(after)['passed'])

    def test_security_routes_credentials_and_other_profile_fields_remain_exact(self):
        changes = [(['servers', 0, 'tls', 'enabled'], False),
                   (['servers', 0, 'tls', 'reality', 'public_key'], 'OTHER'),
                   (['servers', 0, 'uuid'], 'OTHER'),
                   (['servers', 0, 'route', 'rules'], ['OTHER']),
                   (['urlOrPath'], 'https://example.invalid/other'),
                   (['updateDurationMinutes'], 60), (['enable'], 1)]
        for path, value in changes:
            with self.subTest(path=path):
                after = copy.deepcopy(self.before)
                target = after[1]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                audit = self.audit(after)
                self.assertFalse(audit['passed'])
                self.assertTrue(audit['changes'])
                self.assertFalse(all(item['allowed'] for item in audit['changes']))

    def test_added_removed_fields_nodes_profiles_and_order_fail(self):
        cases = []
        added = copy.deepcopy(self.before); added[1]['other'] = 'PUBLIC'; cases.append(added)
        removed = copy.deepcopy(self.before); del removed[1]['updateTime']; cases.append(removed)
        removed_latency = copy.deepcopy(self.before); del removed_latency[1]['servers'][0]['latency']; cases.append(removed_latency)
        added_node = copy.deepcopy(self.before); added_node[1]['servers'].append(copy.deepcopy(added_node[1]['servers'][0])); cases.append(added_node)
        cases += [list(reversed(copy.deepcopy(self.before))), copy.deepcopy(self.before[:1]),
                  copy.deepcopy(self.before) + [copy.deepcopy(self.before[1])]]
        for after in cases:
            with self.subTest(after=after):
                self.assertFalse(self.audit(after)['passed'])
        other = copy.deepcopy(self.before[1]['servers'][0])
        other.update(tag='Other existing node', uuid='PUBLIC-other-identity', server='198.51.100.20')
        self.before[1]['servers'].append(other)
        reordered = copy.deepcopy(self.before)
        reordered[1]['servers'].reverse()
        self.assertFalse(self.audit(reordered)['passed'])

    def test_both_old_and_new_dst_fold_and_gap_values_refuse(self):
        self.use_zone('America/New_York')
        for old, new, start, end in (
            ('2026-11-01 01:30:00', '2026-11-01 03:00:00', '2026-11-01T04:00:00Z', '2026-11-01T09:00:00Z'),
            ('2026-11-01 00:30:00', '2026-11-01 01:30:00', '2026-11-01T04:00:00Z', '2026-11-01T09:00:00Z'),
            ('2026-03-08 02:30:00', '2026-03-08 04:00:00', '2026-03-08T05:00:00Z', '2026-03-08T10:00:00Z'),
            ('2026-03-08 01:30:00', '2026-03-08 02:30:00', '2026-03-08T05:00:00Z', '2026-03-08T10:00:00Z')):
            with self.subTest(old=old, new=new):
                self.before[1]['updateTime'] = old
                self.assertFalse(self.audit(self.changed('updateTime', new),
                                            window_start=start, window_end=end)['passed'])

    def test_frozen_zone_bytes_are_authority_and_substitution_refuses(self):
        self.zone_path.write_bytes((Path('/usr/share/zoneinfo') / 'America/New_York').read_bytes())
        self.zone_path.chmod(0o600)
        with self.assertRaises(ValueError):
            self.audit()

    def test_invalid_window_authority_refuses(self):
        for values in ({'window_start': self.end, 'window_end': self.start},
                       {'window_start': '2026-10-20T01:39:48'},
                       {'window_end': '2026-10-20T03:00:00+08:00'}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.audit(**values)

    def test_static_comparator_never_reads_current_app_store_or_zone(self):
        after = self.changed('updateTime', '2026-10-20 10:52:38.926923')
        with patch.object(RECEIPTS, '_native_bytes', side_effect=AssertionError('current native read')):
            with patch.object(RECEIPTS, 'settings_binding', side_effect=AssertionError('current app read')):
                self.assertTrue(self.audit(after)['passed'])

    def test_native_timezone_binding_ignores_process_tz_and_retains_rules_hash(self):
        zone = self.root / 'zoneinfo/Asia/Hong_Kong'
        zone.parent.mkdir(parents=True)
        zone.write_bytes(self.zone_path.read_bytes()); zone.chmod(0o644)
        link = self.root / 'localtime'; link.symlink_to(zone)
        with patch.object(RECEIPTS, 'NATIVE_TIMEZONE_SOURCE', link), patch.dict(os.environ, TZ='UTC'):
            result = RECEIPTS.native_timezone_binding()
        self.assertEqual(result, {'name': 'Asia/Hong_Kong', 'resolved_source_path': str(zone),
                                  'sha256': self.tzif['sha256']})

    def test_historical_settings_and_connection_checks_are_not_relaxed(self):
        def record(name, value):
            path = self.root / name
            raw = json.dumps(value).encode(); path.write_bytes(raw); path.chmod(0o600)
            return {'source_file': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
        connection = {'configuration': 'Original', 'node': 'Existing', 'connected': True, 'tun_enabled': True}
        facts = {'settings': {'baseline': record('before.json', {'dns': 'A'}),
                              'current': record('after.json', {'dns': 'B'})},
                 'selected_connection': {'baseline': connection, 'current': dict(connection)}}
        with self.assertRaises(ValueError):
            RECEIPTS.preserved(facts)
        for key, value in (('node', 'Other'), ('configuration', 'Other'),
                           ('connected', False), ('tun_enabled', False)):
            current = dict(connection); current[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                RECEIPTS.preserved_connection({'selected_connection': {'baseline': connection, 'current': current}})


if __name__ == '__main__':
    unittest.main()
