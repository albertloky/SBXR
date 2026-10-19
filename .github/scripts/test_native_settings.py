#!/usr/bin/env python3
"""Future settings-policy regressions using public files, never the real app."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


MODULE = Path(__file__).with_name("native-receipts.py")
SPEC = importlib.util.spec_from_file_location("native_settings_receipts", MODULE)
RECEIPTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECEIPTS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def record(path):
    raw = path.read_bytes()
    return {"source_file": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


class NativeSettingsFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.native = self.root / "karing_setting.json"
        self.info = self.root / "Info.plist"
        self.executable = self.root / "Karing"
        self.original_app_executable = RECEIPTS.NATIVE_APP_EXECUTABLE
        self.settings = {
            "window": {"x": 64, "y": 128, "width": 1000, "height": 720, "widget": "home"},
            "dns": {
                "client_subnet_latest_update": "2026-10-19 09:20:00.000000",
                "client_subnet": "198.51.100.0/24", "enable_client_subnet": True,
                "resolver_addresses": ["https://resolver.example/dns-query"], "ttl": 600,
                "enable_rule": True, "test_domain": "example.com",
                "enable_inbound_domain_resolve": True, "enable_static_ip": True,
                "enable_static_ip_for_resolver": False, "proxy_resolve_mode": "prefer_ipv4",
                "outbound_addresses": ["system"], "direct_addresses": ["system"],
                "proxy_addresses": ["https://proxy-resolver.example/dns-query"],
                "static_ips": {"example.com": ["192.0.2.1"]},
                "list": [{"domain": "example.com", "server": "direct"}],
            },
            "routing": {"mode": "rule", "rules": ["direct"]},
            "tun": {"enabled": True}, "selector": {"group": "Original", "node": "Original node"},
            "unknown_future_setting": {"enabled": True, "value": "strict"},
        }
        self.connection = {"configuration": "Original", "node": "Original node",
                           "connected": True, "tun_enabled": True}
        self.write(self.native, canonical(self.settings))
        self.write(self.info, plistlib.dumps({
            "CFBundleIdentifier": "com.nebula.karing", "CFBundleExecutable": "Karing",
            "CFBundleShortVersionString": "1.2.25", "CFBundleVersion": "2802",
        }), 0o644)
        self.write(self.executable, b"PUBLIC SYNTHETIC APP EXECUTABLE\n", 0o755)
        for name, value in (("NATIVE_APP_INFO", self.info), ("NATIVE_APP_EXECUTABLE", self.executable),
                            ("NATIVE_SETTINGS_SOURCE", self.native)):
            boundary = patch.object(RECEIPTS, name, value, create=True)
            boundary.start()
            self.addCleanup(boundary.stop)

    def write(self, path, raw, mode=0o600):
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def save_settings(self):
        self.write(self.native, canonical(self.settings))

    def set_path(self, path, value):
        target = self.settings
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        self.save_settings()

    def connection_facts(self):
        return {"baseline": copy.deepcopy(self.connection), "current": copy.deepcopy(self.connection)}


class FrozenV1SettingsTests(NativeSettingsFixture):
    def test_v1_remains_byte_strict_for_each_newly_permitted_leaf(self):
        baseline = self.write(self.root / "baseline-v1.private", canonical(self.settings))
        current = self.write(self.root / "current-v1.private", baseline.read_bytes())
        facts = {"settings": {"baseline": record(baseline), "current": record(current)},
                 "selected_connection": self.connection_facts()}
        RECEIPTS.preserved(facts)
        original = copy.deepcopy(self.settings)
        for path, value in [(("window", "x"), 65), (("window", "y"), 129),
                            (("dns", "client_subnet_latest_update"), "2026-10-19 09:21:00.000000")]:
            with self.subTest(path=path):
                self.settings = copy.deepcopy(original)
                self.set_path(path, value)
                self.write(current, canonical(self.settings))
                facts["settings"]["current"] = record(current)
                with self.assertRaisesRegex(ValueError, "complete settings"):
                    RECEIPTS.preserved(facts)


class NativeAppIdentityTests(NativeSettingsFixture):
    def test_official_macos_executable_case_and_bytes_are_bound(self):
        binding = RECEIPTS.settings_binding()
        self.assertEqual(self.original_app_executable,
                         Path('/Applications/karing.app/Contents/MacOS/Karing'))
        self.assertEqual(binding['app'], {
            'version': '1.2.25', 'build': '2802',
            'executable_sha256': hashlib.sha256(self.executable.read_bytes()).hexdigest(),
            'info_plist_sha256': hashlib.sha256(self.info.read_bytes()).hexdigest(),
        })

    def test_other_executable_case_spellings_are_rejected(self):
        original = plistlib.loads(self.info.read_bytes())
        for value in ['karing', 'KARING', 'KaRiNg', 'other']:
            with self.subTest(executable=value):
                info = dict(original, CFBundleExecutable=value)
                self.write(self.info, plistlib.dumps(info), 0o644)
                with self.assertRaisesRegex(ValueError, 'Unsupported Karing identity'):
                    RECEIPTS.settings_binding()


class NativeSettingsV2Tests(NativeSettingsFixture):
    def setUp(self):
        super().setUp()
        self.binding = RECEIPTS.settings_binding()
        self.baseline_snapshot = RECEIPTS.settings_readback(self.binding)
        self.baseline = self.write(self.root / "baseline.private", canonical(self.baseline_snapshot))
        self.trusted_baseline_record = record(self.baseline)

    def capture(self):
        return RECEIPTS.capture_settings(self.trusted_baseline_record,
                                         self.root / "current.private", self.binding)

    def verify(self, settings):
        facts = {"settings": settings, "selected_connection": self.connection_facts()}
        RECEIPTS.preserved_v2(facts, self.binding, self.trusted_baseline_record)
        return facts

    def test_each_permitted_change_and_combination_keep_complete_audit(self):
        changes = [(('window', 'x'), 65), (('window', 'y'), 129),
                   (('dns', 'client_subnet_latest_update'), '2026-10-19 09:21:00.123456')]
        original = copy.deepcopy(self.settings)
        for selected in [[change] for change in changes] + [changes]:
            with self.subTest(paths=[path for path, _ in selected]):
                self.settings = copy.deepcopy(original)
                for path, value in selected:
                    self.set_path(path, value)
                current = RECEIPTS.settings_readback(self.binding)
                comparison = RECEIPTS.compare_settings(self.baseline_snapshot, current, self.binding)
                self.assertEqual([item['path'] for item in comparison['changes']],
                                 ['/' + '/'.join(path) for path, _ in selected])
                self.assertNotEqual(current['source_canonical_sha256'],
                                    self.baseline_snapshot['source_canonical_sha256'])
                self.assertNotEqual(current['complete_settings'], self.baseline_snapshot['complete_settings'])
                self.assertEqual(current['binding'], self.binding)
                self.assertEqual(current['native_source']['sha256'],
                                 hashlib.sha256(self.native.read_bytes()).hexdigest())
                self.assertEqual(current['source_canonical_sha256'],
                                 hashlib.sha256(canonical(self.settings)).hexdigest())

    def test_capture_and_consumer_accept_allowed_change(self):
        self.set_path(('window', 'x'), 65)
        settings = self.capture()
        self.verify(settings)
        self.assertEqual(settings['comparison']['changes'][0]['path'], '/window/x')

    def test_unchanged_settings_and_uninitialized_timestamp_are_valid(self):
        self.assertEqual(self.capture()['comparison']['changes'], [])
        self.set_path(('dns', 'client_subnet_latest_update'), '')
        current = RECEIPTS.settings_readback(self.binding)
        comparison = RECEIPTS.compare_settings(self.baseline_snapshot, current, self.binding)
        self.assertEqual([item['path'] for item in comparison['changes']],
                         ['/dns/client_subnet_latest_update'])

    def test_all_other_dns_settings_and_non_dns_siblings_remain_strict(self):
        original = copy.deepcopy(self.settings)
        changes = [
            (('dns', 'client_subnet'), '203.0.113.0/24'), (('dns', 'enable_client_subnet'), False),
            (('dns', 'resolver_addresses'), ['https://other.example/dns-query']), (('dns', 'ttl'), 601),
            (('dns', 'enable_rule'), False), (('dns', 'test_domain'), 'other.example'),
            (('dns', 'enable_inbound_domain_resolve'), False), (('dns', 'enable_static_ip'), False),
            (('dns', 'enable_static_ip_for_resolver'), True),
            (('dns', 'outbound_addresses'), ['https://other.example/dns-query']),
            (('dns', 'direct_addresses'), []), (('dns', 'proxy_addresses'), []),
            (('dns', 'list'), []), (('dns', 'static_ips'), {'example.com': ['192.0.2.2']}),
            (('dns', 'proxy_resolve_mode'), 'prefer_ipv6'), (('dns', 'new_dns_field'), True),
            (('window', 'width'), 1001), (('window', 'height'), 721),
            (('window', 'widget'), 'other'), (('window', 'new_window_field'), True),
            (('routing', 'mode'), 'global'), (('routing', 'rules'), ['proxy']),
            (('tun', 'enabled'), False), (('selector', 'group'), 'Other'),
            (('selector', 'node'), 'Other node'), (('unknown_future_setting', 'value'), 'changed'),
            (('unknown_future_setting', 'enabled'), 1), (('new_top_level_field',), 'unexpected'),
        ]
        for path, value in changes:
            with self.subTest(path=path):
                self.settings = copy.deepcopy(original)
                self.set_path(path, value)
                with self.assertRaises(ValueError):
                    RECEIPTS.compare_settings(self.baseline_snapshot,
                                              RECEIPTS.settings_readback(self.binding), self.binding)

    def test_permitted_change_does_not_hide_strict_changes_or_deleted_unknown_fields(self):
        self.set_path(('window', 'x'), 65)
        self.set_path(('dns', 'client_subnet'), '203.0.113.0/24')
        with self.assertRaises(ValueError):
            RECEIPTS.compare_settings(self.baseline_snapshot,
                                      RECEIPTS.settings_readback(self.binding), self.binding)
        self.settings = copy.deepcopy(self.settings)
        self.settings['dns']['client_subnet'] = '198.51.100.0/24'
        del self.settings['unknown_future_setting']
        self.save_settings()
        with self.assertRaises(ValueError):
            RECEIPTS.compare_settings(self.baseline_snapshot,
                                      RECEIPTS.settings_readback(self.binding), self.binding)

    def test_required_leaves_types_and_dart_timestamp_are_validated(self):
        original = copy.deepcopy(self.settings)
        malformed = [
            (('window', 'x'), True), (('window', 'x'), 64.5), (('window', 'x'), '64'),
            (('window', 'x'), None), (('window', 'y'), []),
            (('dns', 'client_subnet_latest_update'), None),
            (('dns', 'client_subnet_latest_update'), 123),
            (('dns', 'client_subnet_latest_update'), 'not-a-time'),
            (('dns', 'client_subnet_latest_update'), '2026-02-30 09:20:00.000000'),
            (('dns', 'client_subnet_latest_update'), '2026-10-19 25:20:00.000000'),
            (('dns', 'client_subnet_latest_update'), '2026-10-19T09:20:00Z'),
            (('dns', 'client_subnet_latest_update'), '2026-10-19 09:20:00.1'),
            (('dns', 'client_subnet_latest_update'), '2026-10-19 09:20:00.000000+01:00'),
        ]
        for path, value in malformed:
            with self.subTest(path=path, value=value):
                self.settings = copy.deepcopy(original)
                self.set_path(path, value)
                with self.assertRaises(ValueError):
                    RECEIPTS.settings_readback(self.binding)
        for path in [('window', 'x'), ('window', 'y'), ('dns', 'client_subnet_latest_update')]:
            with self.subTest(missing=path):
                self.settings = copy.deepcopy(original)
                del self.settings[path[0]][path[1]]
                self.save_settings()
                with self.assertRaises(ValueError):
                    RECEIPTS.settings_readback(self.binding)
        for parent in ['window', 'dns']:
            with self.subTest(parent=parent):
                self.settings = copy.deepcopy(original)
                self.settings[parent] = []
                self.save_settings()
                with self.assertRaises(ValueError):
                    RECEIPTS.settings_readback(self.binding)

    def test_valid_dart_timestamp_forms(self):
        for value in ['', '2026-10-19 09:20:00.123', '2026-10-19 09:20:00.123456',
                      '2026-10-19 09:20:00.123Z', '2026-10-19 09:20:00.123456Z']:
            with self.subTest(value=value):
                self.set_path(('dns', 'client_subnet_latest_update'), value)
                RECEIPTS.settings_readback(self.binding)

    def test_duplicate_json_and_nonfinite_values_refuse(self):
        original_raw = canonical(self.settings)
        self.write(self.native, original_raw.replace(b'"x":64', b'"x":64,"x":64'))
        with self.assertRaises(ValueError):
            RECEIPTS.settings_readback(self.binding)
        for value in [float('nan'), float('inf'), float('-inf')]:
            with self.subTest(value=repr(value)):
                self.settings['unknown_future_setting']['value'] = value
                self.save_settings()
                with self.assertRaises(ValueError):
                    RECEIPTS.settings_readback(self.binding)
        self.write(self.native, b'[]')
        with self.assertRaises(ValueError):
            RECEIPTS.settings_readback(self.binding)

    def test_binding_rejects_wrong_version_build_and_modified_app(self):
        original = self.info.read_bytes()
        for key, value in [('CFBundleIdentifier', 'other.app'), ('CFBundleExecutable', 'other'),
                           ('CFBundleShortVersionString', '1.2.26'), ('CFBundleVersion', '2803')]:
            with self.subTest(field=key):
                info = plistlib.loads(original)
                info[key] = value
                self.write(self.info, plistlib.dumps(info), 0o644)
                with self.assertRaises(ValueError):
                    RECEIPTS.settings_binding()
        self.write(self.info, original, 0o644)
        self.write(self.executable, b'PUBLIC CHANGED APP EXECUTABLE\n', 0o755)
        with self.assertRaises(ValueError):
            RECEIPTS.settings_readback(self.binding)

    def test_binding_and_snapshot_cannot_widen_the_fixed_policy(self):
        current = RECEIPTS.settings_readback(self.binding)
        for mutation in [lambda value: value.update(policy='caller-selected-policy'),
                         lambda value: value.update(excluded_paths=['/dns']),
                         lambda value: value['app'].update(version='1.2.26'),
                         lambda value: value.update(helper_sha256='0' * 64)]:
            with self.subTest(mutation=mutation):
                binding = copy.deepcopy(self.binding)
                mutation(binding)
                with self.assertRaises(ValueError):
                    RECEIPTS.compare_settings(self.baseline_snapshot, current, binding)
        for mutation in [lambda value: value.update(schema='sbxr-complete-native-settings-readback-v1'),
                         lambda value: value.update(excluded_paths=['/dns']),
                         lambda value: value.update(source_canonical_sha256='not-a-digest'),
                         lambda value: value['permitted_values'].update({'/dns': {}}),
                         lambda value: value['permitted_values'].update({'/window/x': 65}),
                         lambda value: value.pop('complete_settings')]:
            with self.subTest(snapshot_mutation=mutation):
                snapshot = copy.deepcopy(current)
                mutation(snapshot)
                with self.assertRaises(ValueError):
                    RECEIPTS.compare_settings(self.baseline_snapshot, snapshot, self.binding)

    def test_malformed_normalized_audit_is_refused(self):
        current = RECEIPTS.settings_readback(self.binding)
        for malformed in [
            {'type': 'unknown'}, {'type': 'string', 'utf8_length': -1, 'sha256': '0' * 64},
            {'type': 'string', 'utf8_length': 1, 'sha256': 'not-a-digest'},
            {'type': 'number', 'value': True}, {'type': 'number', 'value': float('inf')},
            {'type': 'boolean', 'value': 1}, {'type': 'null', 'value': None},
            {'type': 'object', 'fields': []}, {'type': 'array', 'items': {}},
            {'type': 'object', 'fields': {}, 'excluded': True},
        ]:
            with self.subTest(audit=malformed):
                snapshot = copy.deepcopy(current)
                snapshot['complete_settings']['fields']['unknown_future_setting'] = malformed
                with self.assertRaises(ValueError):
                    RECEIPTS.compare_settings(self.baseline_snapshot, snapshot, self.binding)

    def test_source_proof_and_evidence_metadata_cannot_be_forged(self):
        settings = self.capture()
        current = Path(settings['current']['source_file'])
        original = json.loads(current.read_bytes())
        for key, value in [('source_app_path', str(self.root / 'other.json')), ('sha256', '0' * 64),
                           ('nlink', 2), ('size', 0), ('uid', os.getuid() + 1),
                           ('mode', 0), ('mtime_ns', True), ('ctime_ns', 0), ('ino', 0)]:
            with self.subTest(proof_field=key):
                snapshot = copy.deepcopy(original)
                snapshot['native_source'][key] = value
                self.write(current, canonical(snapshot))
                settings['current'] = record(current)
                with self.assertRaises(ValueError):
                    self.verify(settings)
        self.write(current, canonical(original))
        settings['current'] = record(current)
        current.chmod(0o644)
        with self.assertRaises(ValueError):
            self.verify(settings)

    def test_native_hardlinks_are_refused(self):
        os.link(self.native, self.root / 'second-name.json')
        with self.assertRaises(ValueError):
            RECEIPTS.settings_readback(self.binding)

    def test_real_native_drift_before_capture_publication_leaves_no_current_file(self):
        native_read = RECEIPTS._native_bytes
        reads = []

        def changing_native_read(path, app=False):
            result = native_read(path, app=app)
            if path == self.native:
                reads.append(path)
                if len(reads) == 1:
                    self.set_path(('window', 'x'), 65)
            return result

        with patch.object(RECEIPTS, '_native_bytes', side_effect=changing_native_read):
            with self.assertRaisesRegex(ValueError, 'changed before capture'):
                self.capture()
        self.assertGreaterEqual(len(reads), 2)
        self.assertFalse((self.root / 'current.private').exists())

    def test_capture_reserves_output_exclusively_and_refuses_alias(self):
        self.write(self.root / 'current.private', b'preserved preexisting output')
        with self.assertRaises((ValueError, FileExistsError)):
            self.capture()
        self.assertEqual((self.root / 'current.private').read_bytes(), b'preserved preexisting output')
        with self.assertRaises((ValueError, FileExistsError)):
            RECEIPTS.capture_settings(self.trusted_baseline_record, self.baseline, self.binding)

    def test_consumer_recomputes_comparison_and_checks_evidence_hash(self):
        self.set_path(('window', 'x'), 65)
        settings = self.capture()
        original = copy.deepcopy(settings)
        for mutation in [lambda value: value['comparison'].update(changes=[]),
                         lambda value: value['comparison'].update(policy='caller-selected-policy'),
                         lambda value: value['current'].update(sha256='0' * 64),
                         lambda value: value['baseline'].update(size=1),
                         lambda value: value.update(current=value['baseline'])]:
            with self.subTest(mutation=mutation):
                settings = copy.deepcopy(original)
                mutation(settings)
                with self.assertRaises(ValueError):
                    self.verify(settings)

    def test_consumer_refuses_fresh_alternate_baseline_after_strict_drift(self):
        trusted_record = copy.deepcopy(self.trusted_baseline_record)
        trusted_bytes = self.baseline.read_bytes()
        # A receipt author can honestly capture a new baseline after changing a
        # strict setting. Its internal comparison is valid, but it is not the
        # independently frozen pre-journey baseline.
        self.set_path(('dns', 'client_subnet'), '203.0.113.0/24')
        alternate = self.write(self.root / 'alternate-baseline.private',
                               canonical(RECEIPTS.settings_readback(self.binding)))
        settings = RECEIPTS.capture_settings(record(alternate),
                                             self.root / 'alternate-current.private', self.binding)
        self.assertEqual(settings['comparison']['changes'], [])
        self.assertNotEqual(settings['baseline'], trusted_record)
        self.assertEqual(self.baseline.read_bytes(), trusted_bytes)
        self.assertEqual(record(self.baseline), trusted_record)
        facts = {'settings': settings, 'selected_connection': self.connection_facts()}
        with self.assertRaises(ValueError):
            RECEIPTS.preserved_v2(facts, self.binding, trusted_record)

    def test_consumer_requires_independent_baseline_record_and_unchanged_frozen_bytes(self):
        settings = self.capture()
        facts = {'settings': settings, 'selected_connection': self.connection_facts()}
        with self.assertRaises(TypeError):
            RECEIPTS.preserved_v2(facts, self.binding)
        self.write(self.baseline, canonical({'unexpected': 'changed frozen baseline'}))
        with self.assertRaises(ValueError):
            RECEIPTS.preserved_v2(facts, self.binding, self.trusted_baseline_record)

    def test_consumer_refuses_post_capture_allowed_drift_and_metadata_drift(self):
        settings = self.capture()
        self.set_path(('window', 'x'), 65)
        with self.assertRaises(ValueError):
            self.verify(settings)
        self.settings['window']['x'] = 64
        self.save_settings()
        second = RECEIPTS.capture_settings(self.trusted_baseline_record,
                                          self.root / 'second.private', self.binding)
        info = self.native.stat()
        os.utime(self.native, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
        with self.assertRaises(ValueError):
            self.verify(second)

    def test_current_snapshot_origin_and_native_file_protection_remain_strict(self):
        settings = self.capture()
        snapshot = json.loads(Path(settings['current']['source_file']).read_bytes())
        snapshot['native_source']['source_app_path'] = str(self.root / 'other-native-store.json')
        current = Path(settings['current']['source_file'])
        self.write(current, canonical(snapshot))
        settings['current'] = record(current)
        with self.assertRaises(ValueError):
            self.verify(settings)
        self.native.chmod(0o666)
        with self.assertRaises(ValueError):
            RECEIPTS.settings_readback(self.binding)
        self.native.chmod(0o600)
        target = self.root / 'target.json'
        self.native.rename(target)
        self.native.symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            RECEIPTS.settings_readback(self.binding)

    def test_selected_connection_and_tun_remain_exact(self):
        settings = self.capture()
        for key, value in [('configuration', 'Other'), ('node', 'Other node'),
                           ('connected', False), ('tun_enabled', False), ('tun_enabled', 1)]:
            with self.subTest(field=key):
                facts = {'settings': settings, 'selected_connection': self.connection_facts()}
                facts['selected_connection']['current'][key] = value
                with self.assertRaises(ValueError):
                    RECEIPTS.preserved_v2(facts, self.binding, self.trusted_baseline_record)

    def test_v2_acceptance_does_not_override_saved_url_uuid_and_reality_guards(self):
        self.set_path(('window', 'x'), 65)
        settings = self.capture()
        self.verify(settings)
        url = 'http://107.175.53.219:8443/s/PUBLIC_FIXTURE_NOT_A_REAL_LINK'
        uuid = '12345678-1234-4234-8234-123456789abc'
        wire = (f'vless://{uuid}@198.51.100.10:443?encryption=none&flow=xtls-rprx-vision'
                '&security=reality&sni=example.com&fp=chrome&pbk=' + 'A' * 43
                + '&sid=01020304&type=tcp#SBXR%20Proxy\n')
        profile = {'groupid': 'fixture', 'remark': 'Public fixture', 'urlOrPath': url,
                   'servers': [{'groupid': 'fixture', 'attach': '', 'latency': '166',
                                'outlet_ip': '', 'outlet_region': '', 'server': '198.51.100.10',
                                'server_port': 443, 'tag': 'SBXR Proxy', 'type': 'vless',
                                'uuid': uuid, 'flow': 'xtls-rprx-vision', 'packet_encoding': 'xudp',
                                'tls': {'enabled': True, 'server_name': 'example.com',
                                        'utls': {'enabled': True, 'fingerprint': 'chrome'},
                                        'reality': {'enabled': True, 'public_key': 'A' * 43,
                                                    'short_id': '01020304'}}}]}
        self.write(self.root / 'expected-url.private', url.encode() + b'\n')
        self.write(self.root / 'expected-wire.private', wire.encode())
        native_store = self.root / 'karing_subscribe.json'

        def readbacks(current_profile):
            url_path = self.write(self.root / 'actual-url.private', current_profile['urlOrPath'].encode())
            content = self.write(self.root / 'actual-profile.private', canonical(current_profile))
            raw = canonical({'items': [current_profile]})
            self.write(native_store, raw)
            facts = {'saved_url': record(url_path), 'saved_subscription_content': record(content),
                     'native_subscription_source': {'source_app_path': str(native_store),
                                                    'sha256': hashlib.sha256(raw).hexdigest(),
                                                    'size': len(raw),
                                                    'mtime_ns': native_store.stat().st_mtime_ns}}
            RECEIPTS.readbacks(SimpleNamespace(r=self.root), facts,
                               'expected-url.private', 'expected-wire.private')

        with patch.object(RECEIPTS, 'NATIVE_SUBSCRIPTION_SOURCE', native_store):
            readbacks(profile)
            for path, value in [(('urlOrPath',), url + '-changed'),
                                (('servers', 0, 'uuid'), 'another-identity'),
                                (('servers', 0, 'tls', 'reality', 'public_key'), 'B' * 43),
                                (('servers', 0, 'tls', 'reality', 'short_id'), '01020305')]:
                with self.subTest(profile_field=path):
                    changed = copy.deepcopy(profile)
                    target = changed
                    for part in path[:-1]:
                        target = target[part]
                    target[path[-1]] = value
                    self.verify(settings)
                    with self.assertRaises(ValueError):
                        readbacks(changed)

    def test_actual_subprocess_baseline_capture_and_consumer_for_native_journeys(self):
        # Every phase imports the canonical implementation afresh; only paths to
        # public native/app fixtures move. Real file metadata, hashes, exclusive
        # writes and the producer-to-consumer record format remain in use.
        driver = r'''
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
module, root, phase, journey = sys.argv[1:]
root = Path(root)
spec = importlib.util.spec_from_file_location('receipts_child', module)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
r.NATIVE_APP_INFO = root / 'Info.plist'
r.NATIVE_APP_EXECUTABLE = root / 'Karing'
r.NATIVE_SETTINGS_SOURCE = root / 'karing_setting.json'
def write(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    with path.open('xb') as stream:
        stream.write(raw)
    path.chmod(0o600)
def record(path):
    raw = path.read_bytes()
    return {'source_file': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
baseline = root / (journey + '-baseline.private')
bound = root / (journey + '-binding.private')
facts_path = root / (journey + '-facts.private')
trusted_record_path = root / (journey + '-baseline-source-record.private')
if phase == 'baseline':
    binding = r.settings_binding()
    write(bound, binding)
    write(baseline, r.settings_readback(binding))
    write(trusted_record_path, record(baseline))
else:
    binding = json.loads(bound.read_bytes())
    trusted_baseline_record = json.loads(trusted_record_path.read_bytes())
    if phase == 'capture':
        settings = r.capture_settings(trusted_baseline_record,
                                      root / (journey + '-current.private'), binding)
        connection = {'configuration': 'Original', 'node': 'Original node',
                      'connected': True, 'tun_enabled': True}
        write(facts_path, {'settings': settings, 'selected_connection':
                          {'baseline': connection, 'current': dict(connection)}})
    elif phase == 'consumer':
        r.preserved_v2(json.loads(facts_path.read_bytes()), binding, trusted_baseline_record)
    else:
        raise ValueError('Unknown test phase')
print(json.dumps({'phase': phase, 'journey': journey, 'python': list(sys.version_info[:3])}))
'''
        observed_versions = []
        for journey in ['m2-subscription', 'm3-credentials', 'm5-removal']:
            self.settings['window']['x'] = 64
            self.save_settings()
            for phase in ['baseline', 'capture', 'consumer']:
                if phase == 'capture':
                    self.set_path(('window', 'x'), 65)
                result = subprocess.run([sys.executable, '-B', '-c', driver, str(MODULE),
                                         str(self.root), phase, journey], check=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                observation = json.loads(result.stdout)
                self.assertEqual((observation['phase'], observation['journey']), (phase, journey))
                observed_versions.append(observation['python'])
            # Even an otherwise permitted change after capture is stale evidence.
            self.set_path(('window', 'x'), 66)
            refused = subprocess.run([sys.executable, '-B', '-c', driver, str(MODULE),
                                      str(self.root), 'consumer', journey],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('ValueError', refused.stderr)
        self.assertEqual(observed_versions, [list(sys.version_info[:3])] * 9)


if __name__ == '__main__':
    unittest.main()
