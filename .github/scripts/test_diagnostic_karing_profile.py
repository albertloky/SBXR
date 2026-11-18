import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
HELPER = HERE / 'diagnostic-karing-profile.py'
VECTORS = HERE.parents[1] / 'tests/testdata/subscription_artifact'
REQUEST = 'a' * 64
LABEL = 'SBXR-' + REQUEST[:16]
ATTEMPT = 'run-123-attempt-1'
GROUP = 'af0660bf-34ad-422a-b9f1-18f013029a17'
OTHER = '3ac147be-f7f0-4b4f-af1d-c8ff4e112c05'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, value):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    path.write_bytes(raw)
    path.chmod(0o600)
    return digest(raw)


class NativeDecision(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('diagnostic_profile', HELPER)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.native = self.root / 'native'
        self.native.mkdir(mode=0o700)
        self.handoff = self.root / ('karing-' + ATTEMPT)
        self.path = self.handoff / 'node.txt'
        self.store = self.native / 'karing_subscribe.json'
        self.use = self.native / 'karing_subscribe_use.json'
        self.settings = self.native / 'karing_setting.json'
        self.side = self.native / 'fixture-diversion.json'
        self.before = {'items': [{'groupid': 'custom', 'remark': 'custom', 'servers': []},
                                 {'groupid': 'original', 'remark': 'existing', 'urlOrPath': '/fixture/old',
                                  'servers': [{'tag': 'original-node'}]}], 'value': False}
        write(self.store, self.before)
        write(self.use, {'select_default': 'original-node', 'favorites': ['original-node']})
        self.original_settings = {'dns': {'client_subnet_latest_update': '', 'other': 'original'},
                                  'window': {'x': 10, 'y': 20}}
        write(self.settings, self.original_settings)
        self.args = ['--handoff-dir', str(self.handoff), '--request-sha256', REQUEST,
                     '--connected', 'yes', '--tun', 'no', '--side-file', str(self.side)]
        self.baseline = self.run_cmd('baseline')['baseline_sha256']
        self.handoff.mkdir(mode=0o700)
        wire = (VECTORS / 'vless.txt').read_bytes().split(b'#')[0] + b'#' + LABEL.encode() + b'\n'
        self.receipt = dict(manifest_sha256='b' * 64, request_sha256=REQUEST, attempt_id=ATTEMPT,
                            label=LABEL, client_until_unix=int(time.time()) + 300, sha256=write(self.path, wire), device=self.path.stat().st_dev,
                            inode=self.path.stat().st_ino)
        self.receipt_path = self.handoff / 'receipt.json'
        sha = write(self.receipt_path, self.receipt)
        self.args.extend(['--baseline-sha256', self.baseline, '--receipt-sha256', sha])
        node, = json.loads((VECTORS / 'client-vless.json').read_bytes())['outbounds']
        node.update(groupid=GROUP, tag=LABEL, attach='', latency='', outlet_ip='', outlet_region='',
                    packet_encoding='xudp')
        self.group = dict(groupid=GROUP, remark=LABEL, urlOrPath=str(self.path), servers=[node],
                          enable=True, urltests=[], outboundDns=[], keepDiversionRules=False,
                          testLatencyAutoRemove=False, preferOutboundDns=False,
                          testLatencyAfterProfileUpdate=False, reloadAfterProfileUpdate=False, enableDiversionRules=False)

    def run_cmd(self, phase, *extra, ok=True):
        if phase == 'before-remove' and '--expected-state' not in extra:
            extra = (*extra, '--expected-state', 'complete')
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = self.helper.main([phase, *self.args, *extra], native_dir=self.native)
        if not ok:
            self.assertNotEqual(status, 0)
            self.assertNotIn('original-node', out.getvalue() + err.getvalue())
            self.assertNotIn('vless://', out.getvalue() + err.getvalue())
            self.assertNotIn('12345678-1234', out.getvalue() + err.getvalue())
            return
        self.assertEqual(status, 0, err.getvalue())
        return json.loads(out.getvalue())

    def import_groups(self, *groups):
        write(self.store, dict(self.before, items=self.before['items'] + list(groups)))

    def test_exact_import_scoped_remove_and_uncertain_ack(self):
        self.import_groups(self.group)
        stored = self.store.read_bytes()
        self.assertEqual(self.run_cmd('inspect'), {'state': 'complete', 'group_id': GROUP})
        self.assertEqual(self.run_cmd('before-remove', '--group-id', GROUP)['state'], 'remove-once')
        self.run_cmd('after-remove', '--group-id', GROUP, ok=False)
        self.assertEqual(self.store.read_bytes(), stored)
        write(self.store, self.before)
        self.assertEqual(self.run_cmd('after-remove', '--group-id', GROUP)['state'], 'absent')

    def test_empty_group_only_cleanup_and_replacement_id(self):
        self.import_groups(dict(self.group, servers=[]))
        self.assertEqual(self.run_cmd('inspect'), {'state': 'empty', 'group_id': GROUP})
        self.run_cmd('before-remove', '--group-id', GROUP, '--expected-state', 'complete', ok=False)
        self.assertEqual(self.run_cmd('before-remove', '--group-id', GROUP, '--expected-state', 'empty')['state'], 'remove-once')
        self.import_groups(dict(self.group, servers=[], groupid=OTHER))
        self.run_cmd('before-remove', '--group-id', GROUP, ok=False)

    def test_no_save_or_duplicate_wrong_path_wrong_node(self):
        self.assertEqual(self.run_cmd('inspect'), {'state': 'absent'})
        self.assertEqual(self.run_cmd('before-remove', '--group-id', GROUP)['state'], 'absent')
        damaged = copy.deepcopy(self.group)
        damaged['servers'][0]['tls']['reality']['short_id'] = 'deadbeef'
        for additions in ((self.group, self.group), (dict(self.group, remark='other'),),
                          (dict(self.group, urlOrPath='/unowned'),), (damaged,),
                          (dict(self.group, servers=[*self.group['servers']] * 2),),
                          (dict(self.group, servers=[], testLatencyAutoRemove=True),),
                          (dict(self.group, servers=[], groupid='original'),)):
            with self.subTest():
                self.import_groups(*additions)
                self.run_cmd('inspect', ok=False)

    def test_original_order_type_selection_side_files_and_ui_are_preserved(self):
        self.import_groups(self.group)
        self.run_cmd('before-remove', '--group-id', GROUP, '--tun', 'yes', ok=False)
        write(self.store, dict(self.before, value=0, items=self.before['items'] + [self.group]))
        self.run_cmd('inspect', ok=False)
        write(self.store, dict(self.before, items=[*reversed(self.before['items']), self.group]))
        self.run_cmd('inspect', ok=False)
        self.import_groups(self.group)
        for path in (self.settings, self.use, self.side, self.native / 'karing_routing_group.json'):
            raw = path.read_bytes() if path.exists() else None
            write(path, {'select_default': LABEL})
            self.run_cmd('before-remove', '--group-id', GROUP, ok=False)
            if raw is None:
                path.unlink()
            else:
                write(path, raw)

    def test_clocked_save_and_test_are_refused_while_cleanup_remains_available(self):
        self.assertEqual(self.run_cmd('before-save')['state'], 'save-once')
        self.run_cmd('before-test', '--group-id', GROUP, ok=False)
        self.import_groups(self.group)
        self.run_cmd('before-save', ok=False)
        self.assertEqual(self.run_cmd('before-test', '--group-id', GROUP)['state'], 'test-once')
        self.run_cmd('before-test', '--group-id', OTHER, ok=False)
        for flag in ('keepDiversionRules', 'testLatencyAutoRemove', 'preferOutboundDns',
                     'testLatencyAfterProfileUpdate', 'enableDiversionRules', 'reloadAfterProfileUpdate'):
            self.import_groups(dict(self.group, **{flag: True}))
            self.run_cmd('before-test', '--group-id', GROUP, ok=False)
        self.import_groups(dict(self.group, enable=False))
        self.run_cmd('before-test', '--group-id', GROUP, ok=False)
        for additional in ('urltests', 'outboundDns'):
            self.import_groups(dict(self.group, **{additional: ['unrequested']}))
            self.run_cmd('inspect', ok=False)
        self.import_groups(dict(self.group, servers=[]))
        self.run_cmd('before-test', '--group-id', GROUP, ok=False)
        self.import_groups(self.group)
        self.receipt['client_until_unix'] = int(time.time()) + 30
        self.args[-1] = write(self.receipt_path, self.receipt)
        self.run_cmd('before-test', '--group-id', GROUP, ok=False)
        self.receipt['client_until_unix'] = int(time.time()) - 1
        self.args[-1] = write(self.receipt_path, self.receipt)
        self.assertEqual(self.run_cmd('before-remove', '--group-id', GROUP)['state'], 'remove-once')
        self.import_groups()
        self.run_cmd('before-save', ok=False)
        self.assertEqual(self.run_cmd('after-remove', '--group-id', GROUP)['state'], 'absent')

    def test_semantic_preservation_uses_known_settings_and_original_latency_rules(self):
        self.args = self.args[:self.args.index('--baseline-sha256')]
        self.before['items'][1]['servers'][0]['latency'] = '14'
        write(self.use, {'select_default': 'direct'})
        write(self.store, self.before)
        self.baseline = self.run_cmd('baseline')['baseline_sha256']
        self.args.extend(['--baseline-sha256', self.baseline, '--receipt-sha256', digest(self.receipt_path.read_bytes())])
        write(self.use, b'{  "select_default": "direct"  }')
        write(self.settings, {'dns': {'client_subnet_latest_update': '2026-11-18 09:20:00.123', 'other': 'original'},
                              'window': {'x': 11, 'y': 40}})
        self.before['items'][1]['servers'][0]['latency'] = '16'
        self.import_groups(self.group)
        self.assertEqual(self.run_cmd('inspect')['state'], 'complete')
        self.before['items'][1]['servers'][0]['latency'] = '0'
        self.import_groups(self.group)
        self.run_cmd('inspect', ok=False)

    def test_bound_profile_bundle_allows_only_in_window_forward_refresh(self):
        self.args = self.args[:self.args.index('--baseline-sha256')]
        now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=10)
        self.before['items'][1]['updateTime'] = (now - dt.timedelta(days=1)).strftime('%F %T')
        write(self.store, self.before)
        source = self.root / 'before.private'
        tzif = self.root / 'tz.private'
        zone_bytes = Path('/usr/share/zoneinfo/Etc/UTC').read_bytes()
        # System tzdata can be hard-linked. Supply an owned, one-link source.
        zone = self.root / 'zoneinfo/Etc/UTC'
        zone.parent.mkdir(parents=True)
        zone.write_bytes(zone_bytes)
        zone.chmod(0o644)
        self.helper.native.NATIVE_TIMEZONE_SOURCE = zone

        def record(path, raw):
            return dict(source_file=str(path), sha256=write(path, raw), size=len(raw))

        tz_record = record(tzif, zone_bytes)
        bundle = dict(original_store_baseline=record(source, self.store.read_bytes()),
                      original_store_observed_at=(now - dt.timedelta(seconds=10)).isoformat(),
                      native_tzif=tz_record, native_timezone=self.helper.native.native_timezone_binding())
        inputs = self.root / 'native-inputs.json'
        write(inputs, bundle)
        self.args += ['--native-inputs', str(inputs)]
        original_time = self.before['items'][1]['updateTime']
        self.before['items'][1]['updateTime'] = (now + dt.timedelta(seconds=5)).strftime('%F %T')
        write(self.store, self.before)
        self.run_cmd('baseline', ok=False)  # A stale T0 bundle cannot anchor T2 and later accept T1.
        self.before['items'][1]['updateTime'] = original_time
        write(self.store, self.before)
        pin = self.run_cmd('baseline')['baseline_sha256']
        self.args += ['--baseline-sha256', pin, '--receipt-sha256', digest(self.receipt_path.read_bytes())]
        self.before['items'][1]['updateTime'] = now.strftime('%F %T')
        self.import_groups(self.group)
        self.assertEqual(self.run_cmd('inspect')['state'], 'complete')
        self.before['items'][1]['updateTime'] = (now - dt.timedelta(hours=1)).strftime('%F %T')
        self.import_groups(self.group)
        self.run_cmd('inspect', ok=False)
        self.before['items'][1]['updateTime'] = now.strftime('%F %T')
        self.import_groups(self.group)
        write(tzif, b'replaced')
        self.run_cmd('inspect', ok=False)

    def test_refuses_collisions_in_baseline(self):
        self.args = self.args[:self.args.index('--baseline-sha256')]
        for group in (dict(self.group, remark='other', servers=[]),
                      dict(self.group, urlOrPath='/elsewhere', servers=[]),
                      dict(self.group, remark='other', urlOrPath='/elsewhere')):
            self.import_groups(group)
            self.run_cmd('baseline', ok=False)

    def test_preexisting_orphan_favorite_or_diversion_id_cannot_be_deleted_by_remove(self):
        baseline_args = self.args[:self.args.index('--baseline-sha256')]
        self.args = baseline_args.copy()
        write(self.use, {'select_default': 'original-node', 'favorites': [LABEL]})
        self.run_cmd('baseline', ok=False)
        write(self.use, {'select_default': 'original-node', 'favorites': ['original-node']})
        write(self.side, {'routes': [{'serverGroupId': GROUP}]})
        pin = self.run_cmd('baseline')['baseline_sha256']
        self.args += ['--baseline-sha256', pin, '--receipt-sha256', digest(self.receipt_path.read_bytes())]
        self.import_groups(self.group)
        self.run_cmd('before-remove', '--group-id', GROUP, ok=False)

    def test_receipt_swap_wire_replacement_and_unpinned_uri(self):
        self.import_groups(self.group)
        raw = self.path.read_bytes()
        write(self.path, raw.replace(b'12345678', b'87654321'))
        self.run_cmd('inspect', ok=False)
        self.receipt['sha256'] = digest(self.path.read_bytes())
        write(self.receipt_path, self.receipt)
        self.run_cmd('inspect', ok=False)
        self.receipt['sha256'] = write(self.path, raw)
        write(self.receipt_path, self.receipt)
        replacement = self.handoff / 'other'
        write(replacement, raw)
        replacement.replace(self.path)
        self.run_cmd('inspect', ok=False)

    def test_public_symlink_oversize_or_duplicate_json_is_refused(self):
        self.import_groups(self.group)
        self.path.chmod(0o644)
        self.run_cmd('inspect', ok=False)
        self.path.chmod(0o600)
        self.store.unlink()
        self.store.symlink_to(self.settings)
        self.run_cmd('inspect', ok=False)
        self.store.unlink()
        os.mkfifo(self.store, 0o600)
        self.run_cmd('inspect', ok=False)
        self.store.unlink()
        write(self.store, b'{"items":[],"items":[]}')
        self.run_cmd('inspect', ok=False)
        self.import_groups(self.group)
        with self.path.open('ab') as out:
            out.write(b'x' * 65537)
        self.run_cmd('inspect', ok=False)


if __name__ == '__main__':
    unittest.main()
