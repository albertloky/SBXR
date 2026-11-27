"""Reconcile an interrupted journey from the durable host and operator receipts."""
import errno
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
HOST = runpy.run_path(str(HERE / 'mvp-containment-host.py'))['Host']


def sha(body):
    return hashlib.sha256(body).hexdigest()


class CustodyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.evidence = self.root / 'root/sbxr-qualification-evidence'
        self.evidence.mkdir(parents=True, mode=0o700)
        self.stage = self.root / 'root/sbxr-qualification-v3'
        self.stage.mkdir(mode=0o700)
        machine = self.put('/etc/machine-id', b'fixture-machine\n')
        boot = self.put('/proc/sys/kernel/random/boot_id', b'fixture-boot\n')
        manifest = self.put('/root/sbxr-qualification-v3/qualification-manifest.json',
                            {'workflow': {'commit': 'a'*40}, 'releases': [{}], 'v3_attempt': {'vps_identity_sha256': machine}})
        self.put('/root/sbxr-qualification-v3/staging-owned', b'42-1\n')
        self.put('/root/sbxr-qualification-v3/runtime-deadline', b'5000\n')
        window = self.put('/root/sbxr-qualification-v3/fresh-window-decision.json',
                          {'stage': 'qualification-window', 'outcome': 'accepted',
                           'window': {'workflow': {'run_id': '42'}, 'run_attempt': 1, 'manifest_sha256': manifest,
                                      'start_unix': 980, 'test_until_unix': 4000, 'finish_unix': 5060}})
        request = self.put('/root/sbxr-qualification-evidence/request.json',
                           {'scenario_id': 'mvp-install', 'qualification_manifest_sha256': manifest,
                            'qualification_window_sha256': window, 'deadline_unix': 2700})
        self.put('/root/sbxr-qualification-v3/journey-custody.jsonl', ('42-1 '+manifest+'\n').encode())
        self.intent = {'run_id': 42, 'run_attempt': 1, 'manifest_sha256': manifest, 'request_sha256': request,
                       'window_sha256': window, 'machine_sha256': machine, 'scenario': 'mvp-install',
                       'operation': 'setup', 'remote_deadline': 1240}
        self.host = HOST({'boot_sha256': boot}, root=self.root, command=self.fail, now=lambda: 1000)
        self.process(123, 123, 45)
        self.file = HERE / 'mvp-journey-custody.py'

    def put(self, name, value):
        path = self.root / name.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        body = value if isinstance(value, bytes) else json.dumps(value).encode()
        path.write_bytes(body)
        path.chmod(0o600)
        return sha(body)

    def process(self, pid, group, ticks, flags=0):
        tail = ['S', '1', str(group), str(group)] + ['0'] * 15 + [str(ticks)]
        tail[6] = str(flags)
        self.put(f'/proc/{pid}/stat', (f'{pid} (fixture) ' + ' '.join(tail)).encode())
        self.put(f'/proc/{pid}/environ', b'')

    def module(self):
        self.assertTrue(self.file.is_file(), 'the fixed launcher has no durable ownership writer')
        return runpy.run_path(str(self.file))

    def test_disconnect_requires_exact_pre_effect_record_and_independent_quiescence(self):
        m = self.module()
        record = m['begin'](self.host, self.intent, 123)
        self.assertEqual(record['process'], {'boot_sha256': self.host.scope['boot_sha256'],
                         'pid': 123, 'pgid': 123, 'start_ticks': 45, 'remote_deadline': 1240})
        # The operator retains this copy before acknowledging the effect.
        copies = [json.loads(json.dumps(record))]
        self.assertEqual(len(m['journal'](self.host)), 1)
        with self.assertRaises(FileExistsError):
            m['begin'](self.host, self.intent, 123)
        with self.assertRaises((OSError, ValueError)):
            m['reconcile'](self.host, copies, self.intent)
        m['seal_reaped'](self.host, record)
        with self.assertRaisesRegex(ValueError, 'still present'):
            m['reconcile'](self.host, copies, self.intent)
        (self.root/'proc/123').rename(self.root/'retired-fixture-process')
        self.assertEqual(m['reconcile'](self.host, copies, self.intent), [record['process']])
        wrong = json.loads(json.dumps(record))
        wrong['process']['pid'] = 999
        with self.assertRaises(ValueError):
            m['reconcile'](self.host, [wrong], self.intent)

    def test_action_requires_durable_ack_and_review_collects_independent_installed_facts(self):
        m = self.module()
        copies, events = [], []
        def ack(record):
            self.assertEqual(record, m['journal'](self.host)[m['filename'](self.intent)])
            copies.append(record)
            return m['digest'](m['canonical'](record))
        def disconnect(operation, deadline):
            events.append((operation, deadline))
            raise ConnectionError('fixture transport disconnected')
        with self.assertRaises(ConnectionError):
            m['launch'](self.host, self.intent, 123, ack, disconnect, lambda: None)
        self.assertEqual(events, [('setup', 1240)])
        (self.root/'proc/123').rename(self.root/'finished-owner')
        review = m['review_ownership'](self.host, copies, self.intent)
        self.assertEqual(review['prior_processes'], [copies[0]['process']])
        self.assertFalse(review['installed_executable_present'])
        self.assertFalse(review['exact_installed_identity_verified'])
        self.assertEqual(set(review['authority_snapshot']), {
            '/var/lib/sbxr/installed.json', '/var/lib/sbxr/proxy-ownership.json',
            '/var/lib/sbxr/.proxy-ownership.json.next', '/var/lib/.sbxr-removal.json'})
        link = self.root/'usr/local/bin/sbxr'
        link.parent.mkdir(parents=True)
        link.symlink_to('absent')
        with self.assertRaises((ValueError, OSError)):
            m['review_ownership'](self.host, copies, self.intent)

    def test_fixed_menu_has_no_program_path_or_shell_option(self):
        m = self.module()
        self.assertEqual(m['menu_args']('setup'), ['action', 'Start setup',
            'PROXY-INSTALLATION-SETUP-COMPLETE', '--confirmation', 'yes', '--timeout', '240'])
        self.assertEqual(m['menu_args']('rotate-link')[1], 'Rotate subscription link')
        with self.assertRaises(ValueError):
            m['menu_args']('/bin/sh')
        with self.assertRaises(ValueError):
            m['menu_args']('Complete removal')

    def test_only_m1_disclosure_gets_the_private_receipt_setting(self):
        m = self.module()
        key = 'SBXR_M1_DISCLOSURE_RECEIPT'
        assets = {'v3-packaged-live.sh': b'fixture candidate check',
                  'v3-menu-session.py': (HERE/'v3-menu-session.py').read_bytes()}
        def candidate_check(*args, env, **kwargs):
            self.assertNotIn(key, env)

        with patch.dict(os.environ, {key: 'ambient', 'FIXTURE_SECRET': 'canary'}), patch('subprocess.run', candidate_check):
            for scenario, operations in m['CAPS'].items():
                for op in operations.keys() & m['MENU'].keys():
                    intent = {**self.intent, 'scenario': scenario, 'operation': op}
                    with self.subTest(op=op):
                        argv, env = m['packaged_action'](self.host, intent, assets, {}, None, None)
                        self.assertEqual(argv[5:], m['menu_args'](op))
                        self.assertNotIn('FIXTURE_SECRET', env)
                        self.assertEqual(env.get(key), '1' if op == 'disclose' else None)

    def test_ownership_review_distinguishes_kernel_threads_from_unreadable_userspace(self):
        m = self.module()
        record = m['begin'](self.host, self.intent, 123)
        m['seal_reaped'](self.host, record)
        (self.root/'proc/123').rename(self.root/'finished-owner')
        def review():
            return m['review_ownership'](self.host, [record], self.intent)

        environ = self.root/'proc/2/environ'
        original = Path.read_bytes
        def read_bytes(path):
            if path == environ:
                raise ProcessLookupError(errno.ESRCH, 'fixture has no environment')
            return original(path)
        with patch.object(Path, 'read_bytes', read_bytes):
            self.process(2, 0, 1, flags=0x00200000)  # Linux PF_KTHREAD
            self.assertTrue(review()['process_cleanup_verified'])
            self.process(2, 123, 1, flags=0x00200000)
            with self.assertRaisesRegex(ValueError, 'prior process/group still present'):
                review()
            self.process(2, 1, 1)
            with self.assertRaises(ProcessLookupError):
                review()
        environ.unlink()
        with self.assertRaises(FileNotFoundError):
            review()
        self.put('/proc/2/environ', b'SBXR_Q215_OPERATOR_DEADLINE_UNIX=1240\0')
        with self.assertRaisesRegex(ValueError, 'prior detached child remains'):
            review()

    def test_serving_restart_after_identity_rotation_keeps_the_proxy_running(self):
        from test_mvp_containment_host import HostTests
        units = HostTests()
        units.setUp()
        self.addCleanup(units.doCleanups)
        dropin = '/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf'
        pin = units.write(dropin, b'fixture signed startup policy')
        units.write('/var/lib/sbxr/proxy-ownership.json',
                    json.dumps({'proxy_startup': {'drop_in_sha256': pin}}).encode())
        units.write('/root/sbxr-qualification-v3/qualification-manifest.json', b'{}')
        units.states['sing-box.service']['DropInPaths'] = dropin
        for pid, name, exe in [(91, 'sbxr-subscription.service', '/usr/local/bin/sbxr'),
                               (92, 'sing-box.service', '/usr/bin/sing-box')]:
            units.states[name].update(ActiveState='active', MainPID=str(pid))
            units.write(f'/proc/{pid}/cgroup', ('0::/system.slice/'+name).encode())
            (units.root/f'proc/{pid}/exe').symlink_to(exe)
        assets = {'v3-packaged-live.sh': b'fixture signed-candidate check'}
        intent = {**self.intent, 'scenario': 'mvp-serving', 'operation': 'restart-serving'}
        prepare = self.module()['packaged_action']
        # The absolute Linux product paths are external to the disposable host.
        # Keep unit ownership, drop-in bytes, and process/cgroup observation real.
        with patch('subprocess.run') as candidate_check:
            argv, _ = prepare(units.host, intent, assets, units.scope['expected_units'], pin, None)
            self.assertEqual(argv, ['/usr/bin/systemctl', 'restart', 'sbxr-subscription.service'])
            self.assertIn('exact_candidate', candidate_check.call_args.args[0][-1])
            units.write(dropin, b'foreign startup policy')
            with self.assertRaisesRegex(ValueError, 'changed drop-in'):
                prepare(units.host, intent, assets, units.scope['expected_units'], pin, None)

    def test_lost_or_incorrect_ack_refuses_effect(self):
        m = self.module()
        with self.assertRaisesRegex(ValueError, 'acknowledg'):
            m['launch'](self.host, self.intent, 123, lambda row: '0'*64, self.fail, lambda: None)

    def test_refuses_foreign_expired_or_unrecorded_operations_before_journaling(self):
        m = self.module()
        for key, value in [('run_id', 55), ('run_attempt', 2), ('request_sha256', 'e'*64),
                           ('machine_sha256', 'd'*64), ('window_sha256', 'f'*64),
                           ('operation', 'arbitrary'), ('scenario', 'mvp-removal'),
                           ('remote_deadline', 1000), ('remote_deadline', 2800)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                m['begin'](self.host, {**self.intent, key: value}, 123)
        self.assertEqual(m['journal'](self.host), {})


if __name__ == '__main__':
    unittest.main()
