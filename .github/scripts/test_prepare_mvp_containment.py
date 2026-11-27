"""Run the actual preparation and fixed clock payload against a synthetic host."""
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

HERE = Path(__file__).resolve().parent
SCENARIOS = 'mvp-install mvp-subscription mvp-credentials mvp-serving mvp-removal'.split()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    path.write_bytes(raw)
    path.chmod(0o600)
    return digest(raw)


class ClockPreparation(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.prepared = self.base / 'prepared'
        self.host = self.base / 'fixture'
        self.staging = self.host / 'root/sbxr-qualification-v3'
        self.request = self.host / 'root/sbxr-qualification-evidence/request.json'
        self.draft = self.host / 'root/mvp-observation-draft.json'
        self.now = int(time.time())
        self.origin = {'run_id': '77', 'commit': 'a'*40}
        self.release = {'tag': 'v1.2.3', 'sequence': 7, 'commit': 'a'*40}
        self.manifest = {'schema': 'sbxr-qualification-manifest-v3', 'repository': 'albertloky/SBXR',
                         'source_state': 'v3-subscription-clean', 'mode': 'v3',
                         'workflow': self.origin, 'releases': [self.release],
                         'v3_attempt': {'attempt_id': 'run-77-attempt-1', 'run_attempt': 1,
                                        'required_scenarios': SCENARIOS, 'evidence_policy': 'mvp-http-live-v1',
                                        'started_at': datetime.datetime.fromtimestamp(
                                            self.now-86400, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                                        'vps_identity_sha256': write(self.host / 'etc/machine-id', b'fixture-machine\n')}}
        self.pin = write(self.base / 'manifest.json', self.manifest)
        write(self.staging / 'qualification-manifest.json', self.manifest)
        self.plan = {'origin_run_id': '77', 'start_unix': self.now-20,
                     'test_until_unix': self.now+4000, 'finish_unix': self.now+5800}
        write(self.base / 'plan.json', self.plan)
        self.window = {'schema': 'sbxr-release-qualification-decision-v1', 'stage': 'qualification-window',
                       'outcome': 'accepted', 'window': {'schema': 'sbxr-qualification-window-v1',
                       'start_unix': self.plan['start_unix'], 'test_until_unix': self.plan['test_until_unix'],
                       'finish_unix': self.plan['finish_unix'], 'run_attempt': 1,
                       'workflow': {'run_id': '88'}, 'origin': self.origin, 'release': self.release,
                       'manifest_sha256': self.pin}}
        write(self.staging / 'staging-owned', b'88-1\n')
        write(self.staging / 'runtime-deadline', (str(self.plan['finish_unix']-60)+'\n').encode())
        self.cmd = [sys.executable, '-B', str(HERE/'prepare-mvp-containment.py'), str(self.prepared),
                    '--manifest', str(self.base/'manifest.json'), '--manifest-sha256', self.pin,
                    '--window', str(self.base/'plan.json'), '--host', '192.0.2.21',
                    '--dispatch-guard-by', str(self.now+60)]

    def prepare(self):
        run = subprocess.run(self.cmd, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr.decode())
        self.cfg = json.loads((self.prepared/'preparation.json').read_bytes())
        self.assertFalse(json.loads(run.stdout)['ready_for_live'])
        self.assertEqual(self.cfg['source'], self.origin['commit'])

    def request_for(self, scenario):
        self.window_pin = write(self.staging/'fresh-window-decision.json', self.window)
        self.document = {'qualification_window_sha256': self.window_pin, 'qualification_manifest_sha256': self.pin,
                         'scenario_id': scenario, 'scenario_limit_seconds': 7200 if scenario=='mvp-subscription' else 1800,
                         'required_checks': ['fixture-check'], 'deadline_unix': self.now+900,
                         'not_before': datetime.datetime.fromtimestamp(self.now-1, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
        self.request_pin = write(self.request, self.document)
        if self.draft.exists():
            self.draft.rename(self.draft.with_name('prior-'+scenario))
        subprocess.run([sys.executable, '-B', str(HERE/'mvp-observe.py'), 'start', '--request', str(self.request),
                        '--draft', str(self.draft)], check=True, capture_output=True)

    def read(self, scenario):
        def transport(label, argv, body, *, timeout, cutoff, reserve):
            self.assertEqual(argv, ['python3', '-B', '-'])
            # Map only the payload's fixed chdir('/') to this disposable host.
            def change_root(path):
                self.assertEqual(path, '/')
                original_chdir(self.host)
            original_chdir = os.chdir
            original_cwd = os.getcwd()
            output = io.StringIO()
            try:
                with patch.object(os, 'chdir', change_root), redirect_stdout(output):
                    try:
                        exec(compile(body, '<fixed clock>', 'exec'), {'__name__': '__main__'})
                    except (OSError, KeyError, TypeError, ValueError):
                        return 1, b'', b'refused'
            finally:
                original_chdir(original_cwd)
            return 0, output.getvalue().encode(), b''
        # Exercise the actual entry dispatch with the authenticated candidate
        # already supplied by Entry's initializer. The fixture transport has
        # only the bounded call and cannot repeat candidate authentication.
        entry = runpy.run_path(str(HERE/'mvp-containment-entry.py'))['Entry']
        phase = entry.__new__(entry)
        phase.prepared = self.prepared
        clock = self.prepared / 'read-current-clock.py'
        phase.pins = {str(clock): digest(clock.read_bytes())}
        phase.action = 'clock'
        phase.cfg = self.cfg
        phase.binding = {'run_id': 88, 'manifest_sha256': self.pin, 'request_sha256': self.request_pin}
        phase.remote = types.SimpleNamespace(remote=transport)
        phase.origin = 'fixture'
        phase.deadline = self.now+80
        phase.scope = {'original_cutoff': self.now+950}
        with tempfile.TemporaryDirectory(dir=self.base) as run:
            record = Path(run)/'clock.json'
            phase.runtime = {'scenario': scenario, 'clock_record': str(record)}
            with patch.dict(sys.modules), patch.object(time, 'time', return_value=self.now):
                result = phase.run()
            self.assertEqual(result['origin'], 'fixture')
            observed = json.loads(record.read_bytes())
            self.assertEqual(result['current_cutoff'], min(phase.scope['original_cutoff'],
                                                         observed['effective_deadline_unix']))
            return observed

    def test_prepare_and_read_each_real_recorder_draft(self):
        self.prepare()
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                self.request_for(scenario)
                before = self.draft.read_bytes()
                proof = self.read(scenario)
                self.assertEqual(proof['request_sha256'], self.request_pin)
                self.assertEqual(proof['effective_deadline_unix'], self.now+900)
                self.assertEqual(self.draft.read_bytes(), before)
        self.assertNotEqual(subprocess.run(self.cmd, capture_output=True).returncode, 0)
        proposal = subprocess.run([sys.executable, '-B', str(HERE/'mvp-containment-bindings.py'), str(self.prepared)], capture_output=True)
        self.assertNotEqual(proposal.returncode, 0)
        self.assertIn(b'review-cleanup.py', proposal.stderr)

    def test_changed_remote_authority_before_clock(self):
        self.prepare()
        self.request_for('mvp-serving')
        for path, wrong in ((self.staging/'staging-owned', b'87-1\n'), (self.staging/'staging-owned', b'88-2\n'),
                            (self.host/'etc/machine-id', b'other'), (self.staging/'runtime-deadline', b'1\n'),
                            (self.staging/'fresh-window-decision.json', b'{}')):
            original = path.read_bytes()
            with self.subTest(path=path.name, wrong=wrong), self.assertRaises(ValueError):
                write(path, wrong)
                self.read('mvp-serving')
            write(path, original)
        with self.assertRaises(ValueError):
            self.read('mvp-removal')
        self.request.rename(self.request.with_suffix('.elsewhere'))
        self.request.symlink_to(self.request.with_suffix('.elsewhere'))
        with self.assertRaises((OSError, ValueError)):
            self.read('mvp-serving')

    def test_freeze_rechecks_the_prepared_clock_and_its_recorder(self):
        self.prepare()
        for name in ('remote.py', 'review-cleanup.py', 'outside-run.py', 'direct-control.py',
                     'finalize-failure.py'):
            write(self.prepared / name, b'raise AssertionError("fixture caller executed")')
        helper = self.prepared/'operator-source/native-receipts.py'
        write(self.prepared/'native-inputs.json', {'source_commit': self.cfg['source'],
              'candidate': {k: self.release[k] for k in ('tag', 'sequence')}, 'canonical_helper': {'source_file': str(helper),
              'size': helper.stat().st_size, 'sha256': digest(helper.read_bytes())}})
        freeze = runpy.run_path(str(HERE/'mvp-containment-bindings.py'))['proposal']
        proposal = freeze(HERE.parents[1], self.prepared)
        self.assertFalse(proposal['ready_for_live'])
        pins = proposal['callers']['clock']['dependencies']
        for name in ('read-current-clock.py', 'operator-source/mvp-observe.py'):
            path = self.prepared / name
            original = path.read_bytes()
            self.assertEqual(pins[str(path)], digest(original))
            write(path, original + b'# changed')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'clock'):
                freeze(HERE.parents[1], self.prepared)
            write(path, original)

    def test_removal_uses_its_own_signed_phase_limit(self):
        self.plan.update(start_unix=self.now-3800, test_until_unix=self.now-60, finish_unix=self.now+1700)
        write(self.base/'plan.json', self.plan)
        self.cmd[-1] = str(self.now-1800)
        for key in ('start_unix', 'test_until_unix', 'finish_unix'):
            self.window['window'][key] = self.plan[key]
        write(self.staging/'runtime-deadline', (str(self.plan['finish_unix']-60)+'\n').encode())
        self.prepare()
        self.request_for('mvp-removal')
        self.assertEqual(self.read('mvp-removal')['effective_deadline_unix'], self.now+900)
        self.request_for('mvp-serving')
        with self.assertRaises(ValueError):
            self.read('mvp-serving')

    def test_changed_planned_window_with_matching_request_and_draft(self):
        self.prepare()
        self.window['window']['finish_unix'] += 100
        self.request_for('mvp-install')
        with self.assertRaises(ValueError):
            self.read('mvp-install')

    def test_interruption_requires_an_independent_host_owner(self):
        self.prepare()
        self.request_for('mvp-install')
        proof = self.read('mvp-install')
        # A fixture host owns the work independently from the simulated SSH
        # client. Only a verified readback can distinguish its two states.
        bin_dir = self.base / 'bin'
        bin_dir.mkdir()
        marker = self.base / 'request-sent'
        ssh = bin_dir / 'ssh'
        ssh.write_text('#!/bin/sh\nset -eu\n: > "$SENT"\nexec sleep 12\n')
        ssh.chmod(0o700)
        active = self.base / 'host-work-started'
        serve = ('import sys, time\nfrom pathlib import Path\n'
                 'while not Path(sys.argv[1]).exists(): time.sleep(.01)\n'
                 'Path(sys.argv[2]).touch()\nsys.stdin.readline()')
        server = subprocess.Popen([sys.executable, '-c', serve, str(marker), str(active)],
                                  stdin=subprocess.PIPE)
        try:
            runner = subprocess.Popen(
                [sys.executable, '-B', str(HERE/'mvp-operator-run.py'), '--run-directory', str(self.base),
                 '--label', 'fixture-journey', '--timeout', '6', '--reserve', '320',
                 '--cutoff-unix', str(proof['effective_deadline_unix']), '--', sys.executable, '-B',
                 str(HERE/'bounded-ssh.py'), '5', 'fixture.invalid'],
                env={**os.environ, 'PATH': str(bin_dir)+os.pathsep+os.environ['PATH'], 'SENT': str(marker)})
            try:
                deadline = time.monotonic()+3
                while not active.exists() and runner.poll() is None and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(active.exists(), 'fixture host did not receive the work')
                runner.send_signal(signal.SIGTERM)
                self.assertEqual(runner.wait(timeout=12), -signal.SIGTERM)
                self.assertIsNone(server.poll(), 'simulated host work must still be independently observable')
                host_class = runpy.run_path(str(HERE/'mvp-containment-host.py'))['Host']
                host = host_class({'prior_processes': []}, root=self.host, command=self.fail)
                with self.assertRaisesRegex(ValueError, 'prior process reconciliation missing'):
                    host.prior_processes_absent()
                self.assertEqual(self.read('mvp-install')['request_sha256'], proof['request_sha256'])
            finally:
                if runner.poll() is None:
                    runner.terminate()
                    runner.wait(timeout=12)
        finally:
            # Only the fixture process's actual owner releases and reaps it.
            server.stdin.close()
            if not active.exists():
                server.terminate()
            server.wait(timeout=5)
        self.assertEqual(server.returncode, 0)

    def test_menu_completion_requires_independent_absence(self):
        self.prepare()
        self.request_for('mvp-removal')
        proof = self.read('mvp-removal')
        product = self.host/'usr/local/bin/sbxr'
        product.parent.mkdir(parents=True)
        product.write_text(
            '#!/bin/sh\nset -eu\nprintf "%s\\n" "SBXR V3" "1. Complete removal" "0. Exit"\n'
            'read -r choice; test "$choice" = 1\n'
            'echo "Type REMOVE SBXR to confirm Complete removal. Any other input cancels."\n'
            'read -r answer; test "$answer" = "REMOVE SBXR"\n'
            'mv "$0" "$0.fixture-finished"\necho "Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"\n')
        product.chmod(0o700)
        leftover = self.host/'etc/sing-box/config.json'
        leftover.parent.mkdir(parents=True)
        leftover.symlink_to('absent-target')
        recorder = self.prepared/'operator-source/mvp-observe.py'
        env = {**os.environ, 'SBXR_QUALIFICATION_REQUEST': str(self.request),
               'SBXR_QUALIFICATION_DRAFT': str(self.draft), 'SBXR_QUALIFICATION_CLOCK': str(recorder),
               'SBXR_QUALIFICATION_CLOCK_SHA256': self.cfg['cleanup_clock_sha256']}
        packaged = HERE/'v3-packaged-live.sh'
        before = self.draft.read_bytes()
        menu = subprocess.run(
            ['bash', '-c', 'source "$1"; shift; menu_session_safety_cleanup "$@"', 'fixture', str(packaged),
             'Complete removal', str(proof['effective_deadline_unix']), '660', '--timeout', '3',
             '--runtime-deadline', str(self.staging/'runtime-deadline'), '--executable', str(product)],
            env=env, capture_output=True, timeout=10)
        self.assertEqual(menu.returncode, 0, menu.stderr.decode())
        # Run the maintained presence and broken-link checks. Map their absolute
        # paths to this fake host, and use the documented absent OS statuses.
        probe = r'''
set -eu
source "$1"
ROOT=$2
test() {
  if [[ $# == 3 && $1 == '!' && ( $2 == -e || $2 == -L ) && $3 == /* ]]; then
    builtin test '!' "$2" "$ROOT$3"
  elif [[ $# == 2 && ( $1 == -e || $1 == -L ) && $2 == /* ]]; then
    builtin test "$1" "$ROOT$2"
  else
    builtin test "$@"
  fi
}
dpkg-query() { return 1; }
apt-mark() { return 0; }
systemctl() { return 1; }
ss() { return 0; }
getent() { return 2; }
prove_not_installed
'''
        command = ['bash', '-c', probe, 'fixture', str(packaged), str(self.host)]
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        leftover.rename(self.base/'retained-fixture-link')
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        self.assertEqual(self.draft.read_bytes(), before)

    def test_window_must_follow_origin_and_allow_live_admission(self):
        for change, guard in (({'start_unix': self.now-86400, 'test_until_unix': self.now-83000,
                                'finish_unix': self.now-81000}, self.now-85000),
                              ({'test_until_unix': self.now+300}, self.now+60)):
            with self.subTest(change=change):
                write(self.base/'plan.json', {**self.plan, **change})
                run = subprocess.run([*self.cmd[:-1], str(guard)], capture_output=True)
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(self.prepared.exists())

    def test_bad_manifest_or_origin_cannot_create_preparation(self):
        write(self.base/'manifest.json', {**self.manifest, 'other': 1})
        self.assertNotEqual(subprocess.run(self.cmd, capture_output=True).returncode, 0)
        self.assertFalse(self.prepared.exists())
        write(self.base/'manifest.json', self.manifest)
        write(self.base/'plan.json', {**self.plan, 'origin_run_id': '78'})
        self.assertNotEqual(subprocess.run(self.cmd, capture_output=True).returncode, 0)
        self.assertFalse(self.prepared.exists())


if __name__ == '__main__':
    unittest.main()
