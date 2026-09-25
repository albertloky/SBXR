#!/usr/bin/env python3
"""Disposable amd64 Ubuntu VM only: actual DEB/dpkg, SSH and permission windows.

SBXR records/menu and snap CLI/images are fixtures; the pinned official DEB,
installed binary, dpkg hold/purge, SSH, systemd timer, locks, launcher/wrapper
and source-streamed observer are real. No CA, VPS or product qualification.
"""
import contextlib
import datetime as dt
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

SOURCE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('observer', SOURCE / 'mvp-inspect-window.py')
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
RECEIPT = {'repository': 'https://deb.sagernet.org/', 'name': 'sing-box',
           'version': '1.13.19', 'architecture': 'amd64', 'size': 24597120,
           'sha256': 'fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf'}
ROOT = Path('/root/sbxr-mvp-log-parent')
OWNED = Path('/var/lib/sbxr')
PRODUCT = Path('/usr/local/bin/sbxr')
SNAP = Path('/usr/local/bin/snap')
TIMER = 'snap.certbot.renew.timer'
SERVICE = 'snap.certbot.renew.service'


def run(args, ok=True, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=90, **kwargs)
    assert (result.returncode == 0) == ok, (args, result.returncode, result.stdout, result.stderr)
    return result


def write(path, body, mode=0o600):
    path.write_text(body)
    path.chmod(mode)


def main(deb):
    if sys.flags.optimize:
        raise RuntimeError('fixture-requires-enabled-assertions')
    marker = Path('/run/sbxr-isolated-test-host')
    assert sys.platform == 'linux' and os.geteuid() == 0
    assert marker.read_bytes() == b'disposable SBXR test VM\n'
    observer.protected_file(marker, 0o600)
    assert run(['dpkg', '--print-architecture']).stdout.strip() == b'amd64'
    assert deb.stat().st_size == RECEIPT['size'] and observer.digest(deb) == RECEIPT['sha256']
    paths = [ROOT, OWNED, PRODUCT, SNAP, Path('/usr/bin/sing-box'), Path('/etc/sing-box'),
             Path('/etc/systemd/system/sing-box.service'), Path('/run/lock/sbxr.lock')]
    paths += [Path('/etc/systemd/system') / name for name in (TIMER, SERVICE)]
    paths += [Path(name) for name in ('/etc/letsencrypt', '/var/lib/letsencrypt', '/var/log/letsencrypt')]
    for path in paths:
        assert not os.path.lexists(path), ('preexisting fixture path', path)
    assert run(['dpkg-query', '-W', 'sing-box'], ok=False).returncode == 1
    assert run(['getent', 'passwd', 'sing-box'], ok=False).returncode == 2
    assert run(['getent', 'group', 'sing-box'], ok=False).returncode == 2
    baseline = observer.log_observation()
    assert baseline['log_parent']['mode'] == '0o775'
    initial_packages = run(['dpkg-query', '-W', '-f=${Package}\t${Status}\n']).stdout
    with tempfile.TemporaryDirectory(prefix='observer-linux-') as temp, contextlib.ExitStack() as cleanup:
        work = Path(temp)
        def directory(path):
            path.mkdir(mode=0o700)
            cleanup.callback(path.rmdir)
        def file(path, body, mode=0o600):
            write(path, body, mode)
            cleanup.callback(lambda: path.unlink(missing_ok=True))
        for path in (ROOT, OWNED, Path('/etc/letsencrypt'), Path('/var/lib/letsencrypt'), Path('/var/log/letsencrypt')):
            directory(path)
        for parent in (Path('/var/lib/snapd'), Path('/var/lib/snapd/snaps'), Path('/var/lib/snapd/cache')):
            if not parent.exists():
                directory(parent)
        expected = dict(observer.log_observation(), proxy_package=RECEIPT,
                        installed_binary_sha256='031042edfd30a215e4c69d83eb7d13c194e6ef50c782e2e1308d9d8fa128454a',
                        operator_sha256={}, snap_packages={})
        for name, mode in observer.OPERATOR_MODES.items():
            source = SOURCE / name
            if name in ('with-protected-log-parent.sh', 'protected_command_supervisor.py'):
                source = SOURCE / 'sbxr-snapshot-recovery' / name
            file(ROOT / name, source.read_text(), mode)
            expected['operator_sha256'][name] = observer.digest(source)
        for name in ('certbot', 'core24', 'snapd'):
            path = Path('/var/lib/snapd/snaps') / (name + '_999999.snap')
            assert not os.path.lexists(path)
            file(path, 'not a snap: isolated observer fixture ' + name + '\n')
            cache = Path('/var/lib/snapd/cache') / ('mvp-observer-' + name)
            assert not os.path.lexists(cache)
            os.link(path, cache)
            cleanup.callback(lambda p=cache: p.unlink(missing_ok=True))
            paths.extend((path, cache))
            assert path.stat().st_nlink == 2 and os.path.samefile(path, cache)
            expected['snap_packages'][name] = {'version': 'fixture', 'revision': '999999',
                                               'snap_sha256': observer.digest(path), 'snap_size': path.stat().st_size}
        snap_state = work / 'snap-state.json'
        snap_default = {'change': 'Done', 'next': 'tomorrow at 23:59 UTC'}
        write(snap_state, json.dumps(snap_default))
        file(SNAP, f'''#!/usr/bin/python3
import json,sys
s=json.load(open({str(snap_state)!r}))
if sys.argv[1] == 'list': print('Name Version Rev\\n'+sys.argv[2]+' fixture 999999')
elif sys.argv[1] == 'changes': print('ID Status\\n1 '+s['change'])
elif sys.argv[1:] == ['refresh','--time']: print('next: '+s['next'])
else: raise SystemExit(2)
''', 0o755)
        def set_timer(seconds=10800):
            stamp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)
            write(Path('/etc/systemd/system') / TIMER,
                  '[Timer]\nOnCalendar=' + stamp.strftime('%Y-%m-%d %H:%M:%S UTC') + '\nAccuracySec=1s\n[Install]\nWantedBy=timers.target\n', 0o644)
            run(['systemctl', 'daemon-reload'])
            run(['systemctl', 'enable', '--now', TIMER])
            run(['systemctl', 'restart', TIMER])
        file(Path('/etc/systemd/system') / SERVICE, '[Service]\nType=oneshot\nExecStart=/bin/true\n', 0o644)
        file(Path('/etc/systemd/system') / TIMER, '', 0o644)
        def stop_timer():
            run(['systemctl', 'disable', '--now', TIMER])
            run(['systemctl', 'stop', SERVICE])
        cleanup.callback(stop_timer)
        set_timer()
        file(Path('/run/lock/sbxr.lock'), '')
        ownership_path = OWNED / 'proxy-ownership.json'
        ownership = {'phase': 'Running', 'unfinished_direction': 'none',
                     'proxy_package_identity': observer.ownership_identity(RECEIPT)}
        # All mutations below are fixtures, not a fabricated product acceptance.
        menu = '''#!/usr/bin/python3
import sys
print('SBXR V3\\n1. Check\\n0. Exit', flush=True)
if sys.stdin.readline().strip() != '1': raise SystemExit(2)
print('Code: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT', flush=True)
print('SBXR V3\\n1. Check\\n0. Exit', flush=True)
if sys.stdin.readline().strip() != '0': raise SystemExit(3)
'''
        # Local loopback SSH with independent ephemeral host/client keys.
        for name in ('client', 'host'):
            run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(work / name)])
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        config = work / 'sshd_config'
        write(config, f'''Port {port}
ListenAddress 127.0.0.1
HostKey {work / 'host'}
PidFile {work / 'sshd.pid'}
AuthorizedKeysFile {work / 'client.pub'}
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
StrictModes yes
LogLevel ERROR
''')
        pub = (work / 'host.pub').read_text().split()
        known = work / 'known_hosts'
        write(known, f'[127.0.0.1]:{port} {pub[0]} {pub[1]}\n')
        log = cleanup.enter_context(open(work / 'sshd.log', 'wb'))
        daemon = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(config)], stderr=log)
        def stop_ssh():
            daemon.terminate()
            daemon.wait(timeout=10)
        cleanup.callback(stop_ssh)
        options = ['-p', str(port), '-F', '/dev/null', '-i', str(work / 'client'),
                   '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'UserKnownHostsFile=' + str(known), '-o', 'ConnectTimeout=5']
        for _ in range(50):
            assert daemon.poll() is None, (work / 'sshd.log').read_text()
            if subprocess.run(['ssh'] + options + ['root@127.0.0.1', 'true'], capture_output=True).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise AssertionError('loopback SSH not ready')
        doc = SOURCE.parents[1] / 'docs/acceptance/mvp-protected-log-parent-2026-09-19.md'
        examples = re.findall(r'<!-- mvp-window-observer-ssh -->\n```sh\n(.*?)\n```', doc.read_text(), re.S)
        assert len(examples) == 1
        expectation = work / 'expected.json'
        write(expectation, json.dumps(expected))
        observation = work / 'observation.json'
        sentinel = work / 'continued'
        def check(phase='running', reason=None, extra_options=None):
            sentinel.unlink(missing_ok=True)
            prefix = ('set -euo pipefail\nssh_options=(' + shlex.join(options + (extra_options or [])) + ')\n'
                      + 'acceptance_host=root@127.0.0.1\nphase=' + shlex.quote(phase) + '\nwindow_seconds=900\n'
                      + 'expectation_file=' + shlex.quote(str(expectation)) + '\n'
                      + 'observation_file=' + shlex.quote(str(observation)) + '\n')
            result = run(['bash', '-c', prefix + examples[0] + '\ntouch ' + shlex.quote(str(sentinel))],
                         cwd=SOURCE.parents[1], ok=reason is None)
            assert sentinel.exists() == (reason is None)
            if reason is not None:
                assert not observation.read_bytes(), result.stdout
                assert reason.encode() in result.stderr, result.stderr
                print('PASS refusal-' + phase + '-' + reason, flush=True)
                return
            data = json.loads(observation.read_text())
            assert data['phase'] == phase
            assert data['log_parent'] == expected['log_parent'] and data['log_children'] == expected['log_children']
            assert (data['installed_proxy_package'] is not None) == (phase == 'running')
            print('PASS observer-' + phase, flush=True)
        # Cleanup even on an assertion or an interrupted Python runner. Leave
        # retained wrapper state untouched if restoration itself refuses.
        package_attempted = False
        def purge():
            if package_attempted:
                run(['apt-mark', 'unhold', 'sing-box'])
                run(['dpkg', '--purge', 'sing-box'])
                if subprocess.run(['getent', 'passwd', 'sing-box'], capture_output=True).returncode == 0:
                    run(['userdel', 'sing-box'])
                if subprocess.run(['getent', 'group', 'sing-box'], capture_output=True).returncode == 0:
                    run(['groupdel', 'sing-box'])
            Path('/etc/systemd/system/sing-box.service').unlink(missing_ok=True)
            for p in OWNED.iterdir():
                assert p.name in ('installed.json', 'proxy-ownership.json', 'renewal-attempts.json',
                                  'sing-box_1.13.19_amd64.deb'), p
                p.unlink()
            PRODUCT.unlink(missing_ok=True)
            run(['systemctl', 'daemon-reload'])
        cleanup.callback(purge)
        check('not-installed')
        # Cache links are allowed only for snaps, never staged operator files.
        for name in observer.OPERATOR_MODES:
            link = work / 'operator-link'
            os.link(ROOT / name, link)
            try:
                check('not-installed', 'unsafe-file:')
            finally:
                link.unlink()
        write(PRODUCT, menu, 0o700)
        write(OWNED / 'installed.json', '{}')
        check('not-set-up')
        run(['systemctl', 'mask', 'sing-box.service'])
        package_attempted = True
        run(['dpkg', '--install', str(deb)])
        run(['apt-mark', 'hold', 'sing-box'])
        write(ownership_path, json.dumps(ownership))
        check()
        # A failed test must still purge its real package and remove fixtures.
        if os.environ.get('MVP_OBSERVER_INJECT_FAILURE') == '1':
            raise AssertionError('injected-after-running-observation')
        run(['apt-mark', 'unhold', 'sing-box'])
        check(reason='installed-proxy-package')
        run(['apt-mark', 'hold', 'sing-box'])
        for name in ('not-installed', 'not-set-up', 'removed'):
            check(name, 'unexpected-proxy-package')
        artifact = OWNED / 'sing-box_1.13.19_amd64.deb'
        for is_link in (False, True):
            if is_link:
                artifact.symlink_to('/missing-mvp-artifact')
            else:
                shutil.copyfile(deb, artifact)
            check(reason='temporary-package-artifact')
            artifact.unlink()
        changed = dict(ownership, proxy_package_identity=RECEIPT)
        write(ownership_path, json.dumps(changed))
        check(reason='ownership-package')
        write(ownership_path, json.dumps(ownership))
        renewal = OWNED / 'renewal-attempts.json'
        write(renewal, '{"attempts":[{"completion":null}]}')
        check(reason='incomplete-renewal')
        write(renewal, '{"attempts":[{"completion":{"exit_code":0}}]}')
        check()
        for state in ('window.state', 'window.state.control', 'window.state.result'):
            p = ROOT / state
            p.symlink_to('/missing-mvp-state')
            try:
                check(reason='operator-directory-contents')
            finally:
                p.unlink()
        with open('/run/lock/sbxr.lock', 'r+') as held:
            fcntl.lockf(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            check(reason='held-lock:')
        writer = subprocess.Popen(['bash', '-c', 'exec -a certbot /bin/sleep 90'])
        try:
            time.sleep(.1)
            check(reason='active-writer-pid:')
        finally:
            writer.terminate()
            writer.wait(timeout=5)
        write(snap_state, json.dumps(dict(snap_default, change='Doing')))
        check(reason='active-snap-change')
        write(snap_state, json.dumps(snap_default))
        snap_image = Path('/var/lib/snapd/snaps/certbot_999999.snap')
        original_snap = snap_image.read_text()
        write(snap_image, original_snap + 'changed')
        try:
            check(reason='snap-receipt-drift')
        finally:
            write(snap_image, original_snap)
        launcher = ROOT / 'mvp-protected-menu.sh'
        original_launcher = launcher.read_text()
        write(launcher, original_launcher + '\n', 0o700)
        try:
            check(reason='operator-file-identity:')
        finally:
            write(launcher, original_launcher, 0o700)
        Path('/etc/letsencrypt').chmod(0o775)
        try:
            check(reason='certbot-directory')
        finally:
            Path('/etc/letsencrypt').chmod(0o700)
        changed_expectation = dict(expected, installed_binary_sha256='0' * 64)
        write(expectation, json.dumps(changed_expectation))
        try:
            check(reason='installed-proxy-binary')
        finally:
            write(expectation, json.dumps(expected))
        set_timer(600)
        check(reason='scheduled-event-overlap')
        set_timer()
        drift = Path('/var/log/observer-fixture')
        drift.mkdir()
        try:
            check(reason='log-directory-drift')
        finally:
            drift.rmdir()
        check(reason='Expecting value', extra_options=['-o', 'StdinNull=yes'])
        # No window is opened on any failed observer call; successful windows
        # return before re-observation and the complete purge window is bounded.
        assert observer.log_observation() == {k: expected[k] for k in ('log_parent', 'log_children')}
        run(['python3', str(ROOT / 'v3-menu-session.py'), 'action', 'Check',
             'SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT', '--executable', str(ROOT / 'mvp-protected-menu.sh'), '--protected-wrapper'])
        check()
        run(['apt-mark', 'unhold', 'sing-box'])
        run(['dpkg', '--remove', 'sing-box'])
        check(reason='installed-proxy-package')
        # Real owned-package purge under the unchanged wrapper; not a claim of
        # the product's Complete removal action (the menu above is synthetic).
        run(['bash', str(ROOT / 'with-protected-log-parent.sh'), 'run', str(ROOT / 'window.state'),
             '--', 'dpkg', '--purge', 'sing-box'])
        package_attempted = False
        for kind, command in (('passwd', 'userdel'), ('group', 'groupdel')):
            if subprocess.run(['getent', kind, 'sing-box'], capture_output=True).returncode == 0:
                run([command, 'sing-box'])
        Path('/etc/systemd/system/sing-box.service').unlink()
        for p in OWNED.iterdir():
            p.unlink()
        PRODUCT.unlink()
        check('removed')
        assert not any(os.path.lexists(ROOT / name) for name in ('window.state', 'window.state.control', 'window.state.result'))
        print('PASS real-dpkg-hold-purge-SSH-window-and-refusals', flush=True)
    run(['systemctl', 'daemon-reload'])
    assert observer.log_observation() == baseline
    assert run(['dpkg-query', '-W', '-f=${Package}\t${Status}\n']).stdout == initial_packages
    assert all(not os.path.lexists(p) for p in paths)
    print('PASS fixture-cleanup-and-unrelated-package-preservation', flush=True)


if __name__ == '__main__':
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    assert len(sys.argv) == 2, 'supply the verified pinned amd64 DEB'
    main(Path(sys.argv[1]).resolve())
