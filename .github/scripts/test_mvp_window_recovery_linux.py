#!/usr/bin/env python3
"""Integration extension used only inside the marked dpkg/SSH observer fixture.

Actual terminal/lifecycle Update and Recover, ptrace/fsync, linked files, SSH,
menu driver and wrapper; synthetic release, proxy admission/runtime and snaps.
Not original packaged execution, network trust, real serving or live evidence.
"""
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

SOURCE = Path(__file__).resolve().parent
WINDOW = Path('/root/sbxr-mvp-log-parent')
STATE = Path('/var/lib/sbxr')
PRODUCT = Path('/usr/local/bin/sbxr')
CONTROL = Path('/root/sbxr-update-control')
EVIDENCE = Path('/root/sbxr-qualification-evidence')
sha = lambda body: hashlib.sha256(body).hexdigest()


def run(args, ok=True, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=150, **kwargs)
    if ok is not None:
        assert (result.returncode == 0) == ok, (args, result.returncode, result.stdout, result.stderr)
    return result


def write(path, body, mode=0o600):
    path.write_bytes(body)
    path.chmod(mode)


def rehearse(work, source_binary, candidate_binary, expected, ssh_options):
    assert not sys.flags.optimize and sys.platform == 'linux' and os.geteuid() == 0
    assert Path('/run/sbxr-isolated-test-host').read_bytes() == b'disposable SBXR test VM\n'
    for path in (CONTROL, EVIDENCE): assert not os.path.lexists(path), path
    before = {p: (p.read_bytes(), p.stat().st_mode & 0o777) for p in
              (PRODUCT, STATE / 'installed.json', STATE / 'proxy-ownership.json')}
    transaction = [STATE / name for name in ('update.json', '.update.json.next', '.installed.json.prior', '.installed.json.candidate')]
    transaction += [PRODUCT.parent / name for name in ('.sbxr-update-prior', '.sbxr-update-candidate')]
    assert not any(os.path.lexists(p) for p in transaction)
    doc = (SOURCE.parents[1] / 'docs/acceptance/mvp-protected-log-parent-2026-09-19.md').read_text()
    examples = {}
    for mode in ('mvp-window-observer-ssh', 'mvp-recovery-window-observer-ssh'):
        found = re.findall(r'<!-- ' + mode + r' -->\n```sh\n(.*?)\n```', doc, re.S)
        assert len(found) == 1
        examples[mode] = found[0]
    expected = dict(expected, qualification_manifest_sha256='e' * 64)
    expectation = work / 'window-expected.json'; write(expectation, json.dumps(expected).encode())
    CONTROL.mkdir(mode=0o700); EVIDENCE.mkdir(mode=0o700)
    controller = CONTROL / 'mvp-update-interrupt.py'
    write(controller, (SOURCE / controller.name).read_bytes())
    controller_hash = sha(controller.read_bytes())
    remote = ['ssh', '-T', *ssh_options, 'root@127.0.0.1']
    request_path = EVIDENCE / 'request.json'
    recovery_file = CONTROL / 'expected.json'
    current_case = None
    try:
        for boundary in ('precommit', 'postcommit'):
            case = work / boundary; case.mkdir(mode=0o700); current_case = case
            run([str(candidate_binary), 'prepare', str(case), str(source_binary), str(candidate_binary)])
            write(PRODUCT, (case / 'source').read_bytes(), 0o755)
            write(STATE / 'installed.json', (case / 'source.json').read_bytes())
            owner = json.loads(before[STATE / 'proxy-ownership.json'][0]); owner['schema'] = 2
            owner_bytes = json.dumps(owner).encode(); write(STATE / 'proxy-ownership.json', owner_bytes)
            wanted = dict(prior_executable_sha256=sha((case / 'source').read_bytes()),
                          prior_installed_record_sha256=sha((case / 'source.json').read_bytes()),
                          candidate_executable_sha256=sha((case / 'candidate').read_bytes()),
                          candidate_installed_record_sha256=sha((case / 'candidate.json').read_bytes()),
                          ownership_sha256=sha(owner_bytes))
            write(recovery_file, json.dumps(wanted).encode())
            now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            request = dict(scenario_id='source-v99.0.1-' + boundary, not_before=now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                           deadline_unix=int(now.timestamp()) + 1800, scenario_limit_seconds=1800,
                           qualification_manifest_sha256=expected['qualification_manifest_sha256'], required_checks=['fixture-only'])
            write(request_path, json.dumps(request).encode())
            output = case / 'observation.json'; sentinel = case / 'continued'
            def observe(phase, reason=None, program=None):
                sentinel.unlink(missing_ok=True)
                prefix = ('set -euo pipefail\nssh_options=(' + shlex.join(ssh_options) + ')\n'
                          'acceptance_host=root@127.0.0.1\nphase=' + shlex.quote(phase) + '\nwindow_seconds=900\n'
                          'expectation_file=' + shlex.quote(str(expectation)) + '\n'
                          'recovery_expectation_file=' + shlex.quote(str(recovery_file)) + '\n'
                          'observation_file=' + shlex.quote(str(output)) + '\n')
                example = examples['mvp-recovery-window-observer-ssh' if phase.startswith('recovery-') else 'mvp-window-observer-ssh']
                if program:
                    example = example.replace('.github/scripts/mvp-inspect-window.py', shlex.quote(str(program)))
                result = run(['bash', '-c', prefix + example + '\ntouch ' + shlex.quote(str(sentinel))],
                             cwd=SOURCE.parents[1], ok=reason is None)
                assert sentinel.exists() == (reason is None)
                if reason:
                    assert not output.read_bytes() and reason.encode() in result.stderr, result.stderr
                else:
                    result_json = json.loads(output.read_text())
                    assert result_json['log_parent'] == expected['log_parent'] and result_json['log_children'] == expected['log_children']
                    assert result_json['operator_files_verified'] and result_json['locks_unheld'] and result_json['writers_idle']
                    if phase.startswith('recovery-'):
                        assert result_json['recovery']['checkpoint'] == ('Prepared' if boundary == 'precommit' else 'Committed')
                        assert result_json['recovery']['qualification_manifest_sha256'] == expected['qualification_manifest_sha256']
                print('PASS ' + boundary + ' streamed-' + phase + (' refusal=' + reason if reason else ''), flush=True)
                return result
            observe('running')
            env = ['env', 'SBXR_QUALIFICATION_REQUEST=' + str(request_path), 'SBXR_WINDOW_RECOVERY_FIXTURE=' + str(case)]
            assert sha(controller.read_bytes()) == controller_hash
            result = run(remote + [shlex.join(env + ['python3', str(controller), boundary, '--expectation', str(recovery_file),
                                '--transcript', str(CONTROL / (boundary + '.transcript')), '--timeout', '90', '--protected-log-parent'])], ok=None)
            write(case / 'controller.stdout', result.stdout); write(case / 'controller.stderr', result.stderr)
            assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
            assert result.stdout.startswith(b'SBXR_UPDATE_INTERRUPTED '), result.stdout
            receipt = json.loads(result.stdout.split(b' ', 1)[1]); assert receipt['boundary'] == boundary and receipt['syscall_result'] == 0
            print('RECOVERY_CONTROL_RECEIPT ' + json.dumps(receipt, sort_keys=True), flush=True)
            assert receipt['update_record_sha256'] == sha((STATE / 'update.json').read_bytes())
            assert not (case / 'runtime-completed').exists()
            assert not any(os.path.lexists(WINDOW / name) for name in ('window.state', 'window.state.control', 'window.state.result'))
            assert (Path('/var/log').stat().st_mode & 0o777) == 0o775
            if boundary == 'precommit':
                assert PRODUCT.stat().st_nlink == 2 and os.path.samefile(PRODUCT, PRODUCT.parent / '.sbxr-update-prior')
                legacy = os.environ.get('SBXR_MVP_OBSERVER_BEFORE')
                if legacy:
                    red = observe('running', 'unsafe-file:/usr/local/bin/sbxr', Path(legacy))
                    write(case / 'original-observer-refusal.stderr', red.stderr)
            # Normal Running is NOT a way around a transaction. Recovery uses
            # its named, bound path, with every existing global gate intact.
            observe('running', 'unexpected-update-transaction')
            phase = 'recovery-' + boundary
            original_request = request_path.read_bytes()
            write(request_path, json.dumps(dict(request, scenario_id='source-v99.0.1-upgrade')).encode())
            try: observe(phase, 'recovery-request-scenario')
            finally: write(request_path, original_request)
            with open('/run/lock/sbxr.lock', 'r+') as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                observe(phase, 'held-lock:')
            p = subprocess.Popen(['bash', '-c', 'exec -a mvp-update-interrupt /bin/sleep 120'])
            try: observe(phase, 'active-writer-pid:')
            finally: p.terminate(); p.wait(timeout=5)
            observe(phase)
            if os.environ.get('MVP_RECOVERY_INJECT_FAILURE') == boundary:
                raise AssertionError('injected-after-recovery-observation-' + boundary)
            code = ('SOFTWARE-LIFECYCLE-RECOVER-PRIOR-RESTORED' if boundary == 'precommit'
                    else 'SOFTWARE-LIFECYCLE-RECOVER-CANDIDATE-RETAINED')
            result = run(remote + [shlex.join(env + ['python3', str(WINDOW / 'v3-menu-session.py'), 'action', 'Recover', code,
                                        '--confirmation', 'yes', '--executable', str(WINDOW / 'mvp-protected-menu.sh'),
                                        '--protected-wrapper', '--timeout', '90'])])
            write(case / 'recover.stdout', result.stdout); write(case / 'recover.stderr', result.stderr)
            assert ('Code: ' + code).encode() in result.stdout
            assert not any(os.path.lexists(p) for p in transaction)
            selected = 'source' if boundary == 'precommit' else 'candidate'
            assert PRODUCT.read_bytes() == (case / selected).read_bytes()
            assert (STATE / 'installed.json').read_bytes() == (case / (selected + '.json')).read_bytes()
            assert (STATE / 'proxy-ownership.json').read_bytes() == owner_bytes
            assert PRODUCT.stat().st_nlink == 1 and PRODUCT.stat().st_mode & 0o777 == 0o755
            assert (case / 'runtime-completed').exists() == (boundary == 'postcommit')
            observe('running')
            shutil.copyfile(CONTROL / (boundary + '.transcript'), case / 'interruption.transcript')
            print('PASS actual-lifecycle-terminal-controller-observer-public-Recover-' + boundary, flush=True)
    finally:
        # Preserve original observations even if cleanup itself refuses.
        if current_case:
            for transcript in CONTROL.glob('*.transcript'):
                shutil.copyfile(transcript, current_case / transcript.name)
            for path in transaction:
                if path.is_file():
                    shutil.copyfile(path, current_case / ('retained-' + path.name))
        retained = os.environ.get('SBXR_MVP_RECOVERY_ARTIFACTS')
        if retained:
            shutil.copytree(work, retained)  # refuses an existing destination
        # Fixture disposal only, never a VPS recovery route. Protocol failure
        # can legitimately retain valid wrapper state after descendant death.
        # Prove quiescence first, then use ONLY its existing explicit restore.
        with open('/run/lock/sbxr.lock', 'r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit() or int(proc.name) == os.getpid(): continue
            try: args = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
            except (FileNotFoundError, ProcessLookupError): continue
            assert not (str(CONTROL) in args or args.strip() == str(PRODUCT)), ('fixture process remains', proc.name)
        if (WINDOW / 'window.state').exists():
            run(['bash', str(WINDOW / 'with-protected-log-parent.sh'), 'restore', str(WINDOW / 'window.state')])
        assert not any(os.path.lexists(WINDOW / name) for name in ('window.state', 'window.state.control', 'window.state.result'))
        assert Path('/var/log').stat().st_mode & 0o777 == 0o775
        if current_case:
            for p in transaction:
                p.unlink(missing_ok=True)
        for p, (body, mode) in before.items(): write(p, body, mode)
        assert {p.name for p in EVIDENCE.iterdir()} <= {'request.json'}
        request_path.unlink(missing_ok=True); EVIDENCE.rmdir()
        assert {p.name for p in CONTROL.iterdir()} <= {'mvp-update-interrupt.py', 'expected.json', 'precommit.transcript', 'postcommit.transcript'}
        for p in CONTROL.iterdir(): p.unlink()
        CONTROL.rmdir()
        print('PASS recovery-fixture-quiescence-and-cleanup', flush=True)
