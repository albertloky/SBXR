#!/usr/bin/env python3
"""Real Bash/menu startup cancellation; marked disposable root Linux only.

BASH_ENV supplies test-only DEBUG breakpoints, without editing wrapper bytes.
They stop the real wrapper at artifact boundaries, not after guessed sleeps.
No packaged product, certificate issuance or live acceptance is involved.
"""

import ctypes
import importlib.util
import io
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fixture', SOURCE / 'test_mvp_protected_menu.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
spec = importlib.util.spec_from_file_location('menu', SOURCE / 'v3-menu-session.py')
menu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(menu)


def run():
    assert sys.platform.startswith('linux') and os.geteuid() == 0
    marker = Path('/run/sbxr-isolated-test-host')
    assert marker.read_bytes() == b'disposable SBXR test VM\n'
    assert fixture.identity(marker)[2:] == (0, 0, 1, 0o600) and not marker.is_symlink()
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    root = fixture.ROOT
    assert not os.path.lexists(root)
    root.mkdir(mode=0o700)
    baseline = fixture.identity(fixture.LOG)
    assert baseline[-1] == 0o775
    session = None
    try:
        for name, mode in [('with-protected-log-parent.sh', 0o700),
                           ('protected_command_supervisor.py', 0o600)]:
            fixture.write(root / name, (SOURCE / 'sbxr-snapshot-recovery' / name).read_text(), mode)
        for boundary in ('control', 'channels', 'ready', 'state', 'admission'):
            failures = ('deadline', 'cancel', 'term', 'slow-cleanup', 'replaced-channel', 'open-channel') if boundary == 'channels' else ('deadline', 'cancel', 'term')
            for failure in failures:
                case = Path(tempfile.mkdtemp(prefix=boundary + '-', dir=root))
                state = fixture.STATE
                probe = case / 'probe'
                # The DEBUG trap only observes/stops the owning wrapper shell.
                # It does not stub commands, state, metadata or cleanup.
                fixture.write(probe, r'''
exec 2>>"$STARTUP_CASE/wrapper.stderr"
set -T
trap '
if [[ ${BASH_SOURCE[0]:-} == */with-protected-log-parent.sh && $$ == $BASHPID && -n ${state:-} && ! -e "$STARTUP_CASE/stopped" ]]; then
  hit=false
  case "$STARTUP_BOUNDARY" in
    control) [[ -p "$state.control" && ! -e "$state.result" ]] && hit=true ;;
    channels) [[ -p "$state.result" && ! -e "$state" ]] && hit=true ;;
    ready) [[ $BASH_COMMAND == "facts="* ]] && hit=true ;;
    state) [[ -s "$state" && $BASH_COMMAND == "test "* ]] && hit=true ;;
    admission) [[ $BASH_COMMAND == "send_control START"* ]] && hit=true ;;
  esac || true
  if $hit; then
    printf "%s\n" "$$" > "$STARTUP_CASE/stopped.tmp"
    mv "$STARTUP_CASE/stopped.tmp" "$STARTUP_CASE/stopped"
    kill -STOP "$$"
  fi
fi
' DEBUG
''')
                env = dict(os.environ)
                os.environ.update(BASH_ENV=str(probe), STARTUP_CASE=str(case), STARTUP_BOUNDARY=boundary)
                cancelled = []
                try:
                    session = menu.MenuSession(
                        ['/usr/bin/bash', str(root / 'with-protected-log-parent.sh'), 'run', str(state),
                         '--', '/usr/bin/touch', str(case / 'product-started')],
                        io.BytesIO(), time.monotonic() + 30, lambda: bool(cancelled))
                    # Same opt-in used by the reviewed menu/controller callers.
                    # Assign separately so the original implementation reaches
                    # the real defect instead of failing on a new keyword.
                    session.protected_wrapper = True
                finally:
                    os.environ.clear()
                    os.environ.update(env)
                deadline = time.monotonic() + 15
                while not (case / 'stopped').exists():
                    assert not session.stream.owner_exited() and time.monotonic() < deadline, boundary
                    time.sleep(.005)
                assert int((case / 'stopped').read_text()) == session.process.pid
                stopped_identity = fixture.process(session.process.pid)
                assert stopped_identity is not None
                control = Path(str(state) + '.control')
                held = None
                if failure == 'replaced-channel':
                    # Keep the old inode alive to prevent inode-number reuse.
                    control.rename(case / 'original-control')
                    os.mkfifo(control, 0o600)
                    replacement = fixture.identity(control)
                elif failure == 'open-channel':
                    held = os.open(control, os.O_RDWR | os.O_NONBLOCK)
                if failure == 'deadline':
                    session.deadline = time.monotonic() - 1
                else:
                    cancelled.append(True)
                # Release the test-only stop after cancellation is pending;
                # production uses neither SIGSTOP nor this thread.
                def resume():
                    time.sleep(6 if failure == 'slow-cleanup' else .1)
                    try:
                        if fixture.live(stopped_identity):
                            os.kill(session.process.pid, signal.SIGCONT)
                    except ProcessLookupError:
                        pass
                resumed = threading.Thread(target=resume)
                resumed.start()
                try:
                    try:
                        session.stream.line(session.deadline)
                        raise AssertionError('failure was not raised')
                    except (menu.ProtocolError, InterruptedError):
                        if failure == 'term':
                            os.kill(session.process.pid, signal.SIGTERM)
                            until = time.monotonic() + 10
                            while not session.stream.owner_exited():
                                assert time.monotonic() < until
                                time.sleep(.01)
                        session.stop()
                finally:
                    resumed.join()
                    if held is not None:
                        os.close(held)
                assert not (case / 'product-started').exists(), 'cancelled startup admitted command'
                if boundary == 'admission' and state.exists():
                    # Conservatively retained authority at the START boundary
                    # must still pass the unchanged explicit restore checks.
                    fixture.command(['bash', str(root / 'with-protected-log-parent.sh'), 'restore', str(state)])
                assert fixture.identity(fixture.LOG) == baseline
                leftovers = [str(p) for p in (state, Path(str(state) + '.control'), Path(str(state) + '.result'))
                             if os.path.lexists(p)]
                if failure in ('replaced-channel', 'open-channel'):
                    assert session.returncode == 1 and len(leftovers) == 2 and not state.exists()
                    if failure == 'replaced-channel':
                        assert fixture.identity(control) == replacement
                    # Dispose only this explicit adversarial test fixture;
                    # neither the wrapper nor any live procedure adopts it.
                    assert not Path(f'/proc/self/task/{os.getpid()}/children').read_text().strip()
                    for name in leftovers:
                        Path(name).unlink()
                else:
                    assert not leftovers, (boundary, failure, session.returncode, leftovers,
                                           (case / 'wrapper.stderr').read_text())
                assert not Path(f'/proc/self/task/{os.getpid()}/children').read_text().strip()
                session = None
                shutil.rmtree(case)
                print(f'PASS startup-{boundary}-{failure}', flush=True)
    finally:
        if session is not None:
            session.stop()
        # This is disposal of an absent-at-entry test fixture, not a live
        # orphan recovery route. Retain it if any process/log proof fails.
        assert not Path(f'/proc/self/task/{os.getpid()}/children').read_text().strip()
        assert fixture.identity(fixture.LOG) == baseline
        shutil.rmtree(root)
        print('CLEANUP startup-fixture-absent-and-log-unchanged', flush=True)


if __name__ == '__main__':
    run()
