#!/usr/bin/env python3
"""Gate a real process at a selected file syscall and observed durable checkpoint.

Arm before starting the selected executable in the exact cgroup. This controller
never starts a product role. It traces actual calls, ignores unrelated paths,
and reports only the requested boundary. It holds before-open or after-close;
stdin kill/release controls the already-stopped process. Select a private JSON
record predicate to distinguish an actual checkpoint from a repeated syscall.
Use the persistent egress guard for any official renewal route.
"""
import argparse
import ctypes
from collections import deque
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import stat
import struct
import sys
import time

spec = importlib.util.spec_from_file_location('exec_gate', Path(__file__).with_name('exec-gate.py'))
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)
WALL = 0x40000000


def checkpoint(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate checkpoint key')
            result[key] = value
        return result
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1
                or not 0 < info.st_size <= 1048576):
            raise ValueError('checkpoint record protection refused')
        body = os.read(fd, 1048577)
        after = os.fstat(fd)
        if len(body) != info.st_size or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('checkpoint changed while reading')
        return body, json.loads(body, object_pairs_hook=unique)
    finally:
        os.close(fd)


def trace(root, deadline, path, boundary, record=None, field=None, value=None, no_child=False, child_executable=None):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    def ptrace(request, pid, address=0, data=0):
        ctypes.set_errno(0)
        result = libc.ptrace(request, pid, ctypes.c_void_p(address), ctypes.c_void_p(data))
        if result == -1 and ctypes.get_errno():
            raise OSError(ctypes.get_errno(), 'trace control refused')
        return result
    def pathname(pid, pointer):
        data = bytearray()
        for offset in range(0, 4096, 8):
            word = ptrace(2, pid, pointer+offset) & ((1 << 64)-1)
            data.extend(word.to_bytes(8, 'little'))
            if 0 in data[-8:]:
                return bytes(data).split(b'\0', 1)[0]
        return b''
    def tgid(pid):
        return int(next(line.split()[1] for line in Path('/proc/%d/status' % pid).read_text().splitlines() if line.startswith('Tgid:')))
    def predicate():
        if no_child:
            for task in Path('/proc/%d/task' % root).iterdir():
                if (task/'children').read_text().strip():
                    return None
        if not record:
            return ''
        body, current = checkpoint(record)
        try:
            for part in field.split('.'):
                current = current[int(part)] if isinstance(current, list) else current[part]
            expected = root if value == '@root-pid' else value
            if current != expected:
                return None
            return hashlib.sha256(body).hexdigest()
        except (KeyError, IndexError):
            return None
    traced = {root}
    child_observations = {}
    vanished_tracees = set()
    waiting_close = {}
    stopped = set()
    held_tid = None
    recent_events = deque(maxlen=24)
    try:
        ptrace(24, root)  # PTRACE_SYSCALL
        while time.monotonic() < deadline:
            pid, status = os.waitpid(-1, os.WNOHANG | WALL)
            if not pid:
                time.sleep(.001)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                traced.discard(pid)
                if pid in child_observations:
                    child_observations[pid]['exit_code'] = os.waitstatus_to_exitcode(status)
                if pid == root:
                    raise ValueError('process exited before boundary')
                continue
            traced.add(pid)
            stopped.add(pid)
            sig, event = os.WSTOPSIG(status), status >> 16
            recent_events.append({'pid':pid,'signal':sig,'event':event})
            if event in (1, 2, 3):
                child = ctypes.c_ulong()
                ptrace(0x4201, pid, 0, ctypes.addressof(child))
                traced.add(child.value)
            if event == 4 and pid != root and child_executable:
                image = os.stat('/proc/%d/exe' % pid)
                expected_image = os.stat(child_executable)
                if (image.st_dev, image.st_ino) == (expected_image.st_dev, expected_image.st_ino):
                    fields = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
                    child_observations[pid] = {'pid': pid, 'start_tick': int(fields[19]),
                        'executable_sha256': hashlib.sha256(Path(child_executable).read_bytes()).hexdigest()}
            match = False
            if sig == signal.SIGTRAP | 0x80 and tgid(pid) == root:
                info = ctypes.create_string_buffer(128)
                ptrace(0x420e, pid, 128, ctypes.addressof(info))
                if struct.unpack_from('=I', info, 4)[0] != 0xc000003e:
                    raise ValueError('x86-64 syscall ABI required')
                operation = info.raw[0]
                if operation == 1:
                    number = struct.unpack_from('=Q', info, 24)[0]
                    recent_events[-1]['syscall'] = number
                    args = struct.unpack_from('=6Q', info, 32)
                    if boundary == 'before-open' and number in (2, 257):
                        match = pathname(pid, args[0] if number == 2 else args[1]) == os.fsencode(path)
                    if boundary == 'after-close' and number == 3:
                        try:
                            waiting_close[pid] = os.readlink('/proc/%d/fd/%d' % (pid, args[0])) == path
                        except FileNotFoundError:
                            waiting_close[pid] = False
                elif operation == 2 and boundary == 'after-close':
                    match = waiting_close.pop(pid, False) and struct.unpack_from('=q', info, 24)[0] == 0
            evidence = predicate() if match else None
            if evidence is not None and child_executable and (not child_observations or any('exit_code' not in child for child in child_observations.values())):
                evidence = None
            if evidence is not None:
                held_tid = pid
                # PTRACE_INTERRUPT can return ESRCH after a thread disappears
                # without a final wait status. Never wait indefinitely for that
                # vanished identity, and account for clone events while draining.
                interrupted = set()
                while True:
                    for task in Path('/proc/%d/task' % root).iterdir():
                        traced.add(int(task.name))
                    for other in list(traced-stopped):
                        if not Path('/proc/%d' % other).exists():
                            if other == root:
                                raise ValueError('root disappeared during stop')
                            traced.discard(other)
                            vanished_tracees.add(other)
                            continue
                        if other not in interrupted:
                            try:
                                ptrace(0x4207, other)
                                interrupted.add(other)
                            except OSError as error:
                                if error.errno != 3:
                                    raise
                                # ESRCH also means not attached/not yet dead.
                                # Only actual absence is enough to drop it.
                                if not Path('/proc/%d' % other).exists():
                                    traced.discard(other)
                                    vanished_tracees.add(other)
                    if not traced-stopped:
                        break
                    other, other_status = os.waitpid(-1, os.WNOHANG | WALL)
                    if not other:
                        if time.monotonic() >= deadline:
                            raise TimeoutError('thread stop deadline')
                        time.sleep(.001)
                        continue
                    if os.WIFEXITED(other_status) or os.WIFSIGNALED(other_status):
                        traced.discard(other)
                        stopped.discard(other)
                        if other in child_observations:
                            child_observations[other]['exit_code'] = os.waitstatus_to_exitcode(other_status)
                        if other == root:
                            raise ValueError('root exited during stop')
                    else:
                        traced.add(other)
                        stopped.add(other)
                        if other_status >> 16 in (1, 2, 3):
                            newborn = ctypes.c_ulong()
                            ptrace(0x4201, other, 0, ctypes.addressof(newborn))
                            traced.add(newborn.value)
                # Recheck the actual checkpoint after every live thread stops.
                # A clone/child created during aggregation invalidates no-child.
                if predicate() != evidence:
                    raise ValueError('checkpoint changed during thread stop')
                print(json.dumps({'state': 'boundary-held', 'pid': root, 'tid': pid, 'boundary': boundary,
                                  'path': path, 'record_sha256': evidence, 'children': list(child_observations.values()),
                                  'vanished_tracees': sorted(vanished_tracees)}), flush=True)
                remaining = deadline-time.monotonic()
                if remaining <= 0 or not select.select([sys.stdin], [], [], remaining)[0]:
                    raise TimeoutError('boundary decision deadline')
                command = sys.stdin.readline()
                if command == 'release\n':
                    for other in sorted(traced, reverse=True):
                        try:
                            ptrace(17, other)
                        except OSError as error:
                            if error.errno != 3:
                                raise
                    traced.clear()
                    print('{"state":"released"}', flush=True)
                    return
                if command != 'kill\n':
                    raise ValueError('explicit kill or release required')
                print('{"state":"interrupted"}', flush=True)
                return
            deliver = sig if sig not in (signal.SIGTRAP, signal.SIGTRAP | 0x80) and event == 0 else 0
            ptrace(24, pid, 0, deliver)
            stopped.discard(pid)
        raise TimeoutError('syscall boundary deadline')
    except TimeoutError:
        thread_states = []
        for item in sorted(traced-stopped):
            state = {'pid':item}
            try:
                values = Path('/proc/%d/status' % item).read_text().splitlines()
                state['status'] = [line for line in values if line.split(':',1)[0] in ('State','Tgid','PPid','TracerPid')]
                state['wait_channel'] = Path('/proc/%d/wchan' % item).read_text().strip()
                state['syscall'] = Path('/proc/%d/syscall' % item).read_text().split()[0]
            except OSError as error:
                state['errno'] = error.errno
            thread_states.append(state)
        print(json.dumps({'trace_timeout':True,'root':root,'traced':sorted(traced),
                          'stopped':sorted(stopped),'children':list(child_observations.values()),'pending_threads':thread_states,
                          'recent_events':list(recent_events)}),file=sys.stderr,flush=True)
        raise
    finally:
        for pid in traced:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        # Reap any thread first: waiting specifically for the thread-group
        # leader can deadlock while sibling trace-stop notifications are pending.
        cleanup_deadline = time.monotonic()+5
        while traced:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG | WALL)
            except ChildProcessError:
                break
            if not pid:
                if time.monotonic() >= cleanup_deadline:
                    raise TimeoutError('trace cleanup deadline')
                time.sleep(.001)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                traced.discard(pid)
            elif os.WIFSTOPPED(status):
                try:
                    ptrace(7, pid, 0, signal.SIGKILL)
                except OSError as error:
                    if error.errno != 3:
                        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable')
    parser.add_argument('cgroup')
    parser.add_argument('boundary', choices=['before-open', 'after-close'])
    parser.add_argument('path')
    parser.add_argument('--record')
    parser.add_argument('--field')
    parser.add_argument('--value')
    parser.add_argument('--no-child', action='store_true')
    parser.add_argument('--child-executable')
    parser.add_argument('--timeout', type=int, default=90)
    args = parser.parse_args()
    try:
        if sys.platform != 'linux' or os.uname().machine != 'x86_64':
            raise ValueError('x86-64 Linux required')
        if bool(args.record) != bool(args.field and args.value):
            raise ValueError('record, field and value required together')
        def callback(pid, deadline):
            return trace(pid, deadline, args.path, args.boundary, args.record, args.field, args.value, args.no_child, args.child_executable)
        entry.run(args.executable, args.cgroup, args.timeout, on_held=callback, trace_options=1 | 2 | 4 | 8)
    except Exception as error:
        print(json.dumps({'state': 'refused', 'error_type': type(error).__name__, 'errno': getattr(error, 'errno', None)}), flush=True)
        sys.exit(1)
