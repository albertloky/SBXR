#!/usr/bin/env python3
"""Linux executable permission gate for externally guarded processes.

Never launches a process. Mark the exact executable inode before starting the controlled service.
After a matching exec permission event, seize with EXITKILL before reporting held.
stdin accepts 'deny' or 'release'; EOF, timeout and errors deny execution. Killing the
controller after 'held' kills the traced process rather than releasing it.
A persistent cgroup egress guard is required: fanotify closes fail-open if the
controller dies before ptrace attachment. Kernel fixtures do not prove a live
product route; the managed coordinator separately checks that route and receipt.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import stat
import struct
import sys
import time


def ancestor_in_group(pid, expected_cgroup):
    """Recognize an escaped child through the recorder that remains in its unit."""
    seen = set()
    while pid > 1:
        if pid in seen:
            raise ValueError('process ancestry cycle')
        seen.add(pid)
        root = Path('/proc')/str(pid)
        if '0::'+expected_cgroup in (root/'cgroup').read_text().splitlines():
            return True
        pid = int((root/'stat').read_text().rsplit(')', 1)[1].split()[1])
    return False


def run(path, expected_cgroup, seconds, on_held=None, trace_options=0):
    if sys.platform != 'linux' or not 1 <= seconds <= 120:
        raise ValueError('Linux and timeout 1..120 required')
    target = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(target.st_mode) or target.st_mode & 0o022:
        raise ValueError('expected regular executable with no group/other writes')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    def checked(result):
        if result == -1:
            raise OSError(ctypes.get_errno(), 'kernel control refused')
        return result
    fd = checked(libc.fanotify_init(4 | 1 | 2, os.O_RDONLY | os.O_CLOEXEC))
    pending = []
    seized = []
    try:
        checked(libc.fanotify_mark(fd, 1, ctypes.c_uint64(0x40000), -100, os.fsencode(path)))
        print(json.dumps({'state': 'armed', 'device': target.st_dev, 'inode': target.st_ino}), flush=True)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], max(0, deadline-time.monotonic()))
            if not ready:
                raise TimeoutError('no executable event')
            data = os.read(fd, 4096)
            offset = 0
            while offset < len(data):
                length, version, _, metadata_len, mask, eventfd, pid = struct.unpack_from('=IBBHQii', data, offset)
                if length < 24 or version != 3 or metadata_len != 24 or eventfd < 0:
                    raise ValueError('unexpected fanotify event')
                pending.append(eventfd)
                offset += length
                opened = os.fstat(eventfd)
                if (opened.st_dev, opened.st_ino) != (target.st_dev, target.st_ino) or mask != 0x40000:
                    raise ValueError('unexpected executable identity')
                groups = open('/proc/%d/cgroup' % pid).read().splitlines()
                if '0::' + expected_cgroup not in groups:
                    if ancestor_in_group(pid, expected_cgroup):
                        raise ValueError('controlled child escaped execution cgroup')
                    # The inode mark also sees unrelated users of the same
                    # interpreter. Let them proceed without attaching ptrace.
                    os.write(fd, struct.pack('=iI', eventfd, 1))
                    pending.remove(eventfd)
                    os.close(eventfd)
                    continue
                # PTRACE_SEIZE + PTRACE_O_EXITKILL: controller death kills this
                # process even while the exec permission request is pending.
                checked(libc.ptrace(0x4206, pid, None, ctypes.c_void_p(0x100010 | trace_options)))
                seized.append(pid)
                # Permit kernel exec only after TRACEEXEC and EXITKILL are set.
                # The exec trap stops the actual target image before userspace,
                # so /proc/PID/exe proves more than an about-to-exec launcher.
                os.write(fd, struct.pack('=iI', eventfd, 1))
                pending.remove(eventfd)
                os.close(eventfd)
                while True:
                    observed, status = os.waitpid(pid, os.WNOHANG)
                    if observed:
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError('exec trap deadline')
                    time.sleep(.001)
                if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGTRAP or status >> 16 != 4:
                    raise ValueError('expected target exec trap')
                actual = os.stat('/proc/%d/exe' % pid)
                if (actual.st_dev, actual.st_ino) != (target.st_dev, target.st_ino):
                    raise ValueError('actual executable mismatch')
                process = open('/proc/%d/stat' % pid).read().rsplit(')', 1)[1].split()
                # No more exec events are needed. Remove the global inode mark
                # while ptrace keeps only the selected process stopped.
                os.close(fd)
                fd = -1
                if on_held is not None:
                    seized.remove(pid)  # callback owns tracee cleanup from here
                    return on_held(pid, deadline)
                print(json.dumps({'state': 'held', 'pid': pid, 'start_tick': int(process[19]),
                                  'device': opened.st_dev, 'inode': opened.st_ino,
                                  'boundary': 'actual-image-exec-trap-before-target-code'}), flush=True)
                readable, _, _ = select.select([sys.stdin], [], [], max(0, deadline-time.monotonic()))
                command = ''
                if readable:
                    command = sys.stdin.readline()
                    if command not in ('deny\n', 'release\n', ''):
                        raise ValueError('only deny or release is supported')
                if command == 'release\n':
                    checked(libc.ptrace(17, pid, None, None))  # PTRACE_DETACH
                    seized.remove(pid)
                    print('{"state":"released"}', flush=True)
                else:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
                    seized.remove(pid)
                    print('{"state":"denied"}', flush=True)
                return
        raise TimeoutError('gate deadline')
    finally:
        for eventfd in pending:
            try:
                os.write(fd, struct.pack('=iI', eventfd, 2))
            finally:
                os.close(eventfd)
        for pid in seized:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except ProcessLookupError:
                pass
        if fd >= 0:
            os.close(fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable')
    parser.add_argument('cgroup')
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args()
    try:
        run(args.executable, args.cgroup, args.timeout)
    except Exception as error:
        reason = str(error) if type(error) is ValueError else type(error).__name__
        print(json.dumps({'state': 'refused', 'reason': reason, 'errno': getattr(error, 'errno', None)}), flush=True)
        sys.exit(1)
