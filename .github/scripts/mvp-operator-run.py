#!/usr/bin/env python3
"""Launch a local operator command with private, disjoint outer logs.

By default this reserves local logs and execs the supplied command unchanged.
The optional cutoff/timeout/reserve trio bounds one foreground process group.
Reserve is downstream work, in addition to ten seconds for stopping this group:
now + timeout + 10 + reserve must be strictly before the fixed absolute cutoff.
This does not observe, submit, retry, qualify, or prove remote/client cleanup.
Use a fresh acceptance directory; detached processes are outside its scope.
"""
import argparse
import ctypes
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time


class DarwinSiginfo(ctypes.Structure):
    _fields_ = [("si_signo", ctypes.c_int), ("si_errno", ctypes.c_int),
                ("si_code", ctypes.c_int), ("si_pid", ctypes.c_int),
                ("si_uid", ctypes.c_uint), ("si_status", ctypes.c_int),
                ("si_addr", ctypes.c_void_p), ("si_value", ctypes.c_void_p),
                ("si_band", ctypes.c_long), ("pad", ctypes.c_ulong * 7)]


def child_exited(pid):
    """Observe our waitable child without releasing its PID identity."""
    if hasattr(os, "waitid"):
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    if sys.platform == "darwin":
        # Some macOS Python builds omit os.waitid; the native ABI supplies it.
        waitid = ctypes.CDLL(None, use_errno=True).waitid
        waitid.argtypes = [ctypes.c_int, ctypes.c_uint,
                           ctypes.POINTER(DarwinSiginfo), ctypes.c_int]
        waitid.restype = ctypes.c_int
        info = DarwinSiginfo()
        if waitid(1, pid, ctypes.byref(info), os.WEXITED | os.WNOHANG | os.WNOWAIT) < 0:  # P_PID
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return info.si_pid == pid
    raise OSError("waitid unavailable")


def darwin_lone_exited_child(process, deadline):
    """Prove EPERM came from a group containing only our unreaped zombie."""
    if sys.platform != "darwin" or process.returncode is not None:
        return False
    try:
        while not child_exited(process.pid):
            # proc_find can stop finding an exiting child before waitid sees
            # SZOMB. Wait without reaping only through that proved transition.
            try:
                os.getpgid(process.pid)
            except ProcessLookupError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                time.sleep(min(0.01, remaining))
            else:
                return False
        listpids = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True).proc_listpids
        listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                            ctypes.c_void_p, ctypes.c_int]
        listpids.restype = ctypes.c_int
        # Two slots suffice to refuse any group with another member; a full
        # buffer is never accepted as proof of a lone child.
        pids = (ctypes.c_int * 2)()
        size = listpids(2, process.pid, pids, ctypes.sizeof(pids))  # PROC_PGRP_ONLY
        return size == ctypes.sizeof(ctypes.c_int) and pids[0] == process.pid
    except (OSError, AttributeError):
        return False



STOP_ALLOWANCE = 10


def read_clocks():
    return time.time(), time.monotonic()


def checked_clocks():
    wall, monotonic = read_clocks()
    if not math.isfinite(wall) or not math.isfinite(monotonic):
        raise ValueError('clock unavailable')
    return wall, monotonic


def signal_group(process, signum, deadline):
    # The leader is still waitable. Its PID pins the owned group until signalling
    # finishes; never use poll()/wait() to decide whether it needs a signal.
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass
    except PermissionError:
        if not darwin_lone_exited_child(process, deadline):
            raise


def stop_group(process, signum):
    deadline = time.monotonic() + STOP_ALLOWANCE
    try:
        if signum is not None:
            signal_group(process, signum, deadline)
            grace = time.monotonic() + 5
            while not child_exited(process.pid) and time.monotonic() < grace:
                time.sleep(.01)
    finally:
        # Also stop same-group descendants when their leader exits first. This
        # does not contain descendants which deliberately create another session.
        try:
            signal_group(process, signal.SIGKILL, deadline)
        finally:
            process.wait(timeout=max(0, deadline - time.monotonic()))
    return process.returncode


def run_bounded(command, cutoff, timeout, reserve):
    received = None
    previous = {}
    process = None
    outcome = 'complete'
    status = 1

    def cancelled(signum, _frame):
        nonlocal received
        if received is None:
            received = signum

    try:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.signal(signum, cancelled)
        if (not hasattr(os, 'waitid') and sys.platform != 'darwin') or signal.getsignal(signal.SIGCHLD) == signal.SIG_IGN:
            raise ValueError('child observation unavailable')
        # This check is after log reservation and immediately before spawn.
        wall, monotonic = checked_clocks()
        if wall + timeout + STOP_ALLOWANCE + reserve >= cutoff:
            raise ValueError('budget exhausted')
        if received is not None:
            outcome = 'cancelled'
        else:
            try:
                process = subprocess.Popen(command, start_new_session=True)
            except OSError:
                print('could not launch operator command', file=sys.stderr)
                return 127
            deadline = monotonic + timeout
            wall_deadline = cutoff - STOP_ALLOWANCE - reserve
            while True:
                if received is not None:
                    outcome = 'cancelled'
                    break
                wall, current = checked_clocks()
                if current >= deadline or wall >= wall_deadline:
                    outcome = 'timeout'
                    break
                if child_exited(process.pid):
                    break
                time.sleep(min(.02, deadline - current, wall_deadline - wall))
    except (OSError, ValueError, subprocess.SubprocessError):
        outcome = 'unavailable'
    finally:
        try:
            if process is not None:
                stopping_signal = received or (signal.SIGTERM if outcome != 'complete' else None)
                try:
                    status = stop_group(process, stopping_signal)
                except (OSError, ValueError, subprocess.SubprocessError):
                    outcome = 'unavailable'
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    if received is not None:
        print('Operator command cancelled; outcome requires verification.', file=sys.stderr)
        return -received
    if outcome == 'timeout':
        print('Operator command deadline exceeded; outcome requires verification.', file=sys.stderr)
        return 124
    if outcome == 'unavailable':
        print('Operator budget unavailable; command not launched.' if process is None else
              'Operator supervision failed; outcome requires verification.', file=sys.stderr)
        return 1
    return status


def exit_status(status):
    # Preserve the child's native signal status after our owned group is stopped.
    if status < 0:
        if -status not in (signal.SIGKILL, signal.SIGSTOP):
            signal.signal(-status, signal.SIG_DFL)
        os.kill(os.getpid(), -status)
    sys.exit(status)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--cutoff-unix", type=float, help="fixed absolute cutoff; requires timeout and reserve")
    parser.add_argument("--timeout", type=float, help="full foreground command cap in seconds")
    parser.add_argument("--reserve", type=float, help="downstream seconds, excluding the fixed ten-second stop allowance")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    budgets = (options.cutoff_unix, options.timeout, options.reserve)
    bounded = any(value is not None for value in budgets)
    if bounded and (any(value is None for value in budgets) or
                    not all(math.isfinite(value) for value in budgets) or
                    options.cutoff_unix <= 0 or options.timeout <= 0 or options.reserve < 0):
        parser.error("cutoff, positive timeout and nonnegative reserve must be supplied together and finite")
    command = options.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", options.label):
        parser.error("a command and a simple artifact label are required")
    directory = options.run_directory
    if not directory.is_dir():
        parser.error("run directory must already exist")
    captures = [directory / (options.label + suffix)
                for suffix in (".private", ".stderr", ".receipt.json")]
    logs = [directory / (options.label + suffix)
            for suffix in (".operator.stdout", ".operator.stderr")]
    if any(os.path.lexists(path) for path in captures + logs):
        parser.error("operator log or inner capture already exists; command not launched")
    os.umask(0o077)
    opened = []
    try:
        for path in logs:
            opened.append((path, path.open("xb", buffering=0)))
    except OSError:
        for _, stream in opened:
            stream.close()
        parser.error("could not reserve operator logs; command not launched")
    for descriptor, (_, stream) in zip((1, 2), opened):
        os.dup2(stream.fileno(), descriptor)
        stream.close()
    if bounded:
        return run_bounded(command, *budgets)
    # The default remains an exact exec: same PID, stdin, cwd and cancellation.
    try:
        os.execvp(command[0], command)
    except OSError:
        print("could not launch operator command", file=sys.stderr)
        return 127


if __name__ == "__main__":
    exit_status(main())
