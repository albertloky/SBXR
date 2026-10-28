#!/usr/bin/env python3
"""Bound one local SSH process; a timeout never proves remote completion."""
import os
import signal
import subprocess
import sys


def run(seconds, arguments):
    if not 0 < seconds <= 120 or not arguments:
        raise ValueError('invalid SSH deadline')
    process = subprocess.Popen(['ssh', *arguments], start_new_session=True)
    try:
        return process.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        print('SSH command deadline exceeded; remote outcome unknown.', file=sys.stderr)
        return 124
    finally:
        # Keep the leader unreaped until the owned group has been signalled.
        # Do not poll() before killpg: it could release PID/group ownership.
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


if __name__ == '__main__':
    try:
        def interrupted(signum, _frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        raise SystemExit(run(float(sys.argv[1]), sys.argv[2:]))
    except (IndexError, ValueError, OSError, subprocess.SubprocessError):
        print('SSH command refused; remote outcome unknown.', file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(130)
