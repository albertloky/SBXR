"""Exercise the real trace loop across a delayed child exit notification."""
import contextlib
import ctypes
import errno
import importlib.util
import io
import json
from pathlib import Path
import signal
import struct
import time
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("syscall_exit_race", Path(__file__).with_name("syscall-gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

ROOT, CHILD = 100, 201


def stop(sig, event=0):
    return (event << 16) | (sig << 8) | 0x7f


class TraceExitRaceTest(unittest.TestCase):
    def run_trace(self, *, failure=errno.ESRCH, delayed_status=0, fail_lookup=False, fail_root=False):
        events = [(ROOT, stop(signal.SIGTRAP, 1)), (CHILD, stop(signal.SIGSTOP)),
                  (CHILD, 0), (ROOT, stop(signal.SIGTRAP | 0x80))]
        killed, waits, restarts = [], [], []
        output = io.StringIO()

        class ProcPath:
            def __init__(self, value):
                self.value = str(value)
                self.name = self.value.rsplit("/", 1)[-1]

            def read_text(self):
                pid = int(self.value.split("/")[2])
                if pid == CHILD and fail_lookup:
                    raise FileNotFoundError(errno.ENOENT, "fixture lookup failed")
                return "Tgid:\t%d\n" % pid

            def iterdir(self):
                return iter([ProcPath("/proc/100/task/100")])

            def exists(self):
                return True

        def ptrace(request, pid, address, data):
            if request == 0x4201:
                ctypes.cast(data, ctypes.POINTER(ctypes.c_ulong))[0] = CHILD
            elif request == 0x420e:
                info = bytearray(128)
                info[0] = 1
                struct.pack_into("=I", info, 4, 0xc000003e)
                struct.pack_into("=Q", info, 24, 257)
                struct.pack_into("=6Q", info, 32, 0, 123, 0, 0, 0, 0)
                ctypes.memmove(data, bytes(info), len(info))
            elif request == 2:
                return int.from_bytes(b"/target\0", "little")
            elif request in (7, 24):
                restarts.append(pid)
                if pid == CHILD or fail_root and pid == ROOT:
                    ctypes.set_errno(failure)
                    return -1
            return 0

        def waitpid(pid, options):
            waits.append(pid)
            if killed:
                return killed.pop(0), 0
            if pid == CHILD:
                return (0, 0) if delayed_status == 0 else (CHILD, delayed_status)
            return events.pop(0)

        with patch.object(gate.ctypes, "CDLL", return_value=types.SimpleNamespace(ptrace=ptrace)), \
                patch.object(gate, "Path", ProcPath), \
                patch.object(gate.os, "waitpid", side_effect=waitpid), \
                patch.object(gate.os, "kill", side_effect=lambda pid, sig: killed.append(pid)), \
                patch.object(gate.sys, "stdin", io.StringIO("kill\n")), \
                patch.object(gate.select, "select", return_value=([True], [], [])), \
                contextlib.redirect_stdout(output):
            try:
                gate.trace(ROOT, time.monotonic() + 2, "/target", "before-open")
            except OSError as error:
                return error, output.getvalue(), waits, restarts
        return None, output.getvalue(), waits, restarts

    def test_known_stopped_child_waits_for_terminal_notification_before_next_hold(self):
        error, output, waits, _ = self.run_trace()
        self.assertIsNone(error)
        self.assertEqual(waits[:4], [-1, -1, CHILD, -1])
        records = [json.loads(line) for line in output.splitlines()]
        self.assertEqual([row["state"] for row in records], ["boundary-held", "interrupted"])
        self.assertEqual(records[0]["pid"], ROOT)
        self.assertEqual(records[0]["path"], "/target")
        self.assertEqual(waits[-1], -1)

    def test_permission_loss_never_becomes_a_delayed_exit(self):
        error, output, _, _ = self.run_trace(failure=errno.EPERM)
        self.assertEqual(error.errno, errno.EPERM)
        self.assertEqual(output, "")

    def test_nonterminal_child_notification_still_refuses(self):
        error, output, _, _ = self.run_trace(delayed_status=stop(signal.SIGTRAP))
        self.assertEqual(error.errno, errno.ESRCH)
        self.assertEqual(output, "")

    def test_proc_lookup_failure_is_not_a_failed_restart(self):
        error, output, _, restarts = self.run_trace(fail_lookup=True)
        self.assertEqual(error.errno, errno.ENOENT)
        self.assertNotIn(CHILD, restarts)
        self.assertEqual(output, "")

    def test_root_loss_before_a_known_stop_still_refuses(self):
        error, output, _, _ = self.run_trace(fail_root=True)
        self.assertEqual(error.errno, errno.ESRCH)
        self.assertEqual(output, "")


if __name__ == "__main__":
    unittest.main()
