"""Focused subprocess tests for the shared same-process menu driver."""
import ctypes
import datetime as dt
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
DRIVER = Path(__file__).resolve().parent / "v3-menu-session.py"
spec = importlib.util.spec_from_file_location("menu_driver", DRIVER)
menu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(menu)
FIXTURE = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
root=Path(os.environ["FIXTURE_ROOT"]); spec=json.loads(os.environ["FIXTURE_SPEC"])
for diagnostic in spec.get("diagnostics", []): print(diagnostic,file=sys.stderr,flush=True)
def event(value):
    with (root/"events.jsonl").open("a") as stream: stream.write(json.dumps(value)+"\n")
print("SBXR V3\nProxy status: Running\nCode: PROXY-INSTALLATION-STATUS-RUNNING")
print("2. Rotate Client Identity\n7. "+spec["label"]+"\n0. Exit",flush=True)
selected=sys.stdin.readline().strip(); event({"selected":selected})
if selected != "7": raise SystemExit(90)
if spec["kind"] in ("hang","leader-exit"):
    child=os.fork()
    if child == 0:
        if spec.get("escape"): os.setsid()
        (root/"descendant.pending").write_text(str(os.getpid()))
        (root/"descendant.pending").rename(root/"descendant.pid")
        while True: time.sleep(10)
    deadline=time.monotonic()+3
    while not (root/"descendant.pid").exists() and time.monotonic()<deadline: time.sleep(.01)
    if spec["kind"] == "leader-exit": os._exit(0)
    while True: time.sleep(10)
if spec.get("wizard"):
    print(spec.get("choice_prompt", "Connection [1] (h Help, c Cancel):"), flush=True)
    event({"connection":sys.stdin.readline().rstrip("\n")})
for code in spec.get("review_codes", []): print("Code: "+code,flush=True)
if spec.get("prompt_delay"): time.sleep(spec["prompt_delay"])
if spec.get("prompt"):
    print(spec["prompt"],flush=True); answer=sys.stdin.readline().rstrip("\n"); event({"answer":answer})
kind=spec["kind"]
if kind == "link":
    print("https://203.0.113.1:8443/s/"+"A"*43)
    print("Press Enter to preserve this link in terminal scrollback and return to the menu.",flush=True)
    event({"continue":sys.stdin.readline().rstrip("\n")})
if kind == "details":
    print("Detected fixture fact\nPress Enter to return to the menu.",flush=True)
    event({"continue":sys.stdin.readline().rstrip("\n")})
elif kind == "observe":
    print(spec["expected"],flush=True)
elif kind == "terminal":
    print("Code: "+spec["expected"],flush=True); raise SystemExit(0)
print("SBXR V3\nProxy status: Running\nCode: "+spec.get("actual",spec.get("expected","PROXY-INSTALLATION-STATUS-RUNNING")))
print("1. View details\n0. Exit",flush=True); event({"exit":sys.stdin.readline().strip()})
for diagnostic in spec.get("late_diagnostics", []): print(diagnostic,file=sys.stderr,flush=True)
'''

class SetupDiagnosticSelectionTest(unittest.TestCase):
    """Inert CLI-boundary fixtures: no product, signals, sockets or environment."""
    def test_setup_relays_closed_records_on_success_and_missing_label(self):
        record = dict(query="query-destination-dns", id=89, elapsed_us=15,
                      outcome="timeout", process=dict(location="loop", leader="not-exited",
                      stdout_eof=False, stderr_eof=False, stdout_bytes=0, stderr_bytes=0))
        for refused in (False, True):
            with self.subTest(refused=refused):
                sink = io.StringIO()
                observed = []
                def drive(args, cancelled, timing):
                    observed.append(timing)
                    # Exercise the actual spawn configuration without starting a
                    # child or entering signal/reaping cleanup.
                    with patch.object(menu.subprocess, "Popen") as spawn:
                        session = menu.MenuSession("inert-fixture", io.BytesIO(),
                                                   time.monotonic() + 90, timing=timing)
                        self.assertEqual(spawn.call_args.kwargs["stderr"], subprocess.PIPE)
                        self.assertIsInstance(session.stream.diagnostics, menu.NativeDiagnostics)
                    if timing:
                        timing.native(b"SECRET-SENTINEL /private/path")
                        timing.native(("SBXR_NATIVE_QUERY " + json.dumps({**record, "secret": "SECRET-SENTINEL"})).encode())
                        timing.native(("SBXR_NATIVE_QUERY " + json.dumps(record)).encode())
                    if refused:
                        guard = dict(guard="clock", cause="unsafe", id=90, elapsed_us=16)
                        raw = ("SBXR_NATIVE_READINESS " + json.dumps(guard) + "\n").encode()
                        session.stream.buffer = bytearray(b"SBXR V3\nCode: SOFTWARE-LIFECYCLE-STATUS-READY\n1. View details\n0. Exit\n")
                        with patch.object(menu, "readable", side_effect=[[session.process.stderr], []]), \
                             patch.object(menu.os, "read", return_value=raw):
                            try:
                                session.choose("Start setup")
                            except menu.ProtocolError as error:
                                session.process.stdin.write.assert_not_called()
                                error.code = session.stream.last_code
                                raise
                with patch.object(sys, "argv", [str(DRIVER), "action", "Start setup", "--timeout", "90"]), \
                     patch.object(sys, "platform", "darwin"), patch.object(sys, "stderr", sink), \
                     patch.object(menu.signal, "signal"), patch.object(menu, "drive", side_effect=drive):
                    self.assertEqual(menu.main(), int(refused))
                self.assertIsInstance(observed[0], menu.PhaseTiming)
                output = sink.getvalue()
                self.assertNotIn("SECRET-SENTINEL", output)
                self.assertNotIn("/private/path", output)
                rows = [json.loads(line.split(" ", 1)[1]) for line in output.splitlines()
                        if line.startswith("SBXR_NATIVE_QUERY ")]
                self.assertEqual(len(rows), 1)
                self.assertEqual({key: rows[0][key] for key in record}, record)
                self.assertEqual("phase=label-missing" in output, refused)
                guards = [json.loads(line.split(" ", 1)[1]) for line in output.splitlines()
                          if line.startswith("SBXR_NATIVE_READINESS ")]
                self.assertEqual(len(guards), int(refused))
                if refused:
                    self.assertEqual(guards[0]["guard"], "clock")
                    self.assertEqual(guards[0]["cause"], "unsafe")
                    self.assertLess(output.index("SBXR_NATIVE_READINESS "), output.index("SBXR_MENU_SESSION_REFUSED"))


class MenuSessionDeadlineTest(unittest.TestCase):
    def test_expired_session_never_starts_product(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "started"
            child = "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()"
            session = None
            try:
                with self.assertRaisesRegex(menu.ProtocolError, "deadline-before-start"):
                    session = menu.MenuSession([sys.executable, "-c", child, str(receipt)],
                                               io.BytesIO(), time.monotonic() - 1)
                self.assertFalse(receipt.exists())
            finally:
                if session is not None:
                    session.stop()
                    session.process.stdin.close()
                    session.process.stdout.close()

    def test_buffered_lines_do_not_bypass_expiry(self):
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb", buffering=0) as reader, os.fdopen(write_fd, "wb", buffering=0) as writer:
            writer.write(b"first\nCode: SUCCESS\n")
            stream = menu.LineStream(reader, io.BytesIO())
            self.assertEqual(stream.line(time.monotonic() + 5), "first")
            self.assertEqual(stream.buffer, b"Code: SUCCESS\n")
            with self.assertRaisesRegex(menu.ProtocolError, "output-deadline"):
                stream.line(time.monotonic() - 1)
            self.assertIsNone(stream.last_code)

    def test_transcript_flush_cannot_make_a_late_prompt_usable(self):
        # A real pipe/read/flush; only the monotonic clock advances at the
        # transcript boundary, without a timing-sensitive sleep.
        clock = [0.0]
        class Sink(io.BytesIO):
            def flush(self):
                clock[0] = 11.0
                super().flush()
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb", buffering=0) as reader, os.fdopen(write_fd, "wb", buffering=0) as writer:
            writer.write((menu.DETAILS_PROMPT + "\n").encode())
            journal = io.StringIO()
            stream = menu.LineStream(reader, Sink(), timing=menu.PhaseTiming(journal, 10.0))
            with patch.object(menu.time, "monotonic", side_effect=lambda: clock[0]):
                with self.assertRaisesRegex(menu.ProtocolError, "output-deadline"):
                    stream.line(10.0)
            stream.timing.close()
            self.assertIn('"event": "prompt-received"', journal.getvalue())
            self.assertNotIn('"event": "prompt-accepted"', journal.getvalue())

    def test_details_receipt_before_at_after_deadline_keeps_timing_and_refuses_late_prompt(self):
        for received in (9.0, 10.0, 11.0):
            with self.subTest(received=received):
                clock = [0.0]
                journal = io.StringIO()
                read_fd, write_fd = os.pipe()
                with os.fdopen(read_fd, "rb", buffering=0) as reader, os.fdopen(write_fd, "wb", buffering=0) as writer:
                    writer.write((menu.DETAILS_PROMPT + "\n").encode())
                    native_read = os.read
                    def read(fd, count):
                        block = native_read(fd, count)
                        clock[0] = received
                        return block
                    stream = menu.LineStream(reader, io.BytesIO(), timing=menu.PhaseTiming(journal, 10.0))
                    with patch.object(menu.time, "monotonic", side_effect=lambda: clock[0]), \
                            patch.object(menu.os, "read", side_effect=read):
                        if received < 10:
                            self.assertEqual(stream.line(10.0), menu.DETAILS_PROMPT)
                        else:
                            with self.assertRaisesRegex(menu.ProtocolError, "output-deadline"):
                                stream.line(10.0)
                stream.timing.close()
                events = [json.loads(line.removeprefix("SBXR_MENU_PHASE ")) for line in journal.getvalue().splitlines()]
                self.assertEqual([e["event"] for e in events], ["first-byte-received", "first-line-received", "prompt-received"] +
                                 (["prompt-accepted"] if received < 10 else []))
                self.assertEqual(events[0]["monotonic"], received)

    def test_details_timing_distinguishes_sent_continuation_from_return_wait_timeout(self):
        clock = [0.0]
        journal = io.StringIO()
        timing = menu.PhaseTiming(journal, 10.0)
        child = ("import sys; print('" + menu.DETAILS_PROMPT + "',flush=True); "
                 "sys.stdin.readline(); sys.stdin.read()")
        session = None
        try:
            with patch.object(menu.time, "monotonic", side_effect=lambda: clock[0]):
                session = menu.MenuSession([sys.executable, "-c", child], io.BytesIO(), 10.0, timing=timing)
                session.wait_unconfirmed_marker(menu.DETAILS_PROMPT)
                session.write("\n")
                clock[0] = 11.0
                with self.assertRaisesRegex(menu.ProtocolError, "output-deadline"):
                    session.return_to_menu()
            timing.close()
            events = [json.loads(line.removeprefix("SBXR_MENU_PHASE ")) for line in journal.getvalue().splitlines()]
            self.assertEqual([e["event"] for e in events], ["spawn-attempt", "spawn-complete", "first-byte-received", "first-line-received", "prompt-received", "prompt-accepted",
                             "input-attempt", "input-sent", "return-wait"])
            self.assertEqual(events[7]["class"], "continuation")
            self.assertLess(events[7]["monotonic"], events[8]["monotonic"])
        finally:
            if session is not None:
                session.stop()
                self.assertTrue(session.cleaned)
                self.assertIsNotNone(session.process.returncode)
                session.timing.close()
                session.process.stdin.close()
                session.process.stdout.close()

    def test_delayed_return_frame_cannot_bypass_deadline_after_continuation(self):
        for received in (9.0, 10.0, 11.0):
            with self.subTest(received=received):
                clock = [0.0]
                journal, transcript = io.StringIO(), io.BytesIO()
                child = ("import sys; print('" + menu.DETAILS_PROMPT + "',flush=True); "
                         "sys.stdin.readline(); print('SBXR V3\\n0. Exit',flush=True); sys.stdin.read()")
                session = None
                native_read = os.read
                def read(fd, count):
                    block = native_read(fd, count)
                    if b"SBXR V3" in block:
                        clock[0] = received
                    return block
                try:
                    with patch.object(menu.time, "monotonic", side_effect=lambda: clock[0]), \
                            patch.object(menu.os, "read", side_effect=read):
                        session = menu.MenuSession([sys.executable, "-c", child], transcript, 10.0,
                                                   timing=menu.PhaseTiming(journal, 10.0))
                        session.wait_unconfirmed_marker(menu.DETAILS_PROMPT)
                        session.write("\n")
                        if received < 10:
                            session.return_to_menu()
                        else:
                            with self.assertRaisesRegex(menu.ProtocolError, "output-deadline"):
                                session.return_to_menu()
                    session.timing.close()
                    events = [json.loads(line.removeprefix("SBXR_MENU_PHASE ")) for line in journal.getvalue().splitlines()]
                    sent = [e["class"] for e in events if e["event"] == "input-sent"]
                    self.assertEqual(sent, ["continuation"] + (["exit"] if received < 10 else []))
                    self.assertIn(b"SBXR V3", transcript.getvalue())
                    self.assertEqual(any(e["event"] == "return-frame" for e in events), received < 10)
                finally:
                    if session is not None:
                        session.stop()
                        self.assertTrue(session.cleaned)
                        session.timing.close()
                        session.process.stdin.close()
                        session.process.stdout.close()

    def test_protected_cleanup_services_stderr_until_the_wrapper_finishes(self):
        with tempfile.TemporaryDirectory() as temporary:
            done=Path(temporary)/"done"
            entered=Path(temporary)/"entered"
            child=("import os,signal,sys,pathlib\n"
                   "def finish(*_):\n"
                   " pathlib.Path(sys.argv[2]).touch()\n"
                   " written=os.write(2,b'X'*131072)\n"
                   " pathlib.Path(sys.argv[1]).write_text(str(written))\n"
                   " sys.exit(0)\n"
                   "signal.signal(signal.SIGUSR1,finish)\nprint('READY',flush=True)\nsys.stdin.read()")
            journal=io.StringIO()
            session=menu.MenuSession([sys.executable,"-c",child,str(done),str(entered)],io.BytesIO(),time.monotonic()+5,
                                     timing=menu.PhaseTiming(journal,time.monotonic()+5))
            try:
                self.assertEqual(session.stream.line(session.deadline),"READY")
                # Exercise the post-admission cleanup handshake on this OS.
                session.protected_wrapper=True
                session.stop()
                evidence = dict(returncode=session.returncode,
                                handler_entered=entered.exists(),
                                stderr_bytes=session.stream.diagnostics.total,
                                stderr_exceeded=session.stream.diagnostics.exceeded)
                self.assertTrue(done.exists(),
                                f"stderr must not block lawful wrapper cleanup: {evidence}")
                self.assertEqual(done.read_text(), "131072", evidence)
                self.assertEqual(session.stream.diagnostics.total, 131072, evidence)
                self.assertEqual(session.returncode, 0, evidence)
                self.assertTrue(session.cleaned)
            finally:
                if session.process.returncode is None:session.stop()
                session.timing.close()
                session.process.stdin.close();session.process.stdout.close();session.process.stderr.close()

    def test_cleanup_does_not_relay_after_a_diagnostic_sink_failure(self):
        class Sink(io.StringIO):
            failed=False
            def write(self,value):
                if self.failed:raise OSError("fixture diagnostic sink failed")
                return super().write(value)
        with tempfile.TemporaryDirectory() as temporary:
            ready=Path(temporary)/"ready"
            child=("import json,pathlib,sys\nprint('READY',flush=True)\nsys.stdin.readline()\n"
                   "print('SBXR_NATIVE_PHASE '+json.dumps(dict(phase='snapshot',event='end',id=1,elapsed_us=2)),file=sys.stderr,flush=True)\n"
                   "pathlib.Path(sys.argv[1]).write_text('ready')\nsys.stdin.read()")
            sink=Sink();session=menu.MenuSession([sys.executable,"-c",child,str(ready)],io.BytesIO(),time.monotonic()+5,
                                               timing=menu.PhaseTiming(sink,time.monotonic()+5))
            try:
                self.assertEqual(session.stream.line(session.deadline),"READY")
                session.process.stdin.write(b"go\n");session.process.stdin.flush()
                until=time.monotonic()+3
                while not ready.exists():
                    self.assertLess(time.monotonic(),until);time.sleep(.01)
                sink.failed=True
                session.stop()
                self.assertTrue(session.cleaned)
                self.assertTrue(session.process.stderr.closed)
            finally:
                if session.process.returncode is None:session.stop()
                session.timing.close()
                session.process.stdin.close();session.process.stdout.close();session.process.stderr.close()

    def test_descriptor_duplication_failure_never_falls_back_to_buffered_stderr(self):
        reads, writes = os.pipe()
        buffered_writes = []
        class Sink:
            def fileno(self):
                return writes
            def write(self, value):
                buffered_writes.append(value)
                raise OSError("buffered fallback would block at shutdown")
        try:
            with patch.object(menu.os,"dup",side_effect=OSError(errno.EMFILE,"fixture fd exhaustion")):
                timing = menu.PhaseTiming(Sink(),time.monotonic()+1)
            timing("driver-start")
            timing.close()
            self.assertEqual(buffered_writes,[])
            self.assertTrue(os.get_blocking(writes),"inherited descriptor flags must remain unchanged")
        finally:
            os.close(reads)
            os.close(writes)

    def test_spawn_diagnostic_sink_failure_still_allows_full_protected_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready, done = Path(temporary)/"ready", Path(temporary)/"done"
            failed = threading.Event()
            class Sink(io.StringIO):
                def write(self, value):
                    if "spawn-complete" in value:
                        failed.set()
                        raise OSError("fixture capture unavailable")
                    return super().write(value)
            child = ("import os,signal,sys,pathlib\n"
                     "def finish(*_):\n os.write(2,b'RAW-SECRET /private/path'*8192);pathlib.Path(sys.argv[2]).touch();sys.exit(0)\n"
                     "signal.signal(signal.SIGUSR1,finish)\npathlib.Path(sys.argv[1]).touch()\nprint('READY',flush=True)\nsys.stdin.read()")
            sink = Sink()
            timing = menu.PhaseTiming(sink,time.monotonic()+5)
            session = menu.MenuSession([sys.executable,"-c",child,str(ready),str(done)],
                                       io.BytesIO(),timing.deadline,timing=timing)
            try:
                self.assertEqual(session.stream.line(session.deadline),"READY")
                self.assertTrue(failed.wait(timeout=2),"exercise a real failed relay write")
                session.protected_wrapper = True
                started = time.monotonic()
                self.assertEqual(session.stop(),0)
                self.assertLess(time.monotonic()-started,2)
                self.assertTrue(done.exists())
                self.assertTrue(session.cleaned)
                self.assertTrue(session.process.stderr.closed)
                self.assertNotIn("RAW-SECRET",sink.getvalue())
                self.assertNotIn("/private/path",sink.getvalue())
            finally:
                if session.process.returncode is None:
                    session.stop()
                timing.close()
                session.process.stdin.close()
                session.process.stdout.close()
                session.process.stderr.close()

    def test_fallback_finish_services_late_stderr_before_waiting_for_exit(self):
        journal=io.StringIO()
        child="import os,sys;print('READY',flush=True);sys.stdin.readline();os.write(2,b'X'*2097152)"
        session=menu.MenuSession([sys.executable,"-c",child],io.BytesIO(),time.monotonic()+1,
                                 timing=menu.PhaseTiming(journal,time.monotonic()+1))
        try:
            self.assertEqual(session.stream.line(session.deadline),"READY")
            session.write("0\n")
            # Force the retained portable wait branch; no platform settings change.
            native_os=menu.os
            class WithoutWaitid:
                def __getattr__(self,name):
                    if name=="waitid":raise AttributeError(name)
                    return getattr(native_os,name)
            with patch.object(menu.sys,"platform","fixture"),patch.object(menu,"os",WithoutWaitid()):
                session.finish()
            self.assertTrue(session.cleaned)
        finally:
            if session.process.returncode is None:session.stop()
            session.timing.close()
            session.process.stdin.close();session.process.stdout.close();session.process.stderr.close()

    def test_constructor_failure_still_completes_chatty_protected_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready, done = Path(temporary)/"ready", Path(temporary)/"done"
            child = ("import os,signal,sys,pathlib\n"
                     "def finish(*_):\n os.write(2,b'X'*131072);pathlib.Path(sys.argv[2]).write_text('done');sys.exit(0)\n"
                     "signal.signal(signal.SIGUSR1,finish)\npathlib.Path(sys.argv[1]).touch()\nsys.stdin.read()")
            class FailingTiming(menu.PhaseTiming):
                def __call__(self, event, *args):
                    if event == "spawn-complete":
                        until = time.monotonic()+3
                        while not ready.exists():
                            if time.monotonic() >= until:
                                raise AssertionError("fixture did not install its cleanup handler")
                            time.sleep(.01)
                        raise OSError("fixture post-spawn diagnostics failed")
                    super().__call__(event, *args)
            sessions = []
            class Session(menu.MenuSession):
                def stop(self):
                    self.protected_wrapper = True
                    sessions.append(self)
                    return super().stop()
            timing = FailingTiming(io.StringIO(), time.monotonic()+5)
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(OSError, "post-spawn diagnostics failed"):
                    Session([sys.executable,"-c",child,str(ready),str(done)],
                            io.BytesIO(),timing.deadline,timing=timing)
            finally:
                timing.close()
            self.assertTrue(done.exists(), "constructor failure must not strand wrapper cleanup on stderr")
            self.assertLess(time.monotonic()-started, 2)
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0].process.returncode, 0)
            self.assertTrue(sessions[0].cleaned)
            self.assertTrue(all(pipe.closed for pipe in (sessions[0].process.stdin,
                                                        sessions[0].process.stdout,sessions[0].process.stderr)))

    def test_high_descriptor_pipe_survives_read_and_constructor_failure_cleanup(self):
        # Only the descriptor number is simulated. Readiness, reads, child
        # ownership, the 128KiB cleanup write and reaping use real pipes/processes.
        for failure in (False, True):
            with self.subTest(constructor_failure=failure), tempfile.TemporaryDirectory() as temporary:
                ready, done = Path(temporary)/"ready", Path(temporary)/"done"
                child = ("import os,signal,sys,pathlib\n"
                         "def finish(*_):\n os.write(2,b'X'*131072);pathlib.Path(sys.argv[2]).touch();sys.exit(0)\n"
                         "signal.signal(signal.SIGUSR1,finish)\npathlib.Path(sys.argv[1]).touch()\nprint('READY',flush=True)\nsys.stdin.read()")
                pipes, sessions = [], []
                real_popen, real_read, real_poll = menu.subprocess.Popen, os.read, select.poll
                class HighPipe:
                    def __init__(self, stream):
                        self.stream = stream
                    def fileno(self):
                        return 1024
                    def __getattr__(self, name):
                        return getattr(self.stream,name)
                class Poll:
                    def __init__(self):
                        self.inner, self.aliases = real_poll(), {}
                    def register(self, stream, events):
                        fd = stream if isinstance(stream,int) else stream.fileno()
                        real_fd = pipes[0].stream.fileno() if fd == 1024 else fd
                        self.aliases[real_fd] = fd
                        self.inner.register(real_fd,events)
                    def poll(self, timeout):
                        return [(self.aliases[fd],events) for fd,events in self.inner.poll(timeout)]
                def start(*args, **kwargs):
                    process = real_popen(*args,**kwargs)
                    process.stderr = HighPipe(process.stderr)
                    pipes.append(process.stderr)
                    return process
                def read(fd, count):
                    return real_read(pipes[0].stream.fileno() if fd == 1024 else fd,count)
                class Timing(menu.PhaseTiming):
                    def __call__(self, event, *args):
                        if failure and event == "spawn-complete":
                            until = time.monotonic()+3
                            while not ready.exists():
                                if time.monotonic() >= until:
                                    raise AssertionError("fixture cleanup handler not ready")
                                time.sleep(.01)
                            raise OSError("original constructor diagnostic error")
                        super().__call__(event,*args)
                class Session(menu.MenuSession):
                    def stop(self):
                        self.protected_wrapper = True
                        if self not in sessions:
                            sessions.append(self)
                        return super().stop()
                timing, session = Timing(io.StringIO(),time.monotonic()+5), None
                try:
                    with patch.object(menu.subprocess,"Popen",side_effect=start), \
                            patch.object(menu.os,"read",side_effect=read), \
                            patch.object(menu.select,"poll",Poll):
                        if failure:
                            with self.assertRaisesRegex(OSError,"original constructor diagnostic error"):
                                Session([sys.executable,"-c",child,str(ready),str(done)],
                                        io.BytesIO(),timing.deadline,timing=timing)
                        else:
                            session = Session([sys.executable,"-c",child,str(ready),str(done)],
                                              io.BytesIO(),timing.deadline,timing=timing)
                            self.assertEqual(session.stream.line(session.deadline),"READY")
                            session.stop()
                    self.assertTrue(done.exists(),"high descriptors must not strand protected cleanup")
                    self.assertEqual(len(sessions),1)
                    self.assertTrue(sessions[0].cleaned)
                    self.assertEqual(sessions[0].process.returncode,0)
                    self.assertTrue(sessions[0].process.stderr.closed)
                finally:
                    timing.close()
                    if session is not None and session not in sessions:
                        sessions.append(session)
                    for owned in sessions:
                        if not owned.cleaned:
                            # Dispose only this test's newly owned child if the
                            # assertion exposes the original broken collector.
                            owned.stream.diagnostics = None
                            owned.protected_wrapper = False
                            menu.MenuSession.stop(owned)
                        for pipe in (owned.process.stdin,owned.process.stdout,owned.process.stderr):
                            pipe.close()

    def test_diagnostic_readiness_errors_cannot_preempt_protected_cleanup_or_reap(self):
        for persistent in (False, True):
            with self.subTest(persistent=persistent), tempfile.TemporaryDirectory() as temporary:
                done = Path(temporary)/"done"
                child = ("import os,signal,sys,pathlib\n"
                         "def finish(*_):\n os.write(2,b'X'*131072);pathlib.Path(sys.argv[1]).touch();sys.exit(0)\n"
                         "signal.signal(signal.SIGUSR1,finish)\nprint('READY',flush=True)\nsys.stdin.read()")
                timing = menu.PhaseTiming(io.StringIO(),time.monotonic()+5)
                session = menu.MenuSession([sys.executable,"-c",child,str(done)],
                                           io.BytesIO(),timing.deadline,timing=timing)
                try:
                    self.assertEqual(session.stream.line(session.deadline),"READY")
                    session.protected_wrapper = not persistent
                    original, calls = session.stream.diagnostics.drain, []
                    def fail(*args, **kwargs):
                        calls.append(1)
                        if persistent or len(calls) == 1:
                            raise ValueError("fixture diagnostic readiness failure")
                        return original(*args,**kwargs)
                    with patch.object(session.stream.diagnostics,"drain",side_effect=fail):
                        session.stop()
                    self.assertTrue(session.cleaned)
                    self.assertEqual(session.process.returncode,-signal.SIGKILL if persistent else 0)
                    self.assertTrue(session.process.stderr.closed)
                    if not persistent:
                        self.assertTrue(done.exists(),"retry transient diagnostic readiness failures")
                finally:
                    if not session.cleaned:
                        session.protected_wrapper = False
                        session.stop()
                    timing.close()
                    for pipe in (session.process.stdin,session.process.stdout,session.process.stderr):
                        pipe.close()

    def test_raw_stderr_bound_cancels_and_reaps_without_relaying_unterminated_data(self):
        journal = io.StringIO()
        session = menu.MenuSession([sys.executable, "-c", "import sys; sys.stderr.write('SECRET-SENTINEL /private/path'*100);sys.stderr.flush();sys.stdin.read()"],
                                   io.BytesIO(), time.monotonic()+5,
                                   timing=menu.PhaseTiming(journal,time.monotonic()+5))
        try:
            with patch.object(menu, "MAX_OUTPUT", 256):
                with self.assertRaisesRegex(menu.ProtocolError, "diagnostic-bound"):
                    session.stream.line(session.deadline)
        finally:
            session.stop()
            self.assertTrue(session.cleaned)
            self.assertTrue(session.process.stderr.closed)
            session.timing.close()
            session.process.stdin.close();session.process.stdout.close()
        self.assertNotIn("SECRET-SENTINEL",journal.getvalue())
        self.assertNotIn("/private/path",journal.getvalue())

    def test_details_timing_does_not_record_input_payload(self):
        journal = io.StringIO()
        session = menu.MenuSession([sys.executable, "-c", "import sys; sys.stdin.read()"],
                                   io.BytesIO(), time.monotonic() + 5,
                                   timing=menu.PhaseTiming(journal, time.monotonic() + 5))
        try:
            session.write("SECRET-SENTINEL /private/path\n")
            session.timing.close()
            self.assertNotIn("SECRET-SENTINEL", journal.getvalue())
            self.assertNotIn("/private/path", journal.getvalue())
            self.assertEqual([json.loads(line.removeprefix("SBXR_MENU_PHASE "))["class"]
                              for line in journal.getvalue().splitlines()], ["none", "none", "other", "other"])
        finally:
            session.stop()
            session.process.stdin.close()
            session.process.stdout.close()

    def test_expiry_between_review_and_input_never_sends_confirmation(self):
        for label, answer in (("Update", "y\n"), ("Recover", "y\n"),
                              ("Complete removal", "REMOVE SBXR\n")):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                receipt = Path(temporary) / "input"
                prompt = menu.REMOVAL_PROMPT if label == "Complete removal" else menu.PROMPTS[label]
                # Use an actual child and stdin pipe, not a mocked write.
                child = ("import pathlib,sys; print(sys.argv[1],flush=True); "
                         "pathlib.Path(sys.argv[2]).write_text(sys.stdin.read()); print('done',flush=True)")
                session = menu.MenuSession([sys.executable, "-c", child, prompt, str(receipt)],
                                           io.BytesIO(), time.monotonic() + 5)
                try:
                    session.expect_prompt(prompt)
                    session.deadline = time.monotonic() - 1
                    try:
                        with self.assertRaisesRegex(menu.ProtocolError, "input-deadline"):
                            session.write(answer)
                    finally:
                        session.process.stdin.close()
                        self.assertTrue(select.select([session.process.stdout], [], [], 5)[0])
                        self.assertEqual(session.process.stdout.readline(), b"done\n")
                    self.assertEqual(receipt.read_text(), "")
                finally:
                    session.stop()
                    session.process.stdout.close()


class MenuSessionCleanupTest(unittest.TestCase):
    def session(self, child="import sys; sys.stdin.read()"):
        session = menu.MenuSession([sys.executable, "-c", child], io.BytesIO(),
                                   time.monotonic() + 5)
        self.addCleanup(self.dispose, session)
        return session

    def dispose(self, session):
        if session.process.returncode is None:
            try:
                os.killpg(session.process.pid, signal.SIGKILL)
            except PermissionError:
                # The original macOS defect leaves a lone zombie to reap.
                session.process.kill()
            except ProcessLookupError:
                pass
            session.process.wait(timeout=5)
        session.process.stdin.close()
        session.process.stdout.close()

    def await_exit(self, session):
        # EOF can precede exit; observe the kernel without reaping the leader.
        if not hasattr(os, "waitid") and sys.platform != "darwin":
            self.skipTest("non-reaping exit observation requires Linux or macOS")
        deadline = time.monotonic() + 3
        while not menu.child_exited(session.process.pid):
            self.assertLess(time.monotonic(), deadline, "fixture leader did not exit")
            time.sleep(.01)

    def test_exited_owned_child_cleanup_preserves_status_and_is_repeatable(self):
        for operation in ("stop", "finish"):
            for status in (0, 17):
                with self.subTest(operation=operation, status=status):
                    session = self.session("import sys; sys.stdin.read(); sys.exit(" + str(status) + ")")
                    session.process.stdin.close()
                    if sys.platform == "darwin":
                        deadline = time.monotonic() + 3
                        # Exercise the early exit boundary that preceded EPERM.
                        while True:
                            try:
                                os.getpgid(session.process.pid)
                            except ProcessLookupError:
                                break
                            self.assertLess(time.monotonic(), deadline, "fixture leader did not start exiting")
                    else:
                        self.await_exit(session)
                    if operation == "finish" and status:
                        with self.assertRaisesRegex(menu.ProtocolError, "process-failed"):
                            session.finish()
                    else:
                        getattr(session, operation)()
                    self.assertEqual(session.stop(), status)
                    self.assertEqual(session.process.returncode, status)
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(session.process.pid, os.WNOHANG)

    def test_reaped_leader_never_signals_a_potentially_reused_group(self):
        for reaper in ("popen", "external"):
            with self.subTest(reaper=reaper):
                session = self.session()
                session.process.stdin.close()
                if reaper == "popen":
                    self.assertEqual(session.process.wait(timeout=3), 0)
                else:
                    self.assertEqual(os.waitpid(session.process.pid, 0)[1], 0)
                try:
                    with patch.object(menu.os, "killpg", side_effect=AssertionError("reaped group signalled")):
                        with self.assertRaisesRegex(menu.ProtocolError, "process-ownership"):
                            session.stop()
                finally:
                    # Mark an externally reaped fixture even after a red assertion,
                    # so disposal cannot signal a potentially recycled group.
                    session.process.wait(timeout=3)

    def test_live_child_permission_error_is_preserved(self):
        session = self.session()
        denied = PermissionError(errno.EPERM, "fixture signal denial")
        with patch.object(menu.os, "killpg", side_effect=denied), \
                patch.object(menu.time, "sleep", side_effect=AssertionError("live denial delayed")):
            with self.assertRaises(PermissionError) as caught:
                session.stop()
        self.assertIs(caught.exception, denied)
        self.assertFalse(session.cleaned)
        self.assertIsNone(session.process.returncode)
        self.assertEqual(session.stop(), -signal.SIGKILL)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin exit transition")
    def test_unproved_exit_transition_expires_with_original_permission_error(self):
        session = self.session()
        denied = PermissionError(errno.EPERM, "fixture signal denial")
        with patch.object(menu.os, "killpg", side_effect=denied), \
                patch.object(menu.os, "getpgid", side_effect=ProcessLookupError(errno.ESRCH, "fixture lookup")), \
                patch.object(menu.time, "monotonic", side_effect=[100, 105]), \
                patch.object(menu.time, "sleep", side_effect=AssertionError("expired cleanup delayed")):
            with self.assertRaises(PermissionError) as caught:
                session.stop()
        self.assertIs(caught.exception, denied)
        self.assertFalse(session.cleaned)
        self.assertIsNone(session.process.returncode)
        self.assertEqual(session.stop(), -signal.SIGKILL)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin exit transition")
    def test_reaping_during_exit_observation_preserves_original_permission_error(self):
        session = self.session()
        session.process.stdin.close()
        self.await_exit(session)
        denied = PermissionError(errno.EPERM, "fixture signal denial")
        native_exit = menu.child_exited
        observations = []
        reaped = []
        def observe(pid):
            observations.append(pid)
            return False if len(observations) == 2 else native_exit(pid)
        def reap(_):
            reaped.append(os.waitpid(session.process.pid, 0))
        try:
            with patch.object(menu.os, "killpg", side_effect=denied), \
                    patch.object(menu, "child_exited", side_effect=observe), \
                    patch.object(menu.time, "sleep", side_effect=reap):
                with self.assertRaises(PermissionError) as caught:
                    session.stop()
            self.assertIs(caught.exception, denied)
            self.assertFalse(session.cleaned)
            self.assertEqual(reaped, [(session.process.pid, 0)])
        finally:
            if reaped:
                # Never let disposal signal a PID whose wait ownership was lost.
                session.process.wait(timeout=3)

    def descendant_session(self):
        child = ("import os,signal,sys,time\n"
                 "sys.stdin.read()\n"
                 "if os.fork() == 0:\n"
                 " signal.alarm(5)\n"
                 " print(os.getpid(),flush=True)\n"
                 " while True: time.sleep(.01)\n"
                 "os._exit(0)\n")
        session = self.session(child)
        session.process.stdin.close()
        self.assertTrue(select.select([session.process.stdout], [], [], 3)[0])
        descendant = int(session.process.stdout.readline())
        self.await_exit(session)
        return session, descendant

    def assert_descendant_stopped(self, pid):
        deadline = time.monotonic() + 3
        while True:
            try:
                os.getpgid(pid)
                if sys.platform.startswith("linux"):
                    # An orphan zombie may await init; it is no longer running.
                    if Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].startswith("Z "):
                        return
            except (ProcessLookupError, FileNotFoundError):
                return
            self.assertLess(time.monotonic(), deadline, "fixture descendant still running")
            time.sleep(.01)

    def test_exited_leader_still_terminates_same_group_descendant(self):
        for operation in ("stop", "finish"):
            with self.subTest(operation=operation):
                session, descendant = self.descendant_session()
                getattr(session, operation)()
                self.assertEqual(session.stop(), 0)
                self.assert_descendant_stopped(descendant)

    def test_exited_owner_with_descendant_holding_pipe_is_reported_promptly(self):
        session, descendant = self.descendant_session()
        with self.assertRaisesRegex(menu.ProtocolError, "owner-exited"):
            session.stream.line(time.monotonic() + 3)
        self.assertEqual(session.stop(), 0)
        self.assert_descendant_stopped(descendant)

    def test_exited_leader_does_not_hide_live_descendant_permission_error(self):
        session, descendant = self.descendant_session()
        denied = PermissionError(errno.EPERM, "fixture descendant signal denial")
        with patch.object(menu.os, "killpg", side_effect=denied):
            with self.assertRaises(PermissionError) as caught:
                session.stop()
        self.assertIs(caught.exception, denied)
        self.assertFalse(session.cleaned)
        self.assertEqual(os.getpgid(descendant), session.process.pid)
        self.assertEqual(session.stop(), 0)
        self.assert_descendant_stopped(descendant)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin group inventory boundary")
    def test_unproved_group_inventory_preserves_original_permission_error(self):
        native_cdll = ctypes.CDLL
        for size, member in ((-1, "leader"), (0, "leader"), (3, "leader"),
                             (8, "leader"), (4, "other"), (None, "leader")):
            with self.subTest(size=size, member=member):
                session = self.session()
                session.process.stdin.close()
                self.await_exit(session)
                denied = PermissionError(errno.EPERM, "fixture signal denial")
                def listpids(kind, group, buffer, capacity):
                    if size is None:
                        raise PermissionError(errno.EPERM, "fixture inventory denial")
                    buffer[0] = group if member == "leader" else os.getpid()
                    return size
                class Library:
                    proc_listpids = staticmethod(listpids)
                def library(path, **options):
                    return Library() if path == "/usr/lib/libproc.dylib" else native_cdll(path, **options)
                with patch.object(menu.ctypes, "CDLL", side_effect=library), \
                        patch.object(menu.os, "killpg", side_effect=denied):
                    with self.assertRaises(PermissionError) as caught:
                        session.stop()
                self.assertIs(caught.exception, denied)
                self.assertFalse(session.cleaned)
                self.assertEqual(session.stop(), 0)


class MenuSessionDriverTest(unittest.TestCase):
    def invoke(self,spec,*arguments,timeout=5):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); executable=root/"sbxr"
            executable.write_text(FIXTURE); executable.chmod(0o700)
            env=dict(os.environ,FIXTURE_ROOT=temporary,FIXTURE_SPEC=json.dumps(spec))
            result=subprocess.run([sys.executable,str(DRIVER),*arguments,"--executable",str(executable),"--timeout",str(timeout)],
                                  env=env,text=True,capture_output=True,timeout=10)
            events=[json.loads(line) for line in (root/"events.jsonl").read_text().splitlines()] if (root/"events.jsonl").exists() else []
            return result,events

    def test_unread_diagnostic_sink_cannot_block_success_or_deadline_cleanup(self):
        for kind in ("details", "hang"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                executable = root/"sbxr"
                executable.write_text(FIXTURE)
                executable.chmod(0o700)
                row = "SBXR_NATIVE_PHASE " + json.dumps(dict(phase="snapshot",event="begin",id=1,elapsed_us=1))
                spec = {"label":"View details", "kind":kind, "diagnostics":[row]*1000}
                env = dict(os.environ,FIXTURE_ROOT=temporary,FIXTURE_SPEC=json.dumps(spec))
                process = subprocess.Popen([sys.executable,"-B",str(DRIVER),"details","View details",
                                            "--executable",str(executable),"--timeout","1"],
                                           env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                try:
                    # Deliberately do not read stderr until the driver exits.
                    # A blocked relay has no exception to catch and cannot enforce its deadline.
                    process.wait(timeout=2.5)
                    stderr = process.stderr.read().decode()
                    self.assertEqual(process.returncode, 0 if kind == "details" else 1, stderr)
                    events = [json.loads(line) for line in (root/"events.jsonl").read_text().splitlines()]
                    self.assertEqual(events[0], {"selected":"7"})
                    if kind == "details":
                        self.assertEqual(events, [{"selected":"7"},{"continue":""},{"exit":"0"}])
                    else:
                        descendant = int((root/"descendant.pid").read_text())
                        until = time.monotonic()+2
                        while True:
                            try:
                                os.kill(descendant,0)
                                if sys.platform.startswith("linux") and Path(f"/proc/{descendant}/stat").read_text().rsplit(") ",1)[1].startswith("Z "):
                                    break
                            except (ProcessLookupError,FileNotFoundError):
                                break
                            self.assertLess(time.monotonic(),until,"driver left its fixture descendant running")
                            time.sleep(.01)
                finally:
                    if process.poll() is None:
                        # Release the sink before asking the driver to clean up its own child.
                        process.terminate()
                        try:
                            process.communicate(timeout=7)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.communicate(timeout=3)
                    process.stderr.close()

    def test_details_distinguishes_startup_receipt_and_menu_and_relays_only_fixed_native_events(self):
        begin = {"phase": "query-active", "event": "begin", "id": 1, "elapsed_us": 3}
        end = {**begin, "event": "end", "elapsed_us": 9}
        spec = {"label": "View details", "kind": "details", "diagnostics": [
            "SECRET-SENTINEL /private/path",
            "SECRET-SENTINEL" * 100,
            "SBXR_NATIVE_PHASE " + json.dumps({**begin, "phase": "/private/path"}),
            "SBXR_NATIVE_PHASE " + json.dumps({**begin, "secret": "SECRET-SENTINEL"}),
            'SBXR_NATIVE_PHASE {"phase":"query-active","event":"begin","id":1,"id":2,"elapsed_us":3}',
            "SBXR_NATIVE_PHASE " + json.dumps({**begin, "id": True}),
            "SBXR_NATIVE_PHASE " + json.dumps(begin),
        ], "late_diagnostics": ["SBXR_NATIVE_PHASE " + json.dumps(end)]}
        result, inputs = self.invoke(spec, "details", "View details")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(inputs, [{"selected": "7"}, {"continue": ""}, {"exit": "0"}])
        self.assertNotIn("SECRET-SENTINEL", result.stderr)
        self.assertNotIn("/private/path", result.stderr)
        native = [json.loads(line.removeprefix("SBXR_NATIVE_PHASE ")) for line in result.stderr.splitlines() if line.startswith("SBXR_NATIVE_PHASE ")]
        self.assertEqual([{k: row[k] for k in begin} for row in native], [begin, end])
        self.assertTrue(all(set(row) == set(begin) | {"received_monotonic", "remaining_ms"} for row in native))
        events = [json.loads(line.removeprefix("SBXR_MENU_PHASE "))["event"] for line in result.stderr.splitlines() if line.startswith("SBXR_MENU_PHASE ")]
        expected = ["driver-start", "request-ready", "spawn-attempt", "spawn-complete", "first-byte-received", "first-line-received", "menu-frame-accepted", "menu-label-matched", "menu-ready", "input-attempt", "input-sent"]
        self.assertEqual(events[:len(expected)], expected)

    def test_details_records_prompt_input_and_return_phases_without_input_values(self):
        spec = {"label": "View details", "kind": "details"}
        result, events = self.invoke(spec, "details", "View details")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events, [{"selected": "7"}, {"continue": ""}, {"exit": "0"}])
        journal = [json.loads(line.removeprefix("SBXR_MENU_PHASE "))
                   for line in result.stderr.splitlines() if line.startswith("SBXR_MENU_PHASE ")]
        self.assertEqual([entry["event"] for entry in journal], [
            "driver-start", "request-ready", "spawn-attempt", "spawn-complete", "first-byte-received", "first-line-received", "menu-frame-accepted", "menu-label-matched", "menu-ready",
            "input-attempt", "input-sent", "prompt-received", "prompt-accepted",
            "input-attempt", "input-sent", "return-wait", "return-frame", "return-ready",
            "input-attempt", "input-sent",
        ])
        self.assertEqual([e["class"] for e in journal if e["event"] == "input-sent"],
                         ["selection", "continuation", "exit"])
        self.assertTrue(all(set(e) == {"event", "class", "monotonic", "remaining_ms"} for e in journal))
        self.assertEqual(sorted(e["monotonic"] for e in journal), [e["monotonic"] for e in journal])

    def test_setup_requires_exact_prompt_then_exits_returned_frame(self):
        spec={"label":"Start setup","wizard":True,"prompt":"Apply setup? [y/N]","kind":"action","expected":"PROXY-INSTALLATION-SETUP-COMPLETE"}
        result,events=self.invoke(spec,"action","Start setup",spec["expected"],"--confirmation","yes")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"connection":"1"},{"answer":"y"},{"exit":"0"}])

    def test_setup_never_confirms_a_missing_or_changed_wizard_prompt(self):
        for change in ({"wizard":False}, {"choice_prompt":"Connection [2] (h Help, c Cancel):"},
                       {"prompt":"Start proxy setup? [y/N]"}):
            with self.subTest(change=change):
                spec={"label":"Start setup","wizard":True,"prompt":"Apply setup? [y/N]",
                      "kind":"action","expected":"PROXY-INSTALLATION-SETUP-COMPLETE", **change}
                result,events=self.invoke(spec,"action","Start setup",spec["expected"],"--confirmation","yes",timeout=1)
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn({"answer":"y"},events)
                if "choice_prompt" in change:
                    self.assertNotIn({"connection":"1"},events)

    def test_setup_refusal_after_connection_choice_never_gets_approval(self):
        spec={"label":"Start setup","wizard":True,"prompt":"Apply setup? [y/N]","kind":"action",
              "review_codes":["PROXY-INSTALLATION-ACTION-REFUSED"],"expected":"PROXY-INSTALLATION-SETUP-COMPLETE"}
        result,events=self.invoke(spec,"action","Start setup",spec["expected"],"--confirmation","yes")
        self.assertNotEqual(result.returncode,0)
        self.assertIn("phase=action-refused",result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"connection":"1"}])

    def test_expected_setup_refusal_cancels_and_exits_before_deadline(self):
        spec={"label":"Start setup","wizard":True,"kind":"action",
              "review_codes":["PROXY-INSTALLATION-ACTION-REFUSED"],
              "prompt":"Setup is not ready. r Retry checks, b Back, c Cancel:",
              "expected":"PROXY-INSTALLATION-ACTION-REFUSED",
              "actual":"PROXY-INSTALLATION-ACTION-CANCELLED"}
        result,events=self.invoke(spec,"action","Start setup",spec["expected"],timeout=2)
        # A zero exit requires returning through the menu before the driver's
        # original deadline; c is cancellation and never authorizes setup.
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"connection":"1"},{"answer":"c"},{"exit":"0"}])
        self.assertEqual(result.stdout.count("Code: PROXY-INSTALLATION-ACTION-REFUSED"),1)
        self.assertEqual(result.stdout.count("Code: PROXY-INSTALLATION-ACTION-CANCELLED"),1)

    def test_expected_setup_refusal_requires_exact_review_and_cancel_prompt(self):
        refused="PROXY-INSTALLATION-ACTION-REFUSED"
        for change in ({"review_codes":[]}, {"review_codes":["PROXY-INSTALLATION-SETUP-COMPLETE"]},
                       {"review_codes":[refused,refused]}, {"prompt":"Apply setup? [y/N]"}):
            with self.subTest(change=change):
                spec={"label":"Start setup","wizard":True,"kind":"action","review_codes":[refused],
                      "prompt":"Setup is not ready. r Retry checks, b Back, c Cancel:",
                      "expected":refused,"actual":"PROXY-INSTALLATION-ACTION-CANCELLED",**change}
                result,events=self.invoke(spec,"action","Start setup",refused,timeout=2)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(events,[{"selected":"7"},{"connection":"1"}])

    def test_expected_setup_refusal_requires_proved_cancellation(self):
        spec={"label":"Start setup","wizard":True,"kind":"action",
              "review_codes":["PROXY-INSTALLATION-ACTION-REFUSED"],
              "prompt":"Setup is not ready. r Retry checks, b Back, c Cancel:",
              "expected":"PROXY-INSTALLATION-ACTION-REFUSED","actual":"PROXY-INSTALLATION-SETUP-COMPLETE"}
        result,events=self.invoke(spec,"action","Start setup",spec["expected"],timeout=2)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("phase=result-mismatch",result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"connection":"1"},{"answer":"c"}])

    def test_certificate_replacement_requires_its_prompt_and_exact_result(self):
        spec={"label":"Replace subscription certificate","prompt":"Replace subscription certificate? [y/N]","kind":"action","expected":"PROXY-INSTALLATION-SUBSCRIPTION-CERTIFICATE-REPLACED"}
        result,events=self.invoke(spec,"action",spec["label"],spec["expected"],"--confirmation","yes")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"answer":"y"},{"exit":"0"}])
        spec["actual"]="PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-INCOMPLETE"
        result,events=self.invoke(spec,"action",spec["label"],spec["expected"],"--confirmation","yes")
        self.assertNotEqual(result.returncode,0)
        self.assertIn("phase=result-mismatch",result.stderr)

    def test_details_waits_for_continue_in_same_process(self):
        spec={"label":"View details","kind":"details"}
        result,events=self.invoke(spec,"details","View details")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"continue":""},{"exit":"0"}])
        self.assertIn("Detected fixture fact",result.stdout)

    def test_complete_removal_uses_exact_phrase_and_terminal_result(self):
        spec={"label":"Complete removal","prompt":"Type REMOVE SBXR to confirm Complete removal. Any other input cancels.","kind":"terminal","expected":"SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"}
        result,events=self.invoke(spec,"action","Complete removal",spec["expected"],"--confirmation","remove")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"answer":"REMOVE SBXR"}])

    def test_complete_removal_expected_refusal_sends_no_confirmation(self):
        expected="PROXY-INSTALLATION-ACTION-REFUSED"
        spec={"label":"Complete removal","kind":"action","expected":expected}
        result,events=self.invoke(spec,"action","Complete removal",expected,"--confirmation","remove")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"exit":"0"}])

    def test_unexpected_removal_prompt_during_expected_refusal_gets_no_input(self):
        expected="PROXY-INSTALLATION-ACTION-REFUSED"
        spec={"label":"Complete removal","prompt":"Type REMOVE SBXR to confirm Complete removal. Any other input cancels.","kind":"action","expected":expected}
        result,events=self.invoke(spec,"action","Complete removal",expected,"--confirmation","remove")
        self.assertNotEqual(result.returncode,0)
        self.assertIn("phase=prompt-mismatch",result.stderr)
        self.assertEqual(events,[{"selected":"7"}])

    def test_promptless_finish_removal(self):
        spec={"label":"Finish removal","kind":"terminal","expected":"SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"}
        result,events=self.invoke(spec,"action","Finish removal",spec["expected"])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"}])

    def test_promptless_lifecycle_check_and_update(self):
        for label,code in (("Check","SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT"),("Update","SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT")):
            with self.subTest(label=label):
                spec={"label":label,"kind":"action","expected":code}
                result,events=self.invoke(spec,"action",label,code)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(events,[{"selected":"7"},{"exit":"0"}])

    def lifecycle_spec(self, label):
        return {"label":label, "prompt":label+" SBXR? [y/N]", "kind":"action",
                "review_codes":["SOFTWARE-LIFECYCLE-" + ("CHECK-UPDATE-AVAILABLE" if label == "Update" else "STATUS-RECOVERY-REQUIRED")],
                "expected":"SOFTWARE-LIFECYCLE-" + ("UPDATE-INSTALLED" if label == "Update" else "RECOVER-PRIOR-RESTORED")}

    def test_lifecycle_confirmation_consumes_exact_review_before_prompt(self):
        for label in ("Update", "Recover"):
            with self.subTest(label=label):
                spec=self.lifecycle_spec(label)
                result,events=self.invoke(spec,"action",label,spec["expected"],"--confirmation","yes")
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(events,[{"selected":"7"},{"answer":"y"},{"exit":"0"}])

    def test_lifecycle_missing_wrong_duplicate_or_refused_review_never_confirms(self):
        for label in ("Update", "Recover"):
            good=self.lifecycle_spec(label)["review_codes"][0]
            for codes,phase in (([],"review-missing"), ([good,good],"action-refused"),
                                (["SOFTWARE-LIFECYCLE-CHECK-FAILED"],"action-refused"),
                                ([good,"SOFTWARE-LIFECYCLE-UPDATE-RELEASE-REFUSED"],"action-refused"),
                                ([good+" "],"action-refused"),
                                (self.lifecycle_spec("Recover" if label == "Update" else "Update")["review_codes"],"action-refused")):
                with self.subTest(label=label,codes=codes):
                    spec=self.lifecycle_spec(label); spec["review_codes"]=codes
                    result,events=self.invoke(spec,"action",label,spec["expected"],"--confirmation","yes")
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn("phase="+phase,result.stderr)
                    self.assertEqual(events,[{"selected":"7"}])

    def test_lifecycle_wrong_prompt_or_expired_deadline_never_confirms(self):
        for label in ("Update", "Recover"):
            for failure in ("prompt", "deadline"):
                with self.subTest(label=label,failure=failure):
                    spec=self.lifecycle_spec(label)
                    if failure == "prompt": spec["prompt"]="Start proxy setup? [y/N]"
                    else: spec["prompt_delay"]=3
                    result,events=self.invoke(spec,"action",label,spec["expected"],"--confirmation","yes",timeout=1)
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn("phase="+("prompt-mismatch" if failure == "prompt" else "output-deadline"),result.stderr)
                    self.assertEqual(events,[{"selected":"7"}])

    def test_review_code_is_not_allowed_for_unrelated_confirmation(self):
        spec={"label":"Start setup", "wizard":True, "prompt":"Apply setup? [y/N]", "kind":"action",
              "review_codes":["SOFTWARE-LIFECYCLE-CHECK-UPDATE-AVAILABLE"], "expected":"PROXY-INSTALLATION-SETUP-COMPLETE"}
        result,events=self.invoke(spec,"action",spec["label"],spec["expected"],"--confirmation","yes")
        self.assertNotEqual(result.returncode,0)
        self.assertIn("phase=action-refused",result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"connection":"1"}])

    def test_enable_subscription_consumes_exact_link_pause(self):
        spec={"label":"Enable subscription","prompt":"Enable subscription? [y/N]","kind":"link","expected":"PROXY-INSTALLATION-SUBSCRIPTION-ENABLED"}
        result,events=self.invoke(spec,"action",spec["label"],spec["expected"],"--confirmation","yes")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"answer":"y"},{"continue":""},{"exit":"0"}])

    def test_promptless_recover_branch(self):
        marker="No recovery is available. If a change is in progress, wait for it to finish."
        spec={"label":"Recover","kind":"observe","expected":marker}
        result,events=self.invoke(spec,"observe","Recover",marker)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"exit":"0"}])

    def test_result_mismatch_reports_only_phase_and_actual_code(self):
        spec={"label":"Check","kind":"action","expected":"SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT","actual":"SOFTWARE-LIFECYCLE-CHECK-FAILED"}
        result,events=self.invoke(spec,"action","Check",spec["expected"])
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stderr,"SBXR_MENU_SESSION_REFUSED phase=result-mismatch code=SOFTWARE-LIFECYCLE-CHECK-FAILED\n")
        self.assertEqual(events,[{"selected":"7"}])

    def test_reviewed_response_clock_admits_only_active_completed_handoff(self):
        for variant in ("completed", "pending", "late", "wrong-clock", "linked-clock", "missing-draft"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);executable=root/"sbxr";request=root/"request.json";draft=root/"draft.json";clock=root/"clock.py"
                executable.write_text(FIXTURE);executable.chmod(0o700)
                source=DRIVER.with_name("mvp-observe.py").read_bytes();clock.write_bytes(source);clock.chmod(0o600)
                now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
                stamp=lambda t:t.strftime("%Y-%m-%dT%H:%M:%SZ")
                document={"scenario_id":"source-v3.1.81-upgrade","not_before":stamp(now-dt.timedelta(minutes=80)),
                          "deadline_unix":int(now.timestamp())-50*60,"scenario_limit_seconds":1800,
                          "qualification_manifest_sha256":"a"*64,"required_checks":["menu-status"],
                          "karing_response_limit_seconds":3600,"attended_finish_by":stamp(now+dt.timedelta(hours=3))}
                request.write_text(json.dumps(document));request.chmod(0o600)
                record={"phase":"http-profile-refresh","prepared_at":stamp(now-dt.timedelta(minutes=60)),
                        "notified_at":stamp(now-dt.timedelta(minutes=59)),"responded_at":stamp(now-dt.timedelta(minutes=1))}
                if variant=="pending":record["responded_at"]=None
                if variant=="late":record["notified_at"]=stamp(now-dt.timedelta(minutes=62));record["prepared_at"]=stamp(now-dt.timedelta(minutes=63))
                draft.write_text(json.dumps({"request_sha256":hashlib.sha256(request.read_bytes()).hexdigest(),"observation":{
                    "scenario_id":document["scenario_id"],"started_at":document["not_before"],"completed_at":None,
                    "checks":[{"check":"menu-status","observed_at":None,"result":None}],"karing_handoffs":[record]}}));draft.chmod(0o600)
                if variant=="missing-draft":draft.unlink()
                if variant=="linked-clock":
                    other=root/"original.py";clock.rename(other);clock.symlink_to(other)
                spec={"label":"Check","kind":"action","expected":"SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT"}
                env=dict(os.environ,FIXTURE_ROOT=temporary,FIXTURE_SPEC=json.dumps(spec),SBXR_QUALIFICATION_REQUEST=str(request),
                         SBXR_QUALIFICATION_DRAFT=str(draft),SBXR_QUALIFICATION_CLOCK=str(clock),
                         SBXR_QUALIFICATION_CLOCK_SHA256="0"*64 if variant=="wrong-clock" else hashlib.sha256(source).hexdigest())
                result=subprocess.run([sys.executable,str(DRIVER),"action","Check",spec["expected"],"--executable",str(executable),"--timeout","3"],env=env,text=True,capture_output=True,timeout=5)
                self.assertEqual(result.returncode==0,variant=="completed",result.stderr)
                self.assertEqual((root/"events.jsonl").exists(),variant=="completed")

    def test_expired_request_deadline_refuses_before_product_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); executable=root/"sbxr"; request=root/"request.json"
            executable.write_text(FIXTURE); executable.chmod(0o700)
            request.write_text(json.dumps({"deadline_unix":1}))
            spec={"label":"Check","kind":"action","expected":"SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT"}
            env=dict(os.environ,FIXTURE_ROOT=temporary,FIXTURE_SPEC=json.dumps(spec),SBXR_QUALIFICATION_REQUEST=str(request))
            result=subprocess.run([sys.executable,str(DRIVER),"action","Check",spec["expected"],"--executable",str(executable)],env=env,text=True,capture_output=True,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stderr,"SBXR_MENU_SESSION_REFUSED phase=deadline-before-start\n")
            self.assertFalse((root/"events.jsonl").exists())

    @unittest.skipUnless(sys.platform.startswith("linux"),"subreaper cleanup requires Linux")
    def test_signal_cancellation_reaps_escaped_descendant(self):
        self.assert_owned_descendant_cleaned("hang",signal_driver=True,escape=True)

    @unittest.skipUnless(sys.platform.startswith("linux"),"subreaper cleanup requires Linux")
    def test_early_leader_exit_still_kills_owned_descendant(self):
        self.assert_owned_descendant_cleaned("leader-exit",signal_driver=False,escape=False)

    @unittest.skipUnless(sys.platform.startswith("linux"),"subreaper cleanup requires Linux")
    def test_cancellation_without_proc_children_preserves_unrelated_sibling(self):
        self.assert_owned_descendant_cleaned("hang", signal_driver=True, escape=True,
                                            children_mode="missing")

    @unittest.skipUnless(sys.platform.startswith("linux"),"subreaper cleanup requires Linux")
    def test_kernel_child_list_verifies_ownership_and_preserves_unrelated_sibling(self):
        self.assert_owned_descendant_cleaned("hang", signal_driver=True, escape=True,
                                            children_mode="listed")

    def assert_owned_descendant_cleaned(self,kind,*,signal_driver,escape,children_mode=None):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); executable=root/"sbxr"
            executable.write_text(FIXTURE); executable.chmod(0o700)
            spec={"label":"Start setup","kind":kind,"escape":escape}
            env=dict(os.environ,FIXTURE_ROOT=temporary,FIXTURE_SPEC=json.dumps(spec))
            libc = ctypes.CDLL(None, use_errno=True)
            previous = ctypes.c_int()
            self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
            self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
            unrelated = subprocess.Popen(["sleep", "30"], start_new_session=True)
            if children_mode is not None:
                hook = root / "hook"
                hook.mkdir()
                (hook / "sitecustomize.py").write_text((DRIVER.parent / "testdata" / "proc-children-hook.py").read_text())
                env.update(PYTHONPATH=str(hook), SBXR_TEST_CHILDREN_MODE=children_mode,
                           SBXR_TEST_CHILDREN_OBSERVED=str(root / "children-read"),
                           SBXR_TEST_UNRELATED_PID=str(unrelated.pid))
            descendant = None
            process=subprocess.Popen([sys.executable,str(DRIVER),"action","Start setup",
                                      "PROXY-INSTALLATION-SETUP-COMPLETE","--confirmation","yes",
                                      "--executable",str(executable),"--timeout","5"],
                                     env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
            try:
                deadline=time.monotonic()+3
                while not (root/"descendant.pid").exists() and time.monotonic()<deadline: time.sleep(.01)
                self.assertTrue((root/"descendant.pid").exists())
                descendant=int((root/"descendant.pid").read_text())
                if signal_driver: process.terminate()
                stderr=process.communicate(timeout=8)[1]
                self.assertNotEqual(process.returncode,0); self.assertIn("SBXR_MENU_SESSION_REFUSED",stderr)
                with self.assertRaises(ProcessLookupError): os.kill(descendant,0)
                self.assertIsNone(unrelated.poll())
                if children_mode is not None:
                    self.assertIn(children_mode, (root / "children-read").read_text().splitlines())
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=8)
                # Keep the original assertion before cleanup, and also reap
                # escaped fixture children after a red run or interruption.
                if descendant is not None:
                    try:
                        descriptor = os.pidfd_open(descendant, 0)
                    except ProcessLookupError:
                        pass
                    else:
                        try:
                            os.waitid(os.P_PIDFD, descriptor, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                            os.waitpid(descendant, 0)
                        except (ProcessLookupError, ChildProcessError):
                            pass
                        finally:
                            os.close(descriptor)
                unrelated.kill()
                unrelated.wait(timeout=3)
                libc.prctl(36, previous.value, 0, 0, 0)

class ReadinessDiagnosticTests(unittest.TestCase):
    """Pure strict-filter tests; no product or native process operations."""
    def relay(self, rows):
        sink = io.StringIO()
        timing = menu.PhaseTiming(sink, time.monotonic() + 1)
        try:
            for row in rows:
                timing.native(row if isinstance(row, bytes) else
                              ("SBXR_NATIVE_READINESS " + json.dumps(row)).encode())
        finally:
            timing.close()
        return sink.getvalue().splitlines()

    def test_accepts_closed_guard_and_error_vocabulary(self):
        # Keep each batch below the existing best-effort queue capacity.
        for guard in sorted(menu.READINESS_GUARDS):
            rows = [dict(guard=guard, cause=cause, id=2**64-1, elapsed_us=2**64-1)
                    for cause in sorted(menu.READINESS_CAUSES)]
            received = self.relay(rows)
            self.assertEqual(len(received), len(rows))
            for original, line in zip(rows, received):
                self.assertLessEqual(len(line), 511)
                row = json.loads(line.split(" ", 1)[1])
                self.assertEqual({key: row[key] for key in original}, original)
                self.assertEqual(set(row) - set(original), {"received_monotonic", "remaining_ms"})

    def test_rejects_payloads_unknown_enums_duplicates_and_invalid_scalars(self):
        row = dict(guard="clock", cause="unsafe", id=1, elapsed_us=0)
        bad = [{**row, key: value} for key, value in [
            ("guard", "/private/path"), ("guard", []), ("cause", "SECRET-SENTINEL"),
            ("cause", "completed-zero"), ("cause", []), ("payload", "SECRET-SENTINEL"),
            ("id", True), ("id", 0), ("id", 2**64), ("elapsed_us", True),
            ("elapsed_us", -1), ("elapsed_us", 2**64)]]
        bad += [[], None, {key: value for key, value in row.items() if key != "guard"}]
        raw = ("SBXR_NATIVE_READINESS " + json.dumps(row)).encode()
        bad += [raw.replace(b'"id": 1', b'"id": 1, "id": 2'), raw[:40]]
        self.assertEqual(self.relay(bad), [])


class QueryDiagnosticTests(unittest.TestCase):
    """Pure relay tests; no child, signal, socket or network operations."""
    def row(self):
        return dict(query="query-public-ip-dns", id=7, elapsed_us=5_000_000,
                    outcome="timeout", process=dict(location="stdout-drain", leader="not-exited",
                    stdout_eof=False, stderr_eof=True, stdout_bytes=12, stderr_bytes=3))

    def relay(self, rows, sink=None):
        sink = sink if sink is not None else io.StringIO()
        timing = menu.PhaseTiming(sink, time.monotonic() + 1)
        try:
            for row in rows:
                raw = row if isinstance(row, bytes) else ("SBXR_NATIVE_QUERY " + json.dumps(row)).encode()
                timing.native(raw)
        finally:
            timing.close()
        return sink

    def test_closed_schema_accepts_terminal_states_and_bounds(self):
        rows = []
        for outcome in sorted(menu.QUERY_OUTCOMES):
            for leader in ("unobserved", "not-exited", "exited"):
                row = self.row()
                row.update(outcome=outcome, id=2**64-1, elapsed_us=2**64-1,
                           query="query-configuration-owner")
                row["process"].update(leader=leader, stdout_bytes=1 << 20, stderr_bytes=0)
                rows.append(row)
        received = self.relay(rows).getvalue().splitlines()
        self.assertEqual(len(received), len(rows))
        for original, line in zip(rows, received):
            self.assertLessEqual(len(line), 511)
            row = json.loads(line.removeprefix("SBXR_NATIVE_QUERY "))
            self.assertEqual({k: row[k] for k in original}, original)
            self.assertEqual(set(row) - set(original), {"received_monotonic", "remaining_ms"})

    def test_rejects_payloads_unknown_values_duplicates_and_wrong_types(self):
        bad = []
        for field, value in [("query", "network"), ("query", []), ("outcome", "SECRET-SENTINEL"),
                             ("id", True), ("id", 0), ("elapsed_us", -1), ("process", [])]:
            bad.append({**self.row(), field: value})
        bad.append({**self.row(), "payload": "SECRET-SENTINEL"})
        for field, value in [("location", "/private/path"), ("leader", []), ("stdout_eof", 1),
                             ("stderr_bytes", True), ("stdout_bytes", (1 << 20) + 1),
                             ("stderr_bytes", -1), ("payload", "SECRET-SENTINEL")]:
            row = self.row(); row["process"][field] = value; bad.append(row)
        row = self.row(); row["process"].update(stdout_bytes=1 << 20, stderr_bytes=1); bad.append(row)
        raw = ("SBXR_NATIVE_QUERY " + json.dumps(self.row())).encode()
        bad.extend([raw.replace(b'"id": 7', b'"id": 7, "id": 8'),
                    raw.replace(b'"stdout_bytes": 12', b'"stdout_bytes": 12, "stdout_bytes": 13'),
                    raw[:80]])
        self.assertEqual(self.relay(bad).getvalue(), "")

    def test_failed_sink_does_not_escape_and_worker_finishes(self):
        class Failed(io.StringIO):
            def write(self, value):
                raise BrokenPipeError("SECRET-SENTINEL")
        started = time.monotonic()
        self.relay([self.row()], Failed())
        self.assertLess(time.monotonic() - started, .5)

if __name__ == "__main__": unittest.main()
