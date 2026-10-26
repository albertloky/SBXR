#!/usr/bin/env python3
"""Drive one SBXR numbered-menu process without carrying numbers across runs."""

import argparse
import ctypes
import hashlib
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time


MAX_OUTPUT = 8 * 1024 * 1024
PROMPTS = {
    "Start setup": "Apply setup? [y/N]",
    "Finish cleanup": "Finish proxy cleanup? [y/N]",
    "Finish setup": "Finish proxy setup? [y/N]",
    "Enable subscription": "Enable subscription? [y/N]",
    "Rotate subscription link": "Rotate subscription link? [y/N]",
    "Repair subscription": "Repair subscription? [y/N]",
    "Replace subscription certificate": "Replace subscription certificate? [y/N]",
    "Finish subscription change": "Finish subscription change? [y/N]",
    "Rotate Client Identity": "Rotate Client Identity? [y/N]",
    "Finish Client Identity rotation": "Finish Client Identity rotation? [y/N]",
    "Show client configuration": "Show client configuration? [y/N]",
    "Update": "Update SBXR? [y/N]",
    "Recover": "Recover SBXR? [y/N]",
}
# Lifecycle review results precede these confirmation prompts. They are not
# final action results and must occur exactly once before sending approval.
REVIEW_CODES = {
    "Update": "SOFTWARE-LIFECYCLE-CHECK-UPDATE-AVAILABLE",
    "Recover": "SOFTWARE-LIFECYCLE-STATUS-RECOVERY-REQUIRED",
}
REMOVAL_PROMPT = "Type REMOVE SBXR to confirm Complete removal. Any other input cancels."
DETAILS_PROMPT = "Press Enter to return to the menu."
DISCLOSURE_PROMPT = (
    "Press Enter to preserve this configuration in terminal scrollback and return to the menu."
)
LINK_PROMPT = "Press Enter to preserve this link in terminal scrollback and return to the menu."
LINK_RESULTS = {
    "Enable subscription": "PROXY-INSTALLATION-SUBSCRIPTION-ENABLED",
    "Rotate subscription link": "PROXY-INSTALLATION-SUBSCRIPTION-LINK-ROTATED",
}
SETUP_CHOICE_PROMPT = "Connection [1] (h Help, c Cancel):"
SETUP_REFUSAL_PROMPT = "Setup is not ready. r Retry checks, b Back, c Cancel:"


class ProtocolError(Exception):
    def __init__(self, phase, code=None):
        super().__init__(phase)
        self.phase = phase
        self.code = code


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
    return False


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


def kill_adopted_children():
    """Signal only this dedicated controller's children, binding PID identity."""
    own = os.getpid()
    try:
        with open(f"/proc/self/task/{own}/children", encoding="ascii") as stream:
            children = [int(child) for child in stream.read().split()]
    except FileNotFoundError:
        # CONFIG_CHECKPOINT_RESTORE controls the optional task/children file.
        # Parent IDs remain available on kernels without that interface.
        children = []
        for entry in os.listdir("/proc"):
            if not entry.isdecimal():
                continue
            try:
                with open(f"/proc/{entry}/stat", encoding="ascii") as stream:
                    tail = stream.read().rsplit(") ", 1)[1].split()
            except (FileNotFoundError, ProcessLookupError):
                continue
            if int(tail[1]) == own:
                children.append(int(entry))
    for child in children:
        try:
            descriptor = os.pidfd_open(child, 0)
        except ProcessLookupError:
            continue
        try:
            # Verify ownership through the bound identity, even if a listed
            # PID exited or was reused. WNOWAIT leaves our children unreaped.
            try:
                os.waitid(os.P_PIDFD, descriptor,
                          os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                continue
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
        finally:
            os.close(descriptor)


class PhaseTiming:
    """Details-only bounded events; never transcript bytes or input values."""
    def __init__(self, sink, deadline):
        self.sink = sink
        self.deadline = deadline

    def __call__(self, event, input_class="none"):
        now = time.monotonic()
        print("SBXR_MENU_PHASE " + json.dumps({
            "event": event, "class": input_class, "monotonic": round(now, 6),
            "remaining_ms": round((self.deadline - now) * 1000, 3),
        }, sort_keys=True), file=self.sink, flush=True)


class LineStream:
    def __init__(self, stream, sink, cancelled=None, owner_exited=None, timing=None):
        self.stream = stream
        self.sink = sink
        self.buffer = bytearray()
        self.total = 0
        self.cancelled = cancelled or (lambda: False)
        self.owner_exited = owner_exited or (lambda: False)
        self.last_code = None
        self.timing = timing or (lambda *args: None)

    def line(self, deadline):
        if self.cancelled():
            raise InterruptedError("menu session interrupted")
        # Buffered lines belong to the same deadline as fresh pipe reads.
        if time.monotonic() >= deadline:
            raise ProtocolError("output-deadline")
        while b"\n" not in self.buffer:
            if self.cancelled():
                raise InterruptedError("menu session interrupted")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProtocolError("output-deadline")
            if not select.select([self.stream], [], [], min(remaining, 0.1))[0]:
                if self.owner_exited():
                    raise ProtocolError("owner-exited")
                continue
            block = os.read(self.stream.fileno(), 4096)
            if not block:
                if self.buffer:
                    raise ProtocolError("output-unterminated")
                return None
            self.buffer.extend(block)
            self.total += len(block)
            if self.total > MAX_OUTPUT or len(self.buffer) > 1024 * 1024:
                raise ProtocolError("output-bound")
        raw, _, rest = self.buffer.partition(b"\n")
        self.buffer = bytearray(rest)
        rendered = raw + b"\n"
        details_prompt = raw.rstrip(b"\r") == DETAILS_PROMPT.encode("ascii")
        if details_prompt:
            self.timing("prompt-received", "details-continuation")
        self.sink.write(rendered)
        self.sink.flush()
        # A slow transcript write must not turn a late prompt/result into
        # permission to continue. Keep the captured bytes for diagnosis.
        if self.cancelled():
            raise InterruptedError("menu session interrupted")
        if time.monotonic() >= deadline:
            raise ProtocolError("output-deadline")
        if details_prompt:
            self.timing("prompt-accepted", "details-continuation")
        try:
            line = raw.rstrip(b"\r").decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProtocolError("output-encoding") from error
        match = re.fullmatch(r"Code: ([A-Z0-9-]+)", line)
        if match:
            self.last_code = match.group(1)
        return line


class MenuSession:
    def __init__(self, executable, sink, deadline, cancelled=None, *, protected_wrapper=False, timing=None):
        self.deadline = deadline
        self.timing = timing or (lambda *args: None)
        self.protected_wrapper = protected_wrapper
        if protected_wrapper and not sys.platform.startswith("linux"):
            raise ProtocolError("protected-wrapper-requires-linux")
        self.cancelled = cancelled or (lambda: False)
        if self.cancelled():
            raise InterruptedError("menu session interrupted")
        if time.monotonic() >= deadline:
            raise ProtocolError("deadline-before-start")
        self.process = subprocess.Popen(
            [executable] if isinstance(executable, str) else list(executable),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, start_new_session=True,
        )
        def owner_exited():
            try:
                return child_exited(self.process.pid)
            except ChildProcessError:
                return True
        self.stream = LineStream(self.process.stdout, sink, self.cancelled, owner_exited, self.timing)
        self.cleaned = False
        self.returncode = None

    def write(self, value):
        input_class = ("continuation" if value == "\n" else "exit" if value == "0\n" else
                       "selection" if re.fullmatch(r"[1-9][0-9]*\n", value) else "other")
        self.timing("input-attempt", input_class)
        if self.cancelled():
            raise InterruptedError("menu session interrupted")
        # Covers selection, approval and continuation for every caller,
        # including expiry after a valid prompt but before its reply.
        if time.monotonic() >= self.deadline:
            raise ProtocolError("input-deadline")
        try:
            self.process.stdin.write(value.encode("utf-8"))
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise ProtocolError("input-closed") from error
        self.timing("input-sent", input_class)

    def choose(self, label):
        selection = None
        while True:
            line = self.stream.line(self.deadline)
            if line is None:
                raise ProtocolError("exit-before-selection")
            match = re.fullmatch(r"([1-9][0-9]*)\. (.+)", line)
            if match and match.group(2) == label:
                if selection is not None:
                    raise ProtocolError("label-duplicate")
                selection = match.group(1)
            if line == "0. Exit":
                if selection is None:
                    raise ProtocolError("label-missing")
                self.write(selection + "\n")
                return

    def expect_prompt(self, expected, *, review_code=None):
        reviewed = False
        while True:
            line = self.stream.line(self.deadline)
            if line is None:
                raise ProtocolError("exit-before-prompt")
            if line == expected:
                if review_code is not None and not reviewed:
                    raise ProtocolError("review-missing")
                return
            if line.endswith("? [y/N]") or line.startswith("Type REMOVE SBXR to confirm"):
                raise ProtocolError("prompt-mismatch")
            if line.startswith("Code: "):
                if review_code is None or reviewed or line != "Code: " + review_code:
                    raise ProtocolError("action-refused")
                reviewed = True

    def wait_code(self, expected, *, terminal=False):
        found = False
        frame = False
        while True:
            line = self.stream.line(self.deadline)
            if line is None:
                if found and terminal:
                    return
                raise ProtocolError("exit-before-result")
            if not found and (line.endswith("? [y/N]") or
                              line.startswith("Type REMOVE SBXR to confirm")):
                raise ProtocolError("prompt-mismatch")
            if line == "SBXR V3":
                frame = True
            elif line.startswith("Code: "):
                code = line.removeprefix("Code: ")
                if not found:
                    if code != expected:
                        raise ProtocolError("result-mismatch")
                    found = True
            elif found and frame and line == "0. Exit":
                self.write("0\n")
                return

    def return_to_menu(self):
        self.timing("return-wait")
        frame = False
        while True:
            line = self.stream.line(self.deadline)
            if line is None:
                raise ProtocolError("exit-before-return")
            if line == "SBXR V3":
                self.timing("return-frame")
                frame = True
            elif frame and line == "0. Exit":
                self.timing("return-ready")
                self.write("0\n")
                return

    def wait_line(self, expected):
        while True:
            line = self.stream.line(self.deadline)
            if line is None:
                raise ProtocolError("exit-before-continuation")
            if line == expected:
                return

    def wait_unconfirmed_marker(self, expected):
        while True:
            line = self.stream.line(self.deadline)
            if line is None:
                raise ProtocolError("exit-before-result")
            if line.endswith("? [y/N]") or line.startswith("Type REMOVE SBXR to confirm"):
                raise ProtocolError("prompt-mismatch")
            if line == expected:
                return

    def wait_continuation(self, expected):
        while True:
            line = self.stream.line(self.deadline)
            if line is None:
                raise ProtocolError("exit-before-continuation")
            if line == expected:
                return
            if line.endswith("? [y/N]") or line.startswith("Type REMOVE SBXR to confirm"):
                raise ProtocolError("prompt-mismatch")
            if line.startswith("Code: "):
                raise ProtocolError("result-mismatch")

    def finish(self):
        if not hasattr(os, "waitid") and sys.platform != "darwin":
            remaining = max(0.01, self.deadline - time.monotonic())
            try:
                code = self.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as error:
                raise ProtocolError("exit-deadline") from error
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.cleaned = True
            self.returncode = code
            if code != 0:
                raise ProtocolError("process-failed")
            return
        while True:
            if self.cancelled():
                raise InterruptedError("menu session interrupted")
            if time.monotonic() >= self.deadline:
                raise ProtocolError("exit-deadline")
            if self.stream.owner_exited():
                break
            time.sleep(0.01)
        code = self.stop()
        if code != 0:
            raise ProtocolError("process-failed")

    def stop(self):
        if self.cleaned:
            return self.returncode
        if self.process.returncode is not None:
            raise ProtocolError("process-ownership")
        try:
            child_exited(self.process.pid)
        except ChildProcessError as error:
            raise ProtocolError("process-ownership") from error
        # Do not poll/reap the leader before signaling: its unreaped PID keeps
        # the owned process-group identity from being recycled.
        if self.protected_wrapper:
            # Opt-in private protocol with the reviewed permission wrapper.
            # Signal only its leader: startup helpers must finish recording
            # the identities they create. After product admission the wrapper
            # exits WITHOUT restoration; we still kill/reap every descendant
            # before the caller may use explicit state-bound restore.
            try:
                os.kill(self.process.pid, signal.SIGUSR1)
            except ProcessLookupError:
                pass
            # The wrapper itself may spend five seconds proving quiescence,
            # followed by metadata and /proc descriptor scans. Match the
            # existing explicit-restore budget; five seconds for the entire
            # handshake could kill it halfway through safe channel removal.
            # This runs only AFTER failure; the journey deadline is unchanged.
            cleanup_deadline = time.monotonic() + 20
            while time.monotonic() < cleanup_deadline:
                if self.stream.owner_exited():
                    break
                time.sleep(0.01)
        cleanup_deadline = time.monotonic() + 5
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            # Darwin excludes zombies from group signalling and reports EPERM
            # if no signalable member remains. Never ignore a live/unknown group.
            if not darwin_lone_exited_child(self.process, cleanup_deadline):
                raise
        try:
            remaining = max(0, cleanup_deadline - time.monotonic()) if sys.platform == "darwin" else 5
            code = self.process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise ProtocolError("process-cleanup")
        if not sys.platform.startswith("linux"):
            self.cleaned = True
            self.returncode = code
            return code
        deadline = time.monotonic() + 5
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                self.cleaned = True
                self.returncode = code
                return code
            if pid:
                continue
            kill_adopted_children()
            if time.monotonic() >= deadline:
                raise ProtocolError("descendant-cleanup")
            time.sleep(0.01)


def qualification_deadline(path):
    """Keep legacy callers unchanged; opted-in operations use reviewed clock bytes."""
    with open(path, "rb") as stream:
        document = json.loads(stream.read())
    deadline = document.get("deadline_unix")
    if type(deadline) is not int:
        raise ProtocolError("request-deadline")
    if "karing_response_limit_seconds" not in document:
        return deadline
    clock = os.environ.get("SBXR_QUALIFICATION_CLOCK", "")
    wanted = os.environ.get("SBXR_QUALIFICATION_CLOCK_SHA256", "")
    draft = os.environ.get("SBXR_QUALIFICATION_DRAFT", "")
    if not os.path.isabs(clock) or not os.path.isabs(draft) or not re.fullmatch(r"[0-9a-f]{64}", wanted):
        raise ProtocolError("request-clock-identity")
    try:
        fd = os.open(clock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ProtocolError("request-clock-file")
            body = stream.read(65537)
        if len(body) > 65536 or hashlib.sha256(body).hexdigest() != wanted:
            raise ProtocolError("request-clock-identity")
        # Execute the verified bytes, avoiding a second path lookup after hash.
        result = subprocess.run([sys.executable, "-B", "-", "operation-deadline", "--request", path,
                                 "--draft", draft], input=body, capture_output=True, timeout=10)
        if result.returncode or not re.fullmatch(rb"[0-9]+\n", result.stdout):
            raise ProtocolError("request-clock-refused")
        return int(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise ProtocolError("request-clock-unavailable") from None


def drive(args, cancelled=None):
    deadline = time.monotonic() + float(args.timeout)
    request = os.environ.get("SBXR_QUALIFICATION_REQUEST")
    if request:
        request_deadline = qualification_deadline(request)
        deadline = min(deadline, time.monotonic() + request_deadline - time.time())
    if time.monotonic() >= deadline:
        raise ProtocolError("deadline-before-start")
    session = MenuSession(args.executable, sys.stdout.buffer, deadline, cancelled,
                          protected_wrapper=args.protected_wrapper,
                          timing=PhaseTiming(sys.stderr, deadline) if args.mode == "details" else None)
    try:
        session.choose(args.label)
        if args.mode == "action" and args.label == "Start setup":
            # The qualification journey uses Standard. Never skip the exact
            # wizard prompt or treat another profile/prompt as permission.
            session.expect_prompt(SETUP_CHOICE_PROMPT)
            session.write("1\n")
        if args.mode == "details":
            session.wait_unconfirmed_marker(DETAILS_PROMPT)
            session.write("\n")
            session.return_to_menu()
        elif args.mode == "observe":
            session.wait_unconfirmed_marker(args.expected)
            session.return_to_menu()
        elif args.mode == "disclose":
            session.expect_prompt(PROMPTS[args.label])
            session.write("y\n")
            session.wait_line(DISCLOSURE_PROMPT)
            session.write("\n")
            session.wait_code(args.expected)
        else:
            result_consumed = False
            if (args.label == "Start setup" and args.confirmation == "none" and
                    args.expected == "PROXY-INSTALLATION-ACTION-REFUSED"):
                session.expect_prompt(SETUP_REFUSAL_PROMPT, review_code=args.expected)
                session.write("c\n")
                session.wait_code("PROXY-INSTALLATION-ACTION-CANCELLED")
                result_consumed = True
            elif args.confirmation == "yes":
                prompt = PROMPTS.get(args.label)
                if prompt is None:
                    raise ProtocolError("confirmation-unsupported")
                session.expect_prompt(prompt, review_code=REVIEW_CODES.get(args.label))
                session.write("y\n")
                if LINK_RESULTS.get(args.label) == args.expected:
                    session.wait_continuation(LINK_PROMPT)
                    session.write("\n")
            elif args.confirmation == "remove":
                if args.label != "Complete removal":
                    raise ProtocolError("removal-confirmation-unsupported")
                if args.expected == "PROXY-INSTALLATION-ACTION-REFUSED":
                    session.wait_code(args.expected)
                    result_consumed = True
                else:
                    session.expect_prompt(REMOVAL_PROMPT)
                    session.write("REMOVE SBXR\n")
            if not result_consumed:
                session.wait_code(args.expected,
                                  terminal=args.label in {"Complete removal", "Finish removal"})
        session.finish()
    except BaseException as error:
        code = session.stream.last_code
        session.stop()
        if isinstance(error, ProtocolError) and error.code is None:
            error.code = code
        raise


def parser():
    result = argparse.ArgumentParser(add_help=False)
    result.add_argument("mode", choices=("action", "details", "disclose", "observe"))
    result.add_argument("label")
    result.add_argument("expected", nargs="?", default="")
    result.add_argument("--confirmation", choices=("none", "yes", "remove"), default="none")
    result.add_argument("--executable", default=os.environ.get("SBXR_EXECUTABLE", "/usr/local/bin/sbxr"))
    result.add_argument("--timeout", type=int, default=900)
    result.add_argument("--protected-wrapper", action="store_true")
    return result


def main():
    received_signal = None
    def cancelled():
        return received_signal is not None
    def receive(signum, _frame):
        nonlocal received_signal
        received_signal = signum
    try:
        args = parser().parse_args()
        if not 0 < args.timeout <= 1800:
            raise ProtocolError("deadline-invalid")
        if sys.platform.startswith("linux"):
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(36, 1, 0, 0, 0) != 0:
                raise ProtocolError("subreaper-unavailable")
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(signum, receive)
        drive(args, cancelled)
    except Exception as error:
        phase = ("signal-cancelled" if received_signal is not None else
                 error.phase if isinstance(error, ProtocolError) else "driver-error")
        code = error.code if isinstance(error, ProtocolError) else None
        suffix = " code=" + code if code and re.fullmatch(r"[A-Z0-9-]+", code) else ""
        print("SBXR_MENU_SESSION_REFUSED phase=" + phase + suffix, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
