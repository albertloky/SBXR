#!/usr/bin/env python3
"""Drive one SBXR numbered-menu process without carrying numbers across runs."""

import argparse
import ctypes
import json
import os
import re
import select
import signal
import subprocess
import sys
import time


MAX_OUTPUT = 8 * 1024 * 1024
PROMPTS = {
    "Start setup": "Start proxy setup? [y/N]",
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


class ProtocolError(Exception):
    def __init__(self, phase, code=None):
        super().__init__(phase)
        self.phase = phase
        self.code = code


class LineStream:
    def __init__(self, stream, sink, cancelled=None, owner_exited=None):
        self.stream = stream
        self.sink = sink
        self.buffer = bytearray()
        self.total = 0
        self.cancelled = cancelled or (lambda: False)
        self.owner_exited = owner_exited or (lambda: False)
        self.last_code = None

    def line(self, deadline):
        if self.cancelled():
            raise InterruptedError("menu session interrupted")
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
        self.sink.write(rendered)
        self.sink.flush()
        try:
            line = raw.rstrip(b"\r").decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProtocolError("output-encoding") from error
        match = re.fullmatch(r"Code: ([A-Z0-9-]+)", line)
        if match:
            self.last_code = match.group(1)
        return line


class MenuSession:
    def __init__(self, executable, sink, deadline, cancelled=None):
        self.deadline = deadline
        self.cancelled = cancelled or (lambda: False)
        if self.cancelled():
            raise InterruptedError("menu session interrupted")
        self.process = subprocess.Popen(
            [executable], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, start_new_session=True,
        )
        def owner_exited():
            if not hasattr(os, "waitid"):
                return False
            try:
                return os.waitid(os.P_PID, self.process.pid,
                                 os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
            except ChildProcessError:
                return True
        self.stream = LineStream(self.process.stdout, sink, self.cancelled, owner_exited)
        self.cleaned = False
        self.returncode = None

    def write(self, value):
        if self.cancelled():
            raise InterruptedError("menu session interrupted")
        try:
            self.process.stdin.write(value.encode("utf-8"))
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise ProtocolError("input-closed") from error

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

    def expect_prompt(self, expected):
        while True:
            line = self.stream.line(self.deadline)
            if line is None:
                raise ProtocolError("exit-before-prompt")
            if line == expected:
                return
            if line.endswith("? [y/N]") or line.startswith("Type REMOVE SBXR to confirm"):
                raise ProtocolError("prompt-mismatch")
            if line.startswith("Code: "):
                raise ProtocolError("action-refused")

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
        frame = False
        while True:
            line = self.stream.line(self.deadline)
            if line is None:
                raise ProtocolError("exit-before-return")
            if line == "SBXR V3":
                frame = True
            elif frame and line == "0. Exit":
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
        if not hasattr(os, "waitid"):
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
            if os.waitid(os.P_PID, self.process.pid,
                         os.WEXITED | os.WNOHANG | os.WNOWAIT):
                break
            time.sleep(0.01)
        code = self.stop()
        if code != 0:
            raise ProtocolError("process-failed")

    def stop(self):
        if self.cleaned:
            return self.returncode
        # Do not poll/reap the leader before signaling: its unreaped PID keeps
        # the owned process-group identity from being recycled.
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            raise ProtocolError("process-cleanup")
        if not sys.platform.startswith("linux"):
            self.cleaned = True
            self.returncode = code
            return code
        children = f"/proc/self/task/{os.getpid()}/children"
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
            try:
                adopted = open(children, encoding="ascii").read().split()
            except FileNotFoundError:
                adopted = []
            for child in adopted:
                try:
                    os.kill(int(child), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if time.monotonic() >= deadline:
                raise ProtocolError("descendant-cleanup")
            time.sleep(0.01)


def drive(args, cancelled=None):
    remaining = float(args.timeout)
    request = os.environ.get("SBXR_QUALIFICATION_REQUEST")
    if request:
        document = json.loads(open(request, "rb").read())
        request_deadline = document.get("deadline_unix")
        if type(request_deadline) is not int:
            raise ProtocolError("request-deadline")
        remaining = min(remaining, request_deadline - time.time())
    if remaining <= 0:
        raise ProtocolError("deadline-before-start")
    deadline = time.monotonic() + remaining
    session = MenuSession(args.executable, sys.stdout.buffer, deadline, cancelled)
    try:
        session.choose(args.label)
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
            if args.confirmation == "yes":
                prompt = PROMPTS.get(args.label)
                if prompt is None:
                    raise ProtocolError("confirmation-unsupported")
                session.expect_prompt(prompt)
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
