#!/usr/bin/env python3
import ctypes
import errno
import os
import signal
import sys
import time

PR_SET_PDEATHSIG = 1
PR_SET_CHILD_SUBREAPER = 36
GRACE_SECONDS = 10.0
MANAGED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)


def prctl(option: int, value: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(option, value, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl")


def group_has_live_members() -> bool:
    group = os.getpgrp()
    own = os.getpid()
    try:
        entries = os.listdir("/proc")
    except OSError:
        return True
    for entry in entries:
        if not entry.isdigit() or int(entry) == own:
            continue
        try:
            body = open(f"/proc/{entry}/stat", encoding="ascii").read()
            tail = body.rsplit(") ", 1)[1].split()
            state, process_group = tail[0], int(tail[2])
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ESRCH):
                continue
            return True
        except (ValueError, IndexError):
            return True
        if process_group == group and state != "Z":
            return True
    return False


def reap() -> dict[int, int]:
    statuses: dict[int, int] = {}
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return statuses
        except InterruptedError:
            continue
        if pid == 0:
            return statuses
        statuses[pid] = status


def propagate(signum: int) -> None:
    prior = signal.signal(signum, signal.SIG_IGN)
    try:
        os.killpg(os.getpgrp(), signum)
    except ProcessLookupError:
        pass
    finally:
        signal.signal(signum, prior)


def drain(signum: int) -> bool:
    propagate(signum)
    deadline = time.monotonic() + GRACE_SECONDS
    while time.monotonic() < deadline:
        if not group_has_live_members():
            return True
        time.sleep(0.05)
    os.killpg(os.getpgrp(), signal.SIGKILL)
    return False


def status_code(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


def read_controls(descriptor: int, buffered: bytes) -> tuple[list[str], bytes]:
    try:
        chunk = os.read(descriptor, 4096)
    except BlockingIOError:
        return [], buffered
    if not chunk:
        return ["PARENT_GONE"], buffered
    buffered += chunk
    lines = buffered.split(b"\n")
    return [line.decode("ascii") for line in lines[:-1]], lines[-1]


def send_result(descriptor: int, status: int) -> bool:
    body = f"DONE {status}\n".encode("ascii")
    try:
        while body:
            body = body[os.write(descriptor, body):]
    except (BrokenPipeError, OSError):
        return False
    return True


def send_message(descriptor: int, message: str) -> bool:
    body = (message + "\n").encode("ascii")
    try:
        while body:
            body = body[os.write(descriptor, body):]
    except (BrokenPipeError, OSError):
        return False
    return True


def wait_for_ack(control: int, expected_parent: int, buffered: bytes) -> None:
    while os.getppid() == expected_parent:
        controls, buffered = read_controls(control, buffered)
        if "ACK" in controls or "PARENT_GONE" in controls:
            return
        if any(message not in ("HUP", "INT", "TERM", "START") for message in controls):
            return
        time.sleep(0.02)


def main() -> int:
    if len(sys.argv) < 5:
        return 125
    expected_parent = int(sys.argv[1])
    control = int(sys.argv[2])
    result = int(sys.argv[3])
    for entry in os.listdir("/proc/self/fd"):
        descriptor = int(entry)
        if descriptor > 2 and descriptor not in (control, result):
            try:
                os.close(descriptor)
            except OSError:
                pass
    os.set_blocking(control, False)
    prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
    if os.getppid() != expected_parent or os.getsid(0) != os.getpid() or os.getpgrp() != os.getpid():
        return 125
    prctl(PR_SET_CHILD_SUBREAPER, 1)

    pending: list[int] = []

    def requested(signum: int, _frame: object) -> None:
        pending.append(signum)

    for signum in MANAGED_SIGNALS:
        signal.signal(signum, requested)

    buffered = b""
    if not send_message(result, "READY"):
        return 125
    start_requested = False
    while os.getppid() == expected_parent:
        controls, buffered = read_controls(control, buffered)
        cancellation = pending.pop(0) if pending else None
        for message in controls:
            if message == "PARENT_GONE":
                return 125
            if message == "START":
                start_requested = True
                continue
            try:
                signum = {"HUP": signal.SIGHUP, "INT": signal.SIGINT, "TERM": signal.SIGTERM}[message]
            except KeyError:
                return 125
            if cancellation is None:
                cancellation = signum
        if cancellation is not None:
            status = 128 + cancellation
            if send_result(result, status):
                wait_for_ack(control, expected_parent, buffered)
            return status
        if start_requested:
            break
        time.sleep(0.02)
    else:
        return 125

    signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    controls, buffered = read_controls(control, buffered)
    cancellation = pending.pop(0) if pending else None
    blocked = signal.sigpending()
    if cancellation is None:
        cancellation = next((signum for signum in MANAGED_SIGNALS if signum in blocked), None)
    for message in controls:
        if message == "PARENT_GONE":
            signal.pthread_sigmask(signal.SIG_UNBLOCK, MANAGED_SIGNALS)
            return 125
        if message == "START":
            continue
        try:
            signum = {"HUP": signal.SIGHUP, "INT": signal.SIGINT, "TERM": signal.SIGTERM}[message]
        except KeyError:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, MANAGED_SIGNALS)
            return 125
        if cancellation is None:
            cancellation = signum
    if cancellation is not None:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, MANAGED_SIGNALS)
        status = 128 + cancellation
        if send_result(result, status):
            wait_for_ack(control, expected_parent, buffered)
        return status
    prctl(PR_SET_PDEATHSIG, 0)
    command = os.fork()
    if command == 0:
        os.close(control)
        os.close(result)
        for signum in MANAGED_SIGNALS:
            signal.signal(signum, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, MANAGED_SIGNALS)
        os.execvp(sys.argv[4], sys.argv[4:])
    signal.pthread_sigmask(signal.SIG_UNBLOCK, MANAGED_SIGNALS)

    command_status: int | None = None
    requested_status = 0
    while command_status is None:
        for pid, status in reap().items():
            if pid == command:
                command_status = status
        controls, buffered = read_controls(control, buffered)
        for control_message in controls:
            if control_message == "PARENT_GONE":
                continue
            try:
                pending.append({"HUP": signal.SIGHUP, "INT": signal.SIGINT, "TERM": signal.SIGTERM}[control_message])
            except KeyError:
                return 125
        if pending:
            signum = pending.pop(0)
            requested_status = 128 + signum
            if not drain(signum):
                return 1
        if command_status is None:
            time.sleep(0.02)

    if group_has_live_members():
        requested_status = 1
        if not drain(signal.SIGTERM):
            return 1
    reap()
    if group_has_live_members():
        return 1
    result_status = requested_status or status_code(command_status)
    if os.getppid() != expected_parent:
        return result_status
    if not send_result(result, result_status):
        return result_status
    wait_for_ack(control, expected_parent, buffered)
    return result_status


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        if isinstance(error, OSError) and error.errno in (errno.EINTR,):
            raise SystemExit(1)
        raise SystemExit(125)
