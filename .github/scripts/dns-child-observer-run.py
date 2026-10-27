#!/usr/bin/env python3
"""Unqualified Linux observer wrapper; never sends product input.

Only future explicitly authorized Linux integration may execute main(). Inert
unit tests exercise the launch specification and barrier without subprocesses.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location("dns_observer", Path(__file__).with_name("dns-child-observer.py"))
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
NOTIFY = "__BPFTRACE_NOTIFY_PROBES_ATTACHED"


def launch_spec(binary, program):
    # v0.23.0 src/bpftrace.cpp emits NOTIFY only after both attachment loops.
    # No inherited config, missing-probe warnings, -p (which filters out the child),
    # -c, shell, unsafe mode or extra CLI arguments are permitted.
    if not all(re.fullmatch(r"/[A-Za-z0-9_./-]+", p) and ".." not in p.split("/")
               for p in (binary, program)):
        raise ValueError("invalid wrapper path")
    return [binary, "-q", "-B", "none", program], {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
        NOTIFY: "1", "BPFTRACE_MISSING_PROBES": "error",
        "BPFTRACE_MAX_MAP_KEYS": "64", "BPFTRACE_PERF_RB_PAGES": "8",
        "BPFTRACE_COLOR": "never",
    }


class AttachmentBarrier:
    """Consumes only the pinned observer's stdout, with a fail-closed error latch."""
    def __init__(self, pid):
        self.pid = pid
        self.attached = None
        self.starting = None
        self.failed = False
        self.ended = False

    def reject(self):
        self.failed = True
        raise ValueError("attachment barrier refused")

    def stderr(self, data):
        if data:
            self.reject()

    def stdout(self, line, monotonic_ns):
        if self.failed or self.ended:
            self.reject()
        if line == NOTIFY:
            if self.attached is not None:
                self.reject()
            self.attached = monotonic_ns
            return f"ATTACHED {self.pid} {monotonic_ns}\n"
        if line.startswith("STARTING "):
            fields = line.split()
            if (self.starting is not None or len(fields) != 3 or
                    fields[1] != str(self.pid) or not fields[2].isdigit()):
                self.reject()
            self.starting = int(fields[2])
            if self.attached is not None and self.starting > self.attached:
                self.reject()
        elif not self.ready:
            self.reject()
        elif line.startswith(("BAD ", "DONE ")):
            if line.startswith("BAD "):
                self.reject()
            self.ended = True
        elif not line.startswith(("BEGIN ", "FORK ", "SPAWN ", "WAIT ", "EXIT ", "FINISH ")):
            self.reject()
        if line.startswith(("BEGIN ", "FORK ", "SPAWN ", "WAIT ", "EXIT ", "FINISH ")):
            fields = line.split()
            if len(fields) < 4 or not fields[3].isdigit() or int(fields[3]) <= self.attached:
                self.reject()
        return line + "\n"

    @property
    def ready(self):
        return (not self.failed and not self.ended and self.starting is not None and
                self.attached is not None and self.starting <= self.attached)


def run(args):
    if sys.platform != "linux":
        raise ValueError("Linux integration only")
    binary = Path(args.bpftrace)
    # The supplied digest must be independently reviewed as the v0.23.0 build
    # with the notification semantics above. Version text alone is insufficient.
    if (not re.fullmatch(r"[0-9a-f]{64}", args.bpftrace_sha256) or
            hashlib.sha256(binary.read_bytes()).hexdigest() != args.bpftrace_sha256):
        raise ValueError("observer binary identity refused")
    args.output.mkdir(mode=0o700, exist_ok=False)
    program = args.output / "observer.bt"
    program.write_text(observer.render(args.executable, args.symbol, args.pid))
    command, env = launch_spec(str(binary), str(program.absolute()))
    barrier = AttachmentBarrier(args.pid)
    capture, errors, pending = bytearray(), bytearray(), bytearray()
    announced = False
    expires = time.monotonic() + 100
    child = None
    try:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env, close_fds=True)
        with selectors.DefaultSelector() as selector:
            for stream, label in ((child.stdout, "out"), (child.stderr, "err")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                if time.monotonic() >= expires:
                    raise ValueError("outer observer budget exhausted")
                for key, _ in selector.select(min(.1, max(0, expires - time.monotonic()))):
                    data = os.read(key.fd, 4096)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "err":
                        errors.extend(data[:8192 - len(errors)])
                        barrier.stderr(data)
                    pending.extend(data)
                    if len(pending) > 65536:
                        raise ValueError("observer input bound")
                    while b"\n" in pending:
                        raw, _, rest = pending.partition(b"\n")
                        pending[:] = rest
                        if len(raw) > 256:
                            raise ValueError("observer line bound")
                        line = barrier.stdout(raw.decode("ascii"), time.monotonic_ns())
                        capture.extend(line.encode("ascii"))
                        if len(capture) > 65536:
                            raise ValueError("observer capture bound")
                if barrier.ready and not announced:
                    if child.poll() is not None:
                        raise ValueError("observer exited before barrier")
                    # This is notification only. The wrapper never releases/feeds
                    # the product; its caller must retain its existing deadline.
                    print(f"SBXR_DNS_OBSERVER_ATTACHED {args.pid}", flush=True)
                    announced = True
            if pending or child.wait(timeout=2) != 0:
                raise ValueError("observer incomplete or failed")
        observer.parse_capture(capture.decode("ascii"), args.pid)
    finally:
        try:
            if child is not None:
                try:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=2)
                finally:
                    child.stdout.close()
                    child.stderr.close()
        finally:
            (args.output / "observer.stdout").write_bytes(capture)
            (args.output / "observer.stderr").write_bytes(errors)
    # A passing parser result still does not certify kernel coverage or cleanup.


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bpftrace", "bpftrace-sha256", "executable", "symbol"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        run(args)
    except (ValueError, OSError, subprocess.TimeoutExpired):
        parser.exit(1, "observer refused or cleanup unproved; no diagnostic conclusion\n")
