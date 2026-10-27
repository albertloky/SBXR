#!/usr/bin/env python3
"""Render only; never attach, launch, signal, drive a menu or confer readiness."""
import argparse
import json
from pathlib import Path
import re


def render(executable, symbol, pid):
    # No shell/probe expressions, wildcard symbols, alternate providers or offsets.
    if (type(pid) is not int or not 1 < pid <= 2**31 - 1 or
            not re.fullmatch(r"/[A-Za-z0-9_./-]+", executable) or
            ".." in executable.split("/") or
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.$]*", symbol) or
            "dns_child_observer_hook" not in symbol):
        raise ValueError("invalid exact observer target")
    template = Path(__file__).with_suffix(".bt.in").read_text()
    return template.replace("TARGET_PID", str(pid)).replace("TARGET_EXE", executable).replace("TARGET_SYMBOL", symbol)


def parse_capture(text, expected_pid):
    """Strict offline evidence check. Missing/lost/ambiguous evidence is unknown.

    Input must be bpftrace's quiet stdout, with separate stderr checked for losses
    by the operator. This checker cannot prove attachment or kernel delivery.
    """
    if len(text.encode()) > 65536:
        raise ValueError("capture bound")
    sizes = {"STARTING": 2, "ATTACHED": 2, "BEGIN": 3, "FORK": 3, "SPAWN": 3,
             "WAIT": 6, "EXIT": 7, "FINISH": 3, "DONE": 1}
    records = []
    for line in text.splitlines():
        parts = line.split()
        if (not parts or parts[0] not in sizes or len(parts) != sizes[parts[0]] + 1 or
                any(not re.fullmatch(r"[0-9]{1,20}", v) for v in parts[1:])):
            raise ValueError("unknown or invalid observer record")
        values = list(map(int, parts[1:]))
        if any(v > 2**64 - 1 for v in values):
            raise ValueError("numeric bound")
        records.append((parts[0], values))
    if len(records) > 291:
        raise ValueError("record bound")
    starting = [v for k, v in records if k == "STARTING"]
    ready = [v for k, v in records if k == "ATTACHED"]
    done = [v for k, v in records if k == "DONE"]
    if (len(starting) != 1 or starting[0][0] != expected_pid or
            len(ready) != 1 or ready[0][0] != expected_pid or len(done) != 1 or
            not starting[0][1] <= ready[0][1] <= done[0][0] or
            done[0][0] - starting[0][1] > 100_000_000_000):
        raise ValueError("missing observer lifetime")
    queries = {}
    for kind, v in records:
        if kind in ("STARTING", "ATTACHED", "DONE"):
            continue
        q, child, stamp = v[:3]
        if not q or not ready[0][1] < stamp <= done[0][0]:
            raise ValueError("record outside observer lifetime")
        queries.setdefault(q, []).append((kind, v))
    if not 0 < len(queries) <= 32:
        raise ValueError("query bound")
    result = []
    lifetimes = {}
    parent_scopes = {}
    waits = 0
    for q, rows in sorted(queries.items()):
        one = {}
        for kind in ("BEGIN", "FORK", "SPAWN", "EXIT", "FINISH"):
            matches = [v for k, v in rows if k == kind]
            if len(matches) != 1:
                raise ValueError("missing or duplicate child lifetime")
            one[kind] = matches[0]
        child = one["FORK"][1]
        if (not 1 < one["BEGIN"][1] <= 2**31 - 1 or
                not 1 < child <= 2**31 - 1 or
                any(one[k][1] != child for k in ("SPAWN", "EXIT", "FINISH")) or
                not one["BEGIN"][2] <= one["FORK"][2] <= one["SPAWN"][2] <= one["FINISH"][2] or
                not one["FORK"][2] <= one["EXIT"][2] <= one["FINISH"][2]):
            raise ValueError("child identity or ordering mismatch")
        parent, scope_start, scope_end = one["BEGIN"][1], one["BEGIN"][2], one["FINISH"][2]
        for old_start, old_end in parent_scopes.get(parent, []):
            if scope_start <= old_end and old_start <= scope_end:
                raise ValueError("overlapping parent query scopes")
        parent_scopes.setdefault(parent, []).append((scope_start, scope_end))
        start, end = one["FORK"][2], one["EXIT"][2]
        for old_start, old_end in lifetimes.get(child, []):
            if start <= old_end and old_start <= end:
                raise ValueError("overlapping PID lifetimes")
        lifetimes.setdefault(child, []).append((start, end))
        lifetime = end - start
        calls, total, offcpu, expected_waits = one["EXIT"][3:]
        if calls > 4096 or total > lifetime or offcpu > lifetime:
            raise ValueError("invalid accounting")
        slow = []
        last_end = one["FORK"][2]
        wait_rows = sorted((v for k, v in rows if k == "WAIT"), key=lambda v: v[2])
        if len(wait_rows) != expected_waits:
            raise ValueError("missing wait records")
        for v in wait_rows:
            _, c, stamp, nr, duration, partial = v
            if (c != child or not one["FORK"][2] <= stamp <= one["EXIT"][2] or
                    stamp - duration < last_end or nr > 1024 or partial not in (0, 1) or
                    (partial == 1 and stamp != one["EXIT"][2]) or
                    (partial == 0 and duration < 1000000)):
                raise ValueError("invalid wait")
            last_end = stamp
            slow.append(dict(syscall=nr, duration_ns=duration, unfinished=bool(partial)))
        waits += len(slow)
        reported = sum(w["duration_ns"] for w in slow)
        unreported = calls - len(slow)
        # Every unreported call must be completed and strictly below 1 ms.
        # Every unfinished call is reported, including a zero-duration exit_group.
        if (unreported < 0 or reported > total or
                total - reported > unreported * 999_999 or
                sum(w["unfinished"] for w in slow) > 1):
            raise ValueError("wait accounting mismatch")
        result.append(dict(query_id=q, child_pid=child, lifetime_ns=lifetime,
                           syscall_ns=total, offcpu_ns=offcpu, waits=slow))
    if waits > 128:
        raise ValueError("wait bound")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    render_args = commands.add_parser("render", help="render only; no attachment")
    render_args.add_argument("--executable", required=True)
    render_args.add_argument("--symbol", required=True)
    render_args.add_argument("--pid", type=int, required=True)
    check_args = commands.add_parser("check", help="check a bounded saved capture only")
    check_args.add_argument("--capture", type=Path, required=True)
    check_args.add_argument("--pid", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.command == "render":
            print(render(args.executable, args.symbol, args.pid), end="")
        else:
            with args.capture.open("rb") as capture:
                raw = capture.read(65537)
            if len(raw) > 65536:
                raise ValueError("capture bound")
            print(json.dumps(parse_capture(raw.decode("ascii"), args.pid), sort_keys=True))
    except (ValueError, OSError):
        parser.error("observer target or capture refused; no diagnostic conclusion")
