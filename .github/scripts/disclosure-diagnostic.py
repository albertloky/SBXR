#!/usr/bin/env python3
"""Private diagnostic handoff; never runs SBXR or emits qualification evidence."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("unsafe private input")
        body = stream.read(1000001)
        if len(body) > 1000000:
            raise ValueError("input too large")
        return body


def digest(body):
    return hashlib.sha256(body).hexdigest()


def write_bytes_new(path, body):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)


def write_new(path, value):
    write_bytes_new(path, canonical(value))


def directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("unsafe directory")
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]


def retained(root):
    # Exact old evidence is inspected, never opened for writing or renamed.
    found = {}
    for base in (root / "sbxr-qualification-evidence", root / "mvp-observation-draft.json"):
        paths = [base]
        if base.is_dir() and not base.is_symlink():
            directory(base)
            paths += sorted(base.iterdir())
        if len(paths) > 65:
            raise ValueError("retained inventory exceeds bound")
        for path in paths:
            if not os.path.lexists(path):
                found[str(path.relative_to(root))] = None
                continue
            info = path.lstat()
            meta = [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink]
            if stat.S_ISDIR(info.st_mode) and path == base:
                directory(path)
                found[str(path.relative_to(root))] = meta
            else:
                found[str(path.relative_to(root))] = meta + [digest(read(path))]
    return found


def diagnostic_scope(value):
    attempt = value["v3_attempt"]
    window = attempt["diagnostic"]
    if type(window) is not dict:
        raise ValueError("diagnostic window differs")
    clocks = {"start_unix", "test_until_unix", "finish_unix"}
    one_node = window.get("mode") == "karing-one-node"
    if (set(window) != (clocks | {"mode"} if one_node else clocks) or
            any(type(window[key]) is not int for key in clocks) or
            type(attempt.get("scenario_limit_seconds")) is not int or
            attempt["scenario_limit_seconds"] != (2700 if one_node else 1800) or
            window["start_unix"] <= 0 or
            window["test_until_unix"] != window["start_unix"] + 7200 or
            window["finish_unix"] != window["start_unix"] + 10800 or
            attempt["required_scenarios"] != ["mvp-install"] or
            attempt.get("attended_finish_by") or attempt.get("owner_exception") or attempt.get("proxy_profile") or
            attempt.get("karing_response_limit_seconds", 0) != 0 or
            value["schema"] != "sbxr-qualification-manifest-v3"):
        raise ValueError("diagnostic scope differs")
    identity = attempt["attempt_id"]
    if not re.fullmatch(r"run-[1-9][0-9]*-attempt-[1-9][0-9]*", identity):
        raise ValueError("diagnostic identity differs")
    return identity, window


def context(root, manifest, now):
    raw = read(manifest)
    identity, window = diagnostic_scope(json.loads(raw, object_pairs_hook=pairs))
    if not window["start_unix"] <= now < window["finish_unix"]:
        raise ValueError("diagnostic scope differs")
    return root / ("sbxr-diagnostic-" + identity), digest(raw), window


def parse_deadline(value):
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value):
        raise ValueError("diagnostic protected deadline differs")
    return int(value)


def request_times(window, now, runtime_deadline=None):
    one_node = window.get("mode") == "karing-one-node"
    limit, reserve = (2700, 1500) if one_node else (1800, 900)
    deadline = min(now + limit, window["finish_unix"] - 60)
    if one_node:
        deadline = min(deadline, runtime_deadline)
    test_until = min(deadline - reserve, window["test_until_unix"])
    if test_until - now < (limit - reserve if one_node else 1):
        raise ValueError("insufficient diagnostic/restoration time")
    return limit, deadline, test_until


def check_admission(manifest, security_cutoff, now):
    value = json.loads(read(manifest), object_pairs_hook=pairs)
    if type(value) is not dict or type(value.get("v3_attempt")) is not dict:
        raise ValueError("diagnostic scope differs")
    window = value["v3_attempt"].get("diagnostic")
    if window is None:
        return
    _, window = diagnostic_scope(value)
    if window.get("mode") != "karing-one-node":
        return
    if now < window["start_unix"]:
        raise ValueError("diagnostic scope differs")
    # Transport stores the explicit approved cutoff minus its one-minute
    # teardown margin. The host rechecks the actual stored runtime deadline.
    request_times(window, now, parse_deadline(security_cutoff) - 60)


def prepare(root, manifest, now, *, clock=None, clock_sha256=None, current_time=None):
    target, binding, window = context(root, manifest, now)
    one_node = window.get("mode") == "karing-one-node"
    check = "diagnostic-karing-one-node" if one_node else "diagnostic-observation"
    if one_node:
        if type(clock) is not bytes or not 0 < len(clock) <= 65536 or digest(clock) != clock_sha256:
            raise ValueError("diagnostic recorder differs")
    elif clock is not None or clock_sha256 is not None:
        raise ValueError("diagnostic recorder not declared")
    before = retained(root)
    runtime_deadline = None
    if one_node:
        runtime = read(manifest.with_name("runtime-deadline")).decode("ascii").removesuffix("\n")
        runtime_deadline = parse_deadline(runtime)
        # Evidence inventory may consume the last seconds of the allowance.
        if current_time is not None:
            request_start = current_time()
            if request_start < now:
                raise ValueError("diagnostic clock moved backwards")
            now = request_start
    limit, deadline, test_until = request_times(window, now, runtime_deadline)
    target.mkdir(mode=0o700)  # Refuses an existing directory, including symlinks.
    request = {"deadline_unix": deadline, "diagnostic_test_until_unix": test_until,
               "not_before": dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "qualification_manifest_sha256": binding,
               "required_checks": [check], "scenario_id": "mvp-install", "scenario_limit_seconds": limit}
    write_new(target / "request.json", request)
    state = {"manifest_sha256": binding, "request_sha256": digest(canonical(request)),
             "directory_identity": directory(target), "retained": before,
             "test_until_unix": test_until, "deadline_unix": deadline}
    if one_node:
        path = target / "mvp-observe.py"
        write_bytes_new(path, clock)
        if digest(read(path)) != clock_sha256:
            raise ValueError("staged diagnostic recorder differs")
        state["clock_sha256"] = clock_sha256
    write_new(target / "state.json", state)
    return {"directory": str(target), "state_sha256": digest(canonical(state)),
            "test_until_unix": test_until, "deadline_unix": deadline}


def status(root, manifest, state_sha256, now):
    target, binding, window = context(root, manifest, now)
    state_raw = read(target / "state.json")
    state = json.loads(state_raw, object_pairs_hook=pairs)
    if (digest(state_raw) != state_sha256 or state["manifest_sha256"] != binding or
            directory(target) != state["directory_identity"] or retained(root) != state["retained"] or
            digest(read(target / "request.json")) != state["request_sha256"]):
        raise ValueError("diagnostic preservation binding changed")
    if window.get("mode") == "karing-one-node" and digest(read(target / "mvp-observe.py")) != state["clock_sha256"]:
        raise ValueError("staged diagnostic recorder changed")
    if now >= min(state["deadline_unix"], window["finish_unix"] - 60):
        raise ValueError("diagnostic deadline expired")
    done = target / "operator-finished.json"
    if not os.path.lexists(done):
        return "restore-now" if now >= state["test_until_unix"] else "waiting"
    notice = json.loads(read(done), object_pairs_hook=pairs)
    if notice != {"manifest_sha256": binding, "request_sha256": state["request_sha256"], "status": "operator-finished"}:
        raise ValueError("operator notice differs")
    # This is an additional absence check, never a replacement for the full
    # frozen host/client/secret preservation and supported-removal review.
    if any(os.path.lexists(p) for p in (root.parent / "usr/local/bin/sbxr", root.parent / "var/lib/sbxr")):
        raise ValueError("candidate product remains")
    return "operator-finished"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "status", "check-admission"))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--security-cutoff-unix")
    parser.add_argument("--state-sha256")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--clock-base64")
    parser.add_argument("--clock-sha256")
    args = parser.parse_args()
    if args.operation == "check-admission":
        if args.manifest is None or args.security_cutoff_unix is None:
            parser.error("check-admission requires the manifest and security cutoff")
        check_admission(args.manifest, args.security_cutoff_unix, int(time.time()))
        return
    if args.manifest_sha256 is None:
        parser.error("a staged manifest digest is required")
    if os.geteuid() != 0:
        raise ValueError("root required")
    root = Path("/root")
    manifest = root / "sbxr-qualification-v3/qualification-manifest.json"
    if not re.fullmatch(r"[a-f0-9]{64}", args.manifest_sha256) or digest(read(manifest)) != args.manifest_sha256:
        raise ValueError("staged manifest differs from verified workflow bytes")
    now = int(time.time())
    if args.operation == "prepare":
        clock = base64.b64decode(args.clock_base64, validate=True) if args.clock_base64 is not None else None
        print(canonical(prepare(root, manifest, now, clock=clock,
                                clock_sha256=args.clock_sha256, current_time=lambda: int(time.time()))).decode())
    else:
        print(status(root, manifest, args.state_sha256, now))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError):
        print("Diagnostic handoff refused; preserve evidence and inspect state.", file=sys.stderr)
        raise SystemExit(1)
