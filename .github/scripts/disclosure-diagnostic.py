#!/usr/bin/env python3
"""Private diagnostic handoff; never runs SBXR or emits qualification evidence."""
import argparse
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


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(value))


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


def context(root, manifest, now):
    raw = read(manifest)
    value = json.loads(raw, object_pairs_hook=pairs)
    attempt = value["v3_attempt"]
    window = attempt["diagnostic"]
    if (set(window) != {"start_unix", "test_until_unix", "finish_unix"} or
            any(type(n) is not int for n in window.values()) or
            window["start_unix"] <= 0 or
            window["test_until_unix"] != window["start_unix"] + 7200 or
            window["finish_unix"] != window["start_unix"] + 10800 or
            not window["start_unix"] <= now < window["finish_unix"] or
            attempt["required_scenarios"] != ["mvp-install"] or
            attempt.get("karing_response_limit_seconds", 0) != 0 or
            value["schema"] != "sbxr-qualification-manifest-v3"):
        raise ValueError("diagnostic scope differs")
    identity = attempt["attempt_id"]
    if not re.fullmatch(r"run-[1-9][0-9]*-attempt-[1-9][0-9]*", identity):
        raise ValueError("diagnostic identity differs")
    return root / ("sbxr-diagnostic-" + identity), digest(raw), window


def prepare(root, manifest, now):
    target, binding, window = context(root, manifest, now)
    # The same ordinary 30-minute request bounds all product actions. Reserve
    # at least 15 minutes for the existing M1 guarded removal envelope.
    deadline = min(now + 1800, window["finish_unix"] - 60)
    test_until = min(deadline - 900, window["test_until_unix"])
    if test_until <= now:
        raise ValueError("insufficient diagnostic/restoration time")
    before = retained(root)
    target.mkdir(mode=0o700)  # Refuses an existing directory, including symlinks.
    request = {"deadline_unix": deadline, "diagnostic_test_until_unix": test_until,
               "not_before": dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "qualification_manifest_sha256": binding,
               "required_checks": ["diagnostic-observation"], "scenario_id": "mvp-install", "scenario_limit_seconds": 1800}
    write_new(target / "request.json", request)
    state = {"manifest_sha256": binding, "request_sha256": digest(canonical(request)),
             "directory_identity": directory(target), "retained": before,
             "test_until_unix": test_until, "deadline_unix": deadline}
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
    parser.add_argument("operation", choices=("prepare", "status"))
    parser.add_argument("--state-sha256")
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("root required")
    root = Path("/root")
    manifest = root / "sbxr-qualification-v3/qualification-manifest.json"
    if not re.fullmatch(r"[a-f0-9]{64}", args.manifest_sha256) or digest(read(manifest)) != args.manifest_sha256:
        raise ValueError("staged manifest differs from verified workflow bytes")
    now = int(time.time())
    if args.operation == "prepare":
        print(canonical(prepare(root, manifest, now)).decode())
    else:
        print(status(root, manifest, args.state_sha256, now))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError):
        print("Diagnostic handoff refused; preserve evidence and inspect state.", file=sys.stderr)
        raise SystemExit(1)
