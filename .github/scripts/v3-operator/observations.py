#!/usr/bin/env python3
"""Secret-safe, read-only Linux observations for V4 live qualification.

This helper never creates a lock, changes a file, signals a process, or invokes
an SBXR role.  It reports metadata and digests so an operator can compare real
OS state without copying protected contents into retained evidence.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
from typing import Any


DEFAULT_ABSENCE_PATHS = (
    "/usr/local/bin/sbxr",
    "/var/lib/sbxr",
    "/var/lib/sbxr/installed.json",
    "/var/lib/sbxr/proxy-ownership.json",
    "/var/lib/sbxr/proxy-ownership.finalizing.json",
    "/var/lib/sbxr/.proxy-ownership.json.next",
    "/var/lib/sbxr/client-identity-target.json",
    "/var/lib/sbxr/client-identity-target.json.sbxr-next",
    "/var/lib/sbxr/subscription-token",
    "/var/lib/sbxr/subscription-serving.json",
    "/var/lib/sbxr/subscription-staging",
    "/var/lib/sbxr/renewal-attempts.json",
    "/var/lib/sbxr/.renewal-attempts.json.next",
    "/var/lib/sbxr/renewal-admission.lock",
    "/var/lib/sbxr/renewal-writer.lock",
    "/etc/sing-box/config.json",
    "/etc/sing-box",
    "/var/lib/sing-box",
    "/etc/apt/sources.list.d/sagernet.sources",
    "/etc/apt/keyrings/sagernet.asc",
    "/lib/systemd/system/sing-box.service",
    "/usr/lib/systemd/system/sing-box.service",
    "/etc/systemd/system/sbxr-subscription.service",
    "/etc/systemd/system/sbxr-subscription-firewall.service",
    "/etc/systemd/system/multi-user.target.wants/sbxr-subscription.service",
    "/etc/systemd/system/multi-user.target.wants/sbxr-subscription-firewall.service",
    "/etc/systemd/system/sbxr-subscription.service.sbxr-next",
    "/etc/systemd/system/snap.certbot.renew.service.d",
    "/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf",
    "/etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription",
    "/etc/letsencrypt/renewal-hooks/post/sbxr-subscription",
    "/etc/letsencrypt/live/sbxr-subscription",
    "/etc/letsencrypt/archive/sbxr-subscription",
    "/etc/letsencrypt/renewal/sbxr-subscription.conf",
)

CERTBOT_LOCK_PATHS = (
    "/etc/letsencrypt/.certbot.lock",
    "/var/lib/letsencrypt/.certbot.lock",
    "/var/log/letsencrypt/.certbot.lock",
)


def _digest(path: Path, expected: os.stat_result) -> str:
    value = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino) or not stat.S_ISREG(opened.st_mode):
            raise OSError("path identity changed while opening")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            value.update(block)
        after = path.lstat()
        if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("path identity changed while hashing")
    finally:
        os.close(descriptor)
    return value.hexdigest()


def observe_path(raw_path: str) -> dict[str, Any]:
    path = Path(raw_path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"path": raw_path, "state": "absent"}
    except OSError as error:
        return {"path": raw_path, "state": "unknown", "errno": error.errno}
    kind = "other"
    if stat.S_ISREG(info.st_mode):
        kind = "file"
    elif stat.S_ISDIR(info.st_mode):
        kind = "directory"
    elif stat.S_ISLNK(info.st_mode):
        kind = "symlink"
    result: dict[str, Any] = {
        "path": raw_path,
        "state": "present",
        "kind": kind,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "uid": info.st_uid,
        "gid": info.st_gid,
        "nlink": info.st_nlink,
        "size": info.st_size,
        "device": info.st_dev,
        "inode": info.st_ino,
    }
    if kind == "file":
        try:
            result["sha256"] = _digest(path, info)
        except OSError as error:
            result["state"] = "unknown"
            result["errno"] = error.errno
    return result


_FLOCK = struct.Struct("@hhqqi")


def observe_lock(raw_path: str) -> dict[str, Any]:
    result = observe_path(raw_path)
    if result["state"] != "present":
        result["lock_state"] = "absent" if result["state"] == "absent" else "unknown"
        return result
    if result.get("kind") != "file" or result.get("nlink") != 1:
        result["lock_state"] = "unsafe"
        return result
    before = (result["device"], result["inode"])
    try:
        descriptor = os.open(raw_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            request = _FLOCK.pack(fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
            response = fcntl.fcntl(descriptor, fcntl.F_GETLK, request)
            lock_type, _, _, _, holder = _FLOCK.unpack(response[: _FLOCK.size])
            current = os.fstat(descriptor)
            after = os.lstat(raw_path)
            if before != (current.st_dev, current.st_ino) or before != (after.st_dev, after.st_ino):
                result["lock_state"] = "unknown"
            elif lock_type == fcntl.F_UNLCK:
                result["lock_state"] = "unlocked"
            else:
                result["lock_state"] = "locked"
                result["holder_pid"] = holder
        finally:
            os.close(descriptor)
    except OSError as error:
        result["lock_state"] = "unknown"
        result["errno"] = error.errno
    return result


def observe_flock(raw_path: str, locks_path: str = "/proc/locks") -> dict[str, Any]:
    """Observe Linux BSD flock holders through procfs without taking a lock."""
    result = observe_path(raw_path)
    if result["state"] != "present":
        result["lock_state"] = "absent" if result["state"] == "absent" else "unknown"
        return result
    if result.get("kind") != "file" or result.get("nlink") != 1:
        result["lock_state"] = "unsafe"
        return result
    wanted = (os.major(result["device"]), os.minor(result["device"]), result["inode"])
    holders = []
    try:
        for line in Path(locks_path).read_text().splitlines():
            fields = line.split()
            if len(fields) < 8 or fields[1] != "FLOCK":
                continue
            device = fields[5].split(":")
            if len(device) != 3:
                continue
            identity = (int(device[0], 16), int(device[1], 16), int(device[2]))
            if identity == wanted:
                holders.append({"mode": fields[3], "pid": int(fields[4])})
        after = os.lstat(raw_path)
        if wanted != (os.major(after.st_dev), os.minor(after.st_dev), after.st_ino):
            result["lock_state"] = "unknown"
        else:
            result["lock_state"] = "locked" if holders else "unlocked"
            result["holders"] = holders
    except (OSError, ValueError) as error:
        result["lock_state"] = "unknown"
        result["error"] = type(error).__name__
    return result


def observe_process(pid: int) -> dict[str, Any]:
    root = Path(f"/proc/{pid}")
    try:
        stat_fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
        command = [part for part in (root / "cmdline").read_bytes().split(b"\0") if part]
        if not command:
            raise ValueError("process arguments unavailable")
        command_digest = hashlib.sha256(b"\0".join(command) + b"\0").hexdigest()
        children = [int(value) for value in
                    (root / "task" / str(pid) / "children").read_text().split()]
        return {
            "pid": pid,
            "state": stat_fields[0],
            "parent_pid": int(stat_fields[1]),
            "process_group": int(stat_fields[2]),
            "session": int(stat_fields[3]),
            "start_tick": int(stat_fields[19]),
            "executable": os.readlink(root / "exe"),
            "argument_count": len(command),
            "arguments_sha256": command_digest,
            "children": children,
            "observation": "complete",
        }
    except (FileNotFoundError, ProcessLookupError):
        return {"pid": pid, "observation": "absent"}
    except (OSError, ValueError, IndexError) as error:
        return {"pid": pid, "observation": "unknown", "error": type(error).__name__}


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    absence = subparsers.add_parser("absence")
    absence.add_argument("paths", nargs="*")
    locks = subparsers.add_parser("locks")
    locks.add_argument("paths", nargs="*")
    flocks = subparsers.add_parser("flocks")
    flocks.add_argument("paths", nargs="+")
    process = subparsers.add_parser("process")
    process.add_argument("pid", type=int)
    options = parser.parse_args(arguments)
    if options.command == "absence":
        paths = options.paths or DEFAULT_ABSENCE_PATHS
        observations = [observe_path(path) for path in paths]
        all_absent = all(item["state"] == "absent" for item in observations)
        document = {"schema": "sbxr-v4-absence-observation-v1", "observations": observations,
                    "all_absent": all_absent}
        status = 0 if all_absent else 1
    elif options.command in ("locks", "flocks"):
        if sys.platform != "linux":
            parser.error("lock observation requires Linux")
        paths = options.paths or CERTBOT_LOCK_PATHS
        observer = observe_lock if options.command == "locks" else observe_flock
        document = {"schema": "sbxr-v4-lock-observation-v1",
                    "lock_api": "posix" if options.command == "locks" else "flock",
                    "observations": [observer(path) for path in paths]}
        status = 0 if all(item["lock_state"] not in ("unknown", "unsafe")
                          for item in document["observations"]) else 1
    else:
        if sys.platform != "linux" or options.pid < 1:
            parser.error("process observation requires a positive Linux PID")
        document = {"schema": "sbxr-v4-process-observation-v1",
                    "process": observe_process(options.pid)}
        status = 0 if document["process"]["observation"] != "unknown" else 1
    print(json.dumps(document, sort_keys=True, separators=(",", ":")))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
