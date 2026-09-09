#!/usr/bin/env python3
"""Reversibly hide the supported Certbot service unit for scenario 15.

The helper never starts the service and never edits its bytes. It stops only the
timer, renames the exact unit on the same filesystem, reloads systemd, and can
restore the same inode plus the timer's original enabled/active state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Callable


UNIT = Path("/etc/systemd/system/snap.certbot.renew.service")
HIDDEN = Path("/etc/systemd/system/snap.certbot.renew.service.sbxr-qualification-hidden")
TIMER = "snap.certbot.renew.timer"
SERVICE = "snap.certbot.renew.service"
STATE = Path("/run/sbxr-qualification/unsupported-route-state.json")


def run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError("unit is not a one-link regular file")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            value.update(block)
        current = path.lstat()
        if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise RuntimeError("unit identity changed while hashing")
    finally:
        os.close(descriptor)
    return value.hexdigest()


def identity(path: Path, owner_uid: int = 0) -> dict[str, int | str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or info.st_nlink != 1 or info.st_mode & 0o022:
        raise RuntimeError("unit metadata is unsafe")
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
            "gid": info.st_gid, "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            "size": info.st_size, "sha256": digest(path)}


def timer_state(command: Callable[[list[str], bool], subprocess.CompletedProcess[str]]) -> dict[str, str]:
    enabled = command(["systemctl", "is-enabled", TIMER], False).stdout.strip()
    active = command(["systemctl", "is-active", TIMER], False).stdout.strip()
    if enabled not in ("enabled", "disabled") or active not in ("active", "inactive"):
        raise RuntimeError("timer state is unsupported")
    if command(["systemctl", "is-active", SERVICE], False).stdout.strip() != "inactive":
        raise RuntimeError("Certbot service is active")
    persistent = command(["systemctl", "show", "--property=Persistent", "--value", TIMER], True).stdout.strip()
    if persistent not in ("no", "false"):
        raise RuntimeError("persistent timer cannot be restored without a start risk")
    return {"enabled": enabled, "active": active, "persistent": persistent}


def service_marker(command) -> dict[str, str]:
    marker = {}
    for property_name in ("InvocationID", "ExecMainStartTimestampMonotonic", "ActiveEnterTimestampMonotonic"):
        marker[property_name] = command(
            ["systemctl", "show", "--property=" + property_name, "--value", SERVICE], True
        ).stdout.strip()
    return marker


def save_state(document: dict) -> None:
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, (json.dumps(document, sort_keys=True) + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_state() -> dict:
    descriptor = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return json.loads(os.read(descriptor, 1 << 20))
    finally:
        os.close(descriptor)


def restore_timer(document: dict, command) -> None:
    command(["systemctl", "enable" if document["timer"]["enabled"] == "enabled" else "disable", TIMER], True)
    command(["systemctl", "start" if document["timer"]["active"] == "active" else "stop", TIMER], True)
    if timer_state(command) != document["timer"]:
        raise RuntimeError("timer state was not restored")


def inject(command=run) -> dict:
    if STATE.exists() or HIDDEN.exists() or not UNIT.exists():
        raise RuntimeError("route control is not clean")
    before = identity(UNIT)
    timer = timer_state(command)
    document = {"schema": "sbxr-v4-route-control-v1", "unit": before,
                "timer": timer, "service_marker": service_marker(command),
                "original": str(UNIT), "hidden": str(HIDDEN)}
    save_state(document)
    try:
        command(["systemctl", "stop", TIMER], True)
        if command(["systemctl", "is-active", SERVICE], False).stdout.strip() != "inactive":
            raise RuntimeError("Certbot service became active")
        os.rename(UNIT, HIDDEN)
        if identity(HIDDEN) != before:
            raise RuntimeError("unit identity changed during rename")
        command(["systemctl", "daemon-reload"], True)
        return document
    except Exception:
        if HIDDEN.exists() and not UNIT.exists():
            os.rename(HIDDEN, UNIT)
            command(["systemctl", "daemon-reload"], False)
        if UNIT.exists() and not HIDDEN.exists() and identity(UNIT) == before:
            try:
                restore_timer(document, command)
                if service_marker(command) != document["service_marker"]:
                    raise RuntimeError("Certbot service executed during failed route control")
                STATE.unlink()
            except Exception:
                pass
        raise


def restore(command=run) -> dict:
    if not STATE.is_file():
        raise RuntimeError("route control state is incomplete")
    document = read_state()
    if document.get("schema") != "sbxr-v4-route-control-v1":
        raise RuntimeError("route control state is invalid")
    if command(["systemctl", "is-active", SERVICE], False).stdout.strip() != "inactive":
        raise RuntimeError("Certbot service is active")
    if HIDDEN.exists() and not UNIT.exists():
        if identity(HIDDEN) != document.get("unit"):
            raise RuntimeError("hidden unit no longer matches")
        os.rename(HIDDEN, UNIT)
    elif not UNIT.exists() or HIDDEN.exists() or identity(UNIT) != document.get("unit"):
        raise RuntimeError("unit restore state is ambiguous")
    command(["systemctl", "daemon-reload"], True)
    if identity(UNIT) != document["unit"]:
        raise RuntimeError("restored unit does not match")
    restore_timer(document, command)
    if service_marker(command) != document.get("service_marker"):
        raise RuntimeError("Certbot service executed during route control")
    STATE.unlink()
    return {"schema": document["schema"], "restored": True, "unit": document["unit"],
            "timer": document["timer"]}


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("inject", "restore"))
    options = parser.parse_args(arguments)
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("root on Linux is required")
    result = inject() if options.operation == "inject" else restore()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
