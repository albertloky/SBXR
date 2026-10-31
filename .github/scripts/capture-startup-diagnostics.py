#!/usr/bin/env python3
"""Filter an already approved journal JSONL read; never invokes SSH/systemctl.
Raw records are not written. A private new output contains only fixed categories.
"""
import json
import os
from pathlib import Path
import re
import stat
import sys

STAGES = "build admission lock connect peer descriptor installed authority material unit sandbox public-ip configuration bind ready lender-binding lender-peer lender-role lender-recheck lender-send lender-accept".split()
RECORD = re.compile(r"SBXR_START_V1 role=(serving|lender) stage=(" + "|".join(STAGES) + r") result=(ok|refused|busy|cancelled|deadline) first=(none|" + "|".join(STAGES) + r") elapsed_ms=([0-9]{1,7}) stage_ms=([0-9]{1,7})\n?")
MAX_INPUT = 1 << 20

def capture(stream, output):
    # Open and bind the final parent without following its final symlink.
    # The caller supplies its existing private evidence directory.
    path = Path(output)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(parent)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ValueError("private-parent-required")
        total = 0
        records = []
        while True:
            line = stream.readline(MAX_INPUT + 1)
            if not line:
                break
            total += len(line)
            if total > MAX_INPUT:
                raise ValueError("input-limit")
            row = json.loads(line)
            message = row.get("MESSAGE") if isinstance(row, dict) else None
            if not isinstance(message, str) or not message.startswith("SBXR_START_V1"):
                continue
            match = RECORD.fullmatch(message)
            if not match or row.get("_SYSTEMD_UNIT") != "sbxr-subscription.service":
                raise ValueError("invalid-diagnostic")
            role, stage, result, first, elapsed, stage_ms = match.groups()
            if role != "serving" or int(stage_ms) > int(elapsed) or int(elapsed) > 1200000:
                raise ValueError("invalid-diagnostic")
            records.append(dict(role=role, stage=stage, result=result, first=first,
                                elapsed_ms=int(elapsed), stage_ms=int(stage_ms)))
            if len(records) > 32:
                raise ValueError("record-limit")
        if not records:
            raise ValueError("no-diagnostics")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "w") as target:
            json.dump({"schema": 1, "records": records}, target, sort_keys=True)
            target.write("\n")
    finally:
        os.close(parent)

if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("output-required")
        capture(sys.stdin.buffer, sys.argv[1])
    except (OSError, ValueError, TypeError):
        sys.exit("startup diagnostic capture refused")
