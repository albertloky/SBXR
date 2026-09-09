#!/usr/bin/env python3
"""Validate that one successful outside connection spans a remote action."""
import datetime
import hashlib
import json
import re
import sys

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-key")
        result[key] = value
    return result


def timestamp(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp")
    parsed = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != datetime.timezone.utc:
        raise ValueError("timestamp")
    return parsed


def validate(path, scenario_started, action_started, action_completed, deadline_unix, request_sha256):
    with open(path, "rb") as stream:
        raw = stream.read()
    if not raw.endswith(b"\n") or len(raw) > 1_000_000:
        raise ValueError("bounded-jsonl")
    rows = [json.loads(line, object_pairs_hook=unique) for line in raw.splitlines()]
    if len(rows) < 2:
        raise ValueError("coverage")
    expected_keys = {"check", "connection_id", "request_sha256", "same_connection", "schema", "time"}
    connection = rows[0].get("connection_id")
    if not isinstance(connection, str) or re.fullmatch(r"[0-9a-f]{32}", connection) is None or re.fullmatch(r"[0-9a-f]{64}", request_sha256) is None:
        raise ValueError("connection-id")
    times = []
    for number, row in enumerate(rows, 1):
        if set(row) != expected_keys or row["schema"] != "sbxr-v3-connection-probe-v1" or row["check"] != number or row["connection_id"] != connection or row["request_sha256"] != request_sha256 or row["same_connection"] is not True:
            raise ValueError("sequence")
        times.append(timestamp(row["time"]))
    scenario = timestamp(scenario_started); started = timestamp(action_started); completed = timestamp(action_completed)
    deadline = datetime.datetime.fromtimestamp(deadline_unix, datetime.timezone.utc)
    if not scenario <= times[0] <= started <= completed <= times[-1] <= deadline or any(left >= right for left, right in zip(times, times[1:])):
        raise ValueError("action-coverage")
    return {"action_spanned": True, "checks": len(rows), "same_connection": True,
            "trace_sha256": hashlib.sha256(raw).hexdigest()}


if __name__ == "__main__":
    try:
        print(json.dumps(validate(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), sys.argv[6]), separators=(",", ":")))
    except Exception:
        print('{"connection_observation_failed":true}', file=sys.stderr)
        raise SystemExit(1)
