#!/usr/bin/env python3
"""Record explicit operator observations as they happen; never run product actions."""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


class Refusal(ValueError):
    pass


def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise Refusal("duplicate JSON member")
        value[key] = item
    return value


def load(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise Refusal("input must be an owned, private, one-link regular file")
        raw = stream.read(1000001)
    if not raw or len(raw) > 1000000:
        raise Refusal("input exceeds byte bound")
    return json.loads(raw, object_pairs_hook=pairs), raw


def stamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(value):
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        raise Refusal("invalid observation time")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def publish(path, value, replace=False):
    path = Path(path)
    if not replace and os.path.lexists(path):
        raise Refusal("output already exists")
    fd, temporary = tempfile.mkstemp(prefix=".mvp-observe-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        # The root-owned evidence directory has one operator writer. Refuse
        # existing output rather than overwrite an earlier collector submission.
        if not replace and os.path.lexists(path):
            raise Refusal("output already exists")
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def run(options):
    request, raw = load(options.request)
    if (type(request) is not dict or set(request) != {
            "deadline_unix", "not_before", "qualification_manifest_sha256",
            "required_checks", "scenario_id", "scenario_limit_seconds"} or
            type(request["deadline_unix"]) is not int or
            type(request["scenario_limit_seconds"]) is not int or
            request["scenario_limit_seconds"] not in (1800, 7200) or
            not re.fullmatch(r"[a-f0-9]{64}", request["qualification_manifest_sha256"]) or
            not re.fullmatch(r"[a-z0-9.-]+", request["scenario_id"])):
        raise Refusal("collector request differs")
    required = request["required_checks"]
    if (type(required) is not list or not required or
            any(type(check) is not str or not re.fullmatch(r"[a-z0-9-]+", check) for check in required) or
            len(set(required)) != len(required)):
        raise Refusal("collector checks differ")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    not_before = parse(request["not_before"])
    deadline = dt.datetime.fromtimestamp(request["deadline_unix"], tz=dt.timezone.utc)
    if not_before > now or now > deadline:
        raise Refusal("request not active; do not backdate or submit a late observation")
    if deadline < not_before or (deadline - not_before).total_seconds() > request["scenario_limit_seconds"]:
        raise Refusal("collector time window differs")
    digest = hashlib.sha256(raw).hexdigest()
    if options.command == "start":
        if options.check or options.output:
            raise Refusal("start takes no check or output")
        draft = {"request_sha256": digest, "observation": {
            "scenario_id": request["scenario_id"], "started_at": stamp(now),
            "completed_at": None, "checks": [
                {"check": name, "observed_at": None, "result": None} for name in required]}}
        publish(options.draft, draft)
    else:
        draft, _ = load(options.draft)
        if (type(draft) is not dict or set(draft) != {"request_sha256", "observation"} or
                draft["request_sha256"] != digest):
            raise Refusal("draft belongs to another collector request")
        observation = draft["observation"]
        if (type(observation) is not dict or set(observation) != {
                "scenario_id", "started_at", "completed_at", "checks"} or
                observation["scenario_id"] != request["scenario_id"] or
                observation["completed_at"] is not None or
                not not_before <= parse(observation["started_at"]) <= now or
                type(observation["checks"]) is not list or len(observation["checks"]) != len(required)):
            raise Refusal("draft observation differs")
        for name, check in zip(required, observation["checks"]):
            if type(check) is not dict or set(check) != {"check", "observed_at", "result"} or check["check"] != name:
                raise Refusal("draft checks differ")
            if check["result"] is None and check["observed_at"] is None:
                continue
            if check["result"] != "observed" or not parse(observation["started_at"]) <= parse(check["observed_at"]) <= now:
                raise Refusal("draft contains an invalid observation")
        if options.command == "observe":
            if options.check not in required or options.output:
                raise Refusal("observe needs exactly one named required check")
            check = observation["checks"][required.index(options.check)]
            if check["result"] is not None:
                raise Refusal("check already recorded; preserve its original time")
            check.update(observed_at=stamp(now), result="observed")
            publish(options.draft, draft, replace=True)
        elif options.command == "finish":
            if options.check or not options.output or any(c["result"] != "observed" for c in observation["checks"]):
                raise Refusal("finish needs all observations and an unused output path")
            if os.path.lexists(options.output):
                raise Refusal("output already exists")
            observation["completed_at"] = stamp(now)
            # Seal before submission: after interruption, inspect the original
            # draft/output instead of generating a later duplicate completion.
            publish(options.draft, draft, replace=True)
            publish(options.output, observation)
        elif options.check or options.output:
            raise Refusal("status takes no check or output")
    pending = [c["check"] for c in draft["observation"]["checks"] if c["result"] is None]
    print(json.dumps({"scenario_id": request["scenario_id"], "deadline": stamp(deadline),
                      "seconds_remaining": int((deadline-now).total_seconds()), "pending": pending}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("start", "observe", "status", "finish"))
    parser.add_argument("--request", required=True)
    parser.add_argument("--draft", required=True)
    parser.add_argument("--check")
    parser.add_argument("--output")
    try:
        run(parser.parse_args())
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as error:
        print(f"Observation refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
