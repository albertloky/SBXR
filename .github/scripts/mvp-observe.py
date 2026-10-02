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


# Explicit opt-in belongs to the signed declaration. Old requests retain their
# exact deadlines; an expired request can never be rescued by adding a handoff.
HANDOFF_PHASES = {
    "mvp-subscription": ("profile-import", "profile-refresh"),
    "mvp-credentials": ("credential-refresh", "rotated-link-refresh"),
    "mvp-removal": ("test-profile-removal",),
}


def handoff_phases(scenario):
    if scenario.startswith("source-") and scenario.endswith(("-upgrade", "-postcommit")):
        return ("source-profile-import", "http-profile-refresh")
    return HANDOFF_PHASES.get(scenario, ())


def handoff_deadline(request, observation, now):
    base = dt.datetime.fromtimestamp(request["deadline_unix"], tz=dt.timezone.utc)
    records = observation.get("karing_handoffs", [])
    enabled = request.get("karing_response_limit_seconds") == 3600
    if not enabled:
        if "karing_handoffs" in observation:
            raise Refusal("handoff timing was not declared")
        return base
    finish_by = parse(request["attended_finish_by"])
    if type(records) is not list:
        raise Refusal("handoffs differ")
    previous, seen, paused = parse(observation["started_at"]), set(), dt.timedelta()
    for index, record in enumerate(records):
        if type(record) is not dict or set(record) != {"phase", "prepared_at", "notified_at", "responded_at"}:
            raise Refusal("handoff members differ")
        phase = record["phase"]
        if phase not in handoff_phases(request["scenario_id"]) or phase in seen:
            raise Refusal("handoff phase differs or was already used")
        seen.add(phase)
        prepared, notified = parse(record["prepared_at"]), parse(record["notified_at"])
        response_deadline = notified + dt.timedelta(hours=1)
        if (prepared > notified or notified < previous or notified > now or
                notified > base + paused or response_deadline > finish_by):
            raise Refusal("handoff was not prepared/notified within the active attended window")
        if record["responded_at"] is None:
            if index != len(records)-1 or observation["completed_at"] is not None:
                raise Refusal("pending handoff cannot be followed or sealed")
            return response_deadline
        responded = parse(record["responded_at"])
        if responded < notified or responded > response_deadline or responded > now:
            raise Refusal("handoff response is late or differs")
        if observation["completed_at"] is not None and responded > parse(observation["completed_at"]):
            raise Refusal("handoff response follows completion")
        paused += responded - notified
        previous = responded
    return min(base + paused, finish_by)


def validate_request(request, now):
    keys = {"deadline_unix", "not_before", "qualification_manifest_sha256",
            "required_checks", "scenario_id", "scenario_limit_seconds"}
    if type(request) is not dict:
        raise Refusal("collector request differs")
    enabled = "karing_response_limit_seconds" in request
    if enabled:
        keys |= {"karing_response_limit_seconds", "attended_finish_by"}
    if (set(request) != keys or type(request["deadline_unix"]) is not int or
            type(request["scenario_limit_seconds"]) is not int or
            request["scenario_limit_seconds"] not in (1800, 7200) or
            type(request["qualification_manifest_sha256"]) is not str or
            not re.fullmatch(r"[a-f0-9]{64}", request["qualification_manifest_sha256"]) or
            type(request["scenario_id"]) is not str or
            not re.fullmatch(r"[a-z0-9.-]+", request["scenario_id"])):
        raise Refusal("collector request differs")
    start = parse(request["not_before"])
    deadline = dt.datetime.fromtimestamp(request["deadline_unix"], tz=dt.timezone.utc)
    if start > now or not 0 <= (deadline-start).total_seconds() <= request["scenario_limit_seconds"]:
        raise Refusal("collector time window differs")
    if enabled and (type(request["karing_response_limit_seconds"]) is not int or
                    request["karing_response_limit_seconds"] != 3600 or
                    parse(request["attended_finish_by"]) <= start):
        raise Refusal("attended response window differs")
    return start, deadline


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


def validate_draft(draft, request, digest, now, sealed=False):
    if (type(draft) is not dict or set(draft) != {"request_sha256", "observation"} or
            draft["request_sha256"] != digest):
        raise Refusal("draft belongs to another collector request")
    observation = draft["observation"]
    keys = {"scenario_id", "started_at", "completed_at", "checks"}
    if type(observation) is dict and "karing_handoffs" in observation:
        keys.add("karing_handoffs")
    required = request["required_checks"]
    if (type(observation) is not dict or set(observation) != keys or
            observation["scenario_id"] != request["scenario_id"] or
            not parse(request["not_before"]) <= parse(observation["started_at"]) <= now or
            type(observation["checks"]) is not list or len(observation["checks"]) != len(required)):
        raise Refusal("draft observation differs")
    completed = observation["completed_at"]
    if completed is not None and (not sealed or not parse(observation["started_at"]) <= parse(completed) <= now):
        raise Refusal("draft is sealed or completion differs")
    end = now if completed is None else parse(completed)
    for name, check in zip(required, observation["checks"]):
        if type(check) is not dict or set(check) != {"check", "observed_at", "result"} or check["check"] != name:
            raise Refusal("draft checks differ")
        if check["result"] is None and check["observed_at"] is None and completed is None:
            continue
        if check["result"] != "observed" or not parse(observation["started_at"]) <= parse(check["observed_at"]) <= end:
            raise Refusal("draft contains an invalid observation")
    return observation


def run(options):
    request, raw = load(options.request)
    required = request["required_checks"]
    if (type(required) is not list or not required or
            any(type(check) is not str or not re.fullmatch(r"[a-z0-9-]+", check) for check in required) or
            len(set(required)) != len(required)):
        raise Refusal("collector checks differ")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    not_before, deadline = validate_request(request, now)
    digest = hashlib.sha256(raw).hexdigest()
    if options.command in ("deadline", "operation-deadline"):
        if options.check or options.output or options.phase or options.prepared_at or options.notified_at:
            raise Refusal("deadline takes only request and draft")
        if options.command == "operation-deadline" and not os.path.lexists(options.draft):
            raise Refusal("product action requires a current observation draft")
        observation = {"started_at": request["not_before"], "completed_at": None}
        if os.path.lexists(options.draft):
            draft, _ = load(options.draft)
            observation = validate_draft(draft, request, digest, now, sealed=True)
        deadline = handoff_deadline(request, observation, now)
        if options.command == "operation-deadline":
            if (observation["completed_at"] is not None or now > deadline or
                    any(h["responded_at"] is None for h in observation.get("karing_handoffs", []))):
                raise Refusal("product action requires an active technical window with no pending response")
        print(int(deadline.timestamp()))
        return
    if options.command not in ("ready",) and (options.phase or options.prepared_at or options.notified_at):
        raise Refusal("handoff details require ready")
    if options.command == "start":
        deadline = handoff_deadline(request, {"started_at": stamp(now), "completed_at": None}, now)
        if now > deadline:
            raise Refusal("request not active; do not backdate or submit a late observation")
        if options.check or options.output:
            raise Refusal("start takes no check or output")
        draft = {"request_sha256": digest, "observation": {
            "scenario_id": request["scenario_id"], "started_at": stamp(now),
            "completed_at": None, "checks": [
                {"check": name, "observed_at": None, "result": None} for name in required]}}
        publish(options.draft, draft)
    else:
        draft, _ = load(options.draft)
        observation = validate_draft(draft, request, digest, now)
        deadline = handoff_deadline(request, observation, now)
        if now > deadline:
            raise Refusal("request not active; do not backdate or submit a late observation")
        if options.command == "ready":
            if (request.get("karing_response_limit_seconds") != 3600 or options.check or options.output or
                    not options.phase or not options.prepared_at or not options.notified_at):
                raise Refusal("ready requires declared timing, phase, prepared and actual notification times")
            notified = parse(options.notified_at)
            if not dt.timedelta() <= now-notified <= dt.timedelta(minutes=5):
                raise Refusal("notification time must be fresh and actual")
            records = observation.setdefault("karing_handoffs", [])
            if records and records[-1]["responded_at"] is None:
                raise Refusal("a handoff is already pending")
            records.append({"phase": options.phase, "prepared_at": options.prepared_at,
                            "notified_at": options.notified_at, "responded_at": None})
            deadline = handoff_deadline(request, observation, now)
            publish(options.draft, draft, replace=True)
        elif options.command == "responded":
            records = observation.get("karing_handoffs", [])
            if options.check or options.output or not records or records[-1]["responded_at"] is not None:
                raise Refusal("responded requires one pending handoff and actual attended confirmation")
            records[-1]["responded_at"] = stamp(now)
            deadline = handoff_deadline(request, observation, now)
            publish(options.draft, draft, replace=True)
        elif options.command == "observe":
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
            if any(h["responded_at"] is None for h in observation.get("karing_handoffs", [])):
                raise Refusal("finish needs an actual response to every handoff")
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
    parser.add_argument("command", choices=("start", "observe", "status", "finish", "ready", "responded", "deadline", "operation-deadline"))
    parser.add_argument("--request", required=True)
    parser.add_argument("--draft", required=True)
    parser.add_argument("--check")
    parser.add_argument("--output")
    parser.add_argument("--phase")
    parser.add_argument("--prepared-at")
    parser.add_argument("--notified-at")
    try:
        run(parser.parse_args())
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as error:
        print(f"Observation refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
