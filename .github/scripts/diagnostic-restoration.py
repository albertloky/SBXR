"""Pure diagnostic restoration bindings; never performs an effect or grants authority."""
import datetime
import hashlib
import json
import re


def validate_request(request, manifest_raw, manifest_sha256, request_path, draft_path, window):
    """Bind an existing diagnostic request to independently authenticated bytes."""
    if hashlib.sha256(manifest_raw).hexdigest() != manifest_sha256:
        raise ValueError("diagnostic manifest digest")
    manifest = json.loads(manifest_raw)
    attempt = manifest["v3_attempt"]
    if (manifest["schema"] != "sbxr-qualification-manifest-v3" or
            attempt.get("diagnostic") != window or
            set(window) != {"start_unix", "test_until_unix", "finish_unix"} or
            any(type(n) is not int for n in window.values()) or
            window["start_unix"] <= 0 or
            window["test_until_unix"] != window["start_unix"] + 7200 or
            window["finish_unix"] != window["start_unix"] + 10800 or
            attempt["required_scenarios"] != ["mvp-install"] or
            attempt.get("karing_response_limit_seconds", 0) != 0 or
            attempt.get("attended_finish_by") or attempt.get("owner_exception") or
            attempt.get("proxy_profile")):
        raise ValueError("diagnostic signed scope")
    identity = attempt["attempt_id"]
    if not re.fullmatch(r"run-[1-9][0-9]*-attempt-[1-9][0-9]*", identity):
        raise ValueError("diagnostic run identity")
    directory = "/root/sbxr-diagnostic-" + identity
    if request_path != directory + "/request.json" or draft_path != directory + "/observation-draft.json":
        raise ValueError("diagnostic request paths")
    keys = {"deadline_unix", "diagnostic_test_until_unix", "not_before", "qualification_manifest_sha256",
            "required_checks", "scenario_id", "scenario_limit_seconds"}
    if (set(request) != keys or request["qualification_manifest_sha256"] != manifest_sha256 or
            request["required_checks"] != ["diagnostic-observation"] or
            request["scenario_id"] != "mvp-install" or
            type(request["scenario_limit_seconds"]) is not int or request["scenario_limit_seconds"] != 1800 or
            type(request["deadline_unix"]) is not int or type(request["diagnostic_test_until_unix"]) is not int):
        raise ValueError("diagnostic request scope")
    start = int(datetime.datetime.strptime(request["not_before"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp())
    if not window["start_unix"] <= start < window["finish_unix"]:
        raise ValueError("diagnostic request start")
    deadline = min(start + 1800, window["finish_unix"] - 60)
    cutoff = min(deadline - 900, window["test_until_unix"])
    if request["deadline_unix"] != deadline or request["diagnostic_test_until_unix"] != cutoff or cutoff <= start:
        raise ValueError("diagnostic request reserve")
    return window


def operation_cutoff(request, runtime_deadline, approved_finish):
    """Tighten an authenticated diagnostic clock, reserving removal exactly once.

    Call validate_request first; this calculation neither authenticates inputs
    nor authorizes an operation. Cleanup callers retain their original deadline.
    """
    limits = (request.get("deadline_unix"), request.get("diagnostic_test_until_unix"),
              runtime_deadline, approved_finish)
    if any(type(value) is not int or value <= 0 for value in limits):
        raise ValueError("diagnostic cutoff inputs")
    cleanup = min(request["deadline_unix"], runtime_deadline, approved_finish)
    return min(request["diagnostic_test_until_unix"], cleanup - 900)
