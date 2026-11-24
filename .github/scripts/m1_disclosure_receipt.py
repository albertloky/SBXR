"""Closed M1 diagnostics for the existing attended terminal receipt and failure facts."""
import hashlib
import json
import re


REASONS = frozenset("""
    action-refused deadline-before-start descendant-cleanup diagnostic-bound driver-error
    exit-before-continuation exit-before-prompt exit-before-result exit-before-return
    exit-before-selection exit-deadline input-closed input-deadline label-duplicate label-missing
    output-bound output-deadline output-encoding output-unterminated owner-exited process-cleanup
    process-failed process-ownership prompt-mismatch request-deadline result-mismatch signal-cancelled
""".split())
INPUT_CLASSES = {"none", "selection", "other", "continuation", "exit"}


def valid(diagnostic):
    return (type(diagnostic) is dict and set(diagnostic) == {"reason", "last_input_class", "elapsed_ms"}
            and type(diagnostic["reason"]) is str and diagnostic["reason"] in REASONS
            and type(diagnostic["last_input_class"]) is str and diagnostic["last_input_class"] in INPUT_CLASSES
            and type(diagnostic["elapsed_ms"]) is int and 0 <= diagnostic["elapsed_ms"] <= 120000)


def is_m1(intent):
    return (intent.get("operation"), intent.get("scenario"), intent.get("label")) == (
        "disclose", "mvp-install", "m1-client")


def add_diagnostic(terminal, intent, stderr):
    """Project one driver-emitted line. Missing or ambiguous telemetry leaves the old receipt intact."""
    if terminal["command_exit"] != 1 or not is_m1(intent) or len(stderr) > (8 << 20):
        return
    prefix = b"SBXR_M1_DISCLOSURE "
    lines = [line for line in stderr.split(b"\n") if line.startswith(prefix)]
    if len(lines) != 1:
        return
    match = re.fullmatch(rb"SBXR_M1_DISCLOSURE ([a-z-]{1,40}) ([a-z]{1,16}) (0|[1-9][0-9]{0,5})", lines[0])
    if match:
        diagnostic = dict(reason=match[1].decode("ascii"), last_input_class=match[2].decode("ascii"),
                          elapsed_ms=int(match[3]))
        if valid(diagnostic):
            terminal["m1_disclosure"] = diagnostic


def expected_terminal(base, intent, terminal):
    """Extend an independently constructed expected receipt only for this failed operation."""
    if "m1_disclosure" not in terminal:
        return base
    diagnostic = terminal["m1_disclosure"]
    if (not is_m1(intent) or type(base["command_exit"]) is not int
            or base["command_exit"] != 1 or not valid(diagnostic)):
        raise ValueError("Invalid M1 disclosure diagnostic")
    return dict(base, m1_disclosure=diagnostic)


def bound_diagnostic(failure, intent, result, request_sha256, manifest_sha256, window_sha256):
    """Called after the operator authenticates the run/job and before replaying terminal failure facts."""
    if (not is_m1(intent) or type(intent["attempt"]) is not int or intent["attempt"] != 1 or failure["attempt_id"] != f"run-{intent['run']}-attempt-1"
            or failure["scenario_id"] != "mvp-install" or failure["operation_id"] != "operation-1"
            or failure["actual_result"] != "unexpected-failure"
            or (intent["request_sha256"], intent["manifest_sha256"], intent.get("window_sha256")) !=
               (request_sha256, manifest_sha256, window_sha256)
            or result.get("outcome") != "command-completed" or result.get("no_retry") is not True
            or type(result.get("exit")) is not int or result["exit"] != 1):
        raise ValueError("M1 receipt binding differs")
    binding = json.dumps(intent, sort_keys=True, separators=(",", ":")).encode()
    base = dict(binding_sha256=hashlib.sha256(binding).hexdigest(), command_exit=1,
                stdout_size=result["stdout_size"], stdout_sha256=result["stdout_sha256"])
    terminal = result["remote_terminal"]
    if (type(terminal) is not dict or type(terminal.get("command_exit")) is not int
            or type(result["stdout_size"]) is not int or not 0 <= result["stdout_size"] <= (4 << 20)
            or type(result["stdout_sha256"]) is not str or not re.fullmatch(r"[a-f0-9]{64}", result["stdout_sha256"])
            or terminal != expected_terminal(base, intent, terminal)):
        raise ValueError("M1 terminal receipt differs")
    return terminal.get("m1_disclosure")


def attach_to_failure(facts, live_dir, *, job, request_sha256, manifest_sha256, window_sha256):
    """Project before canonicalization, so local replay, submission and retention use identical bytes."""
    import os
    from pathlib import Path
    import stat

    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("Duplicate receipt field")
            obj[key] = value
        return obj

    def private_record(path):
        with os.fdopen(os.open(path, os.O_NOFOLLOW | os.O_NONBLOCK | os.O_RDONLY), "rb") as stream:
            meta = os.fstat(stream.fileno())
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or
                    stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1 or meta.st_size > 65536):
                raise ValueError("Unexpected receipt identity")
            raw = stream.read(65537)
            after = os.fstat(stream.fileno())
            if len(raw) != meta.st_size or after.st_ctime_ns != meta.st_ctime_ns:
                raise ValueError("Unstable receipt")
        return json.loads(raw, object_pairs_hook=unique)

    if facts.get("stage") != "v3-scenario-failure" or not isinstance(facts.get("failure"), dict):
        return facts
    failure = facts["failure"]
    if "m1_disclosure" in failure:
        raise ValueError("Expected unannotated failure facts")
    if (failure.get("scenario_id") != "mvp-install"
            or failure.get("actual_result") != "unexpected-failure" or failure.get("operation_id") != "operation-1"):
        return facts

    try:
        live_dir = Path(live_dir).absolute()
        if (live_dir.resolve() != live_dir or live_dir.stat().st_uid != os.getuid()
                or stat.S_IMODE(live_dir.stat().st_mode) != 0o700):
            return facts
        intent = private_record(live_dir / "m1-disclose-client-operation-intent.json")
        result = private_record(live_dir / "m1-disclose-client-result.json")
        if type(intent) is not dict or type(result) is not dict:
            return facts
        manifest = facts["qualification_manifest"]
        fresh = facts.get("fresh_window")
        workflow = (fresh or manifest)["workflow"]
        if (str(intent["job"]) != str(job) or str(intent["run"]) != workflow["run_id"]
                or intent["source"] != workflow["commit"] or canonical_hash(manifest) != manifest_sha256
                or (canonical_hash(fresh["window_decision"]) if fresh is not None else None) != window_sha256):
            return facts
        diagnostic = bound_diagnostic(failure, intent, result, request_sha256, manifest_sha256, window_sha256)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        # Optional evidence cannot prevent the original failure from being reported.
        return facts
    if diagnostic is None:
        return facts
    return dict(facts, failure=dict(failure, m1_disclosure=diagnostic))


def canonical_hash(document):
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()
