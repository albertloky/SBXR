#!/usr/bin/env python3
"""Assemble scenario 07–25 receipts into canonical Go facts.

This command performs no live or network operation.  It fails closed unless a
fresh preparation receipt, every retained evidence source, and the pinned Go
validator all bind the exact bytes supplied to this invocation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any

HERE = Path(__file__).resolve().parent


def import_sibling(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError("evidence helper import failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


timing = import_sibling("sbxr_evidence_timing", "evidence-timing.py")
identity = import_sibling("sbxr_identity_outside", "identity-outside.py")
connection = import_sibling("sbxr_connection_observation", "check-connection-observation.py")
links = import_sibling("sbxr_link_evidence", "link-evidence.py")
later = import_sibling("sbxr_scenario_sources", "scenario-sources.py")

POLICY = "repair-issuance-bounded-v4"
SCENARIOS = ("identity-absent", "enable-schema1", "link-precommit", "link-postcommit") + later.SCENARIOS
SCENARIO_INDEX = {scenario: index + 6 for index, scenario in enumerate(SCENARIOS)}
FACTS_SCHEMA = "sbxr-release-qualification-facts-v1"
DECISION_SCHEMA = "sbxr-release-qualification-decision-v1"
RESULT_STAGE = "v3-scenario-result"
EVIDENCE_RESULT = "expected-safety-and-final-state-proved"
PROOF_SCHEMA = "sbxr-v4-scenario-07-08-observation-input-v2"
LINK_PROOF_SCHEMA = "sbxr-v4-link-observation-input-v1"
LATER_PROOF_SCHEMA = "sbxr-v4-scenario-observation-input-v1"
PREPARATION_SCHEMA = "sbxr-v4-evidence-preparation-v1"
OPERATOR_SCHEMA = "sbxr-v4-operator-observations-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
JSON_LIMIT = 1_000_000
BOUNDARY_LIMIT = 16 * 1024 * 1024
VALIDATOR_LIMIT = 64 * 1024 * 1024
RETAINED_07 = (
    "07-outside-started.json", "07-outside-ready.json",
    "07-outside-rotation-request.json", "07-outside-rotation-ready.json",
    "07-outside-collected.json", "07-outside.json",
)


class Refusal(ValueError):
    pass


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("JSON: duplicate key refused")
        result[key] = value
    return result


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def exact(value: Any, keys, label: str):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Refusal(f"{label}: exact object shape required")
    return value


def private_bytes(path: Path, label: str, mode: int = 0o600, limit: int = JSON_LIMIT) -> bytes:
    if not path.is_absolute():
        raise Refusal(f"{label}: absolute path required")
    try:
        before = path.lstat()
    except OSError as error:
        raise Refusal(f"{label}: unreadable: {error.strerror}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1:
        raise Refusal(f"{label}: one-link mode-{mode:04o} regular file required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise Refusal(f"{label}: identity changed while opening")
        blocks = bytearray()
        while len(blocks) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(blocks)))
            if not block:
                break
            blocks.extend(block)
        raw = bytes(blocks)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if len(raw) > limit or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
        raise Refusal(f"{label}: changed or exceeded byte bound")
    current = path.lstat()
    if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
        raise Refusal(f"{label}: path was replaced while reading")
    return raw


def load(path: Path, label: str, newline: bool = False, limit: int = JSON_LIMIT):
    raw = private_bytes(path, label, limit=limit)
    body = raw[:-1] if newline and raw.endswith(b"\n") else raw
    try:
        value = json.loads(body, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"{label}: canonical JSON required") from error
    if canonical(value) != body:
        raise Refusal(f"{label}: canonical compact JSON required")
    return value, body, raw


def instant(value, label):
    try:
        parsed = timing.parse_instant(value, label)
    except timing.EvidenceTimingRefusal as error:
        raise Refusal(str(error)) from error
    return parsed


def before(left, right):
    return instant(left, "time") <= instant(right, "time")


def validate_manifest(value, raw, scenario):
    if not isinstance(value, dict) or value.get("schema") != "sbxr-qualification-manifest-v3" or value.get("mode") != "v3" or value.get("source_state") != "v3-subscription-clean":
        raise Refusal("manifest: V3 clean-install manifest required")
    releases, attempt = value.get("releases"), value.get("v3_attempt")
    if not isinstance(releases, list) or len(releases) != 1 or not isinstance(releases[0], dict) or not isinstance(attempt, dict):
        raise Refusal("manifest: one candidate and one V3 attempt required")
    required = attempt.get("required_scenarios")
    if (attempt.get("schema") != "sbxr-v3-qualification-attempt-v3" or attempt.get("evidence_policy") != POLICY or
            not isinstance(required, list) or len(required) != len(set(required)) or scenario not in required or
            scenario not in SCENARIO_INDEX or required.index(scenario) != SCENARIO_INDEX[scenario]):
        raise Refusal("manifest: policy or exact signed scenario order refused")
    if required[6:8] != list(SCENARIOS[:2]) or not isinstance(attempt.get("packages"), dict) or not isinstance(attempt.get("runner"), dict):
        raise Refusal("manifest: scenario 07/08 packages or order refused")
    if scenario.startswith("link-") and required[6:10] != list(SCENARIOS[:4]):
        raise Refusal("manifest: scenario 09/10 order refused")
    if scenario in later.SCENARIOS and required[6:] != list(SCENARIOS):
        raise Refusal("manifest: remaining scenario order differs")
    if (type(attempt.get("scenario_limit_seconds")) is not int or attempt["scenario_limit_seconds"] <= 0 or
            type(attempt.get("validation_limit_seconds")) is not int or attempt["validation_limit_seconds"] <= 0):
        raise Refusal("manifest: timing limits required")
    return releases[0], attempt, digest(raw)


def validate_request(value, exact_raw, manifest_sha, scenario, attempt):
    exact(value, ("deadline_unix", "not_before", "qualification_manifest_sha256", "scenario_id", "scenario_limit_seconds"), "request")
    limit = attempt.get('karing_limit_seconds') if scenario == 'karing-final' else attempt['scenario_limit_seconds']
    if (value["qualification_manifest_sha256"] != manifest_sha or value["scenario_id"] != scenario or
            type(limit) is not int or limit <= 0 or type(value['scenario_limit_seconds']) is not int or
            value["scenario_limit_seconds"] != limit or type(value["deadline_unix"]) is not int):
        raise Refusal("request: exact manifest, scenario, or signed limit differs")
    instant(value["not_before"], "request.not_before")
    return value, digest(exact_raw)


def validate_prefix(prefix, manifest, manifest_sha, scenario_index):
    if not isinstance(prefix, list) or len(prefix) != scenario_index:
        raise Refusal(f"prior prefix: exactly {scenario_index} scenarios required")
    attempt, candidate = manifest["v3_attempt"], manifest["releases"][0]
    previous, previous_time, operations = manifest_sha, attempt.get("started_at"), set()
    packages = attempt['packages']
    for index, item in enumerate(prefix):
        if not isinstance(item, dict):
            raise Refusal("prior prefix: scenario object required")
        if (item.get("scenario_id") != attempt["required_scenarios"][index] or item.get("prior_scenario_sha256") != previous or
                item.get("operation_id") != f"operation-{index + 1}" or item.get("operation_id") in operations or
                item.get("attempt_id") != attempt.get("attempt_id") or item.get("candidate") != candidate or
                item.get("packages_before") != packages or
                item.get("schema") != "sbxr-v3-scenario-evidence-v3" or item.get("vps_id") != attempt.get("vps_id") or
                item.get("vps_identity_sha256") != attempt.get("vps_identity_sha256")):
            raise Refusal("prior prefix: exact order, chain, package, operation, or candidate binding differs")
        if item['scenario_id'] == 'snap-refresh':
            packages = attempt.get('after_snap_refresh')
            if not isinstance(packages, dict):
                raise Refusal('prior prefix: signed post-refresh packages required')
        if item.get('packages_after') != packages:
            raise Refusal('prior prefix: package transition differs')
        if previous_time and (not before(previous_time, item.get("started_at")) or not before(item.get("completed_at"), item.get("validated_at"))):
            raise Refusal("prior prefix: time order refused")
        operations.add(item["operation_id"])
        previous = digest(canonical(item))
        previous_time = item["validated_at"]
    return previous, previous_time


def validate_preparation(receipt, manifest_sha, boundary_sha, request_sha, prefix_sha, validator_sha, request, scenario):
    exact(receipt, ("accepted_prior_prefix_sha256", "prepared_at", "qualification_boundary_facts_sha256", "qualification_manifest_sha256", "request_sha256", "scenario_id", "schema", "validator_sha256", "verifications"), "preparation receipt")
    if receipt != dict(receipt, schema=PREPARATION_SCHEMA, scenario_id=scenario,
                       qualification_manifest_sha256=manifest_sha, qualification_boundary_facts_sha256=boundary_sha,
                       request_sha256=request_sha, accepted_prior_prefix_sha256=prefix_sha, validator_sha256=validator_sha):
        raise Refusal("preparation receipt: exact artifact binding differs")
    expected = (("fresh-signed-manifest", manifest_sha), ("qualification-boundary", boundary_sha), ("pinned-validator", validator_sha))
    rows = receipt["verifications"]
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise Refusal("preparation receipt: three explicit verifications required")
    for row, (check, sha) in zip(rows, expected):
        exact(row, ("artifact_sha256", "check", "observed_at", "result"), "preparation verification")
        if row["check"] != check or row["artifact_sha256"] != sha or row["result"] != "verified" or not before(request["not_before"], row["observed_at"]) or not before(row["observed_at"], receipt["prepared_at"]):
            raise Refusal("preparation receipt: verification identity, result, or order refused")
    if int(datetime.fromtimestamp(request["deadline_unix"], timezone.utc).timestamp()) < instant(receipt["prepared_at"], "preparation.prepared_at").epoch_second:
        raise Refusal("preparation receipt: outside request deadline")
    return receipt["prepared_at"]


def operator_source(receipt, raw, capture_raw, scenario, manifest_sha, request_sha, rules):
    exact(receipt, ("capture_sha256", "observations", "qualification_manifest_sha256", "request_sha256", "scenario_id", "schema"), "operator observations")
    if receipt["schema"] != OPERATOR_SCHEMA or receipt["scenario_id"] != scenario or receipt["qualification_manifest_sha256"] != manifest_sha or receipt["request_sha256"] != request_sha or receipt["capture_sha256"] != digest(capture_raw):
        raise Refusal("operator observations: source binding or capture bytes SHA differs")
    expected = []
    for rule in rules:
        for anchor in rule.not_before:
            if anchor.source == "entry":
                expected.append((rule.check, anchor.event))
    if len(expected) != len(set(expected)):
        raise Refusal("operator observations: ambiguous entry event map")
    rows = receipt["observations"]
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise Refusal("operator observations: one explicit entry observation per rule required")
    events = {}
    for row, (check, event) in zip(rows, expected):
        exact(row, ("capture_sha256", "check", "event", "observed_at", "result"), "operator observation")
        if row != {"capture_sha256": digest(capture_raw), "check": check, "event": event, "observed_at": row["observed_at"], "result": "observed"}:
            raise Refusal("operator observations: ordered check, event, result, or capture binding differs")
        instant(row["observed_at"], f"operator observation {check}")
        events[event] = row["observed_at"]
    return timing.EventSource("entry", scenario, manifest_sha, request_sha, raw, digest(raw), events)


def route_source(receipt, raw, scenario, manifest_sha, request_sha):
    exact(receipt, ("check", "completed_at", "effective_exec_verified", "owned_artifacts_sha256", "qualification_manifest_sha256", "record_sha256", "request_sha256", "route", "scenario_id", "schema", "started_at", "timer_calendar_verified"), "effective route receipt")
    artifacts = receipt["owned_artifacts_sha256"]
    if (receipt["schema"] != "sbxr-v4-effective-route-v1" or receipt["scenario_id"] != scenario or
            receipt["qualification_manifest_sha256"] != manifest_sha or receipt["request_sha256"] != request_sha or
            receipt["check"] != "supported-effective-route-inspected" or receipt["route"] not in ("official-snap", "owned-recorder") or
            receipt["timer_calendar_verified"] is not True or receipt["effective_exec_verified"] is not True or
            not SHA256.fullmatch(receipt["record_sha256"]) or not isinstance(artifacts, dict) or
            any(not isinstance(name, str) or not name.startswith("/") or not SHA256.fullmatch(value) for name, value in artifacts.items()) or
            not before(receipt["started_at"], receipt["completed_at"])):
        raise Refusal("effective route receipt: exact current route proof differs")
    if receipt["route"] == "official-snap" and artifacts:
        raise Refusal("effective route receipt: official route unexpectedly owns artifacts")
    if receipt["route"] == "owned-recorder" and len(artifacts) != 3:
        raise Refusal("effective route receipt: managed route artifacts incomplete")
    return timing.EventSource("route", scenario, manifest_sha, request_sha, raw, digest(raw), {"completed_at": receipt["completed_at"]})


def state_07_source(state, raw, scenario, manifest_sha, request_sha, request):
    required = {"absence_at", "completed_at", "entry_started_at", "initial_at", "install_at", "issuance_lines_before", "old_established_at", "old_refused_at", "old_terminated_at", "replacement_at", "replacement_disclosure_confirmed", "replacement_pid", "replacement_tick", "reviewed_removal_at", "rotation_completed_at", "rotation_started_at", "setup_at", "source_disclosure_confirmed", "source_group", "source_pid", "source_tick", "started_at"}
    exact(state, required, "07 state")
    if (state["source_disclosure_confirmed"] is not True or state["replacement_disclosure_confirmed"] is not True or
            type(state["issuance_lines_before"]) is not int or state["issuance_lines_before"] < 0 or
            any(not isinstance(state[key], str) or re.fullmatch(r"[1-9][0-9]*", state[key]) is None for key in ("source_group","source_pid","source_tick","replacement_pid","replacement_tick"))):
        raise Refusal("07 state: disclosure, process, or issuance facts refused")
    pairs = (("started_at","initial_at"),("initial_at","entry_started_at"),("entry_started_at","install_at"),("install_at","setup_at"),("setup_at","old_established_at"),
             ("old_established_at","rotation_started_at"),("rotation_started_at","rotation_completed_at"),("rotation_started_at","old_terminated_at"),
             ("rotation_completed_at","old_refused_at"),("old_terminated_at","old_refused_at"),("old_refused_at","replacement_at"),
             ("replacement_at","reviewed_removal_at"),("reviewed_removal_at","absence_at"),("absence_at","completed_at"))
    if any(not before(state[a], state[b]) for a, b in pairs) or not before(request["not_before"], state["started_at"]):
        raise Refusal("07 state: timestamp order refused")
    return timing.EventSource("state", scenario, manifest_sha, request_sha, raw, digest(raw), {key: state[key] for key in ("setup_at", "rotation_started_at", "rotation_completed_at", "absence_at")})


def controller_source(receipt, raw, state, scenario, manifest_sha, request_sha):
    exact(receipt, ("boundary_process", "completed_at", "final_record_sha256", "initial_record_sha256", "observations", "phase", "qualification_manifest_sha256", "request_sha256", "result_code", "scenario", "schema", "started_at"), "controller receipt")
    if (receipt["schema"] != 1 or receipt["scenario"] != scenario or receipt["phase"] != "rotated" or receipt["qualification_manifest_sha256"] != manifest_sha or receipt["request_sha256"] != request_sha or
            receipt["result_code"] != "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATED" or not before(state["rotation_started_at"], receipt["started_at"]) or not before(receipt["completed_at"], state["rotation_completed_at"])):
        raise Refusal("controller receipt: identity, result, or outer action bracket differs")
    process = exact(receipt["boundary_process"], ("cgroup", "executable_device", "executable_inode", "pid", "start_tick"), "controller process")
    if (not isinstance(process["cgroup"], str) or not process["cgroup"].startswith("/system.slice/sbxr-v4-identity-absent-") or
            any(type(process[key]) is not int or process[key] < 1 for key in ("executable_device","executable_inode","pid","start_tick")) or process["pid"] < 2 or
            not SHA256.fullmatch(receipt["initial_record_sha256"]) or not SHA256.fullmatch(receipt["final_record_sha256"])):
        raise Refusal("controller receipt: protected process or record identity refused")
    checkpoints = ("target prepared", "startup integration published", "systemd reloaded", "startup route verified", "source quiescent")
    checks = ("startup-publication", "reload", "effective-route", "source-only-before-gate", "ordinary-start-denied-after-gate")
    rows = receipt["observations"]
    if not isinstance(rows, list) or len(rows) != 5:
        raise Refusal("controller receipt: five startup boundary observations required")
    events = {}; previous_time = receipt["started_at"]
    for index, (row, checkpoint, check) in enumerate(zip(rows, checkpoints, checks)):
        exact(row, ("boundary_index", "boundary_process", "check", "checkpoint", "details", "observed_at", "record_sha256"), "controller observation")
        if row["boundary_index"] != index or row["boundary_process"] != process or row["check"] != check or row["checkpoint"] != checkpoint or not SHA256.fullmatch(row["record_sha256"]):
            raise Refusal("controller receipt: process, order, checkpoint, or record digest differs")
        details = row["details"]
        detail_keys = ({"drop_in_sha256"},
                       {"drop_in_sha256","loaded_condition_exact"},
                       {"drop_in_sha256","loaded_condition_exact"},
                       {"drop_in_sha256","loaded_condition_exact","ordinary_active_start","source_process","target_staged_only","whole_host_owner"},
                       {"drop_in_sha256","loaded_condition_exact","main_pid","ordinary_requests_denied","owned_processes_and_descendants_absent"})[index]
        if not isinstance(details, dict) or set(details) != detail_keys or not SHA256.fullmatch(details.get("drop_in_sha256", "")):
            raise Refusal("controller receipt: exact startup publication detail absent")
        if index >= 1 and details.get("loaded_condition_exact") is not True:
            raise Refusal("controller receipt: loaded startup condition not proved")
        if index == 3 and (details.get("target_staged_only") is not True or details.get("ordinary_active_start") != "no-op" or details.get("whole_host_owner") != process["pid"]):
            raise Refusal("controller receipt: pre-gate route proof differs")
        if index == 3:
            source_process = exact(details.get("source_process"), ("pid","start_tick"), "controller source process")
            if any(type(source_process[key]) is not int or source_process[key] < 1 for key in source_process) or source_process["pid"] < 2:
                raise Refusal("controller receipt: source process identity refused")
        if index == 4 and (details.get("ordinary_requests_denied") != ["start", "restart"] or details.get("main_pid") != 0 or details.get("owned_processes_and_descendants_absent") is not True):
            raise Refusal("controller receipt: post-gate denial proof differs")
        if not before(previous_time, row["observed_at"]):
            raise Refusal("controller receipt: observation sequence is not monotonic")
        previous_time = row["observed_at"]
        events[{"startup-publication":"startup_published_at", "reload":"reload_verified_at", "effective-route":"effective_route_verified_at", "source-only-before-gate":"source_only_before_gate_at", "ordinary-start-denied-after-gate":"ordinary_start_denied_at"}[check]] = row["observed_at"]
    if not before(previous_time, receipt["completed_at"]):
        raise Refusal("controller receipt: observations exceed completion")
    return timing.EventSource("controller", scenario, manifest_sha, request_sha, raw, digest(raw), events)


def outside_source(receipt, raw, collected, collected_body, manifest_raw, request_raw, state, scenario, manifest_sha, request_sha):
    try:
        bound = identity.binding(manifest_raw, request_raw, state)
        identity.check(receipt, bound, state)
    except Exception as error:
        raise Refusal("outside receipt: strict producer adapter refused") from error
    exact(collected, ("receipt_sha256",), "outside collected receipt")
    if collected["receipt_sha256"] != digest(raw):
        raise Refusal("outside collected receipt: exact receipt bytes SHA differs")
    events = {key: receipt[key] for key in ("old_established_at", "old_terminated_at", "old_refused_at", "target_healthy_at", "replacement_at")}
    return timing.EventSource("outside", scenario, manifest_sha, request_sha, raw, digest(raw), events)


def source_08(state, state_raw, safe, safe_raw, scenario, manifest_sha, request_sha, request, candidate):
    exact(state, ("action_completed_at", "action_started_at", "authoritative_link_sha256", "config_sha256", "creation_provenance", "entry_started_at", "install_at", "key_sha256", "ownership_sha256", "proxy_pid", "proxy_start_tick", "release_identity", "setup_at", "started_at", "uuid_sha256"), "08 private state")
    exact(safe, ("action_completed_at", "action_started_at", "authoritative_link_sha256", "completed_at", "final_state", "initial_state", "link_id", "ownership_record_sha256", "ownership_schema", "private_state_sha256", "qualification_manifest_sha256", "request_sha256", "scenario_id", "schema", "started_at", "subscription_observed_at", "subscription_receipt_sha256"), "08 safe state")
    if (safe["schema"] != "sbxr-v4-enable-schema1-safe-state-v1" or safe["scenario_id"] != scenario or safe["qualification_manifest_sha256"] != manifest_sha or safe["request_sha256"] != request_sha or
            safe["private_state_sha256"] != digest(state_raw) or safe["initial_state"] != "Running" or safe["final_state"] != "Running" or safe["ownership_schema"] != 2 or
            not HEX32.fullmatch(safe["link_id"]) or not SHA256.fullmatch(safe["ownership_record_sha256"]) or not SHA256.fullmatch(safe["authoritative_link_sha256"]) or not SHA256.fullmatch(safe["subscription_receipt_sha256"])):
        raise Refusal("08 safe state: exact state, schema, link, or artifact binding differs")
    if state.get("release_identity") != candidate.get("release_identity"):
        raise Refusal("08 state: release identity differs from signed candidate")
    if (any(not SHA256.fullmatch(state.get(key, "")) for key in ("authoritative_link_sha256","config_sha256","key_sha256","ownership_sha256","uuid_sha256")) or
            any(not isinstance(state.get(key), str) or re.fullmatch(r"[1-9][0-9]*", state[key]) is None for key in ("proxy_pid","proxy_start_tick")) or
            not isinstance(state["creation_provenance"], list)):
        raise Refusal("08 state: protected hash, process, or provenance fields refused")
    if any(not before(state[left], state[right]) for left, right in (("started_at","entry_started_at"),("entry_started_at","install_at"),("install_at","setup_at"),("setup_at","action_started_at"),("action_started_at","action_completed_at"))):
        raise Refusal("08 state: action timestamp order refused")
    for key in ("started_at", "action_started_at", "action_completed_at", "authoritative_link_sha256"):
        if state.get(key) != safe[key]:
            raise Refusal(f"08 safe state: {key} differs from private state")
    if not before(safe["started_at"], safe["action_started_at"]) or not before(safe["action_started_at"], safe["action_completed_at"]) or not before(safe["action_completed_at"], safe["subscription_observed_at"]) or not before(safe["subscription_observed_at"], safe["completed_at"]):
        raise Refusal("08 safe state: timestamp order refused")
    events = {"setup_at": state.get("setup_at"), "action_started_at": safe["action_started_at"], "action_completed_at": safe["action_completed_at"]}
    for key, value in events.items(): instant(value, f"08 state.{key}")
    return timing.EventSource("state", scenario, manifest_sha, request_sha, state_raw, digest(state_raw), events)


def validate_08_receipts(options, state, safe, safe_raw, request, request_sha, manifest_sha, scenario):
    trace_raw = private_bytes(options.connection_observation, "connection observation")
    summary, _, summary_raw = load(options.connection_summary, "connection summary", True)
    subscription, _, subscription_raw = load(options.subscription_observation, "subscription observation", True)
    try:
        expected = connection.validate(os.fspath(options.connection_observation), state["started_at"], state["action_started_at"], state["action_completed_at"], request["deadline_unix"], request_sha)
    except Exception as error:
        raise Refusal("connection observation: strict action-spanning adapter refused") from error
    if summary != expected:
        raise Refusal("connection summary: exact trace summary differs")
    exact(subscription, ("artifact_fields_and_name", "certificate_der_sha256", "completed_at", "configuration_sha256", "expected_status", "link_sha256", "qualification_manifest_sha256", "request_sha256", "scenario_id", "schema", "started_at", "trusted_outside_tls"), "subscription observation")
    if (subscription["schema"] != "sbxr-v4-subscription-check-v2" or subscription["scenario_id"] != scenario or
            subscription["qualification_manifest_sha256"] != manifest_sha or subscription["request_sha256"] != request_sha or
            subscription["link_sha256"] != safe["authoritative_link_sha256"] or not SHA256.fullmatch(subscription["configuration_sha256"]) or
            not SHA256.fullmatch(subscription["certificate_der_sha256"]) or subscription["artifact_fields_and_name"] is not True or
            subscription["expected_status"] is not True or subscription["trusted_outside_tls"] is not True or
            safe["subscription_receipt_sha256"] != digest(subscription_raw) or safe["subscription_observed_at"] != subscription["completed_at"] or
            not before(state["action_completed_at"], subscription["started_at"]) or not before(subscription["started_at"], subscription["completed_at"]) or
            instant(subscription["completed_at"], "subscription completed") > timing.Instant(request["deadline_unix"], 0)):
        raise Refusal("subscription observation: authoritative link check differs")
    rows = [json.loads(line, object_pairs_hook=unique) for line in trace_raw.splitlines()]
    connection_events = {"last_at": rows[-1]["time"]}
    subscription_events = {"observed_at": subscription["completed_at"]}
    return (timing.EventSource("connection", scenario, manifest_sha, request_sha, trace_raw, digest(trace_raw), connection_events),
            timing.EventSource("subscription", scenario, manifest_sha, request_sha, subscription_raw, digest(subscription_raw), subscription_events))


def write_new(path, raw):
    parent = path.parent.lstat()
    if (not path.is_absolute() or path.exists() or path.is_symlink() or stat.S_ISLNK(parent.st_mode) or
            not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700):
        raise Refusal("output: new absolute file in mode-0700 directory required")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, raw); os.fsync(fd)
    finally:
        os.close(fd)


def retain_07(state_directory: Path):
    if not state_directory.is_absolute():
        raise Refusal("retention: absolute state directory required")
    info = state_directory.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refusal("retention: mode-0700 non-symlink state directory required")
    copies = []
    for original_name in RETAINED_07:
        original = state_directory / original_name
        retained = state_directory / ("07-retained-" + original_name.removeprefix("07-"))
        raw = private_bytes(original, original_name)
        write_new(retained, raw)
        if private_bytes(retained, retained.name) != raw:
            raise Refusal(f"retention: {original_name} copy differs")
        copies.append((original, retained, digest(raw)))
    for original, _, _ in copies:
        original.unlink()
    directory = os.open(state_directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    for original, retained, expected in copies:
        if original.exists() or original.is_symlink() or digest(private_bytes(retained, retained.name)) != expected:
            raise Refusal("retention: original absence or retained bytes check failed")
    print(json.dumps({"retained": len(copies), "schema": "sbxr-v4-identity-outside-retention-v1"}, sort_keys=True, separators=(",", ":")))


def rules_for(scenario):
    if scenario in later.SCENARIOS:
        return tuple(later.adapter(sys.modules[__name__], scenario).rules(timing, scenario))
    return timing.scenario_rules(scenario)


def packages_for(attempt, scenario):
    if SCENARIO_INDEX[scenario] < 13:
        return attempt['packages'], attempt['packages']
    after = attempt.get('after_snap_refresh')
    if not isinstance(after, dict):
        raise Refusal('scenario: signed post-refresh packages required')
    return (attempt['packages'] if scenario == 'snap-refresh' else after), after


def assemble(options):
    scenario = options.command; index = SCENARIO_INDEX[scenario]
    manifest, manifest_body, manifest_raw = load(options.manifest, "manifest")
    boundary, boundary_body, boundary_raw = load(options.boundary, "boundary", limit=BOUNDARY_LIMIT)
    request, request_body, request_raw = load(options.request, "request", True)
    prefix, prefix_body, prefix_raw = load(options.accepted_prior_prefix, "prior prefix", True)
    preparation, _, _ = load(options.preparation_receipt, "preparation receipt", True)
    operator, _, operator_raw = load(options.operator_observations, "operator observations", True)
    route, _, route_raw = load(options.effective_route, "effective route receipt", True)
    capture_raw = private_bytes(options.operator_capture, "operator capture")
    proof, _, _ = load(options.proof, "proof", True)
    candidate, attempt, manifest_sha = validate_manifest(manifest, manifest_body, scenario)
    request, request_sha = validate_request(request, request_raw, manifest_sha, scenario, attempt)
    prior, previous_time = validate_prefix(prefix, manifest, manifest_sha, index)
    validator_raw = private_bytes(options.validator, "validator", 0o700, VALIDATOR_LIMIT)
    if not SHA256.fullmatch(options.validator_sha256) or digest(validator_raw) != options.validator_sha256 or not os.access(options.validator, os.X_OK):
        raise Refusal("validator: pinned executable SHA or mode differs")
    validator_before = options.validator.lstat()
    prepared_at = validate_preparation(preparation, manifest_sha, digest(boundary_raw), request_sha, digest(prefix_raw), options.validator_sha256, request, scenario)
    rules = rules_for(scenario)
    sources = {"entry": operator_source(operator, operator_raw, capture_raw, scenario, manifest_sha, request_sha, rules),
               "route": route_source(route, route_raw, scenario, manifest_sha, request_sha)}
    if scenario == "identity-absent":
        state, _, state_raw = load(options.state, "07 state")
        controller, _, controller_raw = load(options.controller_receipt, "controller receipt", True)
        outside, _, outside_raw = load(options.outside_receipt, "outside receipt")
        collected, collected_body, _ = load(options.outside_collected, "outside collected")
        sources["state"] = state_07_source(state, state_raw, scenario, manifest_sha, request_sha, request)
        sources["controller"] = controller_source(controller, controller_raw, state, scenario, manifest_sha, request_sha)
        challenge, _, _ = load(options.rotation_request, "rotation request")
        acknowledgement, _, _ = load(options.rotation_ready, "rotation ready")
        try:
            bound = identity.binding(manifest_raw, request_raw, state)
            identity.check_rotation_ack(acknowledgement, challenge, bound, identity.timestamp(state["rotation_started_at"]))
        except Exception as error:
            raise Refusal("outside rotation receipts: strict challenge adapter refused") from error
        if outside.get("connection_id") != acknowledgement.get("connection_id") or outside.get("rotation_ready_at") != acknowledgement.get("alive_at") or outside.get("rotation_challenge_sha256") != digest(canonical(challenge)):
            raise Refusal("outside rotation receipts: final linkage differs")
        sources["outside"] = outside_source(outside, outside_raw, collected, collected_body, manifest_raw, request_raw, state, scenario, manifest_sha, request_sha)
        completed_entry = state["completed_at"]
    elif scenario == "enable-schema1":
        state, _, state_raw = load(options.state, "08 private state")
        safe, _, safe_raw = load(options.safe_state, "08 safe state")
        sources["state"] = source_08(state, state_raw, safe, safe_raw, scenario, manifest_sha, request_sha, request, candidate)
        con, sub = validate_08_receipts(options, state, safe, safe_raw, request, request_sha, manifest_sha, scenario)
        sources["connection"], sources["subscription"] = con, sub
        completed_entry = safe["completed_at"]
    elif scenario.startswith('link-'):
        state, _, state_raw = load(options.state, "link entry state", True)
        sources.update(links.sources(sys.modules[__name__], options, state, state_raw, manifest_raw, request_raw,
                                    scenario, manifest_sha, request_sha, request))
        completed_entry = state["completed_at"]
    else:
        state, _, state_raw = load(options.state, 'scenario entry', True)
        sources['state'] = later.state_source(sys.modules[__name__], state, state_raw, scenario, manifest_sha, request_sha, request)
        context = later.Context(sys.modules[__name__], scenario, manifest, manifest_raw, manifest_sha,
                                request, request_raw, request_sha, state, options.sources_directory)
        family_sources = later.adapter(sys.modules[__name__], scenario).sources(context)
        if set(family_sources) & set(sources):
            raise Refusal('scenario adapter: shared sources cannot be replaced')
        sources.update(family_sources)
        completed_entry = state['completed_at']
    exact(proof, ("completed_at", "link_id", "observations", "operation_id", "scenario_id", "schema"), "proof")
    proof_schema = LATER_PROOF_SCHEMA if scenario in later.SCENARIOS else LINK_PROOF_SCHEMA if scenario.startswith("link-") else PROOF_SCHEMA
    if proof["schema"] != proof_schema or proof["scenario_id"] != scenario or proof["operation_id"] != f"operation-{index+1}" or proof["link_id"] != "":
        raise Refusal("proof: exact schema, scenario, operation, or link contract differs")
    if not before(prepared_at, state["entry_started_at"]) or not before(completed_entry, proof["completed_at"]):
        raise Refusal("preparation, entry, and proof order refused")
    deadline = datetime.fromtimestamp(request["deadline_unix"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if (not before(request["not_before"], state["started_at"]) or not before(proof["completed_at"], deadline) or
            instant(proof["completed_at"], "proof.completed_at").epoch_second - instant(state["started_at"], "state.started_at").epoch_second > request["scenario_limit_seconds"]):
        raise Refusal("scenario: exact current request window or signed limit exceeded")
    try:
        observations = timing.validate_observations(scenario_id=scenario, qualification_manifest_sha256=manifest_sha,
            request_sha256=request_sha, observations=proof["observations"], proof_completed_at=proof["completed_at"], rules=rules, sources=sources)
    except timing.EvidenceTimingRefusal as error:
        raise Refusal(str(error)) from error
    validated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if (not before(proof["completed_at"], validated_at) or
            instant(validated_at, "validated_at").epoch_second - instant(proof["completed_at"], "proof.completed_at").epoch_second > attempt["validation_limit_seconds"]):
        raise Refusal("validation time lies outside signed limit")
    if previous_time and not before(previous_time, state["started_at"]):
        raise Refusal("scenario starts before accepted prefix validation")
    outcome = ("Running", "observed", "none", "Not installed") if scenario == "identity-absent" else ("Running", "observed", "none", "Running")
    if scenario == "link-precommit":
        outcome = ("Running", "before-commitment", "rollback", "Running")
    elif scenario == "link-postcommit":
        outcome = ("Running", "after-commitment", "forward", "Running")
    elif scenario == 'managed-renewal':
        outcome = ('Running', 'observed', 'forward', 'Running')
    elif scenario == 'identity-precommit':
        outcome = ('Running', 'before-commitment', 'rollback', 'Running')
    elif scenario == 'identity-postcommit':
        outcome = ('Running', 'after-commitment', 'forward', 'Running')
    elif scenario in ('remove-certbot', 'remove-writer', 'remove-admission-race', 'remove-directory-lock'):
        outcome = ('Running', 'refusal', 'none', 'Running')
    elif scenario == 'karing-final':
        outcome = ('Running', 'observed', 'none', 'Not installed')
    packages_before, packages_after = packages_for(attempt, scenario)
    references = [{"record": record, "sha256": digest(canonical(record))} for record in observations]
    scenario_value = {"actual_result":EVIDENCE_RESULT,"attempt_id":attempt["attempt_id"],"boundary":outcome[1],"candidate":candidate,
        "completed_at":proof["completed_at"],"evidence":references,"expected_result":EVIDENCE_RESULT,"final_state":outcome[3],"initial_state":outcome[0],
        "link_id":"","operation_id":f"operation-{index+1}","packages_after":packages_after,"packages_before":packages_before,"preflight_at":state["started_at"],
        "prior_scenario_sha256":prior,"recovery_direction":outcome[2],"scenario_id":scenario,"schema":"sbxr-v3-scenario-evidence-v3","source":None,
        "started_at":state["started_at"],"validated_at":validated_at,"vps_id":attempt["vps_id"],"vps_identity_sha256":attempt["vps_identity_sha256"]}
    detailed = {"attempt_id":attempt["attempt_id"],"observed_at":validated_at,"qualification_manifest_sha256":manifest_sha,"scenarios":prefix+[scenario_value],"schema":"sbxr-v3-packaged-live-evidence-v3"}
    facts = {"detailed_evidence":detailed,"detailed_evidence_sha256":digest(canonical(detailed)),"evaluation_time":validated_at,"observed_at":validated_at,
        "prior_decision_sha256":manifest_sha,"qualification_boundary_facts":boundary,"qualification_manifest":manifest,"qualification_manifest_attested":True,
        "releases":manifest["releases"],"runner":attempt["runner"],"schema":FACTS_SCHEMA,"stage":RESULT_STAGE}
    output = canonical(facts)
    result = subprocess.run([os.fspath(options.validator), "qualification"], input=output, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    after = options.validator.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (validator_before.st_dev, validator_before.st_ino, validator_before.st_size, validator_before.st_mtime_ns) or digest(private_bytes(options.validator, "validator", 0o700, VALIDATOR_LIMIT)) != options.validator_sha256:
        raise Refusal("validator: identity or bytes changed during validation")
    expected = {"facts_sha256":digest(output),"outcome":"accepted","prior_decision_sha256":manifest_sha,"records":[],"schema":DECISION_SCHEMA,"stage":RESULT_STAGE}
    try: decision = json.loads(result.stdout, object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError) as error: raise Refusal("validator: invalid decision JSON") from error
    if result.returncode != 0 or decision != expected or canonical(decision) != result.stdout:
        raise Refusal("validator: canonical Go decision did not bind exact output")
    write_new(options.output, output)
    print(f"assembled scenario={scenario} facts_sha256={digest(output)} output={options.output}")


def common(parser):
    for name in ("manifest","boundary","request","accepted-prior-prefix","preparation-receipt","operator-observations","operator-capture","effective-route","state","proof","validator","output"):
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--validator-sha256", required=True)


def parser():
    root=argparse.ArgumentParser(description=__doc__); commands=root.add_subparsers(dest="command",required=True)
    checks=commands.add_parser("required-checks"); checks.add_argument("scenario",choices=SCENARIOS)
    retention=commands.add_parser("retain-07"); retention.add_argument("--state-directory",type=Path,required=True)
    seven=commands.add_parser("identity-absent"); common(seven)
    for name in ("controller-receipt","outside-receipt","outside-collected","rotation-request","rotation-ready"): seven.add_argument("--"+name,type=Path,required=True)
    eight=commands.add_parser("enable-schema1"); common(eight)
    for name in ("safe-state","connection-observation","connection-summary","subscription-observation"): eight.add_argument("--"+name,type=Path,required=True)
    for scenario in ("link-precommit", "link-postcommit"):
        link=commands.add_parser(scenario); common(link)
        for name in ("controller-receipt", "outside-directory", "connection-observation", "connection-summary"):
            link.add_argument("--"+name, type=Path, required=True)
    for scenario in later.SCENARIOS:
        command = commands.add_parser(scenario)
        common(command)
        command.add_argument('--sources-directory', type=Path, required=True)
    return root


def main():
    options=parser().parse_args()
    try:
        if options.command=="required-checks": print("\n".join(rule.check for rule in rules_for(options.scenario)))
        elif options.command=="retain-07": retain_07(options.state_directory)
        else: assemble(options)
    except (Refusal,OSError,subprocess.SubprocessError) as error:
        print(f"refused: {error}",file=sys.stderr); return 1
    return 0


if __name__=="__main__": raise SystemExit(main())
