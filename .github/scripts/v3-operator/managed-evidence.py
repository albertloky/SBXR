#!/usr/bin/env python3
"""Current-request source adapters for managed-renewal scenarios 11--15."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys


SCENARIOS = ("managed-renewal", "recorder-live", "recorder-locks", "snap-refresh", "unsupported-route")
SNAPSHOT_KEYS = (
    "schema", "scenario_id", "qualification_manifest_sha256", "request_sha256", "phase", "observed_at",
    "status", "packages", "proxy_configuration_sha256", "client_identity_sha256", "link_id", "link_sha256",
    "subscription_artifact_sha256", "certificate_generation", "certificate_sha256", "certificate_der_sha256", "ownership_sha256",
    "renewal_history_sha256", "route", "unrelated_packages_sha256", "unrelated_lineages_sha256",
    "active_package_work", "active_certbot", "writer_active", "local_activation_accepted", "bounded_refusal",
)
ROUTE_KEYS = ("timer_sha256", "service_sha256", "dropin_sha256", "hooks_sha256", "recorder_sha256", "exec_start_sha256")


def _refuse(api, message):
    raise api.Refusal("managed evidence: " + message)


def _digest(api, value):
    return isinstance(value, str) and api.SHA256.fullmatch(value) is not None


def _records(api, capture, label):
    events = capture.get("events") if isinstance(capture, dict) else None
    if not isinstance(events, list) or not events:
        _refuse(api, label + " capture has no events")
    records = []
    for event in events:
        api.exact(event, ("observed_at", "record"), label + " capture event")
        if not isinstance(event["record"], dict):
            _refuse(api, label + " emitted non-JSON output")
        records.append((event["observed_at"], event["record"]))
    return records


def _captured(ctx, filename, helper, source_id, expected_states, event_names=None):
    capture, raw = ctx.capture(filename, helper)
    records = _records(ctx.api, capture, helper)
    if [record.get("state") for _, record in records] != list(expected_states):
        _refuse(ctx.api, helper + " event sequence differs")
    event_names = event_names or tuple(state.replace("-", "_") + "_at" for state in expected_states)
    return records, ctx.source(source_id, raw, {
        event: observed for (observed, _), event in zip(records, event_names)
    })


def _snapshot(ctx, filename, phase):
    capture, raw = ctx.capture(filename, "managed-evidence")
    records = _records(ctx.api, capture, filename)
    if len(records) != 1:
        _refuse(ctx.api, filename + " must contain one snapshot")
    observed_at, value = records[0]
    ctx.api.exact(value, SNAPSHOT_KEYS, "managed snapshot")
    if (value["schema"] != "sbxr-v4-managed-snapshot-v1" or value["scenario_id"] != ctx.scenario or
            value["qualification_manifest_sha256"] != ctx.manifest_sha or value["request_sha256"] != ctx.request_sha or
            value["phase"] != phase or value["status"] != "Running" or
            not ctx.api.before(capture["started_at"], value["observed_at"]) or
            not ctx.api.before(value["observed_at"], observed_at) or
            not ctx.api.before(observed_at, capture["completed_at"])):
        _refuse(ctx.api, "snapshot source binding or state differs")
    for key in ("proxy_configuration_sha256", "client_identity_sha256", "link_sha256", "subscription_artifact_sha256", "certificate_der_sha256",
                "ownership_sha256", "renewal_history_sha256", "unrelated_packages_sha256", "unrelated_lineages_sha256"):
        if not _digest(ctx.api, value[key]):
            _refuse(ctx.api, key + " digest required")
    if not isinstance(value["link_id"], str) or re.fullmatch(r"(?:[0-9a-f]{32}|link-[A-Za-z0-9._:-]+)", value["link_id"]) is None:
        _refuse(ctx.api, "non-secret link identity required")
    if type(value["certificate_generation"]) is not int or value["certificate_generation"] < 1:
        _refuse(ctx.api, "certificate generation required")
    if not isinstance(value["certificate_sha256"], list) or len(value["certificate_sha256"]) != 4 or not all(_digest(ctx.api, item) for item in value["certificate_sha256"]):
        _refuse(ctx.api, "four certificate digests required")
    route = ctx.api.exact(value["route"], ROUTE_KEYS, "managed route snapshot")
    if (not all(_digest(ctx.api, route[key]) for key in ROUTE_KEYS if key != "hooks_sha256") or
            not isinstance(route["hooks_sha256"], list) or len(route["hooks_sha256"]) != 2 or
            not all(_digest(ctx.api, item) for item in route["hooks_sha256"])):
        _refuse(ctx.api, "complete managed route digests required")
    if any(type(value[key]) is not bool for key in ("active_package_work", "active_certbot", "writer_active", "local_activation_accepted")):
        _refuse(ctx.api, "typed activity and activation observations required")
    return value, ctx.source(phase, raw, {"observed_at": observed_at})


def _outside(ctx, number):
    initial, _, initial_raw = ctx.read(f"{number}-subscription-before.json")
    final, _, final_raw = ctx.read(f"{number}-subscription-final.json")
    del initial, final
    ready, _, ready_raw = ctx.read(f"{number}-outside-ready.json")
    receipt, _, result_raw = ctx.read(f"{number}-outside-result.json")
    outside = ctx.api.import_sibling("sbxr_renewal_outside", "renewal-outside.py")
    try:
        bound = outside.binding(ctx.manifest_raw, ctx.request_raw)
        initial_value = outside.disclosure(initial_raw, bound)
        outside.check_ready(ready, bound, initial_raw, initial_value,
                            current=outside.link.timestamp(receipt["completed_at"]))
        outside.check(receipt, ctx.manifest_raw, ctx.request_raw, initial_raw, final_raw, ready_raw)
    except Exception as error:
        raise ctx.api.Refusal("managed evidence: outside trusted-TLS witness refused") from error
    if (not ctx.api.before(receipt["ready_at"], ctx.state["action_started_at"]) or
            receipt["action_completed_at"] != ctx.state["action_completed_at"] or
            not ctx.api.before(ctx.state["action_completed_at"], receipt["final_at"])):
        _refuse(ctx.api, "outside witness does not bracket the actual action")
    return receipt, ctx.source("outside", result_raw, {key: receipt[key] for key in
                                                        ("initial_at", "ready_at", "final_at", "completed_at")})


def _lineage(value):
    match = re.fullmatch(r"\.\./\.\./archive/sbxr-subscription/cert([1-9][0-9]*)\.pem", value) if isinstance(value, str) else None
    return int(match.group(1)) if match else None


def _history(ctx, number, phase, source_id=None):
    capture, raw = ctx.capture(f"{number}-renewal-{phase}.json", "managed-evidence")
    records = _records(ctx.api, capture, "renewal history")
    if len(records) != 1:
        _refuse(ctx.api, "renewal history requires one actual document")
    observed, envelope = records[0]
    ctx.api.exact(envelope, ("schema", "source_sha256", "history"), "renewal history source")
    if envelope["schema"] != "sbxr-v4-renewal-history-source-v1" or not _digest(ctx.api, envelope["source_sha256"]):
        _refuse(ctx.api, "renewal history source binding differs")
    value = envelope["history"]
    ctx.api.exact(value, ("schema", "recorder_id", "established_at", "attempts"), "renewal history")
    if (value["schema"] != 1 or re.fullmatch(r"[0-9a-f]{32}", value.get("recorder_id", "")) is None or
            value["recorder_id"] == "0" * 32 or not isinstance(value["established_at"], str) or
            not isinstance(value["attempts"], list) or len(value["attempts"]) > 32):
        _refuse(ctx.api, "renewal history shape differs")
    latest = value["established_at"]
    try:
        ctx.api.before(latest, latest)
    except Exception as error:
        raise ctx.api.Refusal("managed evidence: renewal history anchor differs") from error
    seen = set()
    for attempt in value["attempts"]:
        required = {"attempt_id", "invocation", "started_at", "boot_id", "recorder_pid", "process_tick", "lineage_before"}
        if (not isinstance(attempt, dict) or not required.issubset(attempt) or
                set(attempt) - (required | {"completion", "owned_deploy_hook", "owned_post_hook"}) or
                re.fullmatch(r"[0-9a-f]{32}", attempt.get("attempt_id", "")) is None or attempt["attempt_id"] in seen or
                attempt.get("invocation") not in ("snap-certbot-renew-v1", "snap-certbot-certonly-v1") or
                type(attempt.get("recorder_pid")) is not int or attempt["recorder_pid"] < 1 or
                type(attempt.get("process_tick")) is not int or attempt["process_tick"] < 1 or
                not isinstance(attempt.get("boot_id"), str) or not attempt["boot_id"] or
                _lineage(attempt.get("lineage_before")) is None or not isinstance(attempt.get("started_at"), str)):
            _refuse(ctx.api, "renewal attempt history differs")
        try:
            if not ctx.api.before(latest, attempt["started_at"]):
                _refuse(ctx.api, "renewal attempt history is not ordered")
        except Exception as error:
            raise ctx.api.Refusal("managed evidence: renewal attempt clock differs") from error
        completion = attempt.get("completion")
        completed_at = None
        if completion is not None:
            ctx.api.exact(completion, ("exit_code", "completed_at", "owned_outcome", "lineage_after"), "renewal completion")
            before_generation, after_generation = _lineage(attempt["lineage_before"]), _lineage(completion["lineage_after"])
            deploy, post = attempt.get("owned_deploy_hook"), attempt.get("owned_post_hook")
            expected_outcome = "incomplete"
            if before_generation == after_generation and deploy is None and post is None:
                expected_outcome = "no-op"
            elif (after_generation is not None and after_generation > before_generation and
                  ((attempt["invocation"] == "snap-certbot-certonly-v1" and deploy is None and post is None) or
                   (isinstance(deploy, dict) and isinstance(post, dict) and deploy.get("lineage_target") == completion["lineage_after"] and
                    deploy.get("outcome") == post.get("outcome") == "succeeded"))):
                expected_outcome = "renewed"
            if (type(completion["exit_code"]) is not int or not 0 <= completion["exit_code"] <= 255 or
                    after_generation is None or completion["owned_outcome"] != expected_outcome or
                    not isinstance(completion["completed_at"], str) or
                    not ctx.api.before(attempt["started_at"], completion["completed_at"])):
                _refuse(ctx.api, "renewal completion differs from recorder semantics")
            completed_at = completion["completed_at"]
        hook_times = []
        for key, role in (("owned_deploy_hook", "--certbot-deploy-hook"), ("owned_post_hook", "--certbot-post-hook")):
            hook = attempt.get(key)
            if hook is None:
                continue
            allowed = {"role", "outcome", "recorded_at"} | ({"lineage_target"} if role == "--certbot-deploy-hook" else set())
            if (not isinstance(hook, dict) or set(hook) != allowed or hook.get("role") != role or
                    hook.get("outcome") not in ("succeeded", "failed") or not isinstance(hook.get("recorded_at"), str) or
                    (role == "--certbot-deploy-hook" and _lineage(hook.get("lineage_target")) is None) or
                    not ctx.api.before(attempt["started_at"], hook["recorded_at"]) or
                    (completed_at is not None and not ctx.api.before(hook["recorded_at"], completed_at))):
                _refuse(ctx.api, "renewal hook differs from recorder semantics")
            hook_times.append(hook["recorded_at"])
        if len(hook_times) == 2 and not ctx.api.before(hook_times[0], hook_times[1]):
            _refuse(ctx.api, "renewal hook order differs")
        latest = completed_at or attempt["started_at"]
        seen.add(attempt["attempt_id"])
    return (value, envelope["source_sha256"]), ctx.source(source_id or "history_" + phase, raw, {"observed_at": observed})


def _healthy_noop(attempt):
    completion = attempt.get("completion", {})
    return (completion.get("exit_code") == 0 and completion.get("owned_outcome") == "no-op" and
            completion.get("lineage_after") == attempt.get("lineage_before") and
            "owned_deploy_hook" not in attempt and "owned_post_hook" not in attempt)


def _trace(ctx, number):
    capture, raw = ctx.capture(f"{number}-proxy-trace.json", "connection-probe")
    rows = _records(ctx.api, capture, "proxy trace")
    expected = ("check", "connection_id", "request_sha256", "same_connection", "schema", "time")
    connection = rows[0][1].get("connection_id")
    if len(rows) < 2 or not isinstance(connection, str) or re.fullmatch(r"[0-9a-f]{32}", connection) is None:
        _refuse(ctx.api, "one retained connection with at least two checks required")
    times = []
    for index, (_, row) in enumerate(rows, 1):
        ctx.api.exact(row, expected, "proxy trace row")
        if row != {"check": index, "connection_id": connection, "request_sha256": ctx.request_sha,
                   "same_connection": True, "schema": "sbxr-v3-connection-probe-v1", "time": row["time"]}:
            _refuse(ctx.api, "proxy trace sequence differs")
        times.append(row["time"])
    if (not ctx.api.before(ctx.state["started_at"], times[0]) or
            not ctx.api.before(times[0], ctx.state["action_started_at"]) or
            not ctx.api.before(ctx.state["action_completed_at"], times[-1]) or
            any(not ctx.api.before(left, right) for left, right in zip(times, times[1:]))):
        _refuse(ctx.api, "proxy trace does not span the actual action")
    return ctx.source("connection", raw, {"first_at": times[0], "last_at": times[-1]})


def _unchanged(api, before, final, keys, label):
    if any(before[key] != final[key] for key in keys):
        _refuse(api, label + " changed")


def _operator_sources(ctx, number):
    result = {}
    if ctx.scenario in ("managed-renewal", "recorder-live"):
        records, source = _captured(ctx, f"{number}-managed.json", "managed-hold", "operator",
                                    ("held", "interrupted" if ctx.scenario == "managed-renewal" else "completed"))
        held, final = records[0][1], records[1][1]
        if (held.get("egress_denied") is not True or not _digest(ctx.api, held.get("receipt_sha256")) or
                not isinstance(held.get("attempt_id"), str) or re.fullmatch(r"[0-9a-f]{32}", held["attempt_id"]) is None or
                final.get("no_ca_egress") is not True or not _digest(ctx.api, final.get("receipt_sha256"))):
            _refuse(ctx.api, "managed hold lacks actual receipt and no-egress proof")
        result["operator"] = source
        if ctx.scenario == "managed-renewal":
            boundary, boundary_source = _captured(ctx, "11-repair-boundary.json", "syscall-gate", "repair_boundary",
                                                   ("armed", "boundary-held", "released"),
                                                   ("armed_at", "preclear_at", "released_at"))
            held_boundary = boundary[1][1]
            if (held_boundary.get("boundary") != "after-close" or
                    held_boundary.get("path") != "/var/lib/sbxr/.renewal-attempts.json.next" or
                    not _digest(ctx.api, held_boundary.get("record_sha256")) or held_boundary.get("boundary_index") != 0):
                _refuse(ctx.api, "actual repair pre-clear renewal boundary required")
            result["repair_boundary"] = boundary_source
    elif ctx.scenario == "recorder-locks":
        records, source = _captured(ctx, "13-admission.json", "recorder-boundary", "operator", ("boundary-held", "completed"))
        held, final = records[0][1], records[1][1]
        if (held.get("mode") != "admission" or held.get("writer", {}).get("lock_state") != "unlocked" or
                held.get("admission", {}).get("lock_state") != "locked" or held.get("whole_host", {}).get("lock_state") != "unlocked" or
                final.get("no_ca_egress") is not True):
            _refuse(ctx.api, "actual shared-admission lock boundary differs")
        result["operator"] = source
        lock_records, lock_source = _captured(ctx, "13-whole-host.json", "hold-flock", "whole_host", ("held", "released"))
        holder_pid = lock_records[0][1].get("pid", 0)
        if holder_pid < 2 or not _digest(ctx.api, lock_records[0][1].get("sha256")):
            _refuse(ctx.api, "actual whole-host flock identity required")
        result["whole_host"] = lock_source
        wait_records, wait_source = _captured(ctx, "13-whole-host-wait.json", "observations", "during_wait", (None,), ("observed_at",))
        observed_at, wait = wait_records[0]
        ctx.api.exact(wait, ("schema", "lock_api", "observations"), "whole-host wait locks")
        observations = wait["observations"]
        if (wait["schema"] != "sbxr-v4-lock-observation-v1" or wait["lock_api"] != "flock" or
                not isinstance(observations, list) or len(observations) != 2):
            _refuse(ctx.api, "actual BSD flock observations required during wait")
        by_path = {item.get("path"): item for item in observations if isinstance(item, dict)}
        writer = by_path.get("/var/lib/sbxr/renewal-writer.lock", {})
        whole = by_path.get("/run/lock/sbxr.lock", {})
        if (writer.get("state") != "present" or writer.get("kind") != "file" or writer.get("nlink") != 1 or
                writer.get("lock_state") != "unlocked" or writer.get("holders") != [] or
                whole.get("state") != "present" or whole.get("kind") != "file" or whole.get("nlink") != 1 or
                whole.get("lock_state") != "locked" or {"mode": "WRITE", "pid": holder_pid} not in whole.get("holders", [])):
            _refuse(ctx.api, "writer-unlocked and exact whole-host holder proof required during wait")
        if (not ctx.api.before(lock_source.events["held_at"], observed_at) or
                not ctx.api.before(observed_at, lock_source.events["released_at"]) or
                not ctx.api.before(ctx.state["action_started_at"], observed_at) or
                not ctx.api.before(observed_at, ctx.state["action_completed_at"])):
            _refuse(ctx.api, "whole-host wait lock observation lies outside the actual request action")
        result["during_wait"] = wait_source
    elif ctx.scenario == "unsupported-route":
        injected, inject_source = _captured(ctx, "15-route-inject.json", "route-control", "route_inject", (None,), ("injected_at",))
        restored, restore_source = _captured(ctx, "15-route-restore.json", "route-control", "route_restore", (None,), ("restored_at",))
        first, last = injected[0][1], restored[0][1]
        if first.get("schema") != "sbxr-v4-route-control-v1" or last.get("schema") != first["schema"] or last.get("restored") is not True or last.get("unit") != first.get("unit") or last.get("timer") != first.get("timer"):
            _refuse(ctx.api, "same route inode and timer state were not restored")
        result.update(route_inject=inject_source, route_restore=restore_source)
    return result


def sources(ctx):
    if ctx.scenario not in SCENARIOS:
        _refuse(ctx.api, "unsupported scenario")
    number = {name: str(11 + index) for index, name in enumerate(SCENARIOS)}[ctx.scenario]
    before, before_source = _snapshot(ctx, f"{number}-managed-before.json", "before")
    final, final_source = _snapshot(ctx, f"{number}-managed-final.json", "final")
    if (not ctx.api.before(before['observed_at'], ctx.state['action_started_at']) or
            not ctx.api.before(ctx.state['action_completed_at'], final['observed_at'])):
        _refuse(ctx.api, 'before and final snapshots do not bracket the action')
    (history_before, history_before_sha), history_before_source = _history(ctx, number, "before")
    (history_final, history_final_sha), history_final_source = _history(ctx, number, "final")
    outside, outside_source = _outside(ctx, number)
    result = {"before": before_source, "final": final_source, "outside": outside_source,
              "history_before": history_before_source, "history_final": history_final_source,
              "connection": _trace(ctx, number), **_operator_sources(ctx, number)}
    if (before["renewal_history_sha256"] != history_before_sha or final["renewal_history_sha256"] != history_final_sha or
            history_before["recorder_id"] != history_final["recorder_id"]):
        _refuse(ctx.api, "snapshots do not bind the same recorder history")
    if ctx.scenario != "managed-renewal" and history_final["attempts"][:len(history_before["attempts"])] != history_before["attempts"]:
        _refuse(ctx.api, "renewal history did not preserve its before prefix")
    added = history_final["attempts"][len(history_before["attempts"]):]
    stable = ("proxy_configuration_sha256", "client_identity_sha256", "link_id", "link_sha256", "subscription_artifact_sha256")
    _unchanged(ctx.api, before, final, stable, "proxy, identity, link, or artifact")
    if outside["link_sha256"] != before["link_sha256"] or outside["configuration_sha256"] != before["subscription_artifact_sha256"]:
        _refuse(ctx.api, "outside witness differs from protected snapshots")
    if (outside["initial_certificate_der_sha256"] != before["certificate_der_sha256"] or
            outside["final_certificate_der_sha256"] != final["certificate_der_sha256"]):
        _refuse(ctx.api, "outside served certificate differs from the protected generation")
    if ctx.scenario == "managed-renewal":
        if (final["certificate_generation"] != before["certificate_generation"] + 1 or final["certificate_sha256"] == before["certificate_sha256"] or
                final["renewal_history_sha256"] == before["renewal_history_sha256"] or final["local_activation_accepted"] is not True):
            _refuse(ctx.api, "one repaired production replacement and activation required")
        (interrupted_history, interrupted_sha), interrupted_source = _history(ctx, "11", "interrupted", "history_interrupted")
        (repaired_history, repaired_sha), repaired_source = _history(ctx, "11", "repaired", "history_repaired")
        result.update(history_interrupted=interrupted_source, history_repaired=repaired_source)
        if (interrupted_history["recorder_id"] != history_before["recorder_id"] or
                repaired_history["recorder_id"] != history_before["recorder_id"] or
                interrupted_history["attempts"][:len(history_before["attempts"])] != history_before["attempts"] or
                repaired_history["attempts"][:len(interrupted_history["attempts"])] != interrupted_history["attempts"] or
                not repaired_history["attempts"] or history_final["attempts"] or
                not ctx.api.before(repaired_history["attempts"][-1]["completion"]["completed_at"], history_final["established_at"]) or
                not ctx.api.before(interrupted_source.events["observed_at"], repaired_source.events["observed_at"]) or
                not ctx.api.before(repaired_source.events["observed_at"], final_source.events["observed_at"])):
            _refuse(ctx.api, "repair receipts were not retained before the healthy history reset")
        # The coordinator attempt id is validated below from its actual captured output.
        held_capture, _ = ctx.capture("11-managed.json", "managed-hold")
        held_id = held_capture["events"][0]["record"]["attempt_id"]
        interrupted = next((item for item in interrupted_history["attempts"] if item["attempt_id"] == held_id), None)
        repair_added = repaired_history["attempts"][len(interrupted_history["attempts"]):]
        successes = [item for item in repair_added if item.get("completion", {}).get("exit_code") == 0 and item.get("completion", {}).get("owned_outcome") == "renewed"]
        managed_final = held_capture["events"][-1]["record"]
        repair_boundary_capture, _ = ctx.capture("11-repair-boundary.json", "syscall-gate")
        preclear = repair_boundary_capture["events"][1]["record"]
        if (interrupted is None or interrupted.get("completion", {}).get("exit_code") == 0 or len(repair_added) != 1 or
                len(successes) != 1 or managed_final.get("receipt_sha256") != interrupted_sha or repaired_sha == interrupted_sha or
                preclear.get("record_sha256") != repaired_sha or
                not ctx.api.before(result["repair_boundary"].events["preclear_at"], repaired_source.events["observed_at"]) or
                not ctx.api.before(repaired_source.events["observed_at"], result["repair_boundary"].events["released_at"])):
            _refuse(ctx.api, "failed or unknown attempt was not retained before one successful repair")
    elif ctx.scenario in ("recorder-live", "recorder-locks"):
        _unchanged(ctx.api, before, final, ("certificate_generation", "certificate_sha256"), "non-issuing certificate state")
        if final["renewal_history_sha256"] == before["renewal_history_sha256"]:
            _refuse(ctx.api, "actual recorder completion did not extend renewal history")
        if len(added) != 1 or not _healthy_noop(added[0]):
            _refuse(ctx.api, "exactly one healthy guarded recorder attempt required")
        receipt_file = "12-managed.json" if ctx.scenario == "recorder-live" else "13-admission.json"
        receipt_helper = "managed-hold" if ctx.scenario == "recorder-live" else "recorder-boundary"
        receipt_capture, _ = ctx.capture(receipt_file, receipt_helper)
        if receipt_capture["events"][-1]["record"].get("receipt_sha256") != history_final_sha:
            _refuse(ctx.api, "guarded completion and exact final renewal-history bytes differ")
        if ctx.scenario == "recorder-locks":
            (wait_before, wait_before_sha), wait_before_source = _history(ctx, "13-wait", "before", "wait_history_before")
            (wait_final, wait_final_sha), wait_final_source = _history(ctx, "13-wait", "final", "wait_history_final")
            result.update(wait_history_before=wait_before_source, wait_history_final=wait_final_source)
            held_at, released_at = result["whole_host"].events["held_at"], result["whole_host"].events["released_at"]
            during_at = result["during_wait"].events["observed_at"]
            if (wait_before != wait_final or wait_before_sha != wait_final_sha or
                    wait_before["recorder_id"] != history_final["recorder_id"] or wait_before["attempts"] != history_final["attempts"] or
                    not ctx.api.before(held_at, wait_before_source.events["observed_at"]) or
                    not ctx.api.before(wait_before_source.events["observed_at"], during_at) or
                    not ctx.api.before(during_at, wait_final_source.events["observed_at"]) or
                    not ctx.api.before(wait_final_source.events["observed_at"], released_at)):
                _refuse(ctx.api, "unchanged actual renewal history must bracket the whole-host wait")
            if final["bounded_refusal"] not in ({"active_state": "inactive", "exec_main_status": 125, "certbot_child": False},
                                                {"active_state": "failed", "exec_main_status": 125, "certbot_child": False}):
                _refuse(ctx.api, "typed status-125 whole-host refusal required")
    elif ctx.scenario == "snap-refresh":
        if added:
            _refuse(ctx.api, "snap refresh unexpectedly changed renewal history")
        attempt = ctx.manifest["v3_attempt"]
        if before["packages"] != attempt["packages"] or final["packages"] != attempt["after_snap_refresh"] or before["packages"]["certbot"] == final["packages"]["certbot"]:
            _refuse(ctx.api, "declared Certbot refresh identities required")
        _unchanged(ctx.api, before, final, ("unrelated_packages_sha256", "unrelated_lineages_sha256", "renewal_history_sha256", "certificate_generation", "certificate_sha256", "route"), "undeclared package, lineage, history, certificate, or effective route")
        if any(final[key] for key in ("active_package_work", "active_certbot", "writer_active")):
            _refuse(ctx.api, "refresh final activity is not quiescent")
    elif ctx.scenario == "unsupported-route":
        if added:
            _refuse(ctx.api, "route detection unexpectedly changed renewal history")
        _unchanged(ctx.api, before, final, ("packages", "unrelated_packages_sha256", "unrelated_lineages_sha256", "renewal_history_sha256", "certificate_generation", "certificate_sha256", "route"), "restored managed route or installation")
        if (not ctx.api.before(ctx.state['action_started_at'], result['route_inject'].events['injected_at']) or
                not ctx.api.before(result['route_inject'].events['injected_at'], result['route_restore'].events['restored_at']) or
                not ctx.api.before(result['route_restore'].events['restored_at'], ctx.state['action_completed_at'])):
            _refuse(ctx.api, 'route injection and restoration lie outside the action')
    return result


def _rule(timing, check, source, event, *required, after=None):
    required_sources = (source,) + tuple(required)
    end = (timing.Anchor("$proof", "completed_at"),) if after is None else (timing.Anchor(*after),)
    return timing.ObservationRule(check, required_sources, (timing.Anchor(source, event),), end)


def rules(timing, scenario):
    if scenario not in SCENARIOS:
        raise timing.EvidenceTimingRefusal(f"scenario {scenario!r}: no managed evidence rules")
    common = timing.later_common_rules()
    family = (
        _rule(timing, "proxy-and-traffic-unchanged", "connection", "last_at", "before", "final"),
        _rule(timing, "client-identity-unchanged", "final", "observed_at", "before", "outside"),
        _rule(timing, "unchanged-link", "outside", "final_at", "before", "final"),
    )
    extra = {
        "managed-renewal": (
            _rule(timing, "supported-managed-attempt-interrupted", "operator", "interrupted_at"),
            _rule(timing, "recorder-unknown-or-failed", "history_interrupted", "observed_at", "operator"),
            _rule(timing, "reviewed-repair-targeted-production-replacement", "entry", "repair_reviewed_at", "state"),
            _rule(timing, "fault-retained-until-proof", "history_repaired", "observed_at", "operator", "final", "history_interrupted", "repair_boundary"),
            _rule(timing, "official-schedule-integration", "final", "observed_at", "route"),
            _rule(timing, "recorder-start", "operator", "held_at", "history_interrupted"),
            _rule(timing, "recorder-outcome", "operator", "interrupted_at", "history_interrupted"),
            _rule(timing, "production-issuance", "final", "observed_at", "before"),
            _rule(timing, "canonical-publication", "final", "observed_at"),
            _rule(timing, "accepted-activation", "outside", "final_at", "final"),
            _rule(timing, "outside-tls", "outside", "final_at"),
            _rule(timing, "natural-timer-not-observed", "entry", "natural_timer_not_observed_at"),
            _rule(timing, "naturally-due-renewal-not-observed", "entry", "naturally_due_renewal_not_observed_at"),
        ),
        "recorder-live": (
            _rule(timing, "live-attempt", "operator", "held_at"),
            _rule(timing, "live-and-abandoned-distinguished", "history_final", "observed_at", "operator", "history_before"),
            _rule(timing, "live-not-completed", "operator", "held_at", "history_before", after=("operator", "completed_at")),
        ),
        "recorder-locks": (
            _rule(timing, "lock-order-contention", "operator", "boundary_held_at", "whole_host"),
            _rule(timing, "no-evidence-lock-held-during-child-or-whole-host-wait", "during_wait", "observed_at", "operator", "whole_host"),
            _rule(timing, "bounded-refusal", "wait_history_final", "observed_at", "whole_host", "during_wait", "wait_history_before", "final"),
        ),
        "snap-refresh": (
            _rule(timing, "supported-snap-refresh", "final", "observed_at", "before"),
            _rule(timing, "effective-generated-route-preserved", "final", "observed_at", "before", "route"),
            _rule(timing, "recorder-and-hooks-verified", "final", "observed_at", "before"),
            _rule(timing, "planned-package-change-only", "final", "observed_at", "before"),
        ),
        "unsupported-route": (
            _rule(timing, "new-or-renamed-route-detected", "route_inject", "injected_at", "entry"),
            timing.ObservationRule('problem-detected', ('entry', 'state', 'route_inject', 'route_restore'),
                (timing.Anchor('entry', 'problem_detected_at'), timing.Anchor('route_inject', 'injected_at')),
                (timing.Anchor('route_restore', 'restored_at'),)),
            _rule(timing, "accounting-gap-explicit", "entry", "accounting_gap_observed_at", "final"),
            _rule(timing, "bypass-prevention-not-claimed", "entry", "bypass_limit_observed_at", "final"),
            _rule(timing, "historical-outcomes-unknown", "entry", "historical_outcomes_observed_at", "final", "route_restore"),
        ),
    }
    return tuple(common) + family + extra[scenario]


def _private(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or
                before.st_uid != os.geteuid() or before.st_nlink != 1 or not 0 < before.st_size <= 1_000_000):
            raise ValueError("protected source metadata refused")
        raw = os.read(descriptor, 1_000_001)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        if (len(raw) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError("protected source changed while reading")
        return raw
    finally:
        os.close(descriptor)


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError("duplicate protected key")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict): raise ValueError("object source required")
    return value


def _file(path, mode):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != mode or
                before.st_uid != 0 or before.st_gid != 0 or before.st_nlink != 1 or before.st_size > 1_000_000):
            raise ValueError("managed runtime file metadata refused")
        raw = os.read(descriptor, 1_000_001)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        if (len(raw) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError("managed runtime file changed while reading")
        return raw
    finally:
        os.close(descriptor)


def _command(arguments, check=True):
    return subprocess.run(arguments, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout


def _tree_digest(root, excluded):
    rows = []
    root = Path(root)
    if not root.exists(): return hashlib.sha256(b"").hexdigest()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(relative.parts[:len(parts)] == parts for parts in excluded): continue
        info = path.lstat()
        row = [str(relative), f"{stat.S_IMODE(info.st_mode):04o}", str(info.st_uid), str(info.st_gid), str(info.st_size)]
        if stat.S_ISREG(info.st_mode): row.append(hashlib.sha256(_file(path, stat.S_IMODE(info.st_mode))).hexdigest())
        elif stat.S_ISLNK(info.st_mode): row.append("link:" + os.readlink(path))
        elif stat.S_ISDIR(info.st_mode): continue
        else: raise ValueError("unsupported lineage entry")
        rows.append(row)
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def _runtime_snapshot(phase, subscription_path):
    if sys.platform != "linux" or os.geteuid() != 0 or phase not in ("before", "final"):
        raise ValueError("Linux root and exact snapshot phase required")
    request_path = Path(os.environ["SBXR_QUALIFICATION_REQUEST"])
    manifest_path = Path(os.environ["SBXR_QUALIFICATION_MANIFEST"])
    request_raw, manifest_raw = _private(request_path), _private(manifest_path)
    request, manifest = _json(request_raw), _json(manifest_raw)
    scenario = request.get("scenario_id")
    if scenario not in SCENARIOS or request.get("qualification_manifest_sha256") != hashlib.sha256(manifest_raw).hexdigest():
        raise ValueError("snapshot authority differs")
    package_phase = "after-snap-refresh" if scenario == "snap-refresh" and phase == "final" or SCENARIOS.index(scenario) > SCENARIOS.index("snap-refresh") else "initial"
    _command(["bash", "-c", 'source "$1"; operator_initialize; load_candidate_identity; operator_expect_scenario "$2"; preflight "$3"; operator_exact_candidate',
              "managed-snapshot", str(Path(__file__).with_name("operator-support.sh")), scenario, package_phase])
    attempt = manifest["v3_attempt"]
    packages = attempt["after_snap_refresh" if package_phase == "after-snap-refresh" else "packages"]
    disclosure_raw = _private(subscription_path)
    disclosure = _json(disclosure_raw)
    expected_binding = {"scenario_id": scenario, "request_sha256": hashlib.sha256(request_raw).hexdigest(),
                        "qualification_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                        "deadline_unix": request["deadline_unix"], "not_before": request["not_before"]}
    if set(disclosure) != {"link", "certificate_der_sha256", "configuration", "binding"} or disclosure["binding"] != expected_binding:
        raise ValueError("protected subscription observation differs")
    ownership_raw = _file(Path("/var/lib/sbxr/proxy-ownership.json"), 0o600)
    ownership = _json(ownership_raw)
    serving_raw = _file(Path("/var/lib/sbxr/subscription-serving.json"), 0o600)
    serving_document = _json(serving_raw)
    if set(serving_document) != {"schema", "serving"} or serving_document["schema"] != 1 or not isinstance(serving_document["serving"], dict):
        raise ValueError("serving state envelope differs")
    serving = serving_document["serving"]
    history_raw = _file(Path("/var/lib/sbxr/renewal-attempts.json"), 0o600)
    config_raw = _file(Path("/etc/sing-box/config.json"), 0o640)
    config = _json(config_raw)
    config_sha = hashlib.sha256(config_raw).hexdigest()
    # Go writes the protected configuration as canonical bytes; the outside
    # disclosure must describe those exact fields.
    if ownership.get("phase") != "Running" or ownership.get("configuration_sha256") != config_sha:
        raise ValueError("running ownership or configuration differs")
    try:
        client_uuid = next(user["uuid"] for inbound in config["inbounds"] if inbound.get("type") == "vless" for user in inbound["users"])
    except (KeyError, StopIteration, TypeError):
        raise ValueError("server Client Identity unavailable")
    if not isinstance(client_uuid, str) or re.fullmatch(r"[0-9a-fA-F-]{36}", client_uuid) is None:
        raise ValueError("server Client Identity differs")
    artifact_sha = hashlib.sha256(json.dumps(disclosure["configuration"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    required_serving = {"link_id", "credential_sha256", "certificate_generation", "certificate_sha256"}
    if not required_serving.issubset(serving) or ownership.get("serving") != serving:
        raise ValueError("published serving authority differs")
    generation = serving["certificate_generation"]
    if type(generation) is not int or generation < 1 or not isinstance(serving["certificate_sha256"], list) or len(serving["certificate_sha256"]) != 4:
        raise ValueError("serving certificate authority differs")
    certificate_paths = (("cert", 0o644), ("chain", 0o644), ("fullchain", 0o644), ("privkey", 0o600))
    actual_certificate = [hashlib.sha256(_file(Path(f"/etc/letsencrypt/archive/sbxr-subscription/{name}{generation}.pem"), mode)).hexdigest()
                          for name, mode in certificate_paths]
    if actual_certificate != serving["certificate_sha256"]:
        raise ValueError("published certificate files differ")
    certificate_pem = _file(Path(f"/etc/letsencrypt/archive/sbxr-subscription/cert{generation}.pem"), 0o644)
    certificate_der_sha = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate_pem.decode("ascii"))).hexdigest()
    token_raw = _file(Path("/var/lib/sbxr/subscription-token"), 0o600).rstrip(b"\n")
    expected_link = "https://" + ownership["public_ipv4"] + ":8443/s/" + token_raw.decode("ascii")
    if disclosure["link"] != expected_link or hashlib.sha256(token_raw).hexdigest() != serving["credential_sha256"]:
        raise ValueError("subscription link authority differs")
    route_paths = {
        "dropin_sha256": (Path("/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf"), 0o644),
        "recorder_sha256": (Path("/usr/local/bin/sbxr"), 0o755),
    }
    route = {key: hashlib.sha256(_file(path, mode)).hexdigest() for key, (path, mode) in route_paths.items()}
    route["hooks_sha256"] = [hashlib.sha256(_file(Path(path), 0o700)).hexdigest() for path in
                              ("/etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription", "/etc/letsencrypt/renewal-hooks/post/sbxr-subscription")]
    route["timer_sha256"] = hashlib.sha256(_command(["systemctl", "cat", "snap.certbot.renew.timer"]).encode()).hexdigest()
    route["service_sha256"] = hashlib.sha256(_command(["systemctl", "cat", "snap.certbot.renew.service"]).encode()).hexdigest()
    route["exec_start_sha256"] = hashlib.sha256(_command(["systemctl", "show", "snap.certbot.renew.service", "--property=ExecStart", "--value"]).encode()).hexdigest()
    active_package = any(_command(["systemctl", "is-active", unit], False).strip() in ("active", "activating") for unit in ("apt-daily.service", "apt-daily-upgrade.service"))
    active_package = active_package or any(subprocess.run(["pgrep", "-x", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0 for name in ("apt", "apt-get", "dpkg", "snap"))
    active_certbot = _command(["systemctl", "is-active", "snap.certbot.renew.service"], False).strip() in ("active", "activating", "deactivating")
    lock_spec = importlib.util.spec_from_file_location("managed_snapshot_observations", Path(__file__).with_name("observations.py"))
    lock_api = importlib.util.module_from_spec(lock_spec); lock_spec.loader.exec_module(lock_api)
    writer_active = lock_api.observe_flock("/var/lib/sbxr/renewal-writer.lock").get("lock_state") == "locked"
    package_rows = [line for line in _command(["snap", "list", "--all"]).splitlines() if not line.startswith("certbot ")]
    package_rows += _command(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"]).splitlines()
    lineages = _tree_digest("/etc/letsencrypt", {("archive", "sbxr-subscription"), ("live", "sbxr-subscription"), ("renewal", "sbxr-subscription.conf"),
                                                          ("renewal-hooks", "deploy", "sbxr-subscription"), ("renewal-hooks", "post", "sbxr-subscription")})
    bounded = None
    if scenario == "recorder-locks" and phase == "final":
        status = _command(["systemctl", "show", "snap.certbot.renew.service", "--property=ExecMainStatus", "--value"]).strip()
        active_state = _command(["systemctl", "show", "snap.certbot.renew.service", "--property=ActiveState", "--value"]).strip()
        certbot_child = subprocess.run(["pgrep", "-f", r"/snap/certbot/[0-9]+/bin/certbot"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if status != "125" or active_state not in ("inactive", "failed") or certbot_child:
            raise ValueError("actual status-125 refusal or child absence differs")
        bounded = {"active_state": active_state, "exec_main_status": 125, "certbot_child": False}
    running = (_command(["systemctl", "is-active", "sing-box.service"], False).strip() == "active" and
               _command(["systemctl", "is-active", "sbxr-subscription.service"], False).strip() == "active")
    if active_package or active_certbot or writer_active or not running:
        raise ValueError("managed snapshot is not quiescent and Running")
    result = {"schema": "sbxr-v4-managed-snapshot-v1", "scenario_id": scenario,
              "qualification_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(), "request_sha256": hashlib.sha256(request_raw).hexdigest(),
              "phase": phase, "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
              "status": "Running", "packages": packages, "proxy_configuration_sha256": config_sha,
              "client_identity_sha256": hashlib.sha256(client_uuid.encode()).hexdigest(), "link_id": serving["link_id"],
              "link_sha256": hashlib.sha256(expected_link.encode()).hexdigest(),
              "subscription_artifact_sha256": artifact_sha,
              "certificate_generation": serving["certificate_generation"], "certificate_sha256": serving["certificate_sha256"],
              "certificate_der_sha256": certificate_der_sha,
              "ownership_sha256": hashlib.sha256(ownership_raw).hexdigest(), "renewal_history_sha256": hashlib.sha256(history_raw).hexdigest(),
              "route": route, "unrelated_packages_sha256": hashlib.sha256("\n".join(sorted(package_rows)).encode()).hexdigest(),
              "unrelated_lineages_sha256": lineages, "active_package_work": active_package, "active_certbot": active_certbot,
              "writer_active": writer_active, "local_activation_accepted": running,
              "bounded_refusal": bounded}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    snapshot = commands.add_parser("snapshot")
    snapshot.add_argument("--phase", choices=("before", "final"), required=True)
    snapshot.add_argument("--subscription", type=Path, required=True)
    history = commands.add_parser("history")
    history.add_argument("--source", type=Path, default=Path("/var/lib/sbxr/renewal-attempts.json"))
    options = parser.parse_args(argv)
    if options.command == "snapshot":
        result = _runtime_snapshot(options.phase, options.subscription)
    else:
        raw = _private(options.source)
        value = _json(raw)
        if set(value) != {"schema", "recorder_id", "established_at", "attempts"} or value.get("schema") != 1:
            raise ValueError("exact renewal history shape required")
        result = {"schema": "sbxr-v4-renewal-history-source-v1",
                  "source_sha256": hashlib.sha256(raw).hexdigest(), "history": value}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        print('{"managed_evidence_refused":true}', file=sys.stderr)
        raise SystemExit(1)
