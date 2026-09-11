#!/usr/bin/env python3
"""Strict source adapters and timing rules for identity scenarios 16--18."""
from __future__ import annotations

import re

SCENARIOS = ("identity-precommit", "identity-postcommit", "identity-unavailable")
PREFIX = ("old-established-outside-session", "outside-target-healthy", "startup-publication",
          "reload", "effective-route", "source-only-before-gate",
          "ordinary-start-denied-after-gate", "unchanged-link-and-noncredential-fields")
SUFFIX = {
    "identity-precommit": ("owned-process-groups-and-descendants-terminated",
        "source-restoration-only-before-revocation", "unused-target-removed",
        "source-traffic-restored", "rotation-reported-cancelled"),
    "identity-postcommit": ("owned-process-groups-and-descendants-terminated",
        "old-new-connections-refused", "one-target-forward-after-revocation",
        "replacement-traffic-proved"),
    "identity-unavailable": ("owned-process-groups-and-descendants-terminated",
        "old-new-connections-refused", "replacement-traffic-proved",
        "subscription-fault-reported-separately", "unavailable-subscription-fallback"),
}


def rules(timing, scenario):
    if scenario not in SCENARIOS:
        raise timing.EvidenceTimingRefusal(f"scenario {scenario!r}: identity evidence unsupported")
    A, R = timing.Anchor, timing.ObservationRule
    proof = (A(timing.PROOF_SOURCE, "completed_at"),)
    def rule(check, sources, starts, ends=proof):
        return R(check, tuple(sources), tuple(A(*item) for item in starts), tuple(ends))
    common = tuple(timing.later_common_rules())
    old_sources = ("outside", "state", "baseline") if scenario == "identity-unavailable" else ("outside", "state")
    old_starts = (("outside", "old_established_at"), ("outside", "subscription_outside_failed_at"),
                  ("baseline", "local_public_https_failed_at")) if scenario == "identity-unavailable" else (("outside", "old_established_at"),)
    specific = [
        rule(PREFIX[0], old_sources, old_starts, (A("state", "action_started_at"),)),
        rule(PREFIX[1], ("outside",), (("outside", "target_healthy_at"),)),
        rule(PREFIX[2], ("controller",), (("controller", "startup_publication_at"),)),
        rule(PREFIX[3], ("controller",), (("controller", "reload_at"),)),
        rule(PREFIX[4], ("controller",), (("controller", "effective_route_at"),)),
        rule(PREFIX[5], ("controller",), (("controller", "source_only_at"),)),
        rule(PREFIX[6], ("controller",), (("controller", "source_quiescent_at"),)),
        rule(PREFIX[7], ("outside", "private"), (("outside", "final_traffic_at"), ("private", "unchanged_at"))),
        rule(SUFFIX[scenario][0], ("controller", "outside"),
             (("controller", "source_quiescent_at"), ("outside", "old_terminated_at"))),
    ]
    if scenario == "identity-precommit":
        specific += [
            rule(SUFFIX[scenario][1], ("controller", "outside"), (("controller", "action_completed_at"), ("outside", "fresh_old_checked_at"))),
            rule(SUFFIX[scenario][2], ("runtime",), (("runtime", "unused_target_absent_at"),)),
            rule(SUFFIX[scenario][3], ("outside",), (("outside", "final_traffic_at"),)),
            rule(SUFFIX[scenario][4], ("controller",), (("controller", "action_completed_at"),)),
        ]
    elif scenario == "identity-postcommit":
        specific += [
            rule(SUFFIX[scenario][1], ("outside",), (("outside", "fresh_old_checked_at"),)),
            rule(SUFFIX[scenario][2], ("runtime", "controller"), (("controller", "action_completed_at"), ("runtime", "one_target_at"))),
            rule(SUFFIX[scenario][3], ("outside",), (("outside", "final_traffic_at"),)),
        ]
    else:
        specific += [
            rule(SUFFIX[scenario][1], ("outside",), (("outside", "fresh_old_checked_at"),)),
            rule(SUFFIX[scenario][2], ("outside",), (("outside", "final_traffic_at"),)),
            rule(SUFFIX[scenario][3], ("subscription",), (("subscription", "fault_reported_at"),)),
            rule(SUFFIX[scenario][4], ("outside", "subscription", "repair"),
                 (("outside", "final_traffic_at"), ("subscription", "fallback_disclosed_at"), ("repair", "same_link_restored_at"))),
        ]
    return common + tuple(specific)


def _exact(api, value, keys, label):
    return api.exact(value, tuple(keys), label)


def _digest(api, value, label):
    if not isinstance(value, str) or api.SHA256.fullmatch(value) is None:
        raise api.Refusal(label + ": lowercase SHA-256 required")


def _capture(ctx, name, helper, required):
    api = ctx.api
    document, raw = ctx.capture(name, helper)
    _exact(api, document, ("schema", "scenario_id", "qualification_manifest_sha256", "request_sha256",
                           "helper", "started_at", "completed_at", "exit_code", "events"), name)
    if (document["schema"] != "sbxr-v4-captured-source-v1" or document["scenario_id"] != ctx.scenario or
            document["qualification_manifest_sha256"] != ctx.manifest_sha or
            document["request_sha256"] != ctx.request_sha or document["helper"] != helper or
            type(document["exit_code"]) is not int or document["exit_code"] != 0 or
            not ctx.api.before(document["started_at"], document["completed_at"]) or
            not isinstance(document["events"], list)):
        raise api.Refusal(name + ": capture binding, result, or clock differs")
    events = {}
    for row in document["events"]:
        _exact(api, row, ("observed_at", "record"), name + " event")
        record = row["record"]
        _exact(api, record, ("event", "result", "facts"), name + " record")
        event = record["event"]
        if event in events or event not in required or record["result"] != "observed" or not isinstance(record["facts"], dict):
            raise api.Refusal(name + ": unexpected, duplicate, or refused event")
        if not api.before(document["started_at"], row["observed_at"]) or not api.before(row["observed_at"], document["completed_at"]):
            raise api.Refusal(name + ": event outside capture window")
        expected_facts = required[event]
        if any(record["facts"].get(key) != value for key, value in expected_facts.items()):
            raise api.Refusal(name + ": actual runtime facts differ")
        events[event] = row["observed_at"]
    if set(events) != set(required):
        raise api.Refusal(name + ": complete actual event set required")
    source_id = name.removeprefix("identity-").removesuffix(".json")
    return ctx.source(source_id, raw, events)


def _controller(ctx, state):
    api = ctx.api
    document, _, raw = ctx.read("identity-controller.json")
    keys = ("schema", "scenario", "phase", "qualification_manifest_sha256", "request_sha256",
            "entry_started_at", "started_at", "action_started_at", "interrupted_at", "action_completed_at", "completed_at",
            "initial_record_sha256", "interrupted_record_sha256", "final_record_sha256", "field",
            "checkpoint", "direction", "result_code", "boundary_process", "source_configuration_sha256",
            "target_configuration_sha256", "observations")
    _exact(api, document, keys, "identity controller")
    pre = ctx.scenario == "identity-precommit"
    expected = {"schema": "sbxr-v4-identity-transition-controller-v1", "scenario": ctx.scenario,
                "phase": "recovered" if ctx.scenario != "identity-unavailable" else "rotated",
                "qualification_manifest_sha256": ctx.manifest_sha, "request_sha256": ctx.request_sha,
                "field": "client_identity_rotation.checkpoint",
                "checkpoint": "source quiescent" if pre else "source revoked",
                "direction": "cleanup" if pre else "forward",
                "result_code": "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-CLEANED-UP" if pre else
                               ("PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATION-FINISHED" if ctx.scenario == "identity-postcommit" else
                                "PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATED")}
    if any(document[k] != v for k, v in expected.items()):
        raise api.Refusal("identity controller: boundary or result differs")
    if document["entry_started_at"] != state["entry_started_at"]:
        raise api.Refusal("identity controller: entry binding differs")
    order = [document[k] for k in ("entry_started_at", "started_at", "action_started_at", "interrupted_at", "action_completed_at", "completed_at")]
    if any(not api.before(a, b) for a, b in zip(order, order[1:])):
        raise api.Refusal("identity controller: event order differs")
    for key in ("initial_record_sha256", "interrupted_record_sha256", "final_record_sha256",
                "source_configuration_sha256", "target_configuration_sha256"):
        _digest(api, document[key], "identity controller")
    if document["source_configuration_sha256"] == document["target_configuration_sha256"]:
        raise api.Refusal("identity controller: distinct target required")
    process = _exact(api, document["boundary_process"], ("cgroup", "executable_device", "executable_inode", "pid", "start_tick"), "identity process")
    if process["pid"] < 2 or any(type(process[k]) is not int or process[k] < 1 for k in ("executable_device", "executable_inode", "pid", "start_tick")):
        raise api.Refusal("identity controller: actual process identity required")
    checks = ("startup-publication", "reload", "effective-route", "source-only-before-gate", "ordinary-start-denied-after-gate")
    checkpoints = ('target prepared', 'startup integration published', 'systemd reloaded', 'startup route verified', 'source quiescent')
    events = {"action_started_at": document["action_started_at"], "action_completed_at": document["action_completed_at"]}
    rows = document["observations"]
    if not isinstance(rows, list) or len(rows) != 5:
        raise api.Refusal("identity controller: five ordered startup observations required")
    aliases = ("startup_publication_at", "reload_at", "effective_route_at", "source_only_at", "source_quiescent_at")
    previous = document['action_started_at']
    for index, (row, check, event) in enumerate(zip(rows, checks, aliases)):
        _exact(api, row, ("boundary_index", "boundary_process", "check", "checkpoint", "details", "observed_at", "record_sha256"), "identity startup observation")
        if (row["boundary_index"] != index or row["boundary_process"] != process or row["check"] != check or
                row['checkpoint'] != checkpoints[index] or not api.before(previous, row['observed_at']) or
                not api.before(row['observed_at'], document['interrupted_at'])):
            raise api.Refusal("identity controller: startup observation identity differs")
        _digest(api, row['record_sha256'], 'startup Ownership Record')
        details = row['details']
        keys = ({'drop_in_sha256'}, {'drop_in_sha256', 'loaded_condition_exact'},
                {'drop_in_sha256', 'loaded_condition_exact'},
                {'drop_in_sha256', 'loaded_condition_exact', 'ordinary_active_start', 'source_process', 'target_staged_only', 'whole_host_owner'},
                {'drop_in_sha256', 'loaded_condition_exact', 'main_pid', 'ordinary_requests_denied', 'owned_processes_and_descendants_absent'})[index]
        _exact(api, details, keys, 'identity startup details')
        _digest(api, details['drop_in_sha256'], 'identity startup publication')
        if index >= 1 and details['loaded_condition_exact'] is not True:
            raise api.Refusal('identity controller: loaded startup route differs')
        if index == 3:
            source_process = _exact(api, details['source_process'], ('pid', 'start_tick'), 'identity source process')
            if (details['ordinary_active_start'] != 'no-op' or details['target_staged_only'] is not True or
                    details['whole_host_owner'] != process['pid'] or
                    any(type(value) is not int or value < 1 for value in source_process.values())):
                raise api.Refusal('identity controller: source-only startup facts differ')
        if index == 4 and (details['owned_processes_and_descendants_absent'] is not True or
                          details['ordinary_requests_denied'] != ['start', 'restart'] or details['main_pid'] != 0):
            raise api.Refusal('identity controller: ordinary startup denial differs')
        events[event] = row["observed_at"]
        previous = row['observed_at']
    return ctx.source("controller", raw, events), document, raw


def sources(ctx):
    api, scenario = ctx.api, ctx.scenario
    if scenario not in SCENARIOS:
        raise api.Refusal("identity evidence: unsupported scenario")
    state = ctx.state
    state_raw = api.canonical(state)
    controller_source, controller, controller_raw = _controller(ctx, state)
    ready, _, ready_raw = ctx.read("identity-outside-ready.json")
    _, _, closed_raw = ctx.read("identity-outside-closed.json")
    result, _, result_raw = ctx.read("identity-outside-result.json")
    outside_api = api.import_sibling("sbxr_identity_transition_outside_evidence", "identity-transition-outside.py")
    try:
        verified = outside_api.check_chain(ctx.manifest_raw, ctx.request_raw, state_raw, ready_raw, closed_raw, result_raw)
    except Exception as error:
        raise api.Refusal("identity outside: actual producer chain refused") from error
    if (controller["source_configuration_sha256"] != ready["source_configuration_sha256"] or
            controller["target_configuration_sha256"] != result["selected_configuration_sha256"] and scenario != "identity-precommit"):
        raise api.Refusal("identity evidence: outside selected authority differs")
    outside_events = {k: verified[k] for k in (
        "old_established_at", "old_terminated_at", "fresh_old_checked_at", "target_healthy_at", "final_traffic_at")}
    if scenario == "identity-unavailable":
        outside_events["subscription_outside_failed_at"] = verified["subscription_outside_failed_at"]
    output = {"controller": controller_source,
              "outside": ctx.source("outside", result_raw, outside_events)}
    if scenario == "identity-unavailable":
        baseline, _, baseline_raw = ctx.read("identity-private-baseline.json")
        required = ("schema", "scenario_id", "qualification_manifest_sha256", "request_sha256",
                    "source_configuration_sha256", "noncredential_sha256", "serving_sha256", "observed_at",
                    "local_public_https_failed_at", "issuance_lines")
        _exact(api, baseline, required, "identity unavailable baseline")
        if (baseline["schema"] != "sbxr-v4-identity-private-baseline-v1" or baseline["scenario_id"] != scenario or
                baseline["qualification_manifest_sha256"] != ctx.manifest_sha or baseline["request_sha256"] != ctx.request_sha or
                type(baseline["issuance_lines"]) is not int or baseline["issuance_lines"] < 0):
            raise api.Refusal("identity unavailable baseline binding differs")
        output["baseline"] = ctx.source("baseline", baseline_raw,
            {"local_public_https_failed_at": baseline["local_public_https_failed_at"]})
    output["private"] = _capture(ctx, "identity-private.json", "identity-private-observation", {
        "unchanged_at": {"link_unchanged": True, "noncredential_fields_unchanged": True,
                         "source_target_credentials_distinct": True}})
    runtime_required = ({"unused_target_absent_at": {"unused_target_absent": True, "source_authoritative": True}}
                        if scenario == "identity-precommit" else
                        {"one_target_at": {"exactly_one_target_published": True, "staged_target_absent": True,
                                           "source_not_restored": True}})
    output["runtime"] = _capture(ctx, "identity-runtime.json", "identity-runtime-observation", runtime_required)
    if scenario == "identity-unavailable":
        output["subscription"] = _capture(ctx, "identity-subscription.json", "identity-unavailable-subscription", {
            "fault_reported_at": {"outside_link_failed": True, "local_public_https_failed": True,
                                  "proxy_443_healthy": True, "certificate_unchanged": True},
            "fallback_disclosed_at": {"show_client_configuration_confirmed": True, "configuration_file_not_used": True}})
        output["repair"] = _capture(ctx, "identity-repair.json", "identity-unavailable-repair", {
            "same_link_restored_at": {"runtime_only_plan": True, "no_certbot_child": True, "no_issuance": True,
                                      "certificate_lineage_unchanged": True, "same_link_restored": True,
                                      "proxy_healthy": True, "firewall_exactly_restored": True}})
    return output
