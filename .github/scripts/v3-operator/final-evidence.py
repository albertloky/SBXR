#!/usr/bin/env python3
"""Authenticate retained evidence sources for live scenarios 19 through 25."""

from __future__ import annotations

import hashlib


EXTRAS = {
    "lifecycle-menu": "packaged-zero-argument-menu check-reachable update-reachable recover-reachable safe-no-update safe-no-recovery no-replacement-on-refusal".split(),
    "remove-certbot": "active-certbot-proved removal-refused owned-resources-preserved".split(),
    "remove-writer": "active-writer-proved removal-refused owned-resources-preserved".split(),
    "remove-admission-race": "writer-admission-race-proved removal-refused owned-resources-preserved".split(),
    "remove-directory-lock": "supported-directory-lock-held bounded-contention-refusal owned-resources-preserved".split(),
    "secret-containment": "sandbox-cannot-read-token canonical-and-candidate-protection units-arguments-environment-safe runner-vps-mac-terminal-workflow-retained-scans qualification-secrets-and-client-processes-cleaned unrelated-data-preserved".split(),
    "karing-final": "latest-official-stable-macos-package one-real-remote-profile one-vless-reality-node all-fields-and-name-match settings-preserved manual-refresh genuinely-due-five-minute-auto-refresh owned-process-groups-and-descendants-terminated old-new-connections-refused outside-target-healthy unchanged-real-link replacement-uuid-adopted other-fields-preserved https-outage-preserves-node same-link-recovery complete-removal outside-access-unusable full-owned-absence temporary-secret-and-process-cleanup current-connection-preserved fresh-initial-node-latency fresh-revoked-identity-latency-refused same-link-refresh-before-replacement-latency fresh-replacement-node-latency".split(),
}


def _rule(timing, check, source, event):
    return timing.ObservationRule(check, (source,), (timing.Anchor(source, event),),
                                  (timing.Anchor(timing.PROOF_SOURCE, "completed_at"),))


def rules(timing, scenario):
    if scenario not in EXTRAS:
        raise timing.EvidenceTimingRefusal(f"scenario {scenario!r}: final evidence adapter refused")
    result = list(timing.later_common_rules())
    if scenario == "lifecycle-menu":
        events = ("action_started_at", "action_completed_at", "action_completed_at", "action_completed_at",
                  "action_completed_at", "action_completed_at", "action_completed_at")
        result.extend(_rule(timing, check, "lifecycle", event) for check, event in zip(EXTRAS[scenario], events))
    elif scenario in ("remove-certbot", "remove-writer"):
        active = "managed" if scenario == "remove-certbot" else "writer"
        result.extend((
            _rule(timing, EXTRAS[scenario][0], active, "held_at"),
            _rule(timing, EXTRAS[scenario][1], "refusal", "refused_at"),
            _rule(timing, EXTRAS[scenario][2], "refusal", "completed_at"),
        ))
    elif scenario == "remove-admission-race":
        result.extend((
            _rule(timing, EXTRAS[scenario][0], "admission", "refused_at"),
            _rule(timing, EXTRAS[scenario][1], "admission", "refused_at"),
            _rule(timing, EXTRAS[scenario][2], "admission", "completed_at"),
        ))
    elif scenario == "remove-directory-lock":
        result.extend((
            _rule(timing, EXTRAS[scenario][0], "locks", "held_at"),
            _rule(timing, EXTRAS[scenario][1], "refusal", "refused_at"),
            _rule(timing, EXTRAS[scenario][2], "refusal", "completed_at"),
        ))
    elif scenario == "secret-containment":
        result.extend(_rule(timing, check, "secrets", "action_completed_at") for check in EXTRAS[scenario])
    else:
        event_for = {
            "latest-official-stable-macos-package": "initial-settings",
            "one-real-remote-profile": "profile-imported", "one-vless-reality-node": "profile-imported",
            "all-fields-and-name-match": "profile-imported", "settings-preserved": "final-settings",
            "manual-refresh": "manual-same-link-refresh",
            "genuinely-due-five-minute-auto-refresh": "due-five-minute-auto-refresh",
            "owned-process-groups-and-descendants-terminated": "complete-removal",
            "old-new-connections-refused": "outside-access-refused",
            "outside-target-healthy": "server-old-credential-refused", "unchanged-real-link": "same-link-recovery-refresh",
            "replacement-uuid-adopted": "same-link-replacement-refresh", "other-fields-preserved": "same-link-replacement-refresh",
            "https-outage-preserves-node": "https-outage-refresh-refused", "same-link-recovery": "same-link-recovery-refresh",
            "complete-removal": "complete-removal", "outside-access-unusable": "outside-access-refused",
            "full-owned-absence": "full-owned-absence", "temporary-secret-and-process-cleanup": "test-profile-cleanup",
            "current-connection-preserved": "final-settings", "fresh-initial-node-latency": "initial-node-latency",
            "fresh-revoked-identity-latency-refused": "revoked-node-latency-refused",
            "same-link-refresh-before-replacement-latency": "same-link-replacement-refresh",
            "fresh-replacement-node-latency": "replacement-node-latency",
        }
        result.extend(_rule(timing, check, "karing", event_for[check]) for check in EXTRAS[scenario])
    return tuple(result)


def _exact(api, value, keys, label):
    return api.exact(value, tuple(keys), label)


def _capture_records(api, ctx, name, helper, expected_count=None):
    doc, raw = ctx.capture(name, helper)
    events = doc["events"]
    if expected_count is not None and len(events) != expected_count:
        raise api.Refusal(f"{name}: exact stdout event count required")
    if doc["exit_code"] != 0 or not events:
        raise api.Refusal(f"{name}: successful actual helper execution required")
    records = []
    for index, event in enumerate(events):
        _exact(api, event, ("observed_at", "record"), f"{name} event {index}")
        if not isinstance(event["record"], dict):
            raise api.Refusal(f"{name}: canonical JSON stdout record required")
        records.append((event["observed_at"], event["record"]))
    return records, raw, doc


def _digest(api, raw):
    return api.digest(raw) if hasattr(api, "digest") else hashlib.sha256(raw).hexdigest()


def _bound(api, value, ctx, label):
    if (value.get("scenario_id", value.get("scenario")) != ctx.scenario or
            value.get("qualification_manifest_sha256") != ctx.manifest_sha or
            value.get("request_sha256") != ctx.request_sha):
        raise api.Refusal(label + ": current scenario authority differs")


def _refusal_source(ctx):
    api = ctx.api
    records, raw, capture = _capture_records(api, ctx, f"{ctx.scenario}-removal-refusal.json", "removal-refusal", 1)
    observed, value = records[0]
    _bound(api, value, ctx, "removal refusal")
    required = {"schema", "scenario_id", "qualification_manifest_sha256", "request_sha256",
                "owned_inventory_before_sha256", "owned_inventory_after_sha256", "healthy_running",
                "completed_at", "action_number", "prepared_at", "code", "failed_check",
                "removal_commitment_absent", "refused_at"}
    _exact(api, value, required, "removal refusal")
    if (value["schema"] != "sbxr-v4-held-removal-refusal-v1" or value["code"] != "PROXY-INSTALLATION-ACTION-REFUSED" or
            not isinstance(value["failed_check"], str) or not value["failed_check"] or
            value["removal_commitment_absent"] is not True or value["healthy_running"] is not True or
            value["owned_inventory_before_sha256"] != value["owned_inventory_after_sha256"]):
        raise api.Refusal("removal refusal: actual bounded refusal or preservation differs")
    if (not api.before(capture["started_at"], value["prepared_at"]) or
            not api.before(value["prepared_at"], value["refused_at"]) or
            not api.before(value["refused_at"], value["completed_at"]) or
            not api.before(value["completed_at"], observed)):
        raise api.Refusal("removal refusal: embedded action times lie outside actual helper capture")
    if (not api.before(ctx.state["action_started_at"], capture["started_at"]) or
            not api.before(capture["completed_at"], ctx.state["action_completed_at"])):
        raise api.Refusal("removal refusal: helper capture lies outside common action boundary")
    return ctx.source("refusal", raw, {"prepared_at": value["prepared_at"], "refused_at": value["refused_at"],
                                       "completed_at": value["completed_at"], "captured_at": observed})


def _lifecycle(ctx):
    api = ctx.api
    records, raw, capture = _capture_records(api, ctx, "19-lifecycle-menu.json", "19-lifecycle-menu.sh", 1)
    observed, value = records[0]
    _exact(api, value, ("action_completed_at", "action_started_at", "check_output_sha256", "first_frame_sha256",
                        "inventory_before_and_after", "recover_output_sha256", "schema", "update_output_sha256"), "lifecycle result")
    if value["schema"] != "sbxr-v4-lifecycle-menu-result-v1":
        raise api.Refusal("lifecycle: typed result required")
    if (not api.before(ctx.state["action_started_at"], capture["started_at"]) or
            not api.before(capture["started_at"], value["action_started_at"]) or
            not api.before(value["action_started_at"], value["action_completed_at"]) or
            not api.before(value["action_completed_at"], observed) or
            not api.before(observed, ctx.state["action_completed_at"])):
        raise api.Refusal("lifecycle: embedded action times lie outside actual capture boundary")
    artifacts = {}
    for filename, key in (("19-first-frame.txt", "first_frame_sha256"), ("19-check.txt", "check_output_sha256"),
                          ("19-update.txt", "update_output_sha256"), ("19-recover.txt", "recover_output_sha256")):
        artifact = api.private_bytes(ctx.directory / filename, "source " + filename)
        artifacts[filename] = artifact
        if _digest(api, artifact) != value[key]:
            raise api.Refusal("lifecycle: retained public output bytes differ")
    first, check, update, recover = (artifacts[name].decode("utf-8") for name in
        ("19-first-frame.txt", "19-check.txt", "19-update.txt", "19-recover.txt"))
    if (not all(label in first for label in ("Check", "Update", "Recover")) or
            "SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT" not in check or "Software Lifecycle: Ready" not in check or
            "SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT" not in update or "Update SBXR? [y/N]" in update or
            "No recovery is available." not in recover or "Recover SBXR? [y/N]" in recover):
        raise api.Refusal("lifecycle: actual public outcomes differ")
    return {"lifecycle": ctx.source("lifecycle", raw, {"action_started_at": value["action_started_at"],
                                                        "action_completed_at": value["action_completed_at"]})}


def _managed(ctx, writer=False):
    api = ctx.api
    name, helper, source_id = (("21-writer.json", "recorder-boundary", "writer") if writer else
                               ("20-managed.json", "managed-hold", "managed"))
    records, raw, capture = _capture_records(api, ctx, name, helper, 2)
    held_at, held = records[0]; completed_at, final = records[1]
    if writer:
        if (held.get("state") != "boundary-held" or held.get("mode") != "writer" or
                held.get("actual_boundary", {}).get("boundary") != "before-open" or
                held.get("writer", {}).get("lock_state") != "locked" or held.get("whole_host", {}).get("lock_state") != "unlocked" or
                final != {"state": "completed", "receipt_sha256": final.get("receipt_sha256"), "no_ca_egress": True}):
            raise api.Refusal("writer: actual writer boundary or completion differs")
    else:
        child = held.get("child", {})
        if (held.get("state") != "held" or child.get("boundary") != "actual-image-exec-trap-before-target-code" or
                final.get("state") != "interrupted" or final.get("no_ca_egress") is not True):
            raise api.Refusal("managed Certbot: actual held child or interrupted outcome differs")
    if (not api.before(ctx.state["action_started_at"], capture["started_at"]) or
            not api.before(capture["completed_at"], ctx.state["action_completed_at"])):
        raise api.Refusal("managed hold: helper capture lies outside common action boundary")
    return {source_id: ctx.source(source_id, raw, {"held_at": held_at, "completed_at": completed_at}),
            "refusal": _refusal_source(ctx)}


def _admission(ctx):
    api = ctx.api
    records, raw, capture = _capture_records(api, ctx, "22-admission-race.json", "admission-race-operator", 1)
    _, result = records[0]
    _bound(api, result, ctx, "admission result")
    if (result.get("schema") != "sbxr-v4-admission-race-operator-v1" or
            any(result.get(key) is not True for key in ("prepared_public_removal", "actual_admission_boundary",
                                                        "removal_refused_before_commitment", "owned_resources_preserved",
                                                        "recorder_completed", "healthy_running"))):
        raise api.Refusal("admission race: aggregate actual outcome differs")
    if (not api.before(ctx.state["action_started_at"], capture["started_at"]) or
            not api.before(capture["completed_at"], ctx.state["action_completed_at"])):
        raise api.Refusal("admission race: helper capture lies outside common action boundary")
    held, _, held_raw = ctx.read("22-admission-held.json")
    refusal, _, refusal_raw = ctx.read("22-removal-refusal.json")
    final, _, final_raw = ctx.read("22-admission-final.json")
    if (held.get("state") != "boundary-held" or held.get("mode") != "admission" or
            held.get("admission", {}).get("lock_state") != "locked" or held.get("writer", {}).get("lock_state") != "unlocked" or
            refusal.get("schema") != "sbxr-v4-removal-admission-refusal-v1" or refusal.get("code") != "PROXY-INSTALLATION-ACTION-REFUSED" or
            refusal.get("removal_commitment_absent") is not True or refusal.get("owned_inventory_before_sha256") != refusal.get("owned_inventory_after_sha256") or
            final.get("state") != "completed" or final.get("no_ca_egress") is not True):
        raise api.Refusal("admission race: held/refusal/final retained chain differs")
    combined = raw + held_raw + refusal_raw + final_raw
    return {"admission": ctx.source("admission", combined, {"refused_at": refusal["refused_at"],
                                                             "completed_at": result["completed_at"]})}


def _locks(ctx):
    api = ctx.api
    records, raw, capture = _capture_records(api, ctx, "23-locks.json", "directory-locks", 2)
    held_at, held = records[0]; released_at, released = records[1]
    paths = {"/etc/letsencrypt/.certbot.lock", "/var/lib/letsencrypt/.certbot.lock", "/var/log/letsencrypt/.certbot.lock"}
    if (held.get("schema") != "sbxr-v4-certbot-directory-locks-v1" or released.get("schema") != "sbxr-v4-certbot-directory-locks-released-v1" or
            {item.get("path") for item in held.get("locks", [])} != paths or held.get("locks") != released.get("locks") or held.get("pid") != released.get("pid")):
        raise api.Refusal("directory locks: exact three held and released POSIX locks required")
    if (not api.before(ctx.state["action_started_at"], capture["started_at"]) or
            not api.before(capture["completed_at"], ctx.state["action_completed_at"])):
        raise api.Refusal("directory locks: helper capture lies outside common action boundary")
    return {"locks": ctx.source("locks", raw, {"held_at": held_at, "released_at": released_at}),
            "refusal": _refusal_source(ctx)}


def _secrets(ctx):
    api = ctx.api
    records, wrapper, capture = _capture_records(api, ctx, "24-secret-containment.json", "24-secret-containment.sh", 1)
    observed, result = records[0]
    schemas = {"protection": "sbxr-v4-protection-result-v2", "sandbox": "sbxr-v3-sandbox-token-probe-v1",
               "protected-open": "sbxr-v4-protected-open-probe-v1", "scan": "sbxr-v4-secret-scan-result-v2",
               "removal": "sbxr-v4-inventory-removal-result-v1", "cleanup": "sbxr-v4-cleanup-result-v2"}
    raws, docs = {}, {}
    for name, schema in schemas.items():
        docs[name], _, raws[name] = ctx.read(f"24-{name}.json")
        if docs[name].get("schema") != schema or result.get(name.replace("-", "_") + "_sha256") != _digest(api, raws[name]):
            raise api.Refusal("secret containment: retained result bytes differ")
    scan, sandbox, opened, cleanup = docs["scan"], docs["sandbox"], docs["protected-open"], docs["cleanup"]
    if (result.get("schema") != "sbxr-v4-secret-containment-result-v1" or sandbox.get("protected_reads_refused") != 2 or
            opened.get("protected_reads_refused") != len(opened.get("objects", [])) or opened.get("metadata_unchanged") is not True or
            scan.get("external_surface_attested") is not True or scan.get("external_client_cleanup_attested") is not True or
            scan.get("variants_absent") is not True or scan.get("prohibited_patterns_absent") is not True or
            set(scan.get("capture_files", {})) != {"runner", "vps", "mac", "terminal", "workflow", "retained"} or
            any(type(count) is not int or count < 1 for count in scan["capture_files"].values()) or
            type(cleanup.get("cleanup_paths_absent")) is not int or cleanup["cleanup_paths_absent"] < 1):
        raise api.Refusal("secret containment: exhaustive scans, attestations, or cleanup differ")
    if (not api.before(ctx.state["action_started_at"], capture["started_at"]) or
            not api.before(capture["started_at"], result["action_started_at"]) or
            not api.before(result["action_started_at"], result["action_completed_at"]) or
            not api.before(result["action_completed_at"], observed) or
            not api.before(observed, ctx.state["action_completed_at"])):
        raise api.Refusal("secret containment: embedded action times lie outside actual capture boundary")
    combined = wrapper + b"".join(raws[name] for name in schemas)
    return {"secrets": ctx.source("secrets", combined, {"action_started_at": result["action_started_at"],
                                                         "action_completed_at": result["action_completed_at"]})}


def _karing(ctx):
    api = ctx.api
    records, wrapper, capture = _capture_records(api, ctx, "25-karing-evidence.json", "karing-evidence", 1)
    observed, result = records[0]
    reviewed, _, reviewed_raw = ctx.read("25-karing-reviewed-input.json")
    native, _, native_raw = ctx.read("25-karing-native-capture.json")
    helper = api.import_sibling("sbxr_karing_evidence_validation", "karing-evidence.py")
    try:
        expected = helper.validate(reviewed, reviewed_raw, ctx.manifest, ctx.manifest_raw,
                                   ctx.request, ctx.request_raw, native, native_raw, ctx.directory)
    except Exception as error:
        raise api.Refusal("Karing: reviewed manual capture validation refused") from error
    if (result.get("schema") != "sbxr-v4-karing-evidence-result-v1" or
            result.get("reviewed_capture_sha256") != _digest(api, reviewed_raw) or
            result.get("native_capture_sha256") != _digest(api, native_raw) or
            reviewed.get("schema") != "sbxr-v4-karing-reviewed-capture-v1" or reviewed.get("capture_method") != "owner-reviewed-manual-karing-ui" or
            reviewed.get("scenario_id") != ctx.scenario or reviewed.get("qualification_manifest_sha256") != ctx.manifest_sha or
            reviewed.get("request_sha256") != ctx.request_sha or reviewed.get("package") != ctx.manifest["v3_attempt"]["packages"]["karing"]):
        raise api.Refusal("Karing: current protected reviewed input or package differs")
    if result != expected:
        raise api.Refusal("Karing: captured producer result differs from reviewed bytes")
    timestamps = result.get("event_timestamps")
    if not isinstance(timestamps, dict) or set(timestamps) != set(reviewed.get("events", [{}])[index].get("kind") for index in range(len(reviewed.get("events", [])))):
        raise api.Refusal("Karing: exact actual event timestamp set differs")
    if (not api.before(ctx.state["action_started_at"], result["started_at"]) or
            not api.before(result["completed_at"], capture["started_at"]) or
            not api.before(capture["started_at"], observed) or
            not api.before(observed, ctx.state["action_completed_at"])):
        raise api.Refusal("Karing: reviewed UI journey or validation capture lies outside action boundary")
    return {"karing": ctx.source("karing", wrapper + reviewed_raw + native_raw, timestamps)}


def sources(ctx):
    if ctx.scenario == "lifecycle-menu": return _lifecycle(ctx)
    if ctx.scenario == "remove-certbot": return _managed(ctx)
    if ctx.scenario == "remove-writer": return _managed(ctx, True)
    if ctx.scenario == "remove-admission-race": return _admission(ctx)
    if ctx.scenario == "remove-directory-lock": return _locks(ctx)
    if ctx.scenario == "secret-containment": return _secrets(ctx)
    if ctx.scenario == "karing-final": return _karing(ctx)
    raise ctx.api.Refusal(f"scenario {ctx.scenario!r}: final evidence adapter refused")
