#!/usr/bin/env python3
"""Capture or verify native readbacks for an already authorized qualification.

Uses the existing run-local native-inputs.json and authenticated manifest/request.
It neither operates Karing nor records import, refresh, latency or journey checks.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace


PHASES = {"m2": "mvp-subscription", "m3-identity": "mvp-credentials",
          "m3-link": "mvp-credentials", "m5": "mvp-removal",
          "baseline-check": None, "baseline-check-2": None}


def load_native(inputs_path):
    path = inputs_path.parent / "operator-source/native-receipts.py"
    spec = importlib.util.spec_from_file_location("native_receipts", path)
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    return native


def bindings(n, root, inputs, phase):
    scenario = PHASES[phase]
    if scenario is None:
        return {}, None
    raw = n.private_bytes(root / "qualification-manifest.json")
    manifest = json.loads(raw, object_pairs_hook=n.unique)
    n.require(manifest["schema"] == "sbxr-qualification-manifest-v3" and
              manifest["workflow"]["commit"] == inputs["source_commit"] and
              len(manifest["releases"]) == 1, "Candidate manifest differs")
    candidate = manifest["releases"][0]
    n.require(candidate["tag"] == inputs["candidate"]["tag"] and
              candidate["sequence"] == inputs["candidate"]["sequence"] and
              candidate["commit"] == inputs["source_commit"], "Candidate identity differs")
    attempt = manifest["v3_attempt"]
    n._qualification_proxy_profile(attempt)
    label = "m3" if phase.startswith("m3-") else phase
    request_raw = n.private_bytes(root / (label + "-request.private"))
    request = json.loads(request_raw, object_pairs_hook=n.unique)
    n.require(request["scenario_id"] == scenario and
              request["qualification_manifest_sha256"] == hashlib.sha256(raw).hexdigest(),
              "Request differs from the authenticated manifest/scenario")
    now = dt.datetime.now(dt.timezone.utc)
    # The recorder/collector validates the technical clock and recorded attended
    # pauses. Do not replace its effective deadline with the unpaused timestamp.
    if "karing_response_limit_seconds" in request:
        n.require(request["karing_response_limit_seconds"] == attempt["karing_response_limit_seconds"] == 3600 and
                  request["attended_finish_by"] == attempt["attended_finish_by"], "Attended timing bindings differ")
        finish_by = n.timestamp(request["attended_finish_by"]).timestamp()
    else:
        finish_by = request["deadline_unix"]
    n.require(n.timestamp(request["not_before"]) <= now and now.timestamp() < finish_by,
              "Collector request is not current")
    return {"qualification_manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "request_sha256": hashlib.sha256(request_raw).hexdigest(),
            "attempt_id": attempt["attempt_id"], "candidate": candidate["release_identity"]}, attempt


def retain(root, name, raw):
    path = root / name
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"source_file": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def retain_json(root, name, value):
    return retain(root, name, json.dumps(value, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode())


def preparation(n, inputs_path, inputs_raw, inputs):
    n.require(n.private_bytes(inputs_path) == inputs_raw, "Native inputs changed")
    n.require(n.source_file(inputs["canonical_helper"]) == Path(n.__file__).read_bytes() and
              inputs["canonical_helper"]["source_file"] == str(Path(n.__file__).resolve()),
              "Helper differs from frozen inputs")
    n.require(inputs["settings_binding"] == n.settings_binding(), "App/helper identity differs")
    n.require(inputs["native_timezone"] == n.native_timezone_binding(), "Native timezone differs")


def verify(n, inputs_path, inputs_raw, inputs, phase, result, connected, tun_enabled):
    root = inputs_path.parent.parent
    preparation(n, inputs_path, inputs_raw, inputs)
    authority, attempt = bindings(n, root, inputs, phase)
    n.require(result["phase"] == phase and result["scenario"] == PHASES[phase] and
              result["authority"] == authority and result["frozen_native_inputs_sha256"] ==
              hashlib.sha256(inputs_raw).hexdigest(), "Capture has different phase/candidate/input bindings")
    observed = n._profile_window_utc(result["observed_at"])
    now = dt.datetime.now(dt.timezone.utc)
    n.require(observed <= now and (now - observed).total_seconds() <= 300,
              "Native observation is future or stale")
    raw = n.source_file(result["native_store"])
    current, proof = n._native_bytes(n.NATIVE_SUBSCRIPTION_SOURCE)
    n.require(current == raw and proof == result["native_source"], "Native store changed after capture")
    store = json.loads(raw, object_pairs_hook=n.unique)
    baseline = json.loads(n.source_file(inputs["original_store_baseline"]), object_pairs_hook=n.unique)
    ids = [p["groupid"] for p in baseline["items"]]
    originals = [p for p in store["items"] if p.get("groupid") in ids]
    audit = n.original_profiles_audit_v3(
        baseline["items"], originals, timezone=inputs["native_timezone"],
        tzif_record=inputs["native_tzif"], window_start=inputs["original_store_observed_at"],
        window_end=result["observed_at"])
    n.require(json.loads(n.source_file(result["original_profile_audit"])) == audit and audit["passed"],
              "Original profiles or complete audit differ")
    n.require({k: v for k, v in store.items() if k != "items"} ==
              {k: v for k, v in baseline.items() if k != "items"}, "Non-item store fields differ")
    use_raw, use_proof = n._native_bytes(n.NATIVE_SUBSCRIPTION_SOURCE.with_name("karing_subscribe_use.json"))
    n.require(use_raw == n.source_file(result["selected_use"]) == n.source_file(inputs["selected_use_baseline"]) and
              use_proof == result["selected_use_native_source"], "Original selected-use store differs")
    selected = json.loads(use_raw, object_pairs_hook=n.unique)["select_default"]
    selected_profiles = [p for p in originals if any(s.get("tag") == selected for s in p.get("servers", []))]
    n.require(len(selected_profiles) == 1, "Selected original profile is not unique")
    connection = {"configuration": selected_profiles[0]["remark"], "node": selected,
                  "connected": connected, "tun_enabled": tun_enabled}
    before = json.loads(n.source_file(inputs["selected_connection_baseline"]))["connection"]
    facts = result["facts"]
    records = [result["native_store"], result["original_profile_audit"], result["selected_use"],
               facts["settings"]["current"]]
    if phase in ("m2", "m3-identity", "m3-link"):
        records.extend((facts["saved_url"], facts["saved_subscription_content"]))
    n.require(result["captures"] == {Path(r["source_file"]).name: r for r in records},
              "Native capture inventory differs")
    n.require(n._canonical(facts["selected_connection"]) ==
              n._canonical({"baseline": before, "current": connection}), "Selected connection observation differs")
    n.preserved_v2(facts, inputs["settings_binding"], inputs["settings_baseline"])
    matching = [p for p in store["items"] if p.get("remark") == inputs["profile_remark"]]
    if phase in ("m2", "m3-identity", "m3-link"):
        n.require(len(matching) == 1 and len(store["items"]) == len(ids) + 1,
                  "Expected one unique native test profile")
        n.readbacks(SimpleNamespace(r=root), facts, phase + "-expected-url.private",
                    phase + "-expected-wire.private", attempt=attempt)
    else:
        n.require(not matching and len(store["items"]) == len(ids), "Test profile remains or original count differs")


def capture(n, inputs_path, inputs_raw, inputs, phase, connected, tun_enabled):
    root = inputs_path.parent.parent
    preparation(n, inputs_path, inputs_raw, inputs)
    authority, _ = bindings(n, root, inputs, phase)
    raw, proof = n._native_bytes(n.NATIVE_SUBSCRIPTION_SOURCE)
    observed = dt.datetime.now(dt.timezone.utc).isoformat()
    store = json.loads(raw, object_pairs_hook=n.unique)
    baseline = json.loads(n.source_file(inputs["original_store_baseline"]), object_pairs_hook=n.unique)
    ids = [p["groupid"] for p in baseline["items"]]
    originals = [p for p in store["items"] if p.get("groupid") in ids]
    audit = n.original_profiles_audit_v3(
        baseline["items"], originals, timezone=inputs["native_timezone"],
        tzif_record=inputs["native_tzif"], window_start=inputs["original_store_observed_at"], window_end=observed)
    store_record = retain(root, phase + "-native-store.private", raw)
    audit_record = retain_json(root, phase + "-original-profiles-audit.private", audit)
    n.require(audit["passed"], "Original profiles differ; retained complete audit")
    use_raw, use_proof = n._native_bytes(n.NATIVE_SUBSCRIPTION_SOURCE.with_name("karing_subscribe_use.json"))
    selected = json.loads(use_raw, object_pairs_hook=n.unique)["select_default"]
    selected_profiles = [p for p in originals if any(s.get("tag") == selected for s in p.get("servers", []))]
    n.require(len(selected_profiles) == 1, "Selected original profile is not unique")
    before = json.loads(n.source_file(inputs["selected_connection_baseline"]))["connection"]
    connection = {"configuration": selected_profiles[0]["remark"], "node": selected,
                  "connected": connected, "tun_enabled": tun_enabled}
    settings = n.capture_settings(inputs["settings_baseline"], root / (phase + "-settings.private"),
                                  inputs["settings_binding"])
    facts = {"settings": settings, "selected_connection": {"baseline": before, "current": connection}}
    matching = [p for p in store["items"] if p.get("remark") == inputs["profile_remark"]]
    if phase in ("m2", "m3-identity", "m3-link"):
        n.require(len(matching) == 1, "Expected one unique native test profile")
        profile = matching[0]
        facts.update(saved_url=retain(root, phase + "-saved-url.private", profile["urlOrPath"].encode()),
                     saved_subscription_content=retain_json(root, phase + "-saved-profile.private", profile),
                     native_subscription_source={k: proof[k] for k in ("source_app_path", "sha256", "size", "mtime_ns")})
    use_record = retain(root, phase + "-selected-use.private", use_raw)
    records = [store_record, audit_record, use_record, settings["current"]]
    if phase in ("m2", "m3-identity", "m3-link"):
        records.extend((facts["saved_url"], facts["saved_subscription_content"]))
    result = {"phase": phase, "scenario": PHASES[phase], "observed_at": observed, "authority": authority,
              "frozen_native_inputs_sha256": hashlib.sha256(inputs_raw).hexdigest(), "facts": facts,
              "native_store": store_record, "native_source": proof,
              "selected_use": use_record, "captures": {Path(r["source_file"]).name: r for r in records},
              "selected_use_native_source": use_proof, "original_profile_audit": audit_record,
              "scope": "Native readbacks/preservation only; no import, refresh, latency or journey outcome asserted."}
    verify(n, inputs_path, inputs_raw, inputs, phase, result, connected, tun_enabled)
    retain_json(root, phase + "-native-capture-result.private", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "verify"))
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--phase", choices=tuple(PHASES), required=True)
    parser.add_argument("--connected", choices=("true", "false"), required=True)
    parser.add_argument("--tun-enabled", choices=("true", "false"), required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        inputs_path = args.inputs.resolve(strict=True)
        n = load_native(inputs_path)
        inputs_raw = n.private_bytes(inputs_path)
        inputs = json.loads(inputs_raw, object_pairs_hook=n.unique)
        flags = args.connected == "true", args.tun_enabled == "true"
        if args.action == "capture":
            capture(n, inputs_path, inputs_raw, inputs, args.phase, *flags)
        else:
            path = inputs_path.parent.parent / (args.phase + "-native-capture-result.private")
            result = json.loads(n.private_bytes(path), object_pairs_hook=n.unique)
            verify(n, inputs_path, inputs_raw, inputs, args.phase, result, *flags)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Native capture refused (" + type(error).__name__ + "); private details withheld.", file=sys.stderr)
        return 1
    print(json.dumps({"action": args.action, "phase": args.phase, "native_readbacks": "passed",
                      "journey_checks_recorded": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
