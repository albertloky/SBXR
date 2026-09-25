#!/usr/bin/env python3
"""Assemble one explicitly observed MVP live scenario into recurring V3 facts."""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys


POLICY = "mvp-live-v1"
RECURRING_POLICY = "mvp-recurring-live-v1"
SCENARIOS = {
    "mvp-install": (
        "packaged-install reviewed-setup outside-proxy-traffic "
        "menu-status-and-lifecycle ssh-access-preserved"
    ).split(),
    "mvp-subscription": (
        "trusted-outside-https one-correct-subscription-node wrong-token-refused "
        "private-files-and-logs-protected karing-import fresh-karing-node-latency "
        "manual-refresh selected-connection-preserved"
    ).split(),
    "mvp-credentials": (
        "old-established-session-terminated old-proxy-credential-refused "
        "replacement-proxy-traffic same-link-refreshed-identity old-link-refused "
        "replacement-link-usable proxy-identity-unchanged-by-link-rotation "
        "fresh-karing-replacement-latency"
    ).split(),
    "mvp-renewal": (
        "official-renewal-route certificate-replaced accepted-activation "
        "outside-trusted-tls proxy-traffic-preserved"
    ).split(),
    "mvp-removal": (
        "restart-preserves-access reviewed-complete-removal owned-resources-absent "
        "outside-access-refused unrelated-resources-preserved "
        "test-client-and-secret-cleanup ssh-access-preserved"
    ).split(),
}
ORDER = list(SCENARIOS)
TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def scenario_order(attempt):
    policy = attempt.get("evidence_policy")
    if policy == POLICY:
        return ORDER
    if policy != RECURRING_POLICY:
        refuse("manifest is outside the ordinary live policies")
    sources = attempt.get("sources")
    support = attempt.get("support", {})
    if (type(sources) is not list or len(sources) != 1 or
            type(sources[0]) is not dict or sources[0].get("ownership_schema") != 2 or
            type(support) is not dict or support.get("scope") != "recurring-subscription-upgrade" or
            support.get("contract") != "sbxr-subscription-update-v1" or
            support.get("sources") != [sources[0].get("release_identity")] or
            attempt.get("owner_exception") or attempt.get("late_confirmation_review") or
            "automated_only_scenarios" in attempt):
        refuse("recurring source declaration differs")
    identity = sources[0].get("release_identity")
    if type(identity) is not dict or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", identity.get("tag", "")):
        refuse("recurring source identity differs")
    return [f"source-{identity['tag']}-{suffix}"
            for suffix in ("precommit", "upgrade", "postcommit")] + ORDER


def required_checks(attempt, scenario_id):
    if scenario_id not in scenario_order(attempt):
        refuse("unlisted scenario")
    if scenario_id in SCENARIOS:
        return SCENARIOS[scenario_id]
    checks = ("exact-source-and-candidate actual-source-packaged-updater "
              "source-record-schema-proved both-releases-understand-recovery "
              "reviewed-update-confirmation admission-exclusion creation-provenance-preserved "
              "no-ownership-migration proxy-not-restarted both-credentials-unchanged "
              "subscription-link-unchanged outside-proxy-traffic outside-trusted-https "
              "ssh-access-preserved private-files-and-logs-protected "
              "no-helper-or-intermediate-release").split()
    if scenario_id.endswith("-precommit"):
        return checks + ("observed-precommit-interruption actual-source-packaged-recovery "
                         "prior-exact-restoration source-installed-record-restored "
                         "no-transaction-residue").split()
    if scenario_id.endswith("-postcommit"):
        return checks + ("observed-postcommit-interruption candidate-forward-runtime-completion "
                         "candidate-installed-record-proved serving-only-restart "
                         "no-transaction-residue").split()
    return checks + "candidate-installed-record-proved serving-only-restart no-transaction-residue".split()


class Refusal(ValueError):
    pass


def refuse(message):
    raise Refusal(message)


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            refuse(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def load(path, label, limit):
    path = Path(path)
    try:
        stat = path.stat()
        raw = path.read_bytes()
    except OSError as error:
        refuse(f"{label} unavailable: {error}")
    if not path.is_file() or path.is_symlink() or stat.st_nlink != 1:
        refuse(f"{label} is not an owned regular file")
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        refuse(f"{label} permissions are not private")
    if not raw or len(raw) > limit:
        refuse(f"{label} exceeded byte bound")
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        refuse(f"{label} is not JSON: {error}")
    return value, raw


def exact_object(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        refuse(f"{label} members differ")


def timestamp(value, label):
    if type(value) is not str or not TIME.fullmatch(value):
        refuse(f"{label} is not an RFC3339 UTC second")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        refuse(f"{label} is invalid")


def assemble(options):
    manifest, manifest_raw = load(options.manifest, "manifest", 4 * 1024 * 1024)
    boundary, _ = load(options.boundary, "boundary facts", 16 * 1024 * 1024)
    request, _ = load(options.request, "collector request", 64 * 1024)
    previous, _ = load(options.previous, "prior scenario prefix", 16 * 1024 * 1024)
    observation, _ = load(options.observation, "operator observation", 64 * 1024)

    exact_object(request, (
        "deadline_unix", "not_before", "qualification_manifest_sha256",
        "required_checks", "scenario_id", "scenario_limit_seconds",
    ), "collector request")
    exact_object(observation, ("checks", "completed_at", "scenario_id", "started_at"),
                 "operator observation")
    if type(previous) is not list:
        refuse("prior scenario prefix is not an array")
    if type(manifest) is not dict or type(manifest.get("v3_attempt")) is not dict:
        refuse("manifest lacks a V3 attempt")
    attempt = manifest["v3_attempt"]
    required = attempt.get("required_scenarios")
    if required != scenario_order(attempt) or len(previous) >= len(required):
        refuse("manifest scenario order differs")
    scenario_id = required[len(previous)]
    checks = required_checks(attempt, scenario_id)
    if (request.get("scenario_id") != scenario_id or
            request.get("required_checks") != checks or
            observation.get("scenario_id") != scenario_id):
        refuse("request or observation scenario differs")
    if request.get("qualification_manifest_sha256") != digest(manifest_raw):
        refuse("request manifest digest differs")
    expected_limit = 7200 if scenario_id == "mvp-subscription" else 1800
    if (type(request.get("deadline_unix")) is not int or
            type(request.get("scenario_limit_seconds")) is not int or
            request["scenario_limit_seconds"] != expected_limit):
        refuse("collector timing contract differs")

    request_start = timestamp(request.get("not_before"), "collector start")
    started = timestamp(observation.get("started_at"), "observation start")
    completed = timestamp(observation.get("completed_at"), "observation completion")
    deadline = dt.datetime.fromtimestamp(request["deadline_unix"], tz=dt.timezone.utc)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if started < request_start or completed < started or completed > deadline or completed > now:
        refuse("observation time is outside the collector request")

    supplied = observation.get("checks")
    if type(supplied) is not list or len(supplied) != len(checks):
        refuse("operator observation is missing required checks")
    references = []
    for index, (expected, record) in enumerate(zip(checks, supplied)):
        exact_object(record, ("check", "observed_at", "result"), f"check {index + 1}")
        observed = timestamp(record.get("observed_at"), f"check {index + 1} time")
        if (record.get("check") != expected or record.get("result") != "observed" or
                observed < started or observed > completed):
            refuse(f"check {index + 1} was not explicitly observed during the journey")
        references.append({"record": record, "sha256": digest(canonical(record))})

    version = "v3" if manifest.get("schema") == "sbxr-qualification-manifest-v3" else "v2"
    prior_digest = digest(manifest_raw) if not previous else digest(canonical(previous[-1]))
    states = {
        "mvp-install": ("Not installed", "Running"),
        "mvp-subscription": ("Running", "Running"),
        "mvp-credentials": ("Running", "Running"),
        "mvp-renewal": ("Running", "Running"),
        "mvp-removal": ("Running", "Not installed"),
    }
    validated = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    initial_state, final_state = states.get(scenario_id, ("Running", "Running"))
    boundary_state, recovery, source = "observed", "none", None
    if scenario_id.startswith("source-"):
        source = attempt["sources"][0]
        if scenario_id.endswith("-precommit"):
            boundary_state, recovery = "before-commitment", "rollback"
        elif scenario_id.endswith("-postcommit"):
            boundary_state, recovery = "after-commitment", "forward"
    scenario = {
        "actual_result": "expected-safety-and-final-state-proved",
        "attempt_id": attempt["attempt_id"],
        "boundary": boundary_state,
        "candidate": manifest["releases"][0],
        "completed_at": observation["completed_at"],
        "evidence": references,
        "expected_result": "expected-safety-and-final-state-proved",
        "final_state": final_state,
        "initial_state": initial_state,
        "link_id": "",
        "operation_id": f"operation-{len(previous) + 1}",
        "packages_after": attempt["packages"],
        "packages_before": attempt["packages"],
        "preflight_at": observation["started_at"],
        "prior_scenario_sha256": prior_digest,
        "recovery_direction": recovery,
        "scenario_id": scenario_id,
        "schema": f"sbxr-v3-scenario-evidence-{version}",
        "source": source,
        "started_at": observation["started_at"],
        "validated_at": validated,
        "vps_id": attempt["vps_id"],
        "vps_identity_sha256": attempt["vps_identity_sha256"],
    }
    scenarios = previous + [scenario]
    evidence = {
        "attempt_id": attempt["attempt_id"],
        "observed_at": validated,
        "qualification_manifest_sha256": digest(manifest_raw),
        "scenarios": scenarios,
        "schema": f"sbxr-v3-packaged-live-evidence-{version}",
    }
    result = {
        "detailed_evidence": evidence,
        "detailed_evidence_sha256": digest(canonical(evidence)),
        "evaluation_time": validated,
        "observed_at": validated,
        "prior_decision_sha256": digest(manifest_raw),
        "qualification_boundary_facts": boundary,
        "qualification_manifest": manifest,
        "qualification_manifest_attested": True,
        "releases": manifest["releases"],
        "runner": attempt["runner"],
        "schema": "sbxr-release-qualification-facts-v1",
        "stage": "v3-scenario-result",
    }
    encoded = canonical(result)
    output = Path(options.output)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--checks":
        try:
            manifest, _ = load(sys.argv[2], "manifest", 4 * 1024 * 1024)
            print(" ".join(required_checks(manifest["v3_attempt"], sys.argv[3])))
            return 0
        except (KeyError, IndexError, TypeError, OSError, Refusal) as error:
            print(f"MVP checklist refused: {error}", file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--boundary", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--previous", required=True)
    parser.add_argument("--observation", required=True)
    parser.add_argument("--output", required=True)
    options = parser.parse_args()
    try:
        assemble(options)
    except (KeyError, IndexError, OSError, Refusal) as error:
        print(f"MVP evidence refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
