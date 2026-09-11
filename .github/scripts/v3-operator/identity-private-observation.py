#!/usr/bin/env python3
"""Observe unchanged private identity fields from protected product receipts."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path("/run/sbxr-qualification")
SCENARIOS = ("identity-precommit", "identity-postcommit", "identity-unavailable")


def load_api():
    spec = importlib.util.spec_from_file_location(
        "identity_private_observation_api", HERE / "assemble-evidence.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


api = load_api()


def fail(message="identity private observation refused"):
    raise api.Refusal(message)


def read(path, label):
    raw = api.private_bytes(path, label)
    return json.loads(raw, object_pairs_hook=api.unique)


def request_context():
    path = Path(os.environ["SBXR_QUALIFICATION_REQUEST"])
    raw = api.private_bytes(path, "current request")
    request = json.loads(raw, object_pairs_hook=api.unique)
    scenario = request.get("scenario_id")
    if scenario not in SCENARIOS or not isinstance(request.get("qualification_manifest_sha256"), str):
        fail()
    return path, raw, request, api.digest(raw)


def require_binding(document, request, request_sha, scenario_key="scenario_id"):
    if (document.get(scenario_key) != request["scenario_id"] or
            document.get("qualification_manifest_sha256") != request["qualification_manifest_sha256"] or
            document.get("request_sha256") != request_sha):
        fail("identity private observation input is stale")


def without_uuid(configuration):
    public = copy.deepcopy(configuration)
    try:
        uuid = public["outbounds"][0].pop("uuid")
    except (KeyError, IndexError, TypeError):
        fail("identity private observation client shape differs")
    if re.fullmatch(r"[0-9a-fA-F-]{36}", uuid) is None:
        fail("identity private observation client identity differs")
    return uuid, public


def main():
    if os.geteuid() != 0:
        fail("identity private observation requires root")

    request_path, request_raw, request, request_sha = request_context()
    scenario = request["scenario_id"]
    baseline = read(ROOT / f"{scenario}-private-baseline.json", "identity private baseline")
    controller = read(ROOT / f"transition-{scenario}.json", "identity controller")
    require_binding(baseline, request, request_sha)
    require_binding(controller, request, request_sha, "scenario")

    ownership = read(Path("/var/lib/sbxr/proxy-ownership.json"), "Ownership Record")
    source = read(ROOT / f"{scenario}-source-client.json", "source client")
    source_uuid, source_public = without_uuid(source)
    if (controller.get("source_configuration_sha256") != baseline.get("source_configuration_sha256") or
            api.digest(api.canonical(source_public)) != baseline.get("noncredential_sha256") or
            api.digest(api.canonical(ownership.get("serving"))) != baseline.get("serving_sha256")):
        fail("identity private observation source authority differs")

    if scenario == "identity-precommit":
        if ((ROOT / f"{scenario}-selected-client.json").exists() or
                ownership.get("configuration_sha256") != controller.get("source_configuration_sha256")):
            fail("identity private observation cleanup authority differs")
    else:
        selected = read(ROOT / f"{scenario}-selected-client.json", "selected client")
        selected_uuid, selected_public = without_uuid(selected)
        if (selected_uuid == source_uuid or selected_public != source_public or
                ownership.get("configuration_sha256") != controller.get("target_configuration_sha256")):
            fail("identity private observation target authority differs")

    if (controller.get("source_configuration_sha256") == controller.get("target_configuration_sha256") or
            api.private_bytes(request_path, "current request") != request_raw):
        fail("identity private observation request or credential authority changed")

    facts = {
        "link_unchanged": True,
        "noncredential_fields_unchanged": True,
        "source_target_credentials_distinct": True,
    }
    print(json.dumps({"event": "unchanged_at", "result": "observed", "facts": facts},
                     sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"identity_private_observation_failed":true}', file=sys.stderr)
        sys.exit(1)
