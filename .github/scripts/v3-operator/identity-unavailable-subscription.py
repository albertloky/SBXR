#!/usr/bin/env python3
"""Emit scenario-18 fault and fallback facts from current machine observations."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path("/run/sbxr-qualification")
OWNERSHIP = Path("/var/lib/sbxr/proxy-ownership.json")


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


api = load("identity_unavailable_subscription_api", "assemble-evidence.py")
firewall = load("identity_unavailable_subscription_firewall", "firewall-control.py")


def fail(message="identity unavailable subscription observation refused"):
    raise api.Refusal(message)


def read(path, label):
    raw = api.private_bytes(path, label)
    return json.loads(raw, object_pairs_hook=api.unique)


def require_binding(document, request, request_sha, scenario_key="scenario_id"):
    if (document.get(scenario_key) != request["scenario_id"] or
            document.get("qualification_manifest_sha256") != request["qualification_manifest_sha256"] or
            document.get("request_sha256") != request_sha):
        fail("identity unavailable subscription input is stale")


def without_uuid(configuration):
    public = copy.deepcopy(configuration)
    try:
        uuid = public["outbounds"][0].pop("uuid")
    except (KeyError, IndexError, TypeError):
        fail("identity unavailable selected client shape differs")
    if re.fullmatch(r"[0-9a-fA-F-]{36}", uuid) is None:
        fail("identity unavailable selected client identity differs")
    return uuid, public


def main():
    if os.geteuid() != 0:
        fail("identity unavailable subscription observation requires root")

    request_path = Path(os.environ["SBXR_QUALIFICATION_REQUEST"])
    request_raw = api.private_bytes(request_path, "current request")
    request = json.loads(request_raw, object_pairs_hook=api.unique)
    if (request.get("scenario_id") != "identity-unavailable" or
            not isinstance(request.get("qualification_manifest_sha256"), str)):
        fail("current identity-unavailable request required")
    request_sha = api.digest(request_raw)

    controller = read(ROOT / "transition-identity-unavailable.json", "identity controller")
    baseline = read(ROOT / "identity-unavailable-private-baseline.json", "identity private baseline")
    ready = read(ROOT / "identity-unavailable-outside-ready.json", "identity outside ready")
    result = read(ROOT / "identity-unavailable-outside-result.json", "identity outside result")
    require_binding(controller, request, request_sha, "scenario")
    for document in (baseline, ready, result):
        require_binding(document, request, request_sha)

    state = read(firewall.STATE, "identity unavailable firewall state")
    if firewall.qualification_rules(firewall.rules()) != [firewall.expected_saved_rule(state["ipv4"])]:
        fail("identity unavailable qualification rule differs")
    if ("subscription_outside_failed_at" not in ready or
            "local_public_https_failed_at" not in baseline):
        fail("identity unavailable outage observations are absent")

    subprocess.run(["systemctl", "is-active", "--quiet", "sing-box.service"], check=True)
    ownership = read(OWNERSHIP, "Ownership Record")
    if (api.digest(api.canonical(ownership.get("serving"))) != baseline.get("serving_sha256") or
            ownership.get("configuration_sha256") != controller.get("target_configuration_sha256")):
        fail("identity unavailable current authority differs")

    pid = subprocess.run(
        ["systemctl", "show", "sing-box.service", "-p", "MainPID", "--value"],
        stdout=subprocess.PIPE, check=True, text=True,
    ).stdout.strip()
    listeners = subprocess.run(
        ["ss", "-H", "-ltnp", "sport", "=", ":443"],
        stdout=subprocess.PIPE, check=True, text=True,
    ).stdout
    if not pid.isdigit() or int(pid) < 2 or "sing-box" not in listeners or f"pid={pid}" not in listeners:
        fail("identity unavailable proxy listener differs")

    facts = result.get("facts", {})
    if facts.get("outside_target_healthy") is not True or facts.get("replacement_traffic") is not True:
        fail("identity unavailable outside result differs")

    status = subprocess.run(
        ["/usr/local/bin/sbxr"], input=b"0\n", stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True,
    )
    if (status.stderr or b"Proxy status: Running" not in status.stdout or
            b"Subscription status: Problem detected" not in status.stdout):
        fail("identity unavailable public status differs")

    source = read(ROOT / "identity-unavailable-source-client.json", "source client")
    selected = read(ROOT / "identity-unavailable-selected-client.json", "confirmed selected client")
    source_uuid, source_public = without_uuid(source)
    selected_uuid, selected_public = without_uuid(selected)
    if (source_uuid == selected_uuid or source_public != selected_public or
            api.digest(api.canonical(source_public)) != baseline.get("noncredential_sha256") or
            api.private_bytes(request_path, "current request") != request_raw):
        fail("identity unavailable fallback or request changed")

    fault = {
        "outside_link_failed": True,
        "local_public_https_failed": True,
        "proxy_443_healthy": True,
        "certificate_unchanged": True,
    }
    fallback = {
        "show_client_configuration_confirmed": True,
        "configuration_file_not_used": True,
    }
    print(json.dumps({"event": "fault_reported_at", "result": "observed", "facts": fault},
                     sort_keys=True, separators=(",", ":")))
    print(json.dumps({"event": "fallback_disclosed_at", "result": "observed", "facts": fallback},
                     sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"identity_unavailable_subscription_failed":true}', file=sys.stderr)
        sys.exit(1)
