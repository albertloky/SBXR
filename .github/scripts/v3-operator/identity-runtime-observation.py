#!/usr/bin/env python3
"""Observe final identity authority and absence of every staged target path."""

import importlib.util
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path("/run/sbxr-qualification")
OWNERSHIP = Path("/var/lib/sbxr/proxy-ownership.json")
CONFIGURATION = Path("/etc/sing-box/config.json")
SCENARIOS = ("identity-precommit", "identity-postcommit", "identity-unavailable")

# Complete target and staged Client Identity resources declared by the product,
# plus the one-shot proxy-start authorization consumed during restart. The
# published startup drop-in is durable authority and may remain after rotation.
TRANSIENT_PATHS = (
    Path("/var/lib/sbxr/client-identity-target.json"),
    Path("/var/lib/sbxr/client-identity-target.json.sbxr-next"),
    Path("/etc/sing-box/.config.json.sbxr-next"),
    Path("/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf.sbxr-next"),
    Path("/var/lib/sbxr/subscription-staging/client-artifact"),
    Path("/var/lib/sbxr/subscription-staging/client-artifact.sbxr-next"),
    Path("/var/lib/sbxr/subscription-staging/serving.json"),
    Path("/var/lib/sbxr/subscription-staging/serving.json.sbxr-next"),
    Path("/etc/systemd/system/sbxr-subscription.service.sbxr-next"),
    Path("/etc/systemd/system/sbxr-subscription.service.sbxr-next.sbxr-next"),
    Path("/run/sbxr-client-identity-start"),
)


def load_api():
    spec = importlib.util.spec_from_file_location(
        "identity_runtime_observation_api", HERE / "assemble-evidence.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


api = load_api()


def fail(message="identity runtime observation refused"):
    raise api.Refusal(message)


def read(path, label, mode=0o600):
    raw = api.private_bytes(path, label, mode)
    return json.loads(raw, object_pairs_hook=api.unique)


def request_context():
    path = Path(os.environ["SBXR_QUALIFICATION_REQUEST"])
    raw = api.private_bytes(path, "current request")
    request = json.loads(raw, object_pairs_hook=api.unique)
    if (request.get("scenario_id") not in SCENARIOS or
            not isinstance(request.get("qualification_manifest_sha256"), str)):
        fail()
    return path, raw, request, api.digest(raw)


def main():
    if os.geteuid() != 0:
        fail("identity runtime observation requires root")

    request_path, request_raw, request, request_sha = request_context()
    scenario = request["scenario_id"]
    controller = read(ROOT / f"transition-{scenario}.json", "identity controller")
    if (controller.get("scenario") != scenario or
            controller.get("qualification_manifest_sha256") != request["qualification_manifest_sha256"] or
            controller.get("request_sha256") != request_sha):
        fail("identity runtime observation controller is stale")

    ownership = read(OWNERSHIP, "Ownership Record")
    if (any(path.exists() or path.is_symlink() for path in TRANSIENT_PATHS) or
            ownership.get("client_identity_rotation") is not None):
        fail("identity runtime observation found retained transition state")

    precommit = scenario == "identity-precommit"
    expected = controller.get(
        "source_configuration_sha256" if precommit else "target_configuration_sha256"
    )
    configuration = api.private_bytes(CONFIGURATION, "canonical proxy configuration", 0o640)
    if (api.digest(configuration) != expected or
            ownership.get("configuration_sha256") != expected or
            api.private_bytes(request_path, "current request") != request_raw):
        fail("identity runtime observation authority or request changed")

    if precommit:
        event = "unused_target_absent_at"
        facts = {"unused_target_absent": True, "source_authoritative": True}
    else:
        event = "one_target_at"
        facts = {
            "exactly_one_target_published": True,
            "staged_target_absent": True,
            "source_not_restored": True,
        }
    print(json.dumps({"event": event, "result": "observed", "facts": facts},
                     sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"identity_runtime_observation_failed":true}', file=sys.stderr)
        sys.exit(1)
