#!/usr/bin/env python3
"""Exercise the real public Complete removal refusal while an external hold exists."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent
SCENARIOS = {"remove-certbot", "remove-writer", "remove-directory-lock"}


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError("helper import failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


admission = load("sbxr_removal_refusal_admission", "admission-race-operator.py")


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def preflight(scenario: str, timeout: int) -> tuple[bytes, bytes]:
    if sys.platform != "linux" or os.geteuid() != 0 or scenario not in SCENARIOS or not 10 <= timeout <= 120:
        raise ValueError("live Linux root, supported scenario, and timeout 10..120 required")
    request = Path(os.environ["SBXR_QUALIFICATION_REQUEST"])
    manifest = Path(os.environ["SBXR_QUALIFICATION_MANIFEST"])
    request_raw = admission.managed.protected_bytes(request, 0o600)
    manifest_raw = admission.managed.protected_bytes(manifest, 0o600)
    request_doc = json.loads(request_raw, object_pairs_hook=admission.managed.unique)
    if request_doc.get("scenario_id") != scenario or request_doc.get("qualification_manifest_sha256") != hashlib.sha256(manifest_raw).hexdigest():
        raise ValueError("current request binding refused")
    subprocess.run([
        "/bin/bash", "--noprofile", "--norc", "-c",
        'set -euo pipefail; source "$1"; operator_expect_scenario "$2"; preflight after-snap-refresh; operator_exact_candidate; prove_running',
        "removal-refusal", str(HERE / "operator-support.sh"), scenario,
    ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(30, timeout))
    return request_raw, manifest_raw


def run(scenario: str, timeout: int) -> dict:
    request_raw, manifest_raw = preflight(scenario, timeout)
    deadline = time.monotonic() + timeout
    process = subprocess.Popen([str(admission.EXECUTABLE)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    stream = admission.LineStream(process.stdout)
    reader = lambda _stream, bound: stream.line(bound)
    try:
        prepared = admission.prepare_removal(process, deadline, reader)
        before = admission.owned_snapshot()
        refused = admission.complete_refusal(process, deadline, reader)
        if process.wait(timeout=max(1, deadline - time.monotonic())) != 0:
            raise ValueError("public menu did not exit cleanly after refusal")
        after = admission.owned_snapshot()
        if after != before:
            raise ValueError("owned resources changed during refusal")
        admission.final_health()
        if (admission.managed.protected_bytes(Path(os.environ["SBXR_QUALIFICATION_REQUEST"]), 0o600) != request_raw or
                admission.managed.protected_bytes(Path(os.environ["SBXR_QUALIFICATION_MANIFEST"]), 0o600) != manifest_raw):
            raise ValueError("authority changed during refusal")
        return {
            "schema": "sbxr-v4-held-removal-refusal-v1",
            "scenario_id": scenario,
            "qualification_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "request_sha256": hashlib.sha256(request_raw).hexdigest(),
            "owned_inventory_before_sha256": before,
            "owned_inventory_after_sha256": after,
            "healthy_running": True,
            "completed_at": now(),
            **prepared,
            **refused,
        }
    finally:
        if process.poll() is None:
            try:
                process.stdin.close()
            except Exception:
                pass
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.scenario, args.timeout), sort_keys=True, separators=(",", ":")))
    except Exception as error:
        print(json.dumps({"state": "refused", "error_type": type(error).__name__}, sort_keys=True, separators=(",", ":")))
        raise SystemExit(1)
