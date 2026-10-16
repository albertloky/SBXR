#!/usr/bin/env python3
"""Authenticate an existing prepublication burn; never alter remote state."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


REPOSITORY = "albertloky/SBXR"
RUN_PREFIX = f"https://github.com/{REPOSITORY}/actions/runs/"
LIMIT = 16 << 20


class RecoveryRefusal(Exception):
    pass


def require(condition, code):
    if not condition:
        raise RecoveryRefusal(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def read_json(raw):
    require(len(raw) <= LIMIT, "input-size")
    return json.loads(raw, object_pairs_hook=unique_object)


def command_json(args, code):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={**os.environ, "GH_DEBUG": ""})
    require(result.returncode == 0, code)
    try:
        return read_json(result.stdout)
    except (ValueError, UnicodeError, RecoveryRefusal):
        raise RecoveryRefusal(code) from None


def footer_value(body, label):
    values = re.findall(r"^" + re.escape(label) + r": ([^\r\n]+)$", body, re.MULTILINE)
    require(len(values) == 1, "recovery-footer")
    return values[0]


def failed_record(body):
    prior_url = None
    if "Status: Failed prerelease\n" not in body:
        encoded = footer_value(body, "Prior failed record base64")
        raw = base64.b64decode(encoded, validate=True)
        require(base64.b64encode(raw).decode() == encoded, "recovery-footer")
        require(hashlib.sha256(raw).hexdigest() == footer_value(body, "Prior failed record SHA-256"), "recovery-footer")
        prior_url = footer_value(body, "Prior publication failure")
        body = raw.decode("utf-8")
    require("Status: Failed prerelease\n" in body, "failed-record")
    start, end = body.find("```json\n"), body.rfind("\n```\n")
    require(start >= 0 and end > start, "failed-record")
    record = read_json(body[start + 8:end].encode())
    require(record.get("stable_result_code") == "RELEASE-INSTALLER-UPDATER-PREPUBLICATION-FAILED", "failed-record")
    url = record.get("workflow_run")
    require(isinstance(url, str) and re.fullmatch(re.escape(RUN_PREFIX) + r"[1-9][0-9]*", url), "failure-run")
    require(prior_url is None or prior_url == url, "recovery-footer")
    return body, url


def collect(path):
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    facts = read_json(raw)
    require("publication_recovery" not in facts, "preexisting-recovery")
    releases, burns = facts["releases"], facts["burned_identities"]
    tags = {release["tag"] for release in releases}
    matching = [burn for burn in burns if burn["original_tag"] in tags]
    if not matching:
        return raw
    require(len(releases) == 1 and len(matching) == 1, "candidate-burn")
    release, burn = releases[0], matching[0]
    manifest = facts["signed_manifest"]
    attempt = manifest["v3_attempt"]
    require(manifest["schema"] == "sbxr-qualification-manifest-v3" and manifest["mode"] == "v3"
            and attempt["support"]["scope"] == "subscription-clean-install-only"
            and attempt["support"]["sources"] == [] and attempt["sources"] == []
            and not any(attempt.get(key) for key in ("owner_exception", "late_confirmation_review", "live89_correction_review")), "scope")
    require(release["draft"] is False and release["immutable"] is True, "candidate-state")
    require(burn["reason"] == "prepublication-failure"
            and burn["qualification_run_url"] == manifest["workflow"]["run_url"]
            and burn["commit"] == release["commit"] and burn["sequence"] == release["sequence"]
            and burn["release_index_sha256"] == release["release_identity"]["release_index_sha256"], "candidate-burn")
    body, url = failed_record(release["body"])
    run_id = url.removeprefix(RUN_PREFIX)
    run = command_json(["gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}", "--method", "GET"], "failure-run-read")
    require(type(run["id"]) is int and str(run["id"]) == run_id and run["html_url"] == url
            and run["path"] == ".github/workflows/stable.yml" and run["head_branch"] == "main"
            and run["event"] == "workflow_dispatch" and run["status"] == "completed" and run["conclusion"] == "failure"
            and isinstance(run["head_sha"], str) and re.fullmatch(r"[0-9a-f]{40}", run["head_sha"]), "failure-run-identity")
    # The historical stable workflow signed `jq -S .burn`, including its newline.
    with tempfile.TemporaryDirectory(prefix=".publication-recovery-", dir=path.parent) as directory:
        subject = Path(directory) / "burn.json"
        result = subprocess.run(["jq", "-S", "."], input=json.dumps(burn).encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(result.returncode == 0, "burn-encoding")
        subject.write_bytes(result.stdout)
        verified = command_json(["gh", "attestation", "verify", str(subject), "--repo", REPOSITORY,
            "--signer-workflow", REPOSITORY + "/.github/workflows/stable.yml", "--source-ref", "refs/heads/main",
            "--source-digest", run["head_sha"], "--format=json"], "burn-attestation")
    # Certificate extensions come from GitHub's OIDC identity; predicate fields do not.
    # https://cli.github.com/manual/gh_attestation_verify
    require(isinstance(verified, list) and any(
        isinstance(item, dict) and re.fullmatch(re.escape(url) + r"/attempts/[1-9][0-9]*",
            item.get("verificationResult", {}).get("signature", {}).get("certificate", {}).get("runInvocationURI", "") or "")
        for item in verified), "burn-invocation")
    facts["publication_recovery"] = dict(burn=burn, burn_attested=True, burn_attestation_run_id=run_id,
        failed_body=body, failure_run=dict(created_at=run["created_at"], head_sha=run["head_sha"], id=run_id,
                                          path=run["path"], url=run["html_url"]))
    return json.dumps(facts, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 2, "usage")
        sys.stdout.buffer.write(collect(Path(sys.argv[1])))
    except RecoveryRefusal as error:
        sys.exit("Publication recovery evidence refused: " + str(error))
    except (OSError, ValueError, UnicodeError, KeyError, TypeError, AttributeError):
        sys.exit("Publication recovery evidence refused: invalid-input")
