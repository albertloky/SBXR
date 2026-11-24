#!/usr/bin/env python3
"""Read-only GitHub evidence for the original release and a fresh window."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPOSITORY = "albertloky/SBXR"
WORKFLOW = ".github/workflows/candidate.yml"
SIGNER = REPOSITORY + "/" + WORKFLOW
RUN_PREFIX = f"https://github.com/{REPOSITORY}/actions/runs/"
LIVE_JOBS = {"acceptance-vps", "owner-exception", "live89-correction"}


class Refused(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-field")
        result[key] = value
    return result


def gh_json(args, reason):
    result = subprocess.run(
        ["gh", *args], capture_output=True, timeout=120,
        env={**os.environ, "GH_DEBUG": ""},
    )
    require(result.returncode == 0 and 0 < len(result.stdout) <= 16 << 20, reason)
    try:
        return json.loads(result.stdout, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError):
        raise Refused(reason) from None


def run_workflow(run_id, run):
    require(isinstance(run_id, str) and re.fullmatch(r"[1-9][0-9]*", run_id), "run-id")
    require(run["id"] == int(run_id) and run["path"] == WORKFLOW
            and run["head_branch"] == "main" and run["event"] == "workflow_dispatch"
            and run["html_url"] == RUN_PREFIX + run_id
            and re.fullmatch(r"[a-f0-9]{40}", run["head_sha"]), "run-identity")
    return {
        "commit": run["head_sha"], "path": WORKFLOW, "ref": SIGNER + "@refs/heads/main",
        "run_id": run_id, "run_url": run["html_url"],
    }


def origin_workflow(run_id, run, jobs):
    workflow = run_workflow(run_id, run)
    require(run["status"] == "completed" and run["conclusion"] in ("success", "cancelled")
            and type(run["run_attempt"]) is int and run["run_attempt"] == 1, "origin-run-state")
    sign = [job for job in jobs if job["name"] == "sign"]
    require(len(sign) == 1 and sign[0]["status"] == "completed" and sign[0]["conclusion"] == "success",
            "origin-signing-job")
    attest = [step for step in sign[0]["steps"] if step["name"] == "Attest qualification manifest"]
    require(len(attest) == 1 and attest[0]["conclusion"] == "success", "origin-attestation-step")
    for job in jobs:
        if job["name"] in LIVE_JOBS:
            require(job["status"] == "completed" and job["conclusion"] in ("skipped", "cancelled")
                    and job["steps"] == [], "origin-live-job")
    return workflow


def exact_invocation(verified, expected):
    # Only certificate extensions are trusted. Build predicate fields can be
    # supplied by workflow input and are deliberately ignored here.
    if not isinstance(verified, list) or len(verified) != 1:
        return False
    try:
        return verified[0]["verificationResult"]["signature"]["certificate"]["runInvocationURI"] == expected
    except (KeyError, TypeError):
        return False


def verify_attestation(subject, workflow, run_attempt):
    require(subject.is_file() and not subject.is_symlink(), "subject-file")
    verified = gh_json([
        "attestation", "verify", str(subject), "--repo", REPOSITORY,
        "--signer-workflow", SIGNER, "--source-ref", "refs/heads/main",
        "--source-digest", workflow["commit"], "--deny-self-hosted-runners", "--format=json",
    ], "attestation")
    expected = workflow["run_url"] + f"/attempts/{run_attempt}"
    require(exact_invocation(verified, expected), "attestation-invocation")
    return verified[0]


def origin(subject, run_id):
    require(re.fullmatch(r"[1-9][0-9]*", run_id), "origin-run-id")
    prefix = f"repos/{REPOSITORY}/actions/runs/{run_id}"
    run = gh_json(["api", prefix, "--method", "GET"], "origin-run-read")
    pages = gh_json(["api", prefix + "/attempts/1/jobs?per_page=100", "--method", "GET",
                     "--paginate", "--slurp"], "origin-jobs-read")
    workflow = origin_workflow(run_id, run, [job for page in pages for job in page["jobs"]])
    verify_attestation(subject, workflow, 1)
    return {"live_never_started": True, "manifest_attested": True, "run_attempt": 1,
            "sign_conclusion": "success", "signer_workflow": SIGNER, "workflow": workflow}


def observe_current(run_id):
    require(re.fullmatch(r"[1-9][0-9]*", run_id), "run-id")
    prefix = f"repos/{REPOSITORY}/actions/runs/{run_id}"
    run = gh_json(["api", prefix, "--method", "GET"], "live-run-read")
    require(type(run["run_attempt"]) is int and run["run_attempt"] == 1, "live-run-attempt")
    return prefix, run_workflow(run_id, run), run


def verify_window(subject, run_id):
    _, workflow, _ = observe_current(run_id)
    decision = json.loads(subject.read_bytes(), object_pairs_hook=unique_pairs)
    require(decision["outcome"] == "accepted" and decision["stage"] == "qualification-window" and
            decision["window"]["workflow"] == workflow and decision["window"]["run_attempt"] == 1,
            "window-run-identity")
    bundle = verify_attestation(subject, workflow, 1)["attestation"]["bundle"]
    envelope = bundle.get("dsseEnvelope") if isinstance(bundle, dict) else None
    require(isinstance(envelope, dict) and envelope.get("payload"), "window-bundle")
    return bundle


def live(run_id, completed=False):
    prefix, _, run = observe_current(run_id)
    if completed:
        require(run["status"] == "completed" and run["conclusion"] == "success", "live-run-status")
    else:
        require(run["status"] == "in_progress", "live-run-status")
    pages = gh_json(["api", prefix + "/attempts/1/jobs?per_page=100", "--method", "GET",
                     "--paginate", "--slurp"], "live-jobs-read")
    jobs = [job for page in pages for job in page["jobs"]]
    sign = [job for job in jobs if job["name"] == "sign"]
    acceptance = [job for job in jobs if job["name"] == "acceptance-vps"]
    require(len(sign) == 1 and sign[0]["status"] == "completed" and sign[0]["conclusion"] == "success",
            "window-signing-job")
    steps = [step for step in sign[0]["steps"] if step["name"] == "Attest the fresh qualification window"]
    require(len(steps) == 1 and steps[0]["conclusion"] == "success", "window-signing-step")
    require(len(acceptance) == 1, "live-job")
    if completed:
        require(acceptance[0]["status"] == "completed" and acceptance[0]["conclusion"] == "success",
                "live-job")
        names = {"Run the packaged V3 journey", "Evaluate the Acceptance VPS result and write exact Module records"}
        require({step["name"] for step in acceptance[0]["steps"] if
                 step["name"] in names and step["conclusion"] == "success"} == names, "live-result-steps")
    else:
        require(acceptance[0]["status"] == "in_progress", "live-job")
    approvals = gh_json(["api", prefix + "/approvals", "--method", "GET"], "live-approvals-read")
    require(len(approvals) == 2 and all(review["state"] == "approved" and
            [environment["name"] for environment in review["environments"]] == ["acceptance-vps"]
            for review in approvals), "live-approvals")

def main(args):
    if len(args) == 3 and args[0] == "origin":
        report = origin(Path(args[1]), args[2])
        sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")))
    elif len(args) == 3 and args[0] in ("window", "window-bundle"):
        bundle = verify_window(Path(args[1]), args[2])
        if args[0] == "window-bundle":
            sys.stdout.write(json.dumps(bundle, separators=(",", ":")))
    elif len(args) == 2 and args[0] in ("live", "completed"):
        live(args[1], completed=args[0] == "completed")
    else:
        raise Refused("usage")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Refused as error:
        sys.exit(f"qualification-window authority refused: {error}")
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired):
        sys.exit("qualification-window authority refused: unavailable or malformed observation")
