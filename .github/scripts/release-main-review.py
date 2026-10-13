#!/usr/bin/env python3
"""Bind a human divergence assessment to exact committed candidate/main inputs."""
import hashlib
import json
import re
import subprocess
import sys


def review(candidate, main, assessment, rationale):
    if not all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in (candidate, main)):
        raise ValueError("exact candidate and main SHAs required")
    if assessment not in ("unreviewed", "no-security-fixes-missing", "security-fixes-missing") or not rationale.strip():
        raise ValueError("explicit security assessment and rationale required")
    commits = subprocess.check_output(["git", "log", "--format=%H", f"{candidate}..{main}"])
    diff = subprocess.check_output(["git", "diff", "--binary", "--no-ext-diff", "--no-textconv", candidate, main, "--"])
    return dict(candidate_commit=candidate, reviewed_main=main,
                divergence_sha256=hashlib.sha256(commits + b"\0" + diff).hexdigest(),
                security_assessment=assessment, rationale=rationale)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 5:
            raise ValueError("usage: release-main-review.py CANDIDATE MAIN ASSESSMENT RATIONALE")
        print(json.dumps(review(*sys.argv[1:]), sort_keys=True, separators=(",", ":")), end="")
    except (ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
