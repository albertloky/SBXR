#!/usr/bin/env python3
"""Exercise exact Git divergence and the final publication pause without network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("release-main-review.py").resolve()
WORKFLOW = SCRIPT.parents[1] / "workflows/stable.yml"


class MainReviewTests(unittest.TestCase):
    def test_review_uses_commits_and_exact_trees_preserving_dirty_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(["git", "-c", "commit.gpgsign=false", *args], cwd=root).decode().strip()

            git("init", "-q")
            (root / "README.md").write_text("before\n")
            git("add", "README.md")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "candidate")
            candidate = git("rev-parse", "HEAD")
            (root / "README.md").write_text("after\n")
            git("add", "README.md")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "documentation typo")
            main = git("rev-parse", "HEAD")

            def review(head, assessment="unreviewed", rationale="Review required"):
                return subprocess.run([sys.executable, str(SCRIPT), candidate, head, assessment, rationale], cwd=root, capture_output=True, text=True)

            first = review(main)
            self.assertEqual(first.returncode, 0, first.stderr)
            record = json.loads(first.stdout)
            self.assertEqual(record["candidate_commit"], candidate)
            self.assertEqual(record["reviewed_main"], main)
            self.assertEqual(record["security_assessment"], "unreviewed")
            (root / "README.md").write_text("existing dirty work\n")
            (root / "private.txt").write_text("untracked work\n")
            before = git("status", "--porcelain")
            self.assertEqual(review(main).stdout, first.stdout)
            self.assertEqual(git("status", "--porcelain"), before)
            self.assertEqual((root / "README.md").read_text(), "existing dirty work\n")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "security advisory")
            newer = review(git("rev-parse", "HEAD"), "security-fixes-missing", "Candidate omits a reviewed security fix")
            self.assertEqual(newer.returncode, 0, newer.stderr)
            newer_record = json.loads(newer.stdout)
            self.assertNotEqual(newer_record["divergence_sha256"], record["divergence_sha256"])
            self.assertEqual(newer_record["security_assessment"], "security-fixes-missing")
            (root / "auth.go").write_text("// security-relevant newer fix\n")
            git("add", "auth.go")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "security fix")
            self.assertEqual(json.loads(review(git("rev-parse", "HEAD")).stdout)["security_assessment"], "unreviewed")
            self.assertNotEqual(review(main, "approved", "blanket approval").returncode, 0)
            self.assertNotEqual(review(main, "no-security-fixes-missing", " ").returncode, 0)
            self.assertNotEqual(review("main").returncode, 0)

    def test_further_main_drift_pauses_immediately_before_patch(self):
        workflow = WORKFLOW.read_text()
        start = workflow.index('            if test "$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main"')
        end = workflow.index("            for attempt in", start)
        shell = workflow[start:end]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cli = root / "gh"
            cli.write_text('#!/bin/sh\ncase "$*" in\n *"--method PATCH"*) touch patched;;\n *) printf "%s\\n" "$ACTUAL_MAIN";;\nesac\n')
            cli.chmod(0o755)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"], GITHUB_REPOSITORY="fixture/repo", GITHUB_OUTPUT=str(root / "output"), GITHUB_STEP_SUMMARY=str(root / "summary"))
            prefix = 'set -euo pipefail\nremote_main=' + "a" * 40 + '\nrelease_id=17\naction=\'{"failure_reason":"v3-publication-or-verification-failure"}\'\n'
            for drift in (False, True):
                with self.subTest(drift=drift):
                    env["ACTUAL_MAIN"] = ("b" if drift else "a") * 40
                    result = subprocess.run(["bash", "-c", prefix + shell], cwd=root, env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((root / "patched").exists(), not drift)
                    if drift:
                        self.assertEqual((root / "publication-stage").read_text(), "pending-review\n")
                        self.assertIn("pending=true", (root / "output").read_text())
                    else:
                        (root / "patched").unlink()

    def test_pending_skip_does_not_burn_but_failure_and_abandonment_do(self):
        condition = WORKFLOW.read_text().split("  finalize-failure:\n", 1)[1].splitlines()[0].strip().removeprefix("if: ")
        for operation, preflight, publication, burn in [
            ("publish", "success", "skipped", False),
            ("publish", "success", "success", False),
            ("publish", "failure", "skipped", True),
            ("publish", "cancelled", "skipped", True),
            ("publish", "success", "failure", True),
            ("publish", "success", "cancelled", True),
            ("abandon", "skipped", "skipped", True),
        ]:
            with self.subTest(operation=operation, preflight=preflight, publication=publication):
                expression = condition.replace("always()", "True").replace("&&", " and ").replace("||", " or ")
                expression = expression.replace("inputs.operation", repr(operation)).replace("needs.preflight.result", repr(preflight)).replace("needs.publish.result", repr(publication))
                self.assertEqual(eval(expression, {"__builtins__": {}}), burn)
        workflow = WORKFLOW.read_text()
        self.assertIn("if: inputs.operation == 'publish' && needs.preflight.outputs.request_approval == 'true'", workflow)
        self.assertEqual(workflow.count("if: steps.publication.outputs.pending != 'true'"), 3)


if __name__ == "__main__":
    unittest.main()
