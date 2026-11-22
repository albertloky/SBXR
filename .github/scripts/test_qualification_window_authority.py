"""Test the GitHub observation boundary with inert, synthetic responses."""
import importlib.util
import json
import os
import subprocess
import tempfile
import pathlib
import unittest

SKIP = {"id": 20, "name": "acceptance-vps", "status": "completed", "conclusion": "cancelled", "steps": []}
SIGN = {
    "id": 19, "name": "sign", "status": "completed", "conclusion": "success",
    "steps": [{"name": "Attest qualification manifest", "conclusion": "success"}],
}
RUN = {
    "id": 101, "run_attempt": 1, "path": ".github/workflows/candidate.yml",
    "head_branch": "main", "head_sha": "a" * 40, "event": "workflow_dispatch",
    "status": "completed", "conclusion": "cancelled",
    "html_url": "https://github.com/albertloky/SBXR/actions/runs/101",
}
INVOCATION = RUN["html_url"] + "/attempts/1"


def load():
    path = pathlib.Path(__file__).with_name("qualification-window-authority.py")
    spec = importlib.util.spec_from_file_location("authority", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FreshWindowAuthority(unittest.TestCase):
    def test_origin_requires_exact_closed_signing_result_without_live_activity(self):
        auth = load()
        self.assertEqual(auth.origin_workflow("101", RUN, [SIGN, SKIP])["run_id"], "101")
        for run, jobs in (
            ({**RUN, "run_attempt": 2}, [SIGN, SKIP]),
            ({**RUN, "status": "in_progress"}, [SIGN, SKIP]),
            ({**RUN, "head_branch": "other"}, [SIGN, SKIP]),
            (RUN, [SIGN, SIGN, SKIP]),
            (RUN, [{**SIGN, "steps": []}, SKIP]),
            (RUN, [SIGN, {**SKIP, "steps": [{"name": "Setup"}]}]),
            (RUN, [SIGN, {**SKIP, "name": "owner-exception", "conclusion": "success"}]),
        ):
            with self.subTest(run=run, jobs=jobs), self.assertRaises(auth.Refused):
                auth.origin_workflow("101", run, jobs)

    def test_attestation_requires_the_verified_certificate_invocation(self):
        auth = load()

        def verified(uri):
            return {"verificationResult": {
                "signature": {"certificate": {"runInvocationURI": uri}},
                "statement": {"predicate": {"runInvocationURI": INVOCATION}},
            }}

        self.assertTrue(auth.exact_invocation([verified(INVOCATION)], INVOCATION))
        for result in ([], [verified(INVOCATION + "0")], [verified(RUN["html_url"] + "/attempts/2")],
                       [verified(INVOCATION), verified(INVOCATION)], [verified("https://other.invalid")]):
            with self.subTest(result=result):
                self.assertFalse(auth.exact_invocation(result, INVOCATION))


    def test_expired_or_previously_claimed_source_has_no_admission_receipt(self):
        script = pathlib.Path(__file__).resolve().with_name("fresh-qualification.sh")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "handoff").mkdir()
            gh = root / "gh"
            gh.write_text("#!/bin/sh\ncase \"$*\" in *artifacts?name=fresh-qualification-use-101*) printf '%s' \"$ARTIFACTS\";; *) exit 9;; esac\n")
            gh.chmod(0o700)
            date = root / "date"
            date.write_text("#!/bin/sh\nif test \"$1\" = +%s; then printf '%s' \"$NOW\"; else printf 2026-11-22T13:10:00Z; fi\n")
            date.chmod(0o700)
            window = {"window": {"origin": {"run_id": "101"}, "workflow": {"run_id": "102"},
                                 "run_attempt": 1, "start_unix": 1795352400, "test_until_unix": 1795354200,
                                 "finish_unix": 1795355760}}
            (root / "fresh-window-decision.json").write_text(json.dumps(window))
            (root / "fresh-window-facts.json").write_text("{}")
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"],
                       GITHUB_REPOSITORY="albertloky/SBXR", GITHUB_REF="refs/heads/main",
                       GITHUB_RUN_ID="102", GITHUB_RUN_ATTEMPT="1", GITHUB_SHA="a"*40,
                       SECURITY_CUTOFF_UNIX="1795355760")
            receipt = root / "handoff" / "fresh-window-evidence.json"
            for now, artifacts, succeeds in (
                ("1795353000", [{"artifacts": [{"name": "fresh-qualification-use-101"}]}], False),
                ("1795353001", [{"artifacts": []}], False),
                ("1795353000", [{"artifacts": []}], True),
            ):
                with self.subTest(now=now, artifacts=artifacts):
                    run = subprocess.run(["bash", str(script), "admit"], cwd=root,
                                         env=dict(env, NOW=now, ARTIFACTS=json.dumps(artifacts)),
                                         capture_output=True, text=True)
                    self.assertEqual(run.returncode == 0, succeeds, run.stderr)
                    self.assertEqual(receipt.exists(), succeeds)


if __name__ == "__main__":
    unittest.main()
