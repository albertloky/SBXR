#!/usr/bin/env python3
"""Exercise recovery's real subprocess boundary without credentials or writes."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("publication-recovery.py").resolve()
REPOSITORY = "albertloky/SBXR"
RUN_URL = f"https://github.com/{REPOSITORY}/actions/runs/102"


class PublicationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="publication-recovery-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.burn = dict(commit="a" * 40, original_tag="v3.1.95",
                         qualification_run_url=f"https://github.com/{REPOSITORY}/actions/runs/101",
                         reason="prepublication-failure", recorded_at="2026-10-15T11:36:48Z",
                         release_index_sha256="b" * 64, sequence=173)
        self.failed_body = "Status: Failed prerelease\n```json\n" + json.dumps(dict(
            stable_result_code="RELEASE-INSTALLER-UPDATER-PREPUBLICATION-FAILED",
            workflow_run=RUN_URL)) + "\n```\n"
        self.facts = dict(schema="sbxr-release-qualification-facts-v1", stage="stable-preflight",
                          burned_identities=[self.burn],
                          signed_manifest=dict(schema="sbxr-qualification-manifest-v3", mode="v3",
                              workflow=dict(run_url=self.burn["qualification_run_url"]),
                              v3_attempt=dict(support=dict(scope="subscription-clean-install-only", sources=[]), sources=[])),
                          releases=[dict(tag="v3.1.95", commit="a" * 40, sequence=173,
                              release_identity=dict(release_index_sha256="b" * 64),
                              draft=False, immutable=True, prerelease=True, body=self.failed_body)])
        self.run = dict(id=102, head_sha="c" * 40, path=".github/workflows/stable.yml",
                        head_branch="main", event="workflow_dispatch", status="completed", conclusion="failure",
                        created_at="2026-10-15T11:30:00Z", html_url=RUN_URL)
        self.verification = [dict(verificationResult=dict(signature=dict(certificate=dict(
            runInvocationURI=RUN_URL + "/attempts/1"))))]
        cli = self.root / "gh"
        cli.write_text("""#!/usr/bin/env python3
import json, os
from pathlib import Path
import sys
args = sys.argv[1:]
with Path('calls.jsonl').open('a') as stream:
    stream.write(json.dumps(args) + '\\n')
kind = 'run' if args[0] == 'api' else 'verification'
if os.environ.get('FAIL_COMMAND') == kind:
    sys.stderr.write('private-token-must-not-appear')
    sys.exit(1)
if kind == 'verification':
    assert args[:2] == ['attestation', 'verify']
    assert Path(args[2]).read_bytes() == Path('expected-burn.json').read_bytes()
sys.stdout.write(Path(kind + '.json').read_text())
""")
        cli.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"], GH_DEBUG="api")
        self.input = self.root / "facts.json"
        self.write_fixture()

    def write_fixture(self):
        self.input.write_text(json.dumps(self.facts))
        (self.root / "run.json").write_text(json.dumps(self.run))
        (self.root / "verification.json").write_text(json.dumps(self.verification))
        (self.root / "expected-burn.json").write_bytes(subprocess.check_output(
            ["jq", "-S", "."], input=json.dumps(self.burn).encode()))

    def collect(self):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.input)], cwd=self.root,
                              env=self.env, capture_output=True)

    def assert_refused(self):
        result = self.collect()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Publication recovery evidence refused:", result.stderr)
        self.assertNotIn(b"private-token", result.stderr)

    def test_signed_burn_exact_bytes_and_certificate_invocation_are_bound(self):
        before = self.input.read_bytes()
        result = self.collect()
        self.assertEqual(result.returncode, 0, result.stderr)
        facts = json.loads(result.stdout)
        self.assertEqual(result.stdout, json.dumps(facts, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
        recovery = facts.pop("publication_recovery")
        self.assertEqual(facts, self.facts)
        self.assertEqual(recovery, dict(burn=self.burn, burn_attested=True, burn_attestation_run_id="102",
            failed_body=self.failed_body, failure_run=dict(created_at=self.run["created_at"], head_sha="c" * 40,
                id="102", path=self.run["path"], url=RUN_URL)))
        self.assertEqual(self.input.read_bytes(), before)
        self.assertFalse(list(self.root.glob(".publication-recovery-*")))
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        self.assertEqual(calls[0], ["api", f"repos/{REPOSITORY}/actions/runs/102", "--method", "GET"])
        self.assertEqual(calls[1][3:], ["--repo", REPOSITORY, "--signer-workflow",
            REPOSITORY + "/.github/workflows/stable.yml", "--source-ref", "refs/heads/main",
            "--source-digest", "c" * 40, "--format=json"])

    def test_retry_recovers_exact_failed_body_from_preserved_footer(self):
        release = self.facts["releases"][0]
        release["prerelease"] = False
        release["body"] = ("Status: Qualified\n\nPrior publication failure: " + RUN_URL + "\n"
            "Prior failed record SHA-256: " + hashlib.sha256(self.failed_body.encode()).hexdigest() + "\n"
            "Prior failed record base64: " + base64.b64encode(self.failed_body.encode()).decode() + "\n")
        self.write_fixture()
        result = self.collect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["publication_recovery"]["failed_body"], self.failed_body)

    def test_retry_footer_requires_exact_body_commitment_and_failure_run(self):
        encoded = base64.b64encode(self.failed_body.encode()).decode()
        digest = hashlib.sha256(self.failed_body.encode()).hexdigest()
        body = ("Status: Qualified\nPrior publication failure: " + RUN_URL + "\n"
            "Prior failed record SHA-256: " + digest + "\nPrior failed record base64: " + encoded + "\n")
        for invalid in (body.replace(digest, "0" * 64), body.replace(RUN_URL, RUN_URL + "1"),
                        body + "Prior failed record base64: " + encoded + "\n",
                        body.replace(encoded, encoded + "=")):
            with self.subTest(invalid=invalid[-30:]):
                self.facts["releases"][0].update(body=invalid, prerelease=False)
                self.write_fixture()
                self.assert_refused()
                self.assertFalse((self.root / "calls.jsonl").exists())

    def test_ordinary_candidate_passes_through_exact_original_bytes(self):
        self.facts["burned_identities"] = []
        self.write_fixture()
        result = self.collect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.input.read_bytes())
        self.assertFalse((self.root / "calls.jsonl").exists())

    def test_read_and_attestation_errors_fail_closed_without_raw_stderr(self):
        for command in ("run", "verification"):
            with self.subTest(command=command):
                self.env["FAIL_COMMAND"] = command
                self.assert_refused()

    def test_wrong_run_identity_is_rejected(self):
        for key, value in {"id": 103, "path": ".github/workflows/candidate.yml", "head_branch": "topic",
                           "head_sha": "main", "html_url": RUN_URL + "/other", "event": "pull_request",
                           "status": "in_progress", "conclusion": "success"}.items():
            with self.subTest(key=key):
                run = copy.deepcopy(self.run)
                run[key] = value
                (self.root / "run.json").write_text(json.dumps(run))
                self.assert_refused()
        (self.root / "run.json").write_text("not JSON")
        self.assert_refused()

    def test_only_certificate_invocation_is_trusted(self):
        for invocation in (None, RUN_URL + "0/attempts/1", RUN_URL + "/attempts/0", RUN_URL + "/attempts/1?query=1",
                           RUN_URL.replace("github.com", "example.invalid") + "/attempts/1"):
            with self.subTest(invocation=invocation):
                verification = copy.deepcopy(self.verification)
                verified = verification[0]["verificationResult"]
                verified["signature"]["certificate"]["runInvocationURI"] = invocation
                verified["statement"] = dict(predicate=dict(runInvocationURI=RUN_URL + "/attempts/1"))
                (self.root / "verification.json").write_text(json.dumps(verification))
                self.assert_refused()
        for invalid in ([], {}, "not JSON"):
            with self.subTest(invalid=invalid):
                (self.root / "verification.json").write_text(invalid if isinstance(invalid, str) else json.dumps(invalid))
                self.assert_refused()

    def test_unsupported_burn_or_scope_is_rejected_before_any_read(self):
        original = copy.deepcopy(self.facts)
        changes = (
            lambda f: f["burned_identities"].append(copy.deepcopy(self.burn)),
            lambda f: f["burned_identities"][0].update(reason="post-sign-qualification-failure"),
            lambda f: f["burned_identities"][0].update(qualification_run_url=RUN_URL),
            lambda f: f["signed_manifest"]["v3_attempt"]["support"].update(scope="recurring-subscription-upgrade"),
            lambda f: f["releases"][0].update(immutable=False),
            lambda f: f.update(publication_recovery=dict(burn_attested=True)),
        )
        for change in changes:
            with self.subTest(change=change):
                self.facts = copy.deepcopy(original)
                change(self.facts)
                self.write_fixture()
                self.assert_refused()
                self.assertFalse((self.root / "calls.jsonl").exists())

    def test_corrupt_recovery_footer_and_duplicate_json_keys_are_refused(self):
        self.facts["releases"][0]["body"] = "Status: Qualified\nPrior failed record base64: invalid!\n"
        self.write_fixture()
        self.assert_refused()
        self.input.write_bytes(b'{"releases":[],"releases":[]}')
        self.assert_refused()

    def test_oversized_input_is_refused_before_any_read(self):
        self.input.write_bytes(b" " * ((16 << 20) + 1))
        self.assert_refused()
        self.assertFalse((self.root / "calls.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
