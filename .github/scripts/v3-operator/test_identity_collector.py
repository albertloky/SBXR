#!/usr/bin/env python3
"""Collector contract for the distinct scenario-07 outside producer."""
import json
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
COLLECTOR = ROOT / ".github/scripts/v3-recurring-evidence.sh"


class IdentityCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = COLLECTOR.read_text()
        cls.functions = cls.source.split('if test "${1:-}" = submit; then', 1)[0]
        cls.collect = "collect_identity_driver() {" + cls.source.split("collect_identity_driver() {", 1)[1].split("\n}\n\n# Bind a non-secret", 1)[0] + "\n}\n"

    def matches(self, value):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            request.write_bytes(value)
            command = self.functions + '\nidentity_request_matches "$1" "$2" "$3" "$4"\n'
            return subprocess.run(
                ["bash", "-c", command, "identity-request", str(request), "1788324000", "a" * 64, "identity-absent"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False).returncode == 0

    def test_identity_request_has_distinct_exact_bytes(self):
        value = {
            "deadline_unix": 1788324000,
            "operator_directory": "/run/sbxr-qualification",
            "qualification_manifest_sha256": "a" * 64,
            "request_id": "identity-1",
            "scenario_id": "identity-absent",
            "schema": "sbxr-v4-identity-outside-request-v1",
            "state_directory": "/run/sbxr-qualification",
        }
        valid = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.assertTrue(self.matches(valid))
        invalid = {
            "newline": valid + b"\n",
            "baseline schema": valid.replace(b"sbxr-v4-identity-outside-request-v1", b"sbxr-v3-outside-probe-request-v1"),
            "duplicate": valid.replace(b'"request_id":"identity-1"', b'"request_id":"identity-1","request_id":"identity-1"'),
            "unknown": valid[:-1] + b',"extra":true}',
            "deadline": valid.replace(b"1788324000", b"1788323999"),
            "manifest": valid.replace(b"a" * 64, b"b" * 64),
            "scenario": valid.replace(b"identity-absent", b"baseline-clean"),
            "request id": valid.replace(b"identity-1", b"probe-1"),
            "state path": valid.replace(b'"state_directory":"/run/sbxr-qualification"', b'"state_directory":"/tmp/other"'),
            "operator path": valid.replace(b'"operator_directory":"/run/sbxr-qualification"', b'"operator_directory":"/tmp/other"'),
        }
        for name, body in invalid.items():
            with self.subTest(name=name):
                self.assertFalse(self.matches(body))

    def test_identity_driver_is_bound_and_collected_before_acceptance(self):
        required = [
            'identity_sources_match_commit "$bound_commit"',
            'git show "$bound_commit:$path" | cmp -s - "$path"',
            "identity-outside.py run",
            'timeout --kill-after=5 "$remaining"',
            'identity-outside.py check-result',
            'cmp -s "$directory/identity.stdout"',
            '07-outside-collected.json',
            'outside_identity_required=false outside_identity_started=false outside_identity_done=false',
            'if test "$outside_probe_required" = true && test "$outside_probe_done" != true',
            'if test "$outside_identity_required" = true',
        ]
        for text in required:
            self.assertIn(text, self.source)
        identity_branch = self.source.split("identity-outside-request.json'; then", 1)[1].split("if test \"$(( $(date +%s) - started ))\"", 1)[0]
        self.assertNotIn('ssh -n', identity_branch)
        self.assertLess(self.source.index('if test "$outside_identity_required" = true; then'),
                        self.source.index(".detailed_evidence.scenarios | length"))

    def test_downloaded_manifest_is_private_before_identity_driver_reads_it(self):
        privacy = 'chmod 0600 "$manifest"'
        self.assertIn(privacy, self.source)
        self.assertLess(self.source.index(privacy), self.source.index("identity-outside.py run"))
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "qualification-manifest.json"
            manifest.write_bytes(b'{}')
            manifest.chmod(0o644)
            helper_path = COLLECTOR.with_name("v3-operator") / "identity-outside.py"
            spec = importlib.util.spec_from_file_location("identity_outside_collector_test", helper_path)
            helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(helper)
            with self.assertRaises(ValueError):
                helper.read_private(manifest)
            result = subprocess.run(
                ["bash", "-c", "manifest=$1\n" + privacy, "identity-manifest", str(manifest)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
            self.assertEqual(helper.read_private(manifest), b'{}')

    def test_driver_imports_do_not_create_untracked_sources(self):
        bytecode = "export PYTHONDONTWRITEBYTECODE=1"
        self.assertIn(bytecode, self.source)
        self.assertLess(self.source.index(bytecode), self.source.index("identity_sources_match_commit()"))
        source_check = self.functions.split("identity_sources_match_commit() {", 1)[1].split("\n}\n", 1)[0]
        source_check = "identity_sources_match_commit() {" + source_check + "\n}\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            operator = root / ".github/scripts/v3-operator"
            operator.mkdir(parents=True)
            (operator / "helper.py").write_text("VALUE = 1\n")
            (operator / "other.py").write_text("VALUE = 2\n")
            (root / ".github/scripts/v3-recurring-evidence.sh").write_text("collector\n")
            (root / ".github/scripts/v3-packaged-live.sh").write_text("producer\n")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "collector@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Collector Test"], cwd=root, check=True)
            subprocess.run(["git", "add", ".github"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            command = "\n".join([
                "set -euo pipefail", bytecode, source_check,
                "PYTHONPATH=.github/scripts/v3-operator python3 -c 'import helper'",
                "test ! -e .github/scripts/v3-operator/__pycache__",
                "GITHUB_SHA=$(git rev-parse HEAD)",
                'identity_sources_match_commit "$GITHUB_SHA"',
            ])
            result = subprocess.run(["bash", "-c", command], cwd=root,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_helper_failure_maps_to_canonical_failure_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "identity.stderr").write_text('{"identity_outside_failed":true}\n')
            command = "\n".join([
                'set -uo pipefail',
                self.collect,
                'wait() { return 1; }',
                'directory=$PWD',
                'identity_pid=fixture',
                'reason=unexpected-failure',
                'collect_identity_driver || status=$?',
                'test "$status:$reason" = "1:evidence-refused"',
            ])
            result = subprocess.run(["bash", "-c", command], cwd=directory,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        allowed = {"unexpected-failure", "timeout", "unexplained-drift", "evidence-refused", "failure-recorded"}
        reasons = {line.strip().split("=", 1)[1].split(";", 1)[0]
                   for line in self.source.splitlines() if line.strip().startswith("reason=")}
        self.assertLessEqual(reasons, allowed)

    def test_successful_helper_output_is_collected_before_acknowledgement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            final = b'{"safe":"receipt"}'
            (root / "fixture-final").write_bytes(final)
            (root / "identity.stdout").write_bytes(final + b"\n")
            (root / "identity.stderr").write_bytes(b"")
            sink = root / "sink.sh"
            sink.write_text("#!/bin/sh\ncat >/dev/null\n")
            sink.chmod(0o700)
            digest = hashlib.sha256(final).hexdigest()
            command = "\n".join([
                'set -euo pipefail',
                self.collect,
                'wait() { return 0; }',
                'fetch_identity_file() { case "$1" in *07-outside.json) cp fixture-final "$2" ;; *) printf "{}" > "$2" ;; esac; }',
                'python3() { printf "%s\\n" \'{"identity_outside_verified":true}\'; }',
                f'remote=({sink})',
                'directory=$PWD',
                'identity_pid=fixture',
                'identity_state_directory=/run/sbxr-qualification',
                'identity_request_remote=/root/sbxr-qualification-evidence/identity-outside-request.json',
                'manifest_absolute=/fixture/manifest.json',
                'outside_identity_done=false',
                'reason=evidence-refused',
                'collect_identity_driver',
                'test "$outside_identity_done:$reason" = "true:evidence-refused"',
                'test -z "$identity_request_remote"',
                f'test "$(<07-outside-collected.json)" = \'{{"receipt_sha256":"{digest}"}}\'',
            ])
            result = subprocess.run(["bash", "-c", command], cwd=directory,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_collector_shell_syntax(self):
        subprocess.run(["bash", "-n", str(COLLECTOR)], check=True)


if __name__ == "__main__":
    unittest.main()
