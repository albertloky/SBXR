#!/usr/bin/env python3
"""Exercise actual CLI, filesystem permissions, refusal, and publication."""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("mvp-observe.py")


class ObserveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.request = self.root / "request.json"
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.value = {"scenario_id": "mvp-install", "not_before": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "deadline_unix": int(now.timestamp())+1800, "scenario_limit_seconds": 1800,
                      "qualification_manifest_sha256": "a"*64,
                      "required_checks": ["packaged-install", "outside-proxy-traffic"]}
        self.save_request()
        self.draft, self.output = self.root / "draft.json", self.root / "observation.json"

    def save_request(self):
        self.request.write_text(json.dumps(self.value))
        self.request.chmod(0o600)

    def call(self, command, *args, ok=True):
        result = subprocess.run([sys.executable, str(SCRIPT), command, "--request", str(self.request),
                                 "--draft", str(self.draft), *args], capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, ok, result.stderr)
        self.assertFalse(list(self.root.glob(".mvp-observe-*")), "temporary publication file leaked")
        return result

    def test_explicit_observations_sealed_atomic_publication(self):
        self.call("start")
        self.assertEqual(self.draft.stat().st_mode & 0o777, 0o600)
        before = json.loads(self.draft.read_text())["observation"]
        self.assertIsNone(before["completed_at"])
        self.call("finish", "--output", str(self.output), ok=False)
        self.assertFalse(self.output.exists())
        for check in self.value["required_checks"]:
            self.call("observe", "--check", check)
        self.call("observe", "--check", "packaged-install", ok=False)
        self.call("finish", "--output", str(self.output))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        body = json.loads(self.output.read_text())
        self.assertEqual(set(body), {"scenario_id", "started_at", "completed_at", "checks"})
        self.assertEqual(body["started_at"], before["started_at"])
        self.assertTrue(all(c["result"] == "observed" for c in body["checks"]))
        self.output.unlink()  # Collector consumption cannot authorize resubmission.
        self.call("finish", "--output", str(self.output), ok=False)
        self.assertFalse(self.output.exists())

    def test_stale_request_missing_unknown_and_duplicate_checks_refuse(self):
        self.call("start")
        original = self.draft.read_bytes()
        self.call("observe", "--check", "all", ok=False)
        self.call("observe", ok=False)
        self.assertEqual(self.draft.read_bytes(), original)
        self.value["qualification_manifest_sha256"] = "b"*64
        self.save_request()
        self.call("observe", "--check", "packaged-install", ok=False)
        self.assertEqual(self.draft.read_bytes(), original)

    def test_deadline_cannot_be_backdated_or_extended(self):
        self.call("start")
        self.value["deadline_unix"] -= 1801
        self.save_request()
        self.call("observe", "--check", "packaged-install", ok=False)
        self.value["deadline_unix"] += 1802
        self.save_request()
        self.call("status", ok=False)
        self.assertFalse(self.output.exists())

    def test_permissions_symlinks_hardlinks_and_duplicate_json_refuse(self):
        self.request.chmod(0o644)
        self.call("start", ok=False)
        self.request.chmod(0o600)
        backup = self.root / "original"
        self.request.rename(backup)
        self.request.symlink_to(backup)
        self.call("start", ok=False)
        self.request.unlink()
        os.link(backup, self.request)
        self.call("start", ok=False)
        backup.unlink()
        self.request.write_text(self.request.read_text().replace('"scenario_id":', '"scenario_id":"duplicate", "scenario_id":'))
        self.call("start", ok=False)
        self.assertFalse(self.draft.exists())

    def test_start_and_finish_never_overwrite_existing_files(self):
        self.call("start")
        original = self.draft.read_bytes()
        self.call("start", ok=False)
        self.assertEqual(self.draft.read_bytes(), original)
        for check in self.value["required_checks"]:
            self.call("observe", "--check", check)
        self.output.write_text("retained evidence")
        self.call("finish", "--output", str(self.output), ok=False)
        self.assertEqual(self.output.read_text(), "retained evidence")


if __name__ == "__main__":
    unittest.main()
