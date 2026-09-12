#!/usr/bin/env python3
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parent.parent / "v3-mvp-evidence.py"
SPEC = importlib.util.spec_from_file_location("mvp_evidence", SCRIPT)
MVP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MVP)


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class MVPEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        package = {"certbot": {"name": "certbot"}, "karing": {"name": "karing"},
                   "outside_client": {"name": "outside"}, "proxy": {"name": "proxy"}}
        self.manifest = {
            "schema": "sbxr-qualification-manifest-v3",
            "releases": [{"commit": "a" * 40, "tag": "v3.1.99"}],
            "v3_attempt": {
                "attempt_id": "attempt-1", "evidence_policy": MVP.POLICY,
                "packages": package, "required_scenarios": MVP.ORDER,
                "runner": {"architecture": "amd64", "operating_system": "Ubuntu Server 24.04"},
                "vps_id": "vps-1", "vps_identity_sha256": "b" * 64,
            },
        }
        self.write("manifest.json", self.manifest)
        self.write("boundary.json", {"fixture": "boundary"})
        self.write("previous.json", [])

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.write_bytes(canon(value))
        path.chmod(0o600)
        return path

    def scenario_files(self, scenario="mvp-install", checks=None):
        started = self.now - dt.timedelta(minutes=2)
        completed = self.now - dt.timedelta(minutes=1)
        stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
        expected = MVP.SCENARIOS[scenario]
        request = {
            "deadline_unix": int((self.now + dt.timedelta(minutes=20)).timestamp()),
            "not_before": stamp(started),
            "qualification_manifest_sha256": sha(canon(self.manifest)),
            "required_checks": expected,
            "scenario_id": scenario,
            "scenario_limit_seconds": 7200 if scenario == "mvp-subscription" else 1800,
        }
        if checks is None:
            checks = [{"check": check, "observed_at": stamp(completed), "result": "observed"}
                      for check in expected]
        observation = {"checks": checks, "completed_at": stamp(completed),
                       "scenario_id": scenario, "started_at": stamp(started)}
        return self.write("request.json", request), self.write("observation.json", observation)

    def command(self, request, observation, output="facts.json"):
        return [sys.executable, str(SCRIPT), "--manifest", str(self.root / "manifest.json"),
                "--boundary", str(self.root / "boundary.json"), "--request", str(request),
                "--previous", str(self.root / "previous.json"), "--observation", str(observation),
                "--output", str(self.root / output)]

    def test_assembles_only_explicit_ordered_observations(self):
        request, observation = self.scenario_files()
        result = subprocess.run(self.command(request, observation), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        facts = json.loads((self.root / "facts.json").read_bytes())
        scenario = facts["detailed_evidence"]["scenarios"][0]
        self.assertEqual(scenario["scenario_id"], "mvp-install")
        self.assertEqual(scenario["initial_state"], "Not installed")
        self.assertEqual(scenario["final_state"], "Running")
        self.assertEqual(scenario["packages_before"], scenario["packages_after"])
        self.assertEqual([item["record"]["check"] for item in scenario["evidence"]],
                         MVP.SCENARIOS["mvp-install"])
        for item in scenario["evidence"]:
            self.assertEqual(item["sha256"], sha(canon(item["record"])))
        self.assertEqual(facts["detailed_evidence_sha256"],
                         sha(canon(facts["detailed_evidence"])))

    def test_missing_reordered_or_unobserved_check_is_refused_without_output(self):
        valid = [{"check": check,
                  "observed_at": (self.now - dt.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "result": "observed"} for check in MVP.SCENARIOS["mvp-install"]]
        variants = {
            "missing": valid[:-1],
            "reordered": [valid[1], valid[0], *valid[2:]],
            "not observed": [{**valid[0], "result": "passed"}, *valid[1:]],
        }
        for name, checks in variants.items():
            with self.subTest(name=name):
                request, observation = self.scenario_files(checks=checks)
                output = f"{name}.json"
                result = subprocess.run(self.command(request, observation, output),
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / output).exists())

    def test_duplicate_observation_member_is_refused_before_assembly(self):
        request, observation = self.scenario_files()
        raw = observation.read_text()
        observation.write_text(raw.replace('"scenario_id":"mvp-install"',
                                           '"scenario_id":"mvp-install","scenario_id":"mvp-install"'))
        result = subprocess.run(self.command(request, observation), capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate JSON member", result.stderr)
        self.assertFalse((self.root / "facts.json").exists())

    def test_request_exposes_exact_checks_and_subscription_deadline(self):
        self.write("previous.json", [{"scenario_id": "mvp-install"}])
        request, observation = self.scenario_files("mvp-subscription")
        result = subprocess.run(self.command(request, observation), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        supplied = json.loads(request.read_bytes())
        self.assertEqual(supplied["required_checks"], MVP.SCENARIOS["mvp-subscription"])
        self.assertEqual(supplied["scenario_limit_seconds"], 7200)

    def test_pretty_observation_and_nonmonotonic_check_times_are_accepted(self):
        request, observation = self.scenario_files()
        value = json.loads(observation.read_bytes())
        value["checks"][0]["observed_at"] = value["completed_at"]
        value["checks"][1]["observed_at"] = value["started_at"]
        observation.write_text(json.dumps(value, indent=2) + "\n")
        result = subprocess.run(self.command(request, observation), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
