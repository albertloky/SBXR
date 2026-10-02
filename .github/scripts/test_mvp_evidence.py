#!/usr/bin/env python3
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parent / "v3-mvp-evidence.py"
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
        expected = MVP.required_checks(self.manifest["v3_attempt"], scenario)
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

    def test_recurring_collector_checklist_and_source_recovery_fields(self):
        identity = {"repository": "albertloky/SBXR", "tag": "v3.1.81",
                    "commit": "c"*40, "release_index_sha256": "d"*64}
        source = {"release_identity": identity, "ownership_schema": 2}
        attempt = self.manifest["v3_attempt"]
        attempt.update(evidence_policy=MVP.RECURRING_POLICY, sources=[source],
                       support={"scope": "recurring-subscription-upgrade",
                                "contract": "sbxr-subscription-update-v1", "sources": [identity]})
        attempt["required_scenarios"] = MVP.scenario_order(attempt)
        self.write("manifest.json", self.manifest)
        collector = SCRIPT.with_name("v3-recurring-evidence.sh").read_text()
        function = collector[collector.index("mvp_required_checks() {"):].split("\n}", 1)[0] + "\n}\n"
        for index, (suffix, boundary, recovery) in enumerate([
                ("precommit", "before-commitment", "rollback"),
                ("upgrade", "observed", "none"),
                ("postcommit", "after-commitment", "forward")]):
            scenario = "source-v3.1.81-" + suffix
            self.write("previous.json", [{"scenario_id": s} for s in attempt["required_scenarios"][:index]])
            request, observation = self.scenario_files(scenario)
            result = subprocess.run(self.command(request, observation, suffix+".json"), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            facts = json.loads((self.root / (suffix+".json")).read_text())
            self.assertEqual(facts["qualification_boundary_facts"], {"fixture": "boundary"})
            actual = facts["detailed_evidence"]["scenarios"][-1]
            self.assertEqual((actual["source"], actual["boundary"], actual["recovery_direction"]), (source, boundary, recovery))
            shell = subprocess.run(["bash", "-c", function+'manifest=$1; mvp_required_checks "$2"',
                                    "bash", str(self.root / "manifest.json"), scenario],
                                   cwd=SCRIPT.parents[2], capture_output=True, text=True)
            self.assertEqual(shell.returncode, 0, shell.stderr)
            self.assertEqual(shell.stdout.split(), json.loads(request.read_bytes())["required_checks"])
        attempt["sources"] = []
        self.write("manifest.json", self.manifest)
        refused = subprocess.run([sys.executable, str(SCRIPT), "--checks", str(self.root / "manifest.json"),
                                  "source-v3.1.81-precommit"], capture_output=True, text=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(refused.stdout, "")

    def test_http_policy_changes_only_transport_and_replacement_checks(self):
        identity = {"repository": "albertloky/SBXR", "tag": "v3.1.81",
                    "commit": "c"*40, "release_index_sha256": "d"*64}
        source = {"release_identity": identity, "ownership_schema": 2}
        attempt = self.manifest["v3_attempt"]
        attempt.update(evidence_policy=MVP.HTTP_RECURRING_POLICY, sources=[source],
                       support={"scope": "recurring-subscription-upgrade",
                                "contract": "sbxr-subscription-update-v1", "sources": [identity]})
        order = MVP.scenario_order(attempt)
        self.assertEqual(order, ["source-v3.1.81-precommit", "source-v3.1.81-upgrade", "source-v3.1.81-postcommit", "mvp-install", "mvp-subscription", "mvp-credentials", "mvp-serving", "mvp-removal"])
        attempt["required_scenarios"] = order
        self.write("manifest.json", self.manifest)
        collector = SCRIPT.with_name("v3-recurring-evidence.sh").read_text()
        function = collector[collector.index("mvp_required_checks() {"):].split("\n}", 1)[0] + "\n}\n"
        for index, scenario in enumerate(order):
            with self.subTest(scenario=scenario):
                checks = MVP.required_checks(attempt, scenario)
                self.write("previous.json", [{"scenario_id": name} for name in order[:index]])
                request, observation = self.scenario_files(scenario)
                result = subprocess.run(self.command(request, observation, scenario+"-http.json"), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                shell = subprocess.run(["bash", "-c", function+'manifest=$1; mvp_required_checks "$2"', "bash", str(self.root / "manifest.json"), scenario], cwd=SCRIPT.parents[2], capture_output=True, text=True)
                self.assertEqual(shell.returncode, 0, shell.stderr)
                self.assertEqual(shell.stdout.split(), checks)
        self.assertIn("http-exposure-disclosed", MVP.required_checks(attempt, "mvp-subscription"))
        self.assertIn("no-certificate-or-renewal-resources", MVP.required_checks(attempt, "mvp-serving"))
        self.assertIn("outside-subscription-transport-preserved", MVP.required_checks(attempt, order[0]))
        with self.assertRaises(MVP.Refusal):
            MVP.required_checks(attempt, "mvp-renewal")

    def test_documented_template_preserves_checks_but_cannot_be_submitted(self):
        request, _ = self.scenario_files()
        procedure = SCRIPT.parents[2] / "docs/acceptance/mvp-live-acceptance.md"
        examples = re.findall(r"```sh\n(.*?)\n```", procedure.read_text(), re.DOTALL)
        templates = [example for example in examples
                     if "request=/root/sbxr-qualification-evidence/request.json" in example]
        self.assertEqual(len(templates), 1, "expected one documented observation template")
        draft = self.root / "draft.json"
        # Run the actual shell example, relocating only its live-host file paths.
        script = templates[0].replace("/root/sbxr-qualification-evidence/request.json",
                                      shlex.quote(str(request)))
        script = script.replace("/root/mvp-observation-draft.json", shlex.quote(str(draft)))
        result = subprocess.run(["bash", "-c", script], cwd=self.root,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(draft.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(draft.read_bytes()), {
            "scenario_id": "mvp-install", "started_at": None, "completed_at": None,
            "checks": [{"check": check, "observed_at": None, "result": None}
                       for check in MVP.SCENARIOS["mvp-install"]],
        })

        result = subprocess.run(self.command(request, draft), capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("observation start is not an RFC3339 UTC second", result.stderr)
        self.assertFalse((self.root / "facts.json").exists())

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

    def test_declared_response_wait_is_bound_to_manifest_and_original_budget(self):
        stamp=lambda t:t.strftime("%Y-%m-%dT%H:%M:%SZ")
        attempt=self.manifest["v3_attempt"]
        attempt.update(evidence_policy=MVP.HTTP_POLICY,karing_response_limit_seconds=3600,
                       attended_finish_by=stamp(self.now+dt.timedelta(hours=3)))
        attempt["required_scenarios"]=MVP.scenario_order(attempt)
        self.write("manifest.json",self.manifest)
        self.write("previous.json",[{"scenario_id":"mvp-install"},{"scenario_id":"mvp-subscription"}])
        request,observation=self.scenario_files("mvp-credentials")
        req=json.loads(request.read_bytes());obs=json.loads(observation.read_bytes())
        req.update(not_before=stamp(self.now-dt.timedelta(minutes=80)),deadline_unix=int(self.now.timestamp())-50*60,
                   karing_response_limit_seconds=3600,attended_finish_by=attempt["attended_finish_by"])
        obs.update(started_at=req["not_before"],karing_handoffs=[{
            "phase":"credential-refresh","prepared_at":stamp(self.now-dt.timedelta(minutes=79)),
            "notified_at":stamp(self.now-dt.timedelta(minutes=59)),"responded_at":obs["completed_at"]}])
        self.write("request.json",req);self.write("observation.json",obs)
        result=subprocess.run(self.command(request,observation),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        facts=json.loads((self.root/"facts.json").read_bytes())
        self.assertEqual(facts["detailed_evidence"]["scenarios"][-1]["karing_handoffs"],obs["karing_handoffs"])
        for name,change in [
            ("late",lambda r,o:o["karing_handoffs"][0].update(responded_at=stamp(self.now+dt.timedelta(minutes=2)))),
            ("pending",lambda r,o:o["karing_handoffs"][0].update(responded_at=None)),
            ("unsigned",lambda r,o:r.update(karing_response_limit_seconds=3601)),
            ("technical-overrun",lambda r,o:o["karing_handoffs"][0].update(responded_at=stamp(self.now-dt.timedelta(minutes=20)))),
        ]:
            r=json.loads(json.dumps(req));o=json.loads(json.dumps(obs));change(r,o)
            self.write("request.json",r);self.write("observation.json",o)
            result=subprocess.run(self.command(request,observation,name+".json"),capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0,result.stderr)
            self.assertFalse((self.root/(name+".json")).exists())

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
