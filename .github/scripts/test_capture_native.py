#!/usr/bin/env python3
"""Run the real capture/consumer CLI on public files; never operate Karing."""
import copy
import base64
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import unittest


SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("public_native_fixtures", SCRIPTS / "test_native_receipts.py")
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
SPEC = importlib.util.spec_from_file_location("mvp_evidence", SCRIPTS / "v3-mvp-evidence.py")
MVP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MVP)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def record(path):
    raw = path.read_bytes()
    return {"source_file": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


class NativeCaptureTests(unittest.TestCase):
    def setUp(self):
        self.case = FIXTURES.NativeReadbackTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root = self.case.root
        self.final = self.root / "final"
        (self.final / "operator-source").mkdir(parents=True)
        self.helper = self.final / "operator-source/native-receipts.py"
        self.caller = self.final / "capture-native.py"
        shutil.copyfile(SCRIPTS / "native-receipts.py", self.helper)
        shutil.copyfile(SCRIPTS / "capture-native.py", self.caller)
        self.helper.chmod(0o600)
        self.caller.chmod(0o600)
        self.settings = {"window": {"x": 1, "y": 2, "width": 900},
                         "dns": {"client_subnet_latest_update": "", "client_subnet": "unchanged"},
                         "routing": {"mode": "unchanged"}, "tun": {"enabled": True}}
        self.write("karing_setting.json", self.settings)
        self.case.write("Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.nebula.karing",
                        "CFBundleExecutable": "Karing", "CFBundleShortVersionString": "1.2.25",
                        "CFBundleVersion": "2802"}))
        self.case.write("Karing", b"PUBLIC FIXTURE APP\n")
        (self.root / "Info.plist").chmod(0o644)
        (self.root / "Karing").chmod(0o755)
        zone = self.root / "zoneinfo/Etc/UTC"
        zone.parent.mkdir(parents=True)
        zone.write_bytes(Path("/usr/share/zoneinfo/Etc/UTC").read_bytes())
        zone.chmod(0o644)
        self.original = {"groupid": "PUBLIC-original", "remark": "Original", "urlOrPath": "",
                         "servers": [{"tag": "Original node"}]}
        self.baseline = {"items": [{"groupid": "custom", "remark": "custom", "urlOrPath": "",
                                     "servers": []}, self.original], "non_item": "unchanged"}
        self.write("karing_subscribe_use.json", {"select_default": "Original node"})
        self.write(self.case.native_store.name, self.baseline)
        spec = importlib.util.spec_from_file_location("fixture_helper", self.helper)
        n = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(n)
        self.paths(n)
        connection = {"configuration": "Original", "node": "Original node", "connected": True, "tun_enabled": True}
        self.inputs = {"source_commit": "a" * 40, "candidate": {"tag": "v3.1.999", "sequence": 999},
                       "canonical_helper": record(self.helper), "settings_binding": n.settings_binding(),
                       "settings_baseline": record(self.write("settings-baseline.private", n.settings_readback(n.settings_binding()))),
                       "native_timezone": n.native_timezone_binding(),
                       "native_tzif": record(self.case.write("timezone.private.tzif", zone.read_bytes())),
                       "original_store_baseline": record(self.write("store-baseline.private", self.baseline)),
                       "original_store_observed_at": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat(),
                       "selected_connection_baseline": record(self.write("connection-baseline.private", {"connection": connection})),
                       "selected_use_baseline": record(self.root / "karing_subscribe_use.json"),
                       "profile_remark": self.case.profile["remark"]}
        self.inputs_path = self.final / "native-inputs.json"
        self.write(self.inputs_path, self.inputs)
        attempt, _, _ = self.case.combined()
        self.manifest = {"schema": "sbxr-qualification-manifest-v3", "workflow": {"commit": "a" * 40},
                         "releases": [{"tag": "v3.1.999", "sequence": 999, "commit": "a" * 40,
                                       "release_identity": {"tag": "v3.1.999", "commit": "a" * 40}}],
                         "v3_attempt": {**attempt, "attempt_id": "PUBLIC-FIXTURE-ONLY"}}
        self.write("qualification-manifest.json", self.manifest)

    def paths(self, n):
        n.NATIVE_SUBSCRIPTION_SOURCE = self.case.native_store
        n.NATIVE_SETTINGS_SOURCE = self.root / "karing_setting.json"
        n.NATIVE_APP_INFO = self.root / "Info.plist"
        n.NATIVE_APP_EXECUTABLE = self.root / "Karing"
        n.NATIVE_TIMEZONE_SOURCE = self.root / "zoneinfo/Etc/UTC"

    def write(self, name, value):
        path = self.root / name
        path.write_bytes(canonical(value))
        path.chmod(0o600)
        return path

    def install(self, phase, combined=True):
        attempt, profile, vmess = self.case.combined()
        if not combined:
            profile = copy.deepcopy(self.case.profile)
            self.manifest["v3_attempt"].pop("proxy_profile", None)
            self.write("qualification-manifest.json", self.manifest)
        wire = self.case.combined_wire(vmess) if combined else self.case.wire
        if phase == "m3-identity":
            replacement = "22345678-1234-4234-8234-123456789abc"
            for node in profile["servers"]:
                node["uuid"] = replacement
            vmess["id"] = replacement
            wire = self.case.wire.replace(b"12345678-1234-4234-8234-123456789abc", replacement.encode())
            if combined:
                wire += b"vmess://" + base64.b64encode(canonical(vmess)) + b"\n"
        if phase == "m3-link":
            profile["urlOrPath"] += "-replacement"
        store = copy.deepcopy(self.baseline)
        if phase != "m5":
            store["items"].append(profile)
        self.write(self.case.native_store.name, store)
        self.case.write(phase + "-expected-url.private", profile["urlOrPath"].encode())
        self.case.write(phase + "-expected-wire.private", wire)
        scenario = "mvp-credentials" if phase.startswith("m3-") else {"m2": "mvp-subscription", "m5": "mvp-removal"}[phase]
        label = "m3" if phase.startswith("m3-") else phase
        now = dt.datetime.now(dt.timezone.utc)
        request = {"scenario_id": scenario,
                   "qualification_manifest_sha256": hashlib.sha256((self.root / "qualification-manifest.json").read_bytes()).hexdigest(),
                   "not_before": (now - dt.timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "deadline_unix": int(now.timestamp()) + 300,
                   "scenario_limit_seconds": 7200 if phase == "m2" else 1800,
                   "required_checks": MVP.required_checks(self.manifest["v3_attempt"], scenario)}
        self.write(label + "-request.private", request)

    def run_cli(self, action, phase, connected="true", tun="true"):
        # Only actual native/app paths move to public fixture files. Both caller
        # and canonical helper execute unchanged in every fresh subprocess.
        driver = '''import importlib.util,pathlib,sys
p=pathlib.Path(sys.argv[1]);s=importlib.util.spec_from_file_location('capture',p)
c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
inputs=pathlib.Path(sys.argv[3]);root=inputs.parent.parent
n=c.load_native(inputs)
n.NATIVE_SUBSCRIPTION_SOURCE=root/'native-store.json'
n.NATIVE_SETTINGS_SOURCE=root/'karing_setting.json'
n.NATIVE_APP_INFO=root/'Info.plist';n.NATIVE_APP_EXECUTABLE=root/'Karing'
n.NATIVE_TIMEZONE_SOURCE=root/'zoneinfo/Etc/UTC'
c.load_native=lambda _:n
raise SystemExit(c.main([sys.argv[2],'--inputs',str(inputs),'--phase',sys.argv[4],
                        '--connected',sys.argv[5],'--tun-enabled',sys.argv[6]]))
'''
        return subprocess.run([sys.executable, "-B", "-c", driver, str(self.caller), action,
                               str(self.inputs_path), phase, connected, tun],
                              capture_output=True, text=True)

    def require_pass(self, action, phase):
        result = self.run_cli(action, phase)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["journey_checks_recorded"])
        self.assertNotIn(self.case.url, result.stdout + result.stderr)

    def test_subprocess_capture_and_consumer_for_all_native_phases(self):
        for phase in ("baseline-check", "m2", "m3-identity", "m3-link", "m5"):
            if phase != "baseline-check":
                self.install(phase)
            self.require_pass("capture", phase)
            self.require_pass("verify", phase)
            result_path = self.root / (phase + "-native-capture-result.private")
            self.assertEqual(result_path.stat().st_mode & 0o777, 0o600)
            data = json.loads(result_path.read_bytes())
            self.assertNotIn("latency_ms", data["facts"])
            self.assertEqual(data["scenario"], None if phase == "baseline-check" else
                             "mvp-credentials" if phase.startswith("m3-") else
                             {"m2": "mvp-subscription", "m5": "mvp-removal"}[phase])
        self.assertNotEqual(self.run_cli("capture", "m5").returncode, 0)

    def test_default_one_node_flow_still_works(self):
        self.install("m2", combined=False)
        self.require_pass("capture", "m2")
        self.require_pass("verify", "m2")

    def refuses_mutation(self, name, mutate):
        self.install("m2")
        self.require_pass("capture", "m2")
        changed = json.loads((self.root / name).read_bytes())
        mutate(changed)
        self.write(name, changed)
        self.assertNotEqual(self.run_cli("verify", "m2").returncode, 0)

    def test_consumer_rejects_changed_native_source(self):
        self.refuses_mutation(self.case.native_store.name, lambda v: v.update(non_item="changed"))

    def test_consumer_rejects_changed_selected_use(self):
        self.refuses_mutation("karing_subscribe_use.json", lambda v: v.update(select_default="test node"))

    def test_consumer_rejects_changed_routing(self):
        self.refuses_mutation("karing_setting.json", lambda v: v["routing"].update(mode="changed"))

    def test_consumer_rejects_changed_request(self):
        self.refuses_mutation("m2-request.private", lambda v: v.update(scenario_id="mvp-removal"))

    def test_consumer_rejects_changed_profile_policy(self):
        self.refuses_mutation("qualification-manifest.json", lambda v: v["v3_attempt"].update(proxy_profile="unknown"))

    def test_consumer_rejects_receipt_selected_candidate(self):
        self.refuses_mutation("m2-native-capture-result.private", lambda v: v["authority"].update(attempt_id="other"))

    def test_consumer_rejects_stale_observation(self):
        self.refuses_mutation("m2-native-capture-result.private", lambda v: v.update(observed_at="2000-01-01T00:00:00Z"))

    def test_consumer_rejects_changed_deadline(self):
        self.refuses_mutation("m2-request.private", lambda v: v.update(deadline_unix=0))

    def test_consumer_rejects_incomplete_capture_inventory(self):
        self.refuses_mutation("m2-native-capture-result.private", lambda v: v.update(captures={}))

    def test_changed_app_identity_refuses_before_native_capture(self):
        self.install("m2")
        info = plistlib.loads((self.root / "Info.plist").read_bytes())
        info["CFBundleVersion"] = "other"
        (self.root / "Info.plist").write_bytes(plistlib.dumps(info))
        self.assertNotEqual(self.run_cli("capture", "m2").returncode, 0)
        self.assertFalse((self.root / "m2-native-store.private").exists())

    def test_preservation_failure_retains_private_audit_without_passing_result(self):
        self.install("m2")
        store = json.loads(self.case.native_store.read_bytes())
        store["items"][1]["servers"][0]["tag"] = "changed original"
        self.write(self.case.native_store.name, store)
        self.assertNotEqual(self.run_cli("capture", "m2").returncode, 0)
        audit = self.root / "m2-original-profiles-audit.private"
        self.assertFalse(json.loads(audit.read_bytes())["passed"])
        self.assertEqual(audit.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.root / "m2-native-capture-result.private").exists())

    def test_verified_capture_does_not_complete_the_existing_recorder(self):
        self.install("m2")
        self.require_pass("capture", "m2")
        self.require_pass("verify", "m2")
        command = [sys.executable, "-B", str(SCRIPTS / "mvp-observe.py")]
        args = ["--request", str(self.root / "m2-request.private"),
                "--draft", str(self.root / "recorder-draft.private")]
        started = subprocess.run(command + ["start"] + args, capture_output=True, text=True)
        self.assertEqual(started.returncode, 0, started.stderr)
        output = self.root / "observation.json"
        finished = subprocess.run(command + ["finish"] + args + ["--output", str(output)],
                                  capture_output=True, text=True)
        self.assertNotEqual(finished.returncode, 0)
        self.assertFalse(output.exists(), "Native structure must not become a live journey pass")

    def test_attended_capture_retains_existing_recorder_timing_authority(self):
        self.install("m2")
        now = dt.datetime.now(dt.timezone.utc)
        finish_by = (now + dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.manifest["v3_attempt"].update(karing_response_limit_seconds=3600, attended_finish_by=finish_by)
        self.write("qualification-manifest.json", self.manifest)
        request = json.loads((self.root / "m2-request.private").read_bytes())
        request.update(qualification_manifest_sha256=hashlib.sha256((self.root / "qualification-manifest.json").read_bytes()).hexdigest(),
                       deadline_unix=int(now.timestamp()) - 1, karing_response_limit_seconds=3600,
                       attended_finish_by=finish_by)
        self.write("m2-request.private", request)
        # This captures native state only. Actual pauses and effective technical
        # deadlines remain checked by the unchanged recorder and collector.
        self.require_pass("capture", "m2")
        self.require_pass("verify", "m2")

    def test_consumer_requires_actual_connected_and_tun_observations(self):
        self.install("m2")
        self.require_pass("capture", "m2")
        self.assertNotEqual(self.run_cli("verify", "m2", connected="false").returncode, 0)
        self.assertNotEqual(self.run_cli("verify", "m2", tun="false").returncode, 0)

    def test_unknown_profile_refuses_before_capture_and_errors_are_secret_safe(self):
        self.install("m2")
        self.manifest["v3_attempt"]["proxy_profile"] = self.case.url
        self.write("qualification-manifest.json", self.manifest)
        result = self.run_cli("capture", "m2")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(self.case.url, result.stdout + result.stderr)
        self.assertFalse((self.root / "m2-native-store.private").exists())


if __name__ == "__main__":
    unittest.main()
