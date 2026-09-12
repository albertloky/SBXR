import hashlib
import importlib.util
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
import types
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("test_final_evidence_module", HERE / "final-evidence.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def load(name, filename):
    found = importlib.util.spec_from_file_location(name, HERE / filename)
    loaded = importlib.util.module_from_spec(found)
    import sys
    sys.modules[name] = loaded
    found.loader.exec_module(loaded)
    return loaded


def populate_fixture(ctx):
    """Write a complete positive retained-source family into a real Context directory."""
    def parse(value): return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    def wire(value): return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    action = parse(ctx.state["action_started_at"])
    completed = parse(ctx.state["completed_at"])
    def at(seconds): return wire(action + timedelta(seconds=seconds))
    def write(name, value):
        raw = ctx.api.canonical(value)
        path = ctx.directory / name; path.write_bytes(raw); path.chmod(0o600)
        return raw
    def capture(name, helper, records, start=1, finish=None, event_offsets=None):
        finish = finish if finish is not None else max(start + len(records) + 1, 20)
        event_offsets = event_offsets or [start + index + 1 for index in range(len(records))]
        value = {"schema": "sbxr-v4-captured-source-v1", "scenario_id": ctx.scenario,
                 "qualification_manifest_sha256": ctx.manifest_sha, "request_sha256": ctx.request_sha,
                 "helper": helper, "started_at": at(start), "completed_at": at(finish), "exit_code": 0,
                 "events": [{"observed_at": at(event_offsets[index]), "record": record}
                            for index, record in enumerate(records)]}
        write(name, value)
    def refusal():
        value = {"schema": "sbxr-v4-held-removal-refusal-v1", "scenario_id": ctx.scenario,
                 "qualification_manifest_sha256": ctx.manifest_sha, "request_sha256": ctx.request_sha,
                 "owned_inventory_before_sha256": "d" * 64, "owned_inventory_after_sha256": "d" * 64,
                 "healthy_running": True, "completed_at": at(15), "action_number": 4,
                 "prepared_at": at(8), "code": "PROXY-INSTALLATION-ACTION-REFUSED",
                 "failed_check": "active operation", "removal_commitment_absent": True, "refused_at": at(12)}
        capture(ctx.scenario + "-removal-refusal.json", "removal-refusal", [value], 6, 18, [16])

    if ctx.scenario == "lifecycle-menu":
        outputs = {"19-first-frame.txt": b"1. Check\n2. Update\n3. Recover\n",
                   "19-check.txt": b"Software Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT\n",
                   "19-update.txt": b"Software Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT\n",
                   "19-recover.txt": b"Software Lifecycle: Ready\nNo recovery is available. If a change is in progress, wait for it to finish.\n"}
        for name, raw in outputs.items():
            path = ctx.directory / name; path.write_bytes(raw); path.chmod(0o600)
        value = {"action_completed_at": at(12), "action_started_at": at(2),
                 "check_output_sha256": hashlib.sha256(outputs["19-check.txt"]).hexdigest(),
                 "first_frame_sha256": hashlib.sha256(outputs["19-first-frame.txt"]).hexdigest(),
                 "inventory_before_and_after": "d" * 64,
                 "recover_output_sha256": hashlib.sha256(outputs["19-recover.txt"]).hexdigest(),
                 "schema": "sbxr-v4-lifecycle-menu-result-v1",
                 "update_output_sha256": hashlib.sha256(outputs["19-update.txt"]).hexdigest()}
        capture("19-lifecycle-menu.json", "19-lifecycle-menu.sh", [value], 1, 16, [13])
    elif ctx.scenario == "remove-certbot":
        held = {"state": "held", "child": {"boundary": "actual-image-exec-trap-before-target-code"},
                "recorder_pid": 41, "recorder_tick": 51, "attempt_id": "a" * 32,
                "receipt_sha256": "b" * 64, "egress_denied": True}
        final = {"state": "interrupted", "receipt_sha256": "c" * 64, "no_ca_egress": True}
        capture("20-managed.json", "managed-hold", [held, final], 2, 25, [3, 20]); refusal()
    elif ctx.scenario == "remove-writer":
        held = {"state": "boundary-held", "mode": "writer", "recorder_pid": 41, "process_tick": 51,
                "attempt_id": "a" * 32, "receipt_sha256": "b" * 64,
                "whole_host": {"lock_state": "unlocked"}, "writer": {"lock_state": "locked"},
                "admission": {"lock_state": "locked"}, "actual_boundary": {"boundary": "before-open"}}
        final = {"state": "completed", "receipt_sha256": "c" * 64, "no_ca_egress": True}
        capture("21-writer.json", "recorder-boundary", [held, final], 2, 25, [3, 20]); refusal()
    elif ctx.scenario == "remove-admission-race":
        held = {"state": "boundary-held", "mode": "admission", "writer": {"lock_state": "unlocked"},
                "admission": {"lock_state": "locked"}}
        refused = {"schema": "sbxr-v4-removal-admission-refusal-v1", "code": "PROXY-INSTALLATION-ACTION-REFUSED",
                   "removal_commitment_absent": True, "owned_inventory_before_sha256": "d" * 64,
                   "owned_inventory_after_sha256": "d" * 64, "refused_at": at(12)}
        final = {"state": "completed", "receipt_sha256": "c" * 64, "no_ca_egress": True}
        write("22-admission-held.json", held); write("22-removal-refusal.json", refused); write("22-admission-final.json", final)
        result = {"schema": "sbxr-v4-admission-race-operator-v1", "scenario": ctx.scenario,
                  "qualification_manifest_sha256": ctx.manifest_sha, "request_sha256": ctx.request_sha,
                  "prepared_public_removal": True, "actual_admission_boundary": True,
                  "removal_refused_before_commitment": True, "owned_resources_preserved": True,
                  "recorder_completed": True, "healthy_running": True, "completed_at": at(20)}
        capture("22-admission-race.json", "admission-race-operator", [result], 1, 25, [21])
    elif ctx.scenario == "remove-directory-lock":
        locks = [{"path": path, "device": 1, "inode": index, "mode": "0600", "uid": 0, "gid": 0,
                  "nlink": 1, "size": 0, "sha256": hashlib.sha256(b"").hexdigest(), "created": False}
                 for index, path in enumerate(("/etc/letsencrypt/.certbot.lock", "/var/lib/letsencrypt/.certbot.lock",
                                               "/var/log/letsencrypt/.certbot.lock"), 10)]
        capture("23-locks.json", "directory-locks",
                [{"schema": "sbxr-v4-certbot-directory-locks-v1", "pid": 41, "locks": locks},
                 {"schema": "sbxr-v4-certbot-directory-locks-released-v1", "pid": 41, "locks": locks}], 2, 25, [3, 20])
        refusal()
    elif ctx.scenario == "secret-containment":
        docs = {
            "protection": {"schema": "sbxr-v4-protection-result-v2", "protected_objects": 9, "preserved_objects": 4},
            "sandbox": {"schema": "sbxr-v3-sandbox-token-probe-v1", "protected_reads_refused": 2},
            "protected-open": {"schema": "sbxr-v4-protected-open-probe-v1", "protected_reads_refused": 2,
                               "objects": [{"path": "/a"}, {"path": "/b"}], "metadata_unchanged": True},
            "scan": {"schema": "sbxr-v4-secret-scan-result-v2", "external_surface_attested": True,
                     "external_client_cleanup_attested": True, "variants_absent": True,
                     "prohibited_patterns_absent": True,
                     "capture_files": {name: 1 for name in ("runner", "vps", "mac", "terminal", "workflow", "retained")}},
            "removal": {"schema": "sbxr-v4-inventory-removal-result-v1", "removed_paths": 2, "stopped_processes": 1},
            "cleanup": {"schema": "sbxr-v4-cleanup-result-v2", "cleanup_paths_absent": 2, "cleanup_processes_absent": 1},
        }
        raws = {name: write("24-" + name + ".json", value) for name, value in docs.items()}
        result = {"schema": "sbxr-v4-secret-containment-result-v1", "action_started_at": at(2), "action_completed_at": at(15)}
        result.update({name.replace("-", "_") + "_sha256": hashlib.sha256(raw).hexdigest() for name, raw in raws.items()})
        capture("24-secret-containment.json", "24-secret-containment.sh", [result], 1, 20, [16])
    elif ctx.scenario == "karing-final":
        package = ctx.manifest["v3_attempt"]["packages"]["karing"]
        settings = {name: str(index) * 64 for index, name in enumerate(("application_settings_sha256", "dns_sha256",
            "profile_list_sha256", "routing_sha256", "selected_server_sha256", "tun_sha256"), 1)}
        outcomes = {"initial-settings":"captured","profile-imported":"one-node-matched","initial-node-latency":"fresh-success",
            "manual-same-link-refresh":"advanced-same-link","due-five-minute-auto-refresh":"genuinely-due-and-advanced",
            "auto-refresh-disabled":"disabled-before-rotation","server-old-credential-refused":"outside-target-healthy-and-server-refused",
            "revoked-node-latency-refused":"fresh-failure-with-old-cached-uuid","same-link-replacement-refresh":"uuid-only-replacement",
            "replacement-node-latency":"fresh-success","https-outage-refresh-refused":"cached-node-preserved",
            "https-outage-node-latency":"fresh-success","same-link-recovery-refresh":"advanced-same-link",
            "complete-removal":"software-lifecycle-complete-removal-completed","outside-access-refused":"old-new-proxy-and-link-refused",
            "removed-node-latency-refused":"fresh-failure","full-owned-absence":"proved",
            "test-profile-cleanup":"profile-and-temporary-secrets-removed","final-settings":"equal-initial"}
        kspec = importlib.util.spec_from_file_location("populate_karing", HERE / "karing-evidence.py")
        karing = importlib.util.module_from_spec(kspec); kspec.loader.exec_module(karing)
        offsets = [2, 5, 10, 20, 330] + list(range(340, 340 + 14 * 10, 10))
        native_names = ("synthetic-karing-native-01.png", "synthetic-karing-native-02.mov")
        native_artifacts = []
        for index, name in enumerate(native_names, 1):
            raw = ((b"\x89PNG\r\n\x1a\n" if name.endswith(".png") else b"\x00\x00\x00\x18ftypqt  ") +
                   f"synthetic final Karing native fixture {index}\n".encode())
            path = ctx.directory / name; path.write_bytes(raw); path.chmod(0o600)
            native_artifacts.append({"media_type":"image/png" if name.endswith(".png") else "video/quicktime",
                                     "name":name,"sha256":hashlib.sha256(raw).hexdigest(),"size":len(raw)})
        events = [{"kind": kind, "observed_at": at(offsets[index]), "outcome": outcomes[kind],
                   "native_artifacts":[native_names[index % len(native_names)]],
                   "profile_id_sha256": "b" * 64, "selected_server_sha256": settings["selected_server_sha256"]}
                  for index, kind in enumerate(karing.EVENTS)]
        version = package.get("version", "1.2.24.2709").split(".")
        short_version = ".".join(version[:3])
        build_version = version[3] if len(version) > 3 else "1"
        native = {"application_receipt":{"build_version":build_version,"bundle_identifier":"com.nebula.karing",
                    "executable_sha256":"d"*64,"short_version":short_version},"artifacts":native_artifacts,
                  "capture_method":"owner-operated-native-macos-capture","captured_at":at(475),
                  "package_receipt":{"name":"synthetic-karing.dmg","sha256":package["sha256"],"size":package.get("size")},
                  "qualification_manifest_sha256":ctx.manifest_sha,"request_sha256":ctx.request_sha,
                  "scenario_id":ctx.scenario,"schema":"sbxr-v4-karing-native-capture-v1"}
        native_raw = write("25-karing-native-capture.json", native)
        reviewed = {"capture_method": "owner-reviewed-manual-karing-ui", "events": events, "initial": settings,
                    "final": dict(settings), "native_capture_sha256":hashlib.sha256(native_raw).hexdigest(), "package": package,
                    "node": {"display_name":"SBXR","initial_nonsecret_fields_sha256":"c"*64,"profile_id_sha256":"b"*64,
                             "remote_profile_count":1,"replacement_nonsecret_fields_sha256":"c"*64,"server_count":1,"type":"vless-reality"},
                    "qualification_manifest_sha256":ctx.manifest_sha,"request_sha256":ctx.request_sha,
                    "scenario_id":ctx.scenario,"schema":"sbxr-v4-karing-reviewed-capture-v1"}
        reviewed_raw = write("25-karing-reviewed-input.json", reviewed)
        result = {"schema":"sbxr-v4-karing-evidence-result-v1","reviewed_capture_sha256":hashlib.sha256(reviewed_raw).hexdigest(),
                  "native_capture_sha256":hashlib.sha256(native_raw).hexdigest(),
                  "started_at":events[0]["observed_at"],"completed_at":events[-1]["observed_at"],
                  "event_timestamps":{event["kind"]:event["observed_at"] for event in events},
                  "native_artifact_sha256":{row["name"]:row["sha256"] for row in native_artifacts},
                  "package_sha256":package["sha256"],"profile_id_sha256":"b"*64}
        capture("25-karing-evidence.json", "karing-evidence", [result], 480, 500)
    else:
        raise AssertionError(ctx.scenario)


class Anchor:
    def __init__(self, source, event): self.source, self.event = source, event


class Rule:
    def __init__(self, check, required_sources, not_before, not_after):
        self.check, self.required_sources = check, required_sources
        self.not_before, self.not_after = not_before, not_after


class Refusal(ValueError): pass


class API:
    Refusal = Refusal
    def exact(self, value, keys, label):
        if not isinstance(value, dict) or set(value) != set(keys): raise Refusal(label)
        return value
    def digest(self, raw): return hashlib.sha256(raw).hexdigest()
    def private_bytes(self, path, label): return self.files[path.name]
    def before(self, left, right): return left <= right


class Context:
    def __init__(self):
        self.api, self.scenario = API(), "lifecycle-menu"
        self.files = {}
        self.api.files = self.files
        self.directory = Path("/fixture")
        self.state = {"action_started_at": "2026-09-11T00:00:00Z",
                      "action_completed_at": "2026-09-11T00:00:20Z"}
    def read(self, name):
        raw = self.files[name]
        return None, raw, raw
    def capture(self, name, helper): return self.capture_doc, self.capture_raw
    def source(self, name, raw, events): return (name, raw, events)


class FinalEvidenceTest(unittest.TestCase):
    def test_rules_are_full_go_order_and_exclude_automated_or_omitted_checks(self):
        timing = types.SimpleNamespace(ObservationRule=Rule, Anchor=Anchor, PROOF_SOURCE="$proof",
            EvidenceTimingRefusal=Refusal, later_common_rules=lambda: tuple(Rule(name, (), (), ()) for name in [
                "fresh-disposable-vps-preflight", "unchanged-candidate-bytes", "initial-state-proved",
                "boundary-observed", "final-state-proved", "original-ssh-continuity",
                "capture-coverage-complete", "exact-secrets-absent", "prohibited-patterns-absent",
                "supported-effective-route-inspected"]))
        lifecycle = [rule.check for rule in module.rules(timing, "lifecycle-menu")]
        self.assertNotIn("explicit-confirmation", lifecycle)
        self.assertNotIn("clean-install-target-refused", lifecycle)
        karing = [rule.check for rule in module.rules(timing, "karing-final")]
        for omitted in ("direct-and-proxied-traffic", "old-established-session-terminated",
                        "traffic-restored", "direct-refresh-correction-or-confirmed-fallback"):
            self.assertNotIn(omitted, karing)
        self.assertEqual(karing[-4:], ["fresh-initial-node-latency", "fresh-revoked-identity-latency-refused",
                                       "same-link-refresh-before-replacement-latency", "fresh-replacement-node-latency"])

    def test_lifecycle_requires_retained_real_public_outputs(self):
        ctx = Context()
        outputs = {
            "19-first-frame.txt": b"1 Check\n2 Update\n3 Recover\n",
            "19-check.txt": b"Software Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT\n",
            "19-update.txt": b"Software Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT\n",
            "19-recover.txt": b"Software Lifecycle: Ready\nNo recovery is available. If a change is in progress, wait for it to finish.\n",
        }
        ctx.files.update(outputs)
        result = {"action_completed_at": "2026-09-11T00:00:10Z", "action_started_at": "2026-09-11T00:00:01Z",
                  "check_output_sha256": hashlib.sha256(outputs["19-check.txt"]).hexdigest(),
                  "first_frame_sha256": hashlib.sha256(outputs["19-first-frame.txt"]).hexdigest(),
                  "inventory_before_and_after": "a" * 64,
                  "recover_output_sha256": hashlib.sha256(outputs["19-recover.txt"]).hexdigest(),
                  "schema": "sbxr-v4-lifecycle-menu-result-v1",
                  "update_output_sha256": hashlib.sha256(outputs["19-update.txt"]).hexdigest()}
        ctx.capture_doc = {"exit_code": 0, "started_at": "2026-09-11T00:00:00Z",
                           "completed_at": "2026-09-11T00:00:12Z",
                           "events": [{"observed_at": "2026-09-11T00:00:11Z", "record": result}]}
        ctx.capture_raw = json.dumps(ctx.capture_doc).encode()
        self.assertIn("lifecycle", module.sources(ctx))
        fabricated = b"Software Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-UPDATE-ALREADY-CURRENT\n"
        ctx.files["19-update.txt"] = fabricated
        result["update_output_sha256"] = hashlib.sha256(fabricated).hexdigest()
        with self.assertRaisesRegex(Refusal, "actual public outcomes differ"):
            module.sources(ctx)
        ctx.files["19-update.txt"] = outputs["19-update.txt"]
        result["update_output_sha256"] = hashlib.sha256(outputs["19-update.txt"]).hexdigest()
        del ctx.files["19-check.txt"]
        with self.assertRaises(KeyError): module.sources(ctx)

    def test_lifecycle_refuses_tampered_output_and_action_before_capture(self):
        ctx = Context()
        outputs = {"19-first-frame.txt": b"1. Check\n2. Update\n3. Recover\n",
                   "19-check.txt": b"Software Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT\n",
                   "19-update.txt": b"Software Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT\n",
                   "19-recover.txt": b"Software Lifecycle: Ready\nNo recovery is available.\n"}
        ctx.files.update(outputs)
        result = {"action_completed_at":"2026-09-11T00:00:10Z","action_started_at":"2026-09-11T00:00:01Z",
            "check_output_sha256":hashlib.sha256(outputs["19-check.txt"]).hexdigest(),
            "first_frame_sha256":hashlib.sha256(outputs["19-first-frame.txt"]).hexdigest(),"inventory_before_and_after":"a"*64,
            "recover_output_sha256":hashlib.sha256(outputs["19-recover.txt"]).hexdigest(),"schema":"sbxr-v4-lifecycle-menu-result-v1",
            "update_output_sha256":hashlib.sha256(outputs["19-update.txt"]).hexdigest()}
        ctx.capture_doc = {"exit_code":0,"started_at":"2026-09-11T00:00:02Z","completed_at":"2026-09-11T00:00:12Z",
                           "events":[{"observed_at":"2026-09-11T00:00:11Z","record":result}]}
        ctx.capture_raw = b"capture"
        with self.assertRaisesRegex(Refusal, "outside actual capture boundary"):
            module.sources(ctx)
        ctx.capture_doc["started_at"] = "2026-09-11T00:00:00Z"
        ctx.files["19-check.txt"] += b"tampered"
        with self.assertRaisesRegex(Refusal, "retained public output bytes differ"):
            module.sources(ctx)

    def test_refuses_truthy_but_unstructured_admission_summary(self):
        ctx = Context(); ctx.scenario = "remove-admission-race"
        ctx.manifest_sha, ctx.request_sha = "a" * 64, "b" * 64
        ctx.capture_doc = {"exit_code": 0, "started_at": "2026-09-11T00:00:00Z",
                           "completed_at": "2026-09-11T00:00:12Z",
                           "events": [{"observed_at": "2026-09-11T00:00:11Z",
            "record": {"schema": "sbxr-v4-admission-race-operator-v1", "scenario": ctx.scenario,
                       "qualification_manifest_sha256": ctx.manifest_sha, "request_sha256": ctx.request_sha,
                       "prepared_public_removal": "yes"}}]}
        ctx.capture_raw = b"capture"
        with self.assertRaisesRegex(Refusal, "aggregate actual outcome"):
            module.sources(ctx)

    def test_karing_revalidates_tampered_reviewed_bytes_not_just_wrapper_hash(self):
        api = load("test_final_real_api", "assemble-evidence.py")
        source_api = load("test_final_real_sources", "scenario-sources.py")
        base = int(time.time()) - 10
        stamp = lambda value: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))
        package = {"architecture":"macos-arm64","name":"karing","repository":"https://github.com/KaringX/karing",
                   "sha256":"a"*64,"size":100,"version":"1.2.24.2709"}
        manifest = {"v3_attempt":{"packages":{"karing":package},"karing_limit_seconds":7200}}
        manifest_raw = api.canonical(manifest); manifest_sha = api.digest(manifest_raw)
        request = {"not_before":stamp(base-1),"deadline_unix":base+7200,"scenario_id":"karing-final",
                   "scenario_limit_seconds":7200,"qualification_manifest_sha256":manifest_sha}
        request_raw = api.canonical(request); request_sha = api.digest(request_raw)
        state = {"schema":"sbxr-v4-scenario-entry-v1","scenario_id":"karing-final",
                 "qualification_manifest_sha256":manifest_sha,"request_sha256":request_sha,
                 "started_at":stamp(base),"entry_started_at":stamp(base+1),"action_started_at":stamp(base+2),
                 "action_completed_at":stamp(base+602),"completed_at":stamp(base+650)}
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder); directory.chmod(0o700)
            ctx = source_api.Context(api,"karing-final",manifest,manifest_raw,manifest_sha,
                                     request,request_raw,request_sha,state,directory)
            populate_fixture(ctx)
            module.sources(ctx)
            reviewed_path = directory / "25-karing-reviewed-input.json"
            reviewed = json.loads(reviewed_path.read_bytes())
            reviewed["events"][2]["outcome"] = "passed"
            reviewed_raw = api.canonical(reviewed); reviewed_path.write_bytes(reviewed_raw)
            wrapper_path = directory / "25-karing-evidence.json"
            wrapper = json.loads(wrapper_path.read_bytes())
            wrapper["events"][0]["record"]["reviewed_capture_sha256"] = api.digest(reviewed_raw)
            wrapper_path.write_bytes(api.canonical(wrapper))
            with self.assertRaisesRegex(api.Refusal, "reviewed manual capture validation refused"):
                module.sources(ctx)

    def test_karing_refuses_missing_or_tampered_native_artifact(self):
        api = load("test_final_native_api", "assemble-evidence.py")
        source_api = load("test_final_native_sources", "scenario-sources.py")
        base = int(time.time()) - 10
        stamp = lambda value: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))
        package = {"architecture":"macos-arm64","name":"karing","repository":"https://github.com/KaringX/karing",
                   "sha256":"a"*64,"size":100,"version":"1.2.24.2709"}
        manifest = {"v3_attempt":{"packages":{"karing":package},"karing_limit_seconds":7200}}
        manifest_raw = api.canonical(manifest); manifest_sha = api.digest(manifest_raw)
        request = {"not_before":stamp(base-1),"deadline_unix":base+7200,"scenario_id":"karing-final",
                   "scenario_limit_seconds":7200,"qualification_manifest_sha256":manifest_sha}
        request_raw = api.canonical(request); request_sha = api.digest(request_raw)
        state = {"schema":"sbxr-v4-scenario-entry-v1","scenario_id":"karing-final",
                 "qualification_manifest_sha256":manifest_sha,"request_sha256":request_sha,
                 "started_at":stamp(base),"entry_started_at":stamp(base+1),"action_started_at":stamp(base+2),
                 "action_completed_at":stamp(base+602),"completed_at":stamp(base+650)}
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder); directory.chmod(0o700)
            ctx = source_api.Context(api,"karing-final",manifest,manifest_raw,manifest_sha,
                                     request,request_raw,request_sha,state,directory)
            populate_fixture(ctx)
            native = json.loads((directory / "25-karing-native-capture.json").read_bytes())
            artifact = directory / native["artifacts"][0]["name"]
            artifact.unlink()
            with self.assertRaisesRegex(api.Refusal, "reviewed manual capture validation refused"):
                module.sources(ctx)
            artifact.write_bytes(b"tampered"); artifact.chmod(0o600)
            with self.assertRaisesRegex(api.Refusal, "reviewed manual capture validation refused"):
                module.sources(ctx)


if __name__ == "__main__":
    unittest.main()
