import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import time
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("test_karing_evidence_module", HERE / "karing-evidence.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def stamp(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


class KaringEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.native_root = Path(self.temporary.name)
        self.native_root.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self):
        base = 1_800_000_000
        package = {"architecture": "macos-arm64", "name": "karing",
                   "repository": "https://github.com/KaringX/karing", "sha256": "a" * 64,
                   "size": 123, "version": "1.2.24.2709"}
        manifest = {"v3_attempt": {"packages": {"karing": package}, "karing_limit_seconds": 7200}}
        manifest_raw = canon(manifest)
        request = {"not_before": stamp(base), "deadline_unix": base + 7200,
                   "scenario_limit_seconds": 7200,
                   "scenario_id": "karing-final",
                   "qualification_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}
        request_raw = canon(request)
        settings = {name: str(index) * 64 for index, name in enumerate(
            ("application_settings_sha256", "dns_sha256", "profile_list_sha256",
             "routing_sha256", "selected_server_sha256", "tun_sha256"), 1)}
        outcomes = {
            "initial-settings": "captured", "profile-imported": "one-node-matched",
            "initial-node-latency": "fresh-success", "manual-same-link-refresh": "advanced-same-link",
            "due-five-minute-auto-refresh": "genuinely-due-and-advanced", "auto-refresh-disabled": "disabled-before-rotation",
            "server-old-credential-refused": "outside-target-healthy-and-server-refused",
            "revoked-node-latency-refused": "fresh-failure-with-old-cached-uuid",
            "same-link-replacement-refresh": "uuid-only-replacement", "replacement-node-latency": "fresh-success",
            "https-outage-refresh-refused": "cached-node-preserved", "https-outage-node-latency": "fresh-success",
            "same-link-recovery-refresh": "advanced-same-link", "complete-removal": "software-lifecycle-complete-removal-completed",
            "outside-access-refused": "old-new-proxy-and-link-refused", "removed-node-latency-refused": "fresh-failure",
            "full-owned-absence": "proved", "test-profile-cleanup": "profile-and-temporary-secrets-removed",
            "final-settings": "equal-initial",
        }
        events = []
        artifact_names = ("synthetic-karing-capture-01.png", "synthetic-karing-capture-02.mov")
        artifact_rows = []
        for index, name in enumerate(artifact_names, 1):
            raw = ((b"\x89PNG\r\n\x1a\n" if name.endswith(".png") else b"\x00\x00\x00\x18ftypqt  ") +
                   f"synthetic native fixture {index}\n".encode())
            path = self.native_root / name
            path.write_bytes(raw); path.chmod(0o600)
            artifact_rows.append({"media_type": "image/png" if name.endswith(".png") else "video/quicktime",
                                  "name": name, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)})
        for index, kind in enumerate(module.EVENTS):
            offset = index * 30
            if kind == "due-five-minute-auto-refresh": offset = 390
            if index > 4: offset = 390 + (index - 4) * 30
            events.append({"kind": kind, "observed_at": stamp(base + offset), "outcome": outcomes[kind],
                           "native_artifacts": [artifact_names[index % len(artifact_names)]],
                           "profile_id_sha256": "b" * 64, "selected_server_sha256": settings["selected_server_sha256"]})
        native = {"application_receipt": {"build_version": "2709", "bundle_identifier": "com.nebula.karing",
                                           "executable_sha256": "d" * 64, "short_version": "1.2.24"},
                  "artifacts": artifact_rows, "capture_method": "owner-operated-native-macos-capture",
                  "captured_at": stamp(base + 900), "package_receipt": {"name": "synthetic-karing.dmg",
                    "sha256": package["sha256"], "size": package["size"]},
                  "qualification_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                  "request_sha256": hashlib.sha256(request_raw).hexdigest(), "scenario_id": "karing-final",
                  "schema": module.NATIVE_SCHEMA}
        native_raw = canon(native)
        doc = {"capture_method": "owner-reviewed-manual-karing-ui", "events": events,
               "initial": settings, "final": copy.deepcopy(settings), "package": package,
               "native_capture_sha256": hashlib.sha256(native_raw).hexdigest(),
               "node": {"display_name": "SBXR", "initial_nonsecret_fields_sha256": "c" * 64,
                        "profile_id_sha256": "b" * 64, "remote_profile_count": 1,
                        "replacement_nonsecret_fields_sha256": "c" * 64, "server_count": 1,
                        "type": "vless-reality"},
               "qualification_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
               "request_sha256": hashlib.sha256(request_raw).hexdigest(), "scenario_id": "karing-final",
               "schema": module.SCHEMA}
        return doc, manifest, manifest_raw, request, request_raw, native, native_raw

    def validate(self, fixture):
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = fixture
        return module.validate(doc, canon(doc), manifest, manifest_raw, request, request_raw,
                               native, native_raw, self.native_root)

    def test_accepts_exact_fresh_reviewed_manual_capture(self):
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = self.fixture()
        result = self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))
        self.assertEqual(result["schema"], module.RESULT_SCHEMA)
        self.assertEqual(result["event_timestamps"]["initial-node-latency"], doc["events"][2]["observed_at"])

    def test_refuses_not_genuinely_due_automatic_refresh(self):
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = self.fixture()
        doc["events"][4]["observed_at"] = stamp(1_800_000_000 + 150)
        with self.assertRaisesRegex(module.Refusal, "not genuinely five-minute due"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))

    def test_refuses_fixture_label_or_wrong_signed_package(self):
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = self.fixture()
        doc["capture_method"] = "model-row-fixture"
        with self.assertRaisesRegex(module.Refusal, "actual manual Karing capture"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = self.fixture()
        doc["package"] = dict(doc["package"], sha256="d" * 64)
        with self.assertRaisesRegex(module.Refusal, "signed package"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))

    def test_refuses_selected_server_or_settings_change(self):
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = self.fixture()
        doc["final"]["tun_sha256"] = "e" * 64
        with self.assertRaisesRegex(module.Refusal, "settings changed"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))

    def test_refuses_missing_or_reordered_final_ui_events(self):
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = self.fixture()
        doc["events"].pop()
        with self.assertRaisesRegex(module.Refusal, "exact ordered Karing event set"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = self.fixture()
        doc["events"][-1], doc["events"][-2] = doc["events"][-2], doc["events"][-1]
        with self.assertRaisesRegex(module.Refusal, "exact ordered Karing event set"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))

    def test_refuses_event_outside_current_request_deadline(self):
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = self.fixture()
        doc["events"][-1]["observed_at"] = stamp(request["deadline_unix"] + 1)
        with self.assertRaisesRegex(module.Refusal, "original deadline"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))

    def test_refuses_missing_or_tampered_native_capture(self):
        fixture = self.fixture()
        native = fixture[5]
        path = self.native_root / native["artifacts"][0]["name"]
        path.unlink()
        with self.assertRaisesRegex(module.Refusal, "native capture unavailable"):
            self.validate(fixture)
        fixture = self.fixture()
        native = fixture[5]
        path = self.native_root / native["artifacts"][0]["name"]
        path.write_bytes(b"tampered native fixture"); path.chmod(0o600)
        with self.assertRaisesRegex(module.Refusal, "native capture"):
            self.validate(fixture)

    def test_refuses_unbound_native_artifact_or_event(self):
        fixture = self.fixture()
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = fixture
        doc["events"][0]["native_artifacts"] = []
        with self.assertRaisesRegex(module.Refusal, "selected server or profile"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))
        fixture = self.fixture()
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = fixture
        native["artifacts"].append({"media_type": "image/png", "name": "unreferenced.png",
                                     "sha256": "", "size": 0})
        extra = b"\x89PNG\r\n\x1a\nx"
        native["artifacts"][-1]["sha256"] = hashlib.sha256(extra).hexdigest()
        native["artifacts"][-1]["size"] = len(extra)
        native_raw = canon(native); doc["native_capture_sha256"] = hashlib.sha256(native_raw).hexdigest()
        path = self.native_root / "unreferenced.png"; path.write_bytes(extra); path.chmod(0o600)
        with self.assertRaisesRegex(module.Refusal, "every retained native artifact"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))

    def test_refuses_unbound_native_path_or_manifest(self):
        fixture = self.fixture()
        doc, manifest, manifest_raw, request, request_raw, native, _ = fixture
        native["artifacts"][0]["name"] = "../outside.png"
        native_raw = canon(native)
        doc["native_capture_sha256"] = hashlib.sha256(native_raw).hexdigest()
        with self.assertRaisesRegex(module.Refusal, "exact native capture artifact inventory"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))
        fixture = self.fixture()
        doc, manifest, manifest_raw, request, request_raw, native, native_raw = fixture
        native["application_receipt"]["executable_sha256"] = "f" * 64
        tampered = canon(native)
        with self.assertRaisesRegex(module.Refusal, "not bound to native capture manifest"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, tampered))

    def test_refuses_native_package_receipt_different_from_signed_package(self):
        fixture = self.fixture()
        doc, manifest, manifest_raw, request, request_raw, native, _ = fixture
        native["package_receipt"]["size"] += 1
        native_raw = canon(native)
        doc["native_capture_sha256"] = hashlib.sha256(native_raw).hexdigest()
        with self.assertRaisesRegex(module.Refusal, "native package identity"):
            self.validate((doc, manifest, manifest_raw, request, request_raw, native, native_raw))


if __name__ == "__main__":
    unittest.main()
