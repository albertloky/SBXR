#!/usr/bin/env python3
"""Real-file readback regressions; public fixtures never access Karing or a server."""
import copy
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "native_receipts", Path(__file__).with_name("native-receipts.py"))
RECEIPTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECEIPTS)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class NativeReadbackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.native_store = self.root / "native-store.json"
        # Only the native file boundary moves into the fixture; parsing,
        # metadata, source/hash and whole-profile checks execute unchanged.
        native_path = patch.object(RECEIPTS, "NATIVE_SUBSCRIPTION_SOURCE", self.native_store)
        native_path.start()
        self.addCleanup(native_path.stop)
        self.live = SimpleNamespace(r=self.root)
        self.url = "http://107.175.53.219:8443/s/PUBLIC_FIXTURE_NOT_A_REAL_LINK"
        uuid = "12345678-1234-4234-8234-123456789abc"
        self.wire = (
            f"vless://{uuid}@198.51.100.10:443?encryption=none&flow=xtls-rprx-vision"
            "&security=reality&sni=example.com&fp=chrome&pbk=" + "A" * 43
            + "&sid=01020304&type=tcp#SBXR%20Proxy\n"
        ).encode()
        # hq7 observed this native field set and packet_encoding='xudp'.
        # Values identifying the real link/identity are replaced with public fixtures.
        self.profile = {
            "groupid": "fixture-group", "remark": "SBXR public fixture", "urlOrPath": self.url,
            "servers": [{
                "groupid": "fixture-group", "attach": "", "latency": "166",
                "outlet_ip": "", "outlet_region": "", "server": "198.51.100.10",
                "server_port": 443, "tag": "SBXR Proxy", "type": "vless", "uuid": uuid,
                "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
                "tls": {
                    "enabled": True, "server_name": "example.com",
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {"enabled": True, "public_key": "A" * 43, "short_id": "01020304"},
                },
            }],
        }
        self.write("expected-url.private", self.url.encode() + b"\n")
        self.write("expected-wire.private", self.wire)
        self.persist()

    def write(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def record(self, path):
        raw = path.read_bytes()
        return {"source_file": str(path), "sha256": sha(raw), "size": len(raw)}

    def persist(self, store=None):
        url = self.write("actual-url.private", self.profile["urlOrPath"].encode() + b"\n")
        profile = self.write("actual-profile.private", canonical(self.profile))
        raw = canonical(store if store is not None else {"items": [self.profile]})
        self.write(self.native_store.name, raw)
        self.facts = {
            "saved_url": self.record(url), "saved_subscription_content": self.record(profile),
            "native_subscription_source": {
                "source_app_path": str(self.native_store), "sha256": sha(raw), "size": len(raw),
                "mtime_ns": self.native_store.stat().st_mtime_ns,
            },
        }

    def verify(self):
        RECEIPTS.readbacks(self.live, self.facts, "expected-url.private", "expected-wire.private")

    def test_accepts_saved_karing_xudp_for_the_omitted_wire_default(self):
        self.verify()

    def test_rejects_disabled_different_or_malformed_packet_encoding(self):
        for encoding in ("", "packetaddr", "XUDP", "unknown", None, False, 0, []):
            with self.subTest(encoding=encoding):
                self.profile["servers"][0]["packet_encoding"] = encoding
                self.persist()
                with self.assertRaisesRegex(ValueError, "packet_encoding"):
                    self.verify()
        del self.profile["servers"][0]["packet_encoding"]
        self.persist()
        with self.assertRaisesRegex(ValueError, "Native node fields differ"):
            self.verify()

    def test_preserves_exact_identity_tls_and_node_shape_checks(self):
        original = copy.deepcopy(self.profile)
        mutations = [
            ("uuid", "another-identity"), ("server", "198.51.100.11"),
            ("server_port", 444), ("server_port", "443"), ("type", "vmess"),
            ("flow", ""), ("attach", "unexpected"), ("unexpected", True),
        ]
        for key, value in mutations:
            with self.subTest(field=key, value=value):
                self.profile = copy.deepcopy(original)
                self.profile["servers"][0][key] = value
                self.persist()
                with self.assertRaises(ValueError):
                    self.verify()
        for path, value in [
            (("enabled",), False), (("server_name",), "other.example"),
            (("utls", "enabled"), False), (("utls", "fingerprint"), "firefox"),
            (("reality", "enabled"), False), (("reality", "public_key"), "B" * 43),
            (("reality", "short_id"), "01020305"),
        ]:
            with self.subTest(tls_field=path):
                self.profile = copy.deepcopy(original)
                target = self.profile["servers"][0]["tls"]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.persist()
                with self.assertRaises(ValueError):
                    self.verify()
        self.profile = copy.deepcopy(original)
        self.profile["servers"].append(copy.deepcopy(self.profile["servers"][0]))
        self.persist()
        with self.assertRaisesRegex(ValueError, "Exactly one"):
            self.verify()

    def test_rejects_changed_url_or_unbound_native_store(self):
        self.profile["urlOrPath"] += "-changed"
        self.persist()
        with self.assertRaisesRegex(ValueError, "Actual saved URL readback differs"):
            self.verify()
        self.profile["urlOrPath"] = self.url
        self.persist()
        original = copy.deepcopy(self.facts)
        for field, value in (("sha256", "0" * 64), ("mtime_ns", 0), ("source_app_path", "/wrong-store")):
            with self.subTest(provenance=field):
                self.facts = copy.deepcopy(original)
                self.facts["native_subscription_source"][field] = value
                with self.assertRaises(ValueError):
                    self.verify()
        self.persist(store={"items": []})
        with self.assertRaisesRegex(ValueError, "unique actual native profile"):
            self.verify()

    def test_rejects_expected_bytes_substituted_for_actual_readback(self):
        self.facts["saved_url"] = self.record(self.root / "expected-url.private")
        with self.assertRaisesRegex(ValueError, "Expected transport bytes"):
            self.verify()

    def original_profiles(self, count):
        profiles = [{"groupid": "custom", "remark": "custom", "servers": []}]
        for index in range(1, count):
            profile = copy.deepcopy(self.profile)
            profile.update(groupid=f"original-{index}", remark=f"Original {index}",
                           updateTime="2026-10-23 01:00:00")
            profile["servers"][0]["groupid"] = profile["groupid"]
            profiles.append(profile)
        return profiles

    def audit_originals(self, before, after):
        zone = self.write("timezone.private.tzif", Path("/usr/share/zoneinfo/Etc/UTC").read_bytes())
        return RECEIPTS.original_profiles_audit_v3(
            before, after, timezone={"name": "Etc/UTC", "resolved_source_path": "/PUBLIC/zoneinfo/Etc/UTC",
                                     "sha256": sha(zone.read_bytes())},
            tzif_record=self.record(zone), window_start="2026-10-23T01:10:00Z",
            window_end="2026-10-23T02:00:00Z")

    def test_original_profile_counts_follow_frozen_baseline_with_same_cache_rules(self):
        for count in (1, 2, 3, 5):
            with self.subTest(count=count):
                before = self.original_profiles(count)
                exact = self.audit_originals(before, copy.deepcopy(before))
                self.assertTrue(exact["passed"], exact["refusals"])
                self.assertEqual(exact["changes"], [])
                after = copy.deepcopy(before)
                for profile in after[1:]:
                    profile["updateTime"] = "2026-10-23 01:20:00"
                    profile["servers"][0]["latency"] = "222"
                audit = self.audit_originals(before, after)
                self.assertTrue(audit["passed"])
                self.assertEqual(len(audit["changes"]), 2 * (count - 1))
                self.assertTrue(all(change["allowed"] for change in audit["changes"]))

    def test_original_profile_count_identity_and_order_changes_refuse(self):
        before = self.original_profiles(3)
        extra = copy.deepcopy(before[1]); extra["groupid"] = "unexpected-original"
        changed_id = copy.deepcopy(before); changed_id[2]["groupid"] = "changed-identity"
        duplicate = copy.deepcopy(before); duplicate[2]["groupid"] = duplicate[1]["groupid"]
        missing_id = copy.deepcopy(before); del missing_id[2]["groupid"]
        empty_id = copy.deepcopy(before); empty_id[2]["groupid"] = ""
        for after in (before[:2], before + [extra], list(reversed(before)), changed_id,
                      duplicate, missing_id, empty_id, before[1:]):
            with self.subTest(after=after):
                self.assertFalse(self.audit_originals(before, after)["passed"])
        for invalid in ([], before[1:], duplicate, missing_id, empty_id):
            with self.subTest(invalid_baseline=invalid):
                audit = self.audit_originals(invalid, copy.deepcopy(invalid))
                self.assertFalse(audit["passed"])
                self.assertTrue(audit["refusals"])

    def test_additional_original_profiles_keep_full_content_guards(self):
        before = self.original_profiles(3)
        for path, value in [(("urlOrPath",), "other"), (("groupid",), "other"),
                            (("servers", 0, "uuid"), "other"),
                            (("servers", 0, "tls", "enabled"), False),
                            (("servers", 0, "tls", "reality", "public_key"), "other"),
                            (("servers", 0, "flow"), "other"), (("unexpected",), True)]:
            with self.subTest(path=path):
                after = copy.deepcopy(before)
                target = after[2]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assertFalse(self.audit_originals(before, after)["passed"])
        after = copy.deepcopy(before); after[2]["servers"].clear()
        self.assertFalse(self.audit_originals(before, after)["passed"])
        after = copy.deepcopy(before); after[0]["latency"] = "222"
        self.assertFalse(self.audit_originals(before, after)["passed"])

    def combined(self):
        attempt = {
            "schema": "sbxr-v3-qualification-attempt-v3", "proxy_profile": "vless-vmess",
            "evidence_policy": "mvp-http-live-v1", "sources": [],
            "support": {"scope": "subscription-clean-install-only", "sources": [],
                        "contract": "sbxr-subscription-update-v1"},
        }
        host = "tunnel.example.com"
        wire = {"v": "2", "ps": f"SBXR VMess ({host})", "add": host, "port": "443",
                "id": self.profile["servers"][0]["uuid"], "aid": "0", "scy": "auto",
                "net": "ws", "type": "none", "host": host, "path": "/sbxr-vmess",
                "tls": "tls", "sni": host}
        # Karing 1.2.25/2802's saved baseline node shape, with public replacements.
        # The observed zero-legacy-ID VMess node omits alter_id entirely.
        profile = copy.deepcopy(self.profile)
        profile["servers"].append({
            "groupid": profile["groupid"], "attach": "", "latency": "167",
            "outlet_ip": "", "outlet_region": "", "server": host, "server_port": 443,
            "tag": wire["ps"], "type": "vmess", "uuid": wire["id"],
            "security": "auto", "tls": {"enabled": True, "server_name": host},
            "transport": {"type": "ws", "path": "/sbxr-vmess", "headers": {"Host": host}},
        })
        return attempt, profile, wire

    def combined_wire(self, vmess):
        return self.wire + b"vmess://" + base64.b64encode(canonical(vmess)) + b"\n"

    def test_signed_combined_profile_requires_exactly_both_nodes(self):
        attempt, profile, vmess = self.combined()
        RECEIPTS.subscription_nodes(profile, self.combined_wire(vmess), attempt=attempt)
        RECEIPTS.subscription_nodes(self.profile, self.wire)
        for nodes in (profile["servers"][:1], profile["servers"] * 2,
                      list(reversed(profile["servers"])), [profile["servers"][0]] * 2):
            with self.subTest(nodes=nodes):
                bad = {**profile, "servers": nodes}
                with self.assertRaises(ValueError):
                    RECEIPTS.subscription_nodes(bad, self.combined_wire(vmess), attempt=attempt)
        with self.assertRaises(ValueError):
            RECEIPTS.subscription_nodes(profile, self.combined_wire(vmess))
        for wire in (self.wire, self.combined_wire(vmess) + self.wire,
                     b"vmess://not-base64\n" + self.wire,
                     self.wire + b"vmess://not-base64\n"):
            with self.subTest(wire=wire):
                with self.assertRaises(ValueError):
                    RECEIPTS.subscription_nodes(profile, wire, attempt=attempt)

    def test_combined_native_identity_transport_tls_and_fields_are_strict(self):
        attempt, profile, vmess = self.combined()
        for path, value in [
            (("uuid",), "other"), (("server",), "other.example.com"),
            (("server_port",), "443"), (("type",), "vless"), (("alter_id",), False),
            (("alter_id",), 0), (("alter_id",), 1), (("security",), "none"), (("tag",), "other"),
            (("groupid",), "other"), (("attach",), "fallback"),
            (("tls", "enabled"), False), (("tls", "server_name"), "other.example.com"),
            (("tls", "insecure"), True), (("transport", "type"), "tcp"),
            (("transport", "path"), "/other"),
            (("transport", "headers", "Host"), "other.example.com"),
            (("unexpected",), True),
        ]:
            with self.subTest(path=path):
                bad = copy.deepcopy(profile)
                target = bad["servers"][1]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    RECEIPTS.subscription_nodes(bad, self.combined_wire(vmess), attempt=attempt)
        for path, value in [(("uuid",), "other"), (("packet_encoding",), ""),
                            (("tls", "reality", "public_key"), "wrong")]:
            bad = copy.deepcopy(profile)
            target = bad["servers"][0]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.assertRaises(ValueError):
                RECEIPTS.subscription_nodes(bad, self.combined_wire(vmess), attempt=attempt)

    def test_combined_rejects_wrong_vless_contract_even_when_wire_and_native_agree(self):
        attempt, profile, vmess = self.combined()
        for path, value, before, after in (
            (("flow",), "xtls-rprx-splice", b"flow=xtls-rprx-vision", b"flow=xtls-rprx-splice"),
            (("server_port",), 1443, b":443?", b":1443?"),
            (("tls", "utls", "fingerprint"), "firefox", b"fp=chrome", b"fp=firefox"),
        ):
            with self.subTest(field=path):
                bad = copy.deepcopy(profile)
                target = bad["servers"][0]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                wire = self.combined_wire(vmess).replace(before, after, 1)
                with self.assertRaisesRegex(ValueError, "Two-node VLESS transport differs"):
                    RECEIPTS.subscription_nodes(bad, wire, attempt=attempt)
                # Omitted-profile behavior still compares the original one-node contract.
                RECEIPTS.subscription_nodes({**bad, "servers": bad["servers"][:1]},
                                            wire.splitlines(keepends=True)[0])

    def test_combined_wire_contract_rejects_legacy_authentication_and_wrong_routes(self):
        attempt, profile, vmess = self.combined()
        for key, value in [("v", "1"), ("id", "other"), ("port", 443), ("port", "80"),
                           ("aid", "1"), ("scy", "none"), ("net", "tcp"), ("type", "http"),
                           ("tls", ""), ("sni", "other.example.com"), ("host", "other.example.com"),
                           ("path", "/other"), ("unexpected", "value")]:
            with self.subTest(field=key):
                bad = {**vmess, key: value}
                with self.assertRaises(ValueError):
                    RECEIPTS.subscription_nodes(profile, self.combined_wire(bad), attempt=attempt)
        raw = canonical(vmess).replace(b'"aid":"0"', b'"aid":"0","aid":"0"')
        with self.assertRaises(ValueError):
            RECEIPTS.subscription_nodes(profile, self.wire + b"vmess://" + base64.b64encode(raw), attempt=attempt)

    def test_combined_requires_every_vmess_field_and_canonical_hostname(self):
        attempt, profile, vmess = self.combined()
        for key in profile["servers"][1]:
            with self.subTest(missing_native=key):
                bad = copy.deepcopy(profile)
                del bad["servers"][1][key]
                with self.assertRaises(ValueError):
                    RECEIPTS.subscription_nodes(bad, self.combined_wire(vmess), attempt=attempt)
        for key in vmess:
            with self.subTest(missing_wire=key):
                bad = dict(vmess)
                del bad[key]
                with self.assertRaises(ValueError):
                    RECEIPTS.subscription_nodes(profile, self.combined_wire(bad), attempt=attempt)
        for host in ("127.0.0.1", "https://example.com", "EXAMPLE.com", "a..example",
                     "-bad.example", "a" * 64 + ".example"):
            with self.subTest(host=host):
                bad = {**vmess, "add": host, "host": host, "sni": host,
                       "ps": f"SBXR VMess ({host})"}
                with self.assertRaises(ValueError):
                    RECEIPTS.subscription_nodes(profile, self.combined_wire(bad), attempt=attempt)

    def test_combined_profile_refuses_incompatible_attempts(self):
        attempt, profile, vmess = self.combined()
        for fields in [
            {"proxy_profile": "unknown"}, {"proxy_profile": None},
            {"schema": "sbxr-v3-qualification-attempt-v2"},
            {"evidence_policy": "mvp-live-v1"}, {"sources": [{}]},
            {"support": {**attempt["support"], "scope": "subscription-clean-install-repair"}},
            {"owner_exception": "reuse"}, {"live89_correction_review": {}},
            {"late_confirmation_review": {}}, {"automated_only_scenarios": []},
        ]:
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    RECEIPTS.subscription_nodes(profile, self.combined_wire(vmess), attempt={**attempt, **fields})

    def test_combined_actual_file_readbacks_accept_observed_native_shape(self):
        attempt, profile, vmess = self.combined()
        self.assertNotIn("alter_id", profile["servers"][1])
        self.profile = profile
        self.write("expected-wire.private", self.combined_wire(vmess))
        self.persist()
        RECEIPTS.readbacks(SimpleNamespace(r=self.root, bindings=object()), self.facts,
                           "expected-url.private", "expected-wire.private", attempt=attempt)

    def test_combined_readbacks_preserve_source_and_whole_profile_guards(self):
        attempt, profile, vmess = self.combined()
        self.profile = profile
        self.write("expected-wire.private", self.combined_wire(vmess))
        self.persist()
        original = copy.deepcopy(self.facts)
        for field, value in (("sha256", "0" * 64), ("size", 0), ("mtime_ns", 0),
                             ("source_app_path", str(self.root / "receipt-selected-store.json"))):
            with self.subTest(provenance=field):
                self.facts = copy.deepcopy(original)
                self.facts["native_subscription_source"][field] = value
                with self.assertRaises(ValueError):
                    RECEIPTS.readbacks(self.live, self.facts, "expected-url.private",
                                       "expected-wire.private", attempt=attempt)
        for store in ({"items": []}, {"items": [profile, profile]},
                      {"items": [{**profile, "unexpected": True}]}):
            with self.subTest(store=store):
                self.persist(store=store)
                with self.assertRaisesRegex(ValueError, "unique actual native profile"):
                    RECEIPTS.readbacks(self.live, self.facts, "expected-url.private",
                                       "expected-wire.private", attempt=attempt)
        self.persist()
        self.native_store.chmod(0o640)
        with self.assertRaisesRegex(ValueError, "Native app store file is not protected"):
            RECEIPTS.readbacks(self.live, self.facts, "expected-url.private",
                               "expected-wire.private", attempt=attempt)

    def test_readbacks_reject_incompatible_attempt_before_any_file_read(self):
        attempt, _, _ = self.combined()
        for fields in ({"proxy_profile": "unknown"}, {"evidence_policy": "mvp-live-v1"},
                       {"sources": [{}]}):
            with self.subTest(fields=fields), \
                    patch.object(RECEIPTS, "source_file", side_effect=AssertionError("read receipt")), \
                    patch.object(RECEIPTS, "private_bytes", side_effect=AssertionError("read expected bytes")), \
                    patch.object(RECEIPTS.os, "open", side_effect=AssertionError("read native store")):
                with self.assertRaises(ValueError):
                    RECEIPTS.readbacks(self.live, self.facts, "expected-url.private",
                                       "expected-wire.private", attempt={**attempt, **fields})

    def test_combined_receipt_cannot_choose_profile_or_downgrade_to_legacy_reader(self):
        _, profile, vmess = self.combined()
        self.profile = profile
        self.write("expected-wire.private", self.combined_wire(vmess))
        self.persist()
        self.facts["proxy_profile"] = "vless-vmess"
        original_open = RECEIPTS.os.open

        def protected_open(path, *args, **kwargs):
            if Path(path) == self.native_store:
                raise AssertionError("native store was opened before node validation")
            return original_open(path, *args, **kwargs)

        with patch.object(RECEIPTS.os, "open", side_effect=protected_open):
            with self.assertRaisesRegex(ValueError, "Exactly one"):
                self.verify()

    def test_live_bound_context_keeps_existing_default_vless_readbacks(self):
        RECEIPTS.readbacks(SimpleNamespace(r=self.root, bindings=object()), self.facts,
                           "expected-url.private", "expected-wire.private")


if __name__ == "__main__":
    unittest.main()
