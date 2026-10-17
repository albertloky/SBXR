#!/usr/bin/env python3
"""Real-file readback regressions; public fixtures never access Karing or a server."""
import copy
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


if __name__ == "__main__":
    unittest.main()
