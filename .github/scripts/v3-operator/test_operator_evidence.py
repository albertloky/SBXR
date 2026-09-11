#!/usr/bin/env python3
import datetime
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse
from unittest import mock

ROOT = Path(__file__).parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

connection = load("connection_observation", "check-connection-observation.py")
subscription = load("subscription_check", "check-subscription.py")
observation = load("subscription_observation", "subscription-observation.py")

class OperatorEvidenceTest(unittest.TestCase):
    def trace(self, rows):
        temporary = tempfile.NamedTemporaryFile("w", delete=False)
        with temporary:
            for row in rows:
                temporary.write(json.dumps(row, separators=(",", ":")) + "\n")
        self.addCleanup(Path(temporary.name).unlink)
        return temporary.name

    def rows(self):
        return [{"check": number, "connection_id": "a" * 32,
                 "request_sha256": "b" * 64,
                 "same_connection": True, "schema": "sbxr-v3-connection-probe-v1",
                 "time": f"2026-09-09T10:40:0{number}.100Z"} for number in range(1, 5)]

    def validate(self, rows, scenario="2026-09-09T10:40:00Z", started="2026-09-09T10:40:02Z", completed="2026-09-09T10:40:03Z"):
        return connection.validate(self.trace(rows), scenario, started, completed, 4102444800, "b" * 64)

    def test_connection_trace_must_be_one_contiguous_session_spanning_action(self):
        result = self.validate(self.rows())
        self.assertEqual((result["same_connection"], result["checks"]), (True, 4))
        for mutate in (
            lambda rows: rows[2].update(connection_id="b" * 32),
            lambda rows: rows[2].update(same_connection=False),
            lambda rows: rows[2].update(check=9),
        ):
            with self.subTest(mutate=mutate):
                rows = self.rows(); mutate(rows)
                with self.assertRaises(ValueError):
                    self.validate(rows)
        with self.assertRaises(ValueError):
            self.validate(self.rows()[1:3], started="2026-09-09T10:40:00Z", completed="2026-09-09T10:40:04Z")
        duplicate = self.trace(self.rows())
        body = Path(duplicate).read_text().replace('"check":1', '"check":1,"check":1', 1)
        Path(duplicate).write_text(body)
        with self.assertRaises(ValueError):
            connection.validate(duplicate, "2026-09-09T10:40:00Z", "2026-09-09T10:40:02Z", "2026-09-09T10:40:03Z", 4102444800, "b" * 64)

    def test_connection_trace_refuses_bad_request_time_order_and_deadline(self):
        cases = []
        bad = self.rows(); bad[1]["request_sha256"] = "c" * 64; cases.append(bad)
        bad = self.rows(); bad[0]["connection_id"] = "z" * 32; cases.append(bad)
        bad = self.rows(); bad[2]["time"] = bad[1]["time"]; cases.append(bad)
        bad = self.rows(); bad[2]["time"] = "2026-09-09T10:40:01.000Z"; cases.append(bad)
        for rows in cases:
            with self.assertRaises(ValueError): self.validate(rows)
        with self.assertRaises(ValueError): self.validate(self.rows(), started="2026-09-09T10:40:04Z", completed="2026-09-09T10:40:03Z")
        with self.assertRaises(ValueError):
            connection.validate(self.trace(self.rows()), "2026-09-09T10:40:00Z", "2026-09-09T10:40:02Z", "2026-09-09T10:40:03Z", 1788948003, "b" * 64)

    def test_subscription_artifact_requires_exact_fields_and_name(self):
        config = {"outbounds":[{"type":"vless","server":"203.0.113.7","server_port":443,
            "uuid":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision",
            "tls":{"enabled":True,"server_name":"www.example.com","reality":{"enabled":True,"public_key":"public","short_id":"abcd"},"utls":{"enabled":True,"fingerprint":"chrome"}}}]}
        query = urllib.parse.urlencode({"encryption":"none","flow":"xtls-rprx-vision","security":"reality","sni":"www.example.com","fp":"chrome","pbk":"public","sid":"abcd","type":"tcp"})
        artifact = f"vless://11111111-1111-1111-1111-111111111111@203.0.113.7:443?{query}#SBXR%20Proxy%20%28203.0.113.7%29\n".encode()
        self.assertTrue(subscription.fields_match(artifact, config))
        self.assertFalse(subscription.fields_match(artifact.replace(b"&type=tcp", b"&type=tcp&type=tcp"), config))
        self.assertFalse(subscription.fields_match(artifact.replace(b"SBXR%20Proxy", b"Other"), config))

    def test_bound_subscription_result_records_actual_request_and_tls_interval(self):
        data={"configuration":{"outbounds":[]},"certificate_der_sha256":"c"*64,"link":"https://203.0.113.7:8443/s/"+"A"*43,
              "binding":{"deadline_unix":4102444800,"not_before":"2030-01-01T00:00:00Z","qualification_manifest_sha256":"a"*64,
                         "request_sha256":"b"*64,"scenario_id":"enable-schema1"}}
        base={"artifact_fields_and_name":True,"expected_status":True,"link_sha256":"d"*64,"schema":"sbxr-v3-subscription-check-v1","trusted_outside_tls":True}
        with mock.patch.object(subscription,"check",return_value=base), mock.patch.object(subscription,"now",side_effect=["2030-01-01T00:00:01.000001Z","2030-01-01T00:00:02.000002Z"]), mock.patch.object(subscription.time,"time",return_value=1893456002):
            result=subscription.check_bound(data)
        self.assertEqual((result["schema"],result["request_sha256"],result["started_at"],result["completed_at"]),("sbxr-v4-subscription-check-v2","b"*64,"2030-01-01T00:00:01.000001Z","2030-01-01T00:00:02.000002Z"))
        changed=dict(data); changed["binding"]=dict(data["binding"],request_sha256="0"*63)
        with self.assertRaises(subscription.SafeFailure): subscription.check_bound(changed)

    def test_protected_subscription_observation_is_assembled_from_bytes(self):
        link = b"https://203.0.113.7:8443/s/" + b"A" * 43
        result = observation.assemble(link, b"b" * 64, b'{"outbounds":[]}')
        self.assertEqual(result["link"], link.decode())
        for bad in (link + b"\n", b"https://example.com/s/" + b"A" * 43):
            with self.assertRaises(ValueError): observation.assemble(bad, b"b" * 64, b'{}')
        with self.assertRaises(ValueError): observation.assemble(link, b"b" * 64, b'{"x":1,"x":2}')

if __name__ == "__main__":
    unittest.main()
