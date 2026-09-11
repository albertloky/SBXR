#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("renewal_outside", HERE / "renewal-outside.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class Probe:
    def __init__(self): self.values = iter(("2030-01-01T00:00:02.000Z", "2030-01-01T00:00:04.000Z"))
    def complete(self, value, expected, timeout):
        assert expected == 200 and timeout == 12 and value["configuration"]["outbounds"]
        return next(self.values)


class RenewalOutside(unittest.TestCase):
    def setUp(self):
        self.manifest = {"schema": "sbxr-qualification-manifest-v3", "mode": "v3", "v3_attempt": {
            "evidence_policy": "repair-issuance-bounded-v4", "scenario_limit_seconds": 1800,
            "required_scenarios": list(m.SCENARIOS), "outside_runner_id": "runner-1"}}
        self.manifest_raw = canonical(self.manifest)
        self.request = {"scenario_id": "managed-renewal", "qualification_manifest_sha256": m.link.digest(self.manifest_raw),
                        "scenario_limit_seconds": 1800, "not_before": "2030-01-01T00:00:00Z", "deadline_unix": 1893457800}
        self.request_raw = canonical(self.request) + b"\n"
        config = {"inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
                  "outbounds": [{"type": "vless", "tag": "SBXR", "server": "203.0.113.7",
                                 "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}], "log": {}}
        self.initial = {"link": "https://203.0.113.7:8443/s/" + "A" * 43,
                        "certificate_der_sha256": "a" * 64, "configuration": config,
                        "binding": {**self.request, "request_sha256": m.link.digest(self.request_raw)}}
        self.initial["binding"].pop("scenario_limit_seconds")
        self.final = copy.deepcopy(self.initial)
        self.final["certificate_der_sha256"] = "b" * 64
        self.initial_raw, self.final_raw = canonical(self.initial), canonical(self.final)

    def produce(self):
        with patch.object(m.link, "now", side_effect=("2030-01-01T00:00:01.000Z", "2030-01-01T00:00:02.500Z",
                                                       "2030-01-01T00:00:03.000Z", "2030-01-01T00:00:05.000Z")):
            return m.produce(self.manifest_raw, self.request_raw, self.initial_raw, self.final_raw, Probe())

    def test_produces_secret_safe_current_request_witness(self):
        value, ready = self.produce()
        self.assertEqual(m.check(value, self.manifest_raw, self.request_raw, self.initial_raw, self.final_raw,
                                 canonical(ready)), value)
        self.assertEqual(value["outside_runner_id"], "runner-1")
        encoded = canonical(value)
        self.assertNotIn(b"/s/", encoded)
        self.assertNotIn(b"outbounds", encoded)
        self.assertNotEqual(value["initial_certificate_der_sha256"], value["final_certificate_der_sha256"])

    def test_refuses_changed_link_configuration_and_artifact_claim(self):
        value, ready = self.produce()
        for field, changed in (("link_sha256", "f" * 64), ("configuration_sha256", "e" * 64)):
            with self.subTest(field=field):
                bad = dict(value, **{field: changed})
                with self.assertRaises(m.link.Refused):
                    m.check(bad, self.manifest_raw, self.request_raw, self.initial_raw, self.final_raw, canonical(ready))
        changed = copy.deepcopy(self.final)
        changed["link"] = "https://203.0.113.7:8443/s/" + "B" * 43
        with self.assertRaises(m.link.Refused):
            with patch.object(m.link, "now", side_effect=("2030-01-01T00:00:01.000Z", "2030-01-01T00:00:02.500Z",
                                                           "2030-01-01T00:00:03.000Z", "2030-01-01T00:00:05.000Z")):
                m.produce(self.manifest_raw, self.request_raw, self.initial_raw, canonical(changed), Probe())

    def test_refuses_request_manifest_and_time_drift(self):
        value, ready = self.produce()
        for mutate in (lambda r: dict(r, request_sha256="0" * 64),
                       lambda r: dict(r, initial_at="2029-12-31T23:59:59Z"),
                       lambda r: {k: v for k, v in r.items() if k != "facts"}):
            with self.assertRaises(m.link.Refused):
                m.check(mutate(value), self.manifest_raw, self.request_raw, self.initial_raw, self.final_raw,
                        canonical(ready))

    def test_live_producer_publishes_ready_before_waiting_for_action_and_final(self):
        bound = m.binding(self.manifest_raw, self.request_raw)
        action = {"schema": "sbxr-v4-scenario-entry-v1", "scenario_id": "managed-renewal",
                  "qualification_manifest_sha256": bound["qualification_manifest_sha256"],
                  "request_sha256": bound["request_sha256"], "started_at": "2030-01-01T00:00:00Z",
                  "entry_started_at": "2030-01-01T00:00:02Z", "action_started_at": "2030-01-01T00:00:03Z",
                  "action_completed_at": "2030-01-01T00:00:04Z"}

        class Backend:
            manifest_raw, request_raw = self.manifest_raw, self.request_raw
            probe = Probe()
            def __init__(self):
                self.events = []
                self.times = iter(("2030-01-01T00:00:00.500Z", "2030-01-01T00:00:01.000Z",
                                   "2030-01-01T00:00:01.500Z", "2030-01-01T00:00:02.500Z",
                                   "2030-01-01T00:00:04.100Z", "2030-01-01T00:00:04.500Z",
                                   "2030-01-01T00:00:05.000Z"))
            def unchanged(self): self.events.append("unchanged")
            def timeout(self): return 12
            def clock(self): return next(self.times)
            def prepare_client(self): self.events.append("prepare")
            def start_disclosed_client(self, raw):
                self.assert_client = m.link.decode(raw)["inbounds"][0]["listen_port"] == 2080
                self.events.append("client-start")
            def routes(self): self.events.append("routes")
            def connect(self):
                backend = self
                class Connection:
                    def request(inner): backend.events.append("connection-request")
                    def close(inner): backend.events.append("connection-close")
                return Connection()
            def client_alive(self): self.events.append("client-alive")
            def pause(self): self.events.append("pause")
            def cleanup(self): self.events.append("cleanup")
            def exists(self, name): return True
            def fetch(self, name):
                self.events.append(("fetch", name))
                return canonical(action) if name.endswith("action-complete.json") else self.initial_raw
            def publish(self, name, value):
                self.events.append(("publish", name)); self.published = getattr(self, "published", {}); self.published[name] = value
            def wait(self, name):
                self.events.append(("wait", name))
                return canonical(action) if name.endswith("action-complete.json") else self.final_raw
        backend = Backend()
        backend.initial_raw, backend.final_raw = self.initial_raw, self.final_raw
        with patch.object(m.link, "now", return_value="2030-01-01T00:00:05.500Z"), \
                patch.object(m.time, "time", return_value=1893456003):
            result = m.produce_live(backend, bound)
        self.assertLess(backend.events.index(("publish", "11-outside-ready.json")),
                        backend.events.index(("fetch", "scenario-managed-renewal-action-complete.json")))
        self.assertEqual(backend.events[-1], ("publish", "11-outside-result.json"))
        self.assertEqual(result["action_completed_at"], action["action_completed_at"])
        self.assertTrue(backend.assert_client)
        self.assertIn(("publish", "11-proxy-trace.json"), backend.events)
        self.assertLess(backend.events.index("cleanup"), backend.events.index(("publish", "11-proxy-trace.json")))

    def test_collector_accepts_only_exact_current_managed_trigger(self):
        collector = (HERE.parent / "v3-recurring-evidence.sh").read_text()
        match = re.search(r"managed_outside_request_matches\(\) \{.*?\n\}", collector, re.S)
        self.assertIsNotNone(match)
        request_digest, manifest_digest = "a" * 64, "b" * 64
        value = {"schema": "sbxr-v4-managed-outside-request-v1", "scenario_id": "managed-renewal",
                 "qualification_manifest_sha256": manifest_digest, "request_sha256": request_digest,
                 "outside_runner_id": "runner-1", "deadline_unix": 1893457800,
                 "operator_directory": "/run/sbxr-qualification", "state_directory": "/run/sbxr-qualification"}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "trigger.json"
            path.write_bytes(canonical(value))
            command = match.group(0) + '\nmanaged_outside_request_matches "$1" "$2" "$3" "$4" "$5" "$6"'
            args = ["bash", "-c", command, "collector-test", str(path), "1893457800", manifest_digest,
                    request_digest, "managed-renewal", "runner-1"]
            self.assertEqual(subprocess.run(args, check=False).returncode, 0)
            value["outside_runner_id"] = "runner-2"
            path.write_bytes(canonical(value))
            self.assertNotEqual(subprocess.run(args, check=False).returncode, 0)
        for dependency in ("renewal-outside.py", "scenario-subscription.py", "scenario-subscription-input.sh",
                           "link-subscription-input.sh", "subscription-observation.py"):
            self.assertIn(dependency, collector)

    def test_live_producer_uses_numbered_protocol_for_all_five_scenarios(self):
        for index, scenario in enumerate(m.SCENARIOS, 11):
            with self.subTest(scenario=scenario):
                request = dict(self.request, scenario_id=scenario)
                request_raw = canonical(request) + b"\n"
                bound = m.binding(self.manifest_raw, request_raw)
                initial = copy.deepcopy(self.initial)
                initial["binding"].update(scenario_id=scenario, request_sha256=m.link.digest(request_raw))
                final = copy.deepcopy(initial)
                final["certificate_der_sha256"] = "b" * 64
                initial_raw, final_raw = canonical(initial), canonical(final)
                action = {"schema": "sbxr-v4-scenario-entry-v1", "scenario_id": scenario,
                          "qualification_manifest_sha256": bound["qualification_manifest_sha256"],
                          "request_sha256": bound["request_sha256"], "started_at": "2030-01-01T00:00:00Z",
                          "entry_started_at": "2030-01-01T00:00:02Z", "action_started_at": "2030-01-01T00:00:03Z",
                          "action_completed_at": "2030-01-01T00:00:04Z"}
                class Backend:
                    probe = Probe()
                    def __init__(backend_self):
                        backend_self.manifest_raw = self.manifest_raw
                        backend_self.request_raw = request_raw
                        backend_self.published = []
                        backend_self.times = iter(("2030-01-01T00:00:00.500Z", "2030-01-01T00:00:01.000Z",
                                                   "2030-01-01T00:00:01.500Z", "2030-01-01T00:00:02.500Z",
                                                   "2030-01-01T00:00:04.100Z", "2030-01-01T00:00:04.500Z",
                                                   "2030-01-01T00:00:05.000Z"))
                    def unchanged(backend_self): pass
                    def timeout(backend_self): return 12
                    def clock(backend_self): return next(backend_self.times)
                    def prepare_client(backend_self): pass
                    def start_disclosed_client(backend_self, raw): pass
                    def routes(backend_self): pass
                    def connect(backend_self):
                        class Connection:
                            def request(connection_self): pass
                            def close(connection_self): pass
                        return Connection()
                    def client_alive(backend_self): pass
                    def pause(backend_self): pass
                    def cleanup(backend_self): pass
                    def exists(backend_self, name): return True
                    def fetch(backend_self, name):
                        return canonical(action) if name.endswith("action-complete.json") else initial_raw
                    def wait(backend_self, name):
                        return canonical(action) if name.endswith("action-complete.json") else final_raw
                    def publish(backend_self, name, value): backend_self.published.append(name)
                backend = Backend()
                with patch.object(m.link, "now", return_value="2030-01-01T00:00:05.500Z"), \
                        patch.object(m.time, "time", return_value=1893456003):
                    m.produce_live(backend, bound)
                self.assertEqual(backend.published, [f"{index}-outside-ready.json", f"{index}-proxy-trace.json",
                                                     f"{index}-outside-result.json"])

    def test_live_failure_closes_connection_and_cleans_transient_client(self):
        bound = m.binding(self.manifest_raw, self.request_raw)
        class Backend:
            manifest_raw, request_raw = self.manifest_raw, self.request_raw
            def __init__(backend_self):
                backend_self.closed = backend_self.cleaned = False
                backend_self.published = []
            def unchanged(backend_self): pass
            def fetch(backend_self, name): return self.initial_raw
            def clock(backend_self): return "2030-01-01T00:00:00.500Z"
            def prepare_client(backend_self): pass
            def start_disclosed_client(backend_self, raw): pass
            def routes(backend_self): pass
            def connect(backend_self):
                backend = backend_self
                class Connection:
                    def request(connection_self): raise RuntimeError("connection failed")
                    def close(connection_self):
                        backend.closed = True
                        raise RuntimeError("close failed")
                return Connection()
            def cleanup(backend_self): backend_self.cleaned = True
        backend = Backend()
        with self.assertRaisesRegex(RuntimeError, "close failed"):
            m.produce_live(backend, bound)
        self.assertTrue(backend.closed)
        self.assertTrue(backend.cleaned)
        self.assertEqual(backend.published, [])


if __name__ == "__main__": unittest.main()
