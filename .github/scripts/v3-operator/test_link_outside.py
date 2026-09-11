import copy
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import tempfile
import time
import unittest
from unittest import mock


PATH = Path(__file__).with_name("link-outside.py")
SPEC = importlib.util.spec_from_file_location("link_outside", PATH)
link = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(link)


def stamp(seconds):
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Fixture:
    def __init__(self, scenario="link-precommit"):
        self.base = time.time()
        self.bound = {"scenario_id": scenario, "request_sha256": "1" * 64,
                      "qualification_manifest_sha256": "2" * 64,
                      "deadline_unix": int(self.base + 300), "not_before": stamp(self.base - 5),
                      "outside_runner_id": "runner-1"}
        self.configuration = {"outbounds": [{"type": "vless", "server": "192.0.2.1", "server_port": 443,
            "uuid": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision",
            "tls": {"enabled": True, "server_name": "example.com", "reality": {"enabled": True,
                    "public_key": "A" * 43, "short_id": "01020304"},
                    "utls": {"enabled": True, "fingerprint": "chrome"}}}]}
        binding = {key: self.bound[key] for key in ("scenario_id", "request_sha256",
                   "qualification_manifest_sha256", "deadline_unix", "not_before")}
        self.initial = {"link": "https://192.0.2.1:8443/s/" + "A" * 43,
                        "certificate_der_sha256": "3" * 64, "configuration": self.configuration,
                        "binding": binding}
        self.final = copy.deepcopy(self.initial)
        if scenario == "link-postcommit":
            self.final["link"] = "https://192.0.2.1:8443/s/" + "B" * 43
        self.initial_raw, self.final_raw = canon(self.initial), canon(self.final)
        initial_hash = link.hashes(self.initial)
        self.ready = dict(link.public_bound(self.bound), schema="sbxr-v4-link-outside-ready-v1",
            started_at=stamp(self.base), old_initial_at=stamp(self.base + 1), ready_at=stamp(self.base + 2),
            old_link_sha256=initial_hash["link"], configuration_sha256=initial_hash["configuration"],
            certificate_der_sha256=initial_hash["certificate"], initial_disclosure_sha256=sha(self.initial_raw),
            facts={"artifact_matches": True, "old_initial_200": True, "outside_route_distinct": True,
                   "trusted_tls": True})
        self.ready_raw = canon(self.ready)
        self.challenge = dict(link.public_bound(self.bound), schema="sbxr-v4-link-outside-challenge-v1",
            nonce="4" * 64, challenged_at=stamp(self.base + 3), ready_sha256=sha(self.ready_raw),
            initial_disclosure_sha256=sha(self.initial_raw), transition_record_sha256="5" * 64)
        self.challenge_raw = canon(self.challenge)
        self.ack = dict(link.public_bound(self.bound), schema="sbxr-v4-link-outside-ack-v1",
            challenge_sha256=sha(self.challenge_raw), connection_id="6" * 32,
            tls_established_at=stamp(self.base + 3.1), partial_request_sent_at=stamp(self.base + 3.2),
            pending_ready_at=stamp(self.base + 3.3), old_link_sha256=initial_hash["link"])
        self.ack_raw = canon(self.ack)
        self.closed = dict(link.public_bound(self.bound), schema="sbxr-v4-link-outside-closed-v1",
            challenge_sha256=sha(self.challenge_raw), ack_sha256=sha(self.ack_raw), connection_id="6" * 32,
            partial_request_sent_at=self.ack["partial_request_sent_at"], pending_ready_at=self.ack["pending_ready_at"],
            closed_at=stamp(self.base + 4), closure_kind="eof", pending_elapsed_milliseconds=700,
            server_deadline_seconds=5, old_link_sha256=initial_hash["link"])
        self.closed_raw = canon(self.closed)
        self.finalize = dict(link.public_bound(self.bound), schema="sbxr-v4-link-outside-finalize-v1",
            challenge_sha256=sha(self.challenge_raw), closed_sha256=sha(self.closed_raw),
            final_disclosure_sha256=sha(self.final_raw), recovered_transition_sha256="7" * 64,
            recovered_at=stamp(self.base + 5), finalized_at=stamp(self.base + 6))
        self.finalize_raw = canon(self.finalize)
        post = scenario == "link-postcommit"
        self.result = dict(link.public_bound(self.bound), schema="sbxr-v4-link-outside-result-v1",
            ready_sha256=sha(self.ready_raw), challenge_sha256=sha(self.challenge_raw), ack_sha256=sha(self.ack_raw),
            closed_sha256=sha(self.closed_raw), finalize_sha256=sha(self.finalize_raw),
            final_disclosure_sha256=sha(self.final_raw), started_at=self.ready["started_at"],
            old_initial_at=self.ready["old_initial_at"], pending_ready_at=self.ack["pending_ready_at"],
            closed_at=self.closed["closed_at"], old_final_at=stamp(self.base + 7),
            new_final_at=stamp(self.base + 8) if post else None, cleanup_at=stamp(self.base + 9),
            old_link_sha256=initial_hash["link"], new_link_sha256=link.hashes(self.final)["link"] if post else None,
            configuration_sha256=initial_hash["configuration"], certificate_der_sha256=initial_hash["certificate"],
            facts={"old_final_200": not post, "new_final_200": post, "old_final_404": post,
                   "same_configuration": True, "same_certificate": True, "same_old_link": not post,
                   "trusted_tls": True, "runner_cleanup_complete": True})

    def handoffs(self):
        return {"ready": self.ready_raw, "challenge": self.challenge_raw, "ack": self.ack_raw,
                "closed": self.closed_raw, "finalize": self.finalize_raw}


class FakeTLS:
    def __init__(self, cert=b"cert", recv=b""):
        self.cert, self.recv_value, self.closed = cert, recv, False
        self.sent = []
    def getpeercert(self, binary_form=False): return self.cert
    def sendall(self, value): self.sent.append(value)
    def recv(self, size):
        if isinstance(self.recv_value, BaseException): raise self.recv_value
        return self.recv_value
    def settimeout(self, value): self.timeout = value
    def close(self): self.closed = True
    def __enter__(self): return self
    def __exit__(self, *args): self.close()


class LinkOutsideTests(unittest.TestCase):
    def test_complete_accepts_expected_200_artifact_and_404(self):
        fixture = Fixture()
        probe = link.HTTPSProbe()
        tls = FakeTLS(cert=b"cert")
        value = copy.deepcopy(fixture.initial)
        value["certificate_der_sha256"] = sha(b"cert")
        response = mock.Mock(status=200)
        response.read.return_value = b"artifact"
        with mock.patch.object(probe, "connect", return_value=(tls, __import__("urllib.parse").parse.urlsplit(value["link"]))), \
             mock.patch.object(link.http.client, "HTTPResponse", return_value=response), \
             mock.patch.object(link.subscription, "fields_match", return_value=True):
            probe.complete(value, 200, 1)
        response.status, response.read.return_value = 404, b"Not Found\n"
        with mock.patch.object(probe, "connect", return_value=(FakeTLS(), __import__("urllib.parse").parse.urlsplit(value["link"]))), \
             mock.patch.object(link.http.client, "HTTPResponse", return_value=response):
            probe.complete(value, 404, 1)

    def test_pending_sends_partial_header_and_eof_closes_before_deadline(self):
        fixture = Fixture()
        probe = link.HTTPSProbe()
        tls = FakeTLS()
        parsed = __import__("urllib.parse").parse.urlsplit(fixture.initial["link"])
        with mock.patch.object(probe, "connect", return_value=(tls, parsed)), \
             mock.patch.object(link.time, "monotonic", side_effect=[10, 10.5]):
            pending, started, _, _ = probe.pending(fixture.initial, 1)
            kind, elapsed, _ = probe.closure(pending, started, 1)
        self.assertEqual((kind, elapsed), ("eof", 500))
        self.assertNotIn(b"\r\n\r\n", tls.sent[0])
        self.assertTrue(tls.closed)

    def test_timeout_data_and_generic_tls_error_never_count_as_closure(self):
        for outcome in (socket.timeout("late"), b"H", ssl.SSLError("bad record")):
            tls = FakeTLS(recv=outcome)
            with mock.patch.object(link.time, "monotonic", side_effect=[1.0]), self.assertRaises(Exception):
                link.HTTPSProbe.closure(tls, 0.0, 1)
            self.assertTrue(tls.closed)

    def test_reset_is_a_conclusive_closure(self):
        tls = FakeTLS(recv=ConnectionResetError())
        with mock.patch.object(link.time, "monotonic", return_value=2.0):
            kind, elapsed, _ = link.HTTPSProbe.closure(tls, 1.0, 1)
        self.assertEqual((kind, elapsed), ("reset", 1000))

    def test_tls_trust_error_is_not_hidden(self):
        context = mock.Mock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError("untrusted")
        raw = mock.Mock()
        with mock.patch.object(link.socket, "create_connection", return_value=raw), self.assertRaises(ssl.SSLCertVerificationError):
            link.HTTPSProbe(context).connect(Fixture().initial, 1)
        raw.close.assert_called_once()

    def test_full_precommit_and_postcommit_chains(self):
        for scenario in link.SCENARIOS:
            fixture = Fixture(scenario)
            self.assertIs(link.check_result(fixture.result, fixture.bound, fixture.handoffs(),
                                            fixture.initial_raw, fixture.final_raw), fixture.result)

    def test_wrong_event_order_is_refused(self):
        fixture = Fixture()
        fixture.closed["closed_at"] = stamp(fixture.base + 3.1)
        with self.assertRaises(link.Refused):
            link.check_closed(fixture.closed, fixture.bound, fixture.ready_raw, fixture.challenge_raw, fixture.ack_raw)

    def test_wrong_request_binding_is_refused(self):
        fixture = Fixture()
        fixture.ack["request_sha256"] = "9" * 64
        with self.assertRaises(link.Refused):
            link.check_ack(fixture.ack, fixture.bound, fixture.ready_raw, fixture.challenge_raw)
        fixture = Fixture()
        fixture.result["scenario_id"] = "link-postcommit"
        with self.assertRaises(link.Refused):
            link.check_result(fixture.result, fixture.bound, fixture.handoffs(),
                              fixture.initial_raw, fixture.final_raw)

    def test_missing_closure_cannot_validate_result(self):
        fixture = Fixture()
        handoffs = fixture.handoffs()
        del handoffs["closed"]
        with self.assertRaises(KeyError):
            link.check_result(fixture.result, fixture.bound, handoffs, fixture.initial_raw, fixture.final_raw)

    def test_changed_configuration_or_certificate_is_refused(self):
        fixture = Fixture()
        changed = copy.deepcopy(fixture.final)
        changed["configuration"]["outbounds"][0]["server_port"] = 444
        with self.assertRaises(link.Refused):
            link.check_result(fixture.result, fixture.bound, fixture.handoffs(), fixture.initial_raw, canon(changed))
        changed = copy.deepcopy(fixture.final)
        changed["certificate_der_sha256"] = "8" * 64
        with self.assertRaises(link.Refused):
            link.check_result(fixture.result, fixture.bound, fixture.handoffs(), fixture.initial_raw, canon(changed))

    def test_receipts_redact_link_and_configuration(self):
        fixture = Fixture("link-postcommit")
        raw = canon(fixture.result) + fixture.ready_raw + fixture.ack_raw + fixture.closed_raw
        self.assertNotIn(fixture.initial["link"].encode(), raw)
        self.assertNotIn(fixture.configuration["outbounds"][0]["uuid"].encode(), raw)
        self.assertNotIn(b'"configuration"', raw)

    def test_private_reader_rejects_permissions_and_atomic_writer_cleans_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            source = root / "source"
            source.write_bytes(b"secret")
            source.chmod(0o644)
            with self.assertRaises(link.Refused): link.read_private(source)
            source.chmod(0o600)
            self.assertEqual(link.read_private(source), b"secret")
            target = root / "receipt"
            link.atomic_write_new(target, b"{}")
            self.assertEqual(target.read_bytes(), b"{}")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual([p for p in root.iterdir() if p.name.startswith(".link-outside-")], [])


if __name__ == "__main__":
    unittest.main()
