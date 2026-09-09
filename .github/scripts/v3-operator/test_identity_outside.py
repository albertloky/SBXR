"""No live targets: exercise the producer, receipt checker and OS/network seams."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


PATH = Path(__file__).with_name("identity-outside.py")
SPEC = importlib.util.spec_from_file_location("identity_outside", PATH)
identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity)
EPOCH = identity.timestamp("2026-09-09T10:00:00Z")


def stamp(seconds):
    return identity.dt.datetime.fromtimestamp(EPOCH + seconds, identity.dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def inputs():
    state = {"started_at": stamp(0), "setup_at": stamp(0), "source_disclosure_confirmed": True}
    manifest = {"schema": "sbxr-qualification-manifest-v3", "mode": "v3", "v3_attempt": {
        "evidence_policy": "repair-issuance-bounded-v4", "proxy_package": identity.PACKAGE.copy(), "outside_runner_id": "runner-1"}}
    raw = identity.canonical(manifest)
    request = {"qualification_manifest_sha256": identity.hashlib.sha256(raw).hexdigest(),
               "scenario_id": "identity-absent", "not_before": stamp(0), "scenario_limit_seconds": 1800,
               "deadline_unix": int(EPOCH + 1800)}
    return raw, identity.canonical(request), state


class FixtureConnection:
    def __init__(self, backend, kind):
        self.backend, self.kind, self.count = backend, kind, 0
        self.closed = False

    def request(self):
        self.count += 1
        self.backend.events.append(("traffic", self.kind, self.count))
        if self.kind == "established" and self.count >= self.backend.close_at:
            if self.backend.old_timeout:
                raise socket.timeout("not termination evidence")
            raise identity.ClosedTransport()
        if self.kind == "fresh-old":
            if self.backend.refusal == "timeout":
                raise socket.timeout("not refusal evidence")
            if self.backend.refusal == "closed":
                raise identity.ClosedTransport()
        if self.kind == "healthy" and not self.backend.healthy:
            raise OSError("fixture target unhealthy")
        if self.kind == "replacement" and not self.backend.replacement:
            raise identity.ClosedTransport()

    def close(self):
        self.closed = True


class FixtureBackend:
    """Only the transport/OS seam is substituted; produce and check are real."""
    def __init__(self, bound, state):
        self.bound, self.initial = bound, state
        self.seconds = 0
        self.events, self.published, self.connections = [], {}, []
        self.close_at, self.old_timeout = 3, False
        self.refusal, self.healthy, self.replacement = "closed", True, True
        self.cleanup_ok, self.alive, self.current_client = True, True, "old"
        self.closed_cleanup, self.acknowledged, self.delayed_rotation = False, False, False

    def prepare(self):
        self.events.append(("prepare",))

    def start_client(self, replacement=False):
        self.current_client = "replacement" if replacement else "old"
        return {"pid": 202 if replacement else 101, "start_tick": 987 if replacement else 123,
                "listener_owned": True, "confirmed_disclosure": True}

    def routes(self):
        self.events.append(("route-proof", self.current_client))

    def connect(self, proxy=True):
        kind = "healthy" if not proxy else "replacement" if self.current_client == "replacement" else "fresh-old" if self.connections else "established"
        result = FixtureConnection(self, kind)
        self.connections.append(result)
        return result

    def clock(self):
        self.seconds += 1
        identity.require(EPOCH + self.seconds <= self.bound["deadline_unix"])
        return stamp(self.seconds)

    def pause(self):
        self.clock()

    def publish(self, name, document):
        identity.require(name not in self.published)
        self.published[name] = copy.deepcopy(document)
        if name == "07-outside-rotation-ready.json":
            self.acknowledged = True

    def challenge(self):
        return dict(self.bound, nonce="f" * 32, challenged_at=stamp(self.seconds))

    def client_alive(self):
        identity.require(self.alive)

    def state(self):
        if self.delayed_rotation:
            return self.initial.copy()
        return dict(self.initial, rotation_started_at=stamp(4.5), rotation_completed_at=stamp(6),
                    replacement_disclosure_confirmed=True)

    def stop_client(self):
        self.events.append(("stop-client", self.current_client))

    def cleanup(self):
        self.closed_cleanup = True
        identity.require(self.cleanup_ok)


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.request, self.state = inputs()
        self.bound = identity.binding(self.manifest, self.request, self.state)
        self.backend = FixtureBackend(self.bound, self.state)

    def produce(self):
        return identity.produce(self.backend, self.bound, self.state)

    def assert_failed(self):
        with self.assertRaises(Exception):
            self.produce()
        self.assertTrue(self.backend.closed_cleanup)
        self.assertNotIn("07-outside.json", self.backend.published)

    def test_real_producer_builds_checkable_complete_receipt_and_orders_observations(self):
        receipt = self.produce()
        self.assertEqual(identity.check(receipt, self.bound, self.backend.state()), receipt)
        self.assertTrue(self.backend.closed_cleanup)
        self.assertEqual(list(self.backend.published), ["07-outside-ready.json", "07-outside-rotation-ready.json", "07-outside.json"])
        self.assertEqual([item.kind for item in self.backend.connections], ["established", "fresh-old", "healthy", "replacement"])
        self.assertEqual(self.backend.connections[0].count, 3)
        self.assertTrue(all(item.closed for item in self.backend.connections))
        self.assertEqual(receipt["facts"], identity.FACTS)
        self.assertNotIn("outbounds", identity.canonical(receipt).decode())

    def test_closure_before_handshake_cannot_authorize_rotation(self):
        self.backend.close_at = 2
        self.assert_failed()
        self.assertNotIn("07-outside-rotation-ready.json", self.backend.published)

    def test_timeout_is_neither_termination_nor_refusal_evidence(self):
        self.backend.old_timeout = True
        self.assert_failed()
        self.backend = FixtureBackend(self.bound, self.state)
        self.backend.refusal = "timeout"
        self.assert_failed()
        self.assertEqual(len([item for item in self.backend.connections if item.kind == "fresh-old"]), 1)

    def test_fresh_old_success_fails_without_retry(self):
        self.backend.refusal = "success"
        self.assert_failed()
        self.assertEqual(len(self.backend.connections), 2)

    def test_target_failure_replacement_failure_and_cleanup_failure_publish_no_pass(self):
        for field in ("healthy", "replacement", "cleanup_ok", "alive"):
            with self.subTest(field=field):
                self.backend = FixtureBackend(self.bound, self.state)
                setattr(self.backend, field, False)
                self.assert_failed()

    def test_original_deadline_bounds_held_session_and_wait_for_remote_completion(self):
        self.backend.bound["deadline_unix"] = EPOCH + 12
        self.backend.close_at = 100
        self.assert_failed()
        self.backend = FixtureBackend(self.bound, self.state)
        self.backend.delayed_rotation = True
        self.assert_failed()

    def test_checker_refuses_timestamp_only_or_changed_binding_and_negative_facts(self):
        receipt = self.produce()
        with self.assertRaises(ValueError):
            identity.check({key: receipt[key] for key in ("old_established_at", "old_terminated_at", "old_refused_at", "replacement_at")}, self.bound, self.backend.state())
        for field, bad in (("request_sha256", "0" * 64), ("qualification_manifest_sha256", "1" * 64),
                           ("outside_runner_id", "runner-2"), ("deadline_unix", EPOCH + 1900),
                           ("old_terminated_at", stamp(1)), ("old_refused_at", stamp(5)),
                           ("cleanup_at", stamp(1801)), ("rotation_ready_at", stamp(5))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                identity.check(dict(receipt, **{field: bad}), self.bound, self.backend.state())
        for fact in identity.FACTS:
            for value in (False, 1):
                bad = copy.deepcopy(receipt)
                bad["facts"][fact] = value
                with self.subTest(fact=fact, value=value), self.assertRaises(ValueError):
                    identity.check(bad, self.bound, self.backend.state())

    def test_challenge_cannot_be_replayed_stale_or_from_another_request(self):
        self.produce()
        ack = self.backend.published["07-outside-rotation-ready.json"]
        challenge = {key: value for key, value in ack.items() if key not in ("connection_id", "alive_at")}
        identity.check_rotation_ack(ack, challenge, self.bound, EPOCH + 5)
        for bad, current in ((dict(ack, nonce="e" * 32), EPOCH + 5), (ack, EPOCH + 10),
                             (dict(ack, request_sha256="0" * 64), EPOCH + 5)):
            with self.assertRaises(ValueError):
                identity.check_rotation_ack(bad, challenge, self.bound, current)

    def test_binding_refuses_manifest_package_deadline_and_request_drift(self):
        for field, value in (("scenario_id", "enable-schema1"), ("scenario_limit_seconds", 1801),
                             ("qualification_manifest_sha256", "0" * 64), ("deadline_unix", int(EPOCH + 1801))):
            request = identity.decode(self.request)
            request[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                identity.binding(self.manifest, identity.canonical(request), self.state)

    def test_cli_checker_verifies_generated_proof_and_companion_challenge_files(self):
        receipt = self.produce()
        ack = self.backend.published["07-outside-rotation-ready.json"]
        challenge = {key: value for key, value in ack.items() if key not in ("connection_id", "alive_at")}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, raw in (("manifest", self.manifest), ("request", self.request), ("state", identity.canonical(self.backend.state())),
                              ("07-outside.json", identity.canonical(receipt)), ("07-outside-rotation-request.json", identity.canonical(challenge)),
                              ("07-outside-rotation-ready.json", identity.canonical(ack))):
                identity.write_new(root / name, raw)
            command = [sys.executable, str(PATH), "check-result", "--manifest", str(root / "manifest"), "--request", str(root / "request"),
                       "--state", str(root / "state"), "--receipt", str(root / "07-outside.json")]
            good = subprocess.run(command, capture_output=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(good.stdout, b'{"identity_outside_verified":true}\n')
            (root / "07-outside-rotation-ready.json").unlink()
            failed = subprocess.run(command, capture_output=True)
            self.assertEqual(failed.returncode, 1)
            self.assertEqual(failed.stdout, b"")
            self.assertEqual(failed.stderr, b'{"identity_outside_failed":true}\n')


class SafetySeamTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "actual renameat2 requires the outside Linux runner")
    def test_atomic_phase_publication_has_one_link_no_overwrite_and_no_temporary_residue(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "receipt.json"
            payload = b'{"complete":true}'
            identity.atomic_write_new(target, payload)
            self.assertEqual(identity.read_private(target), payload)
            self.assertEqual(target.stat().st_nlink, 1)
            with self.assertRaises(OSError):
                identity.atomic_write_new(target, b'{"replacement":true}')
            self.assertEqual(identity.read_private(target), payload)
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_private_input_rejects_symlinks_hardlinks_mode_and_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            identity.write_new(source, b'{"private":"value"}')
            self.assertEqual(identity.read_private(source), source.read_bytes())
            symlink = root / "symlink"
            symlink.symlink_to(source)
            with self.assertRaises(OSError):
                identity.read_private(symlink)
            os.link(source, root / "hardlink")
            with self.assertRaises(ValueError):
                identity.read_private(source)
            (root / "hardlink").unlink()
            source.chmod(0o644)
            with self.assertRaises(ValueError):
                identity.read_private(source)
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(ValueError):
                identity.read_private(fifo)

    def test_subprocess_capture_never_exposes_raw_failure_details(self):
        options = {"ssh_key": "/private/key", "known_hosts": "/private/hosts", "host": "fixture.invalid"}
        backend = identity.LiveBackend(options, {"deadline_unix": EPOCH + 1800})
        raw = b"fixture-secret-uuid-do-not-print"
        with mock.patch.object(identity.time, "time", return_value=EPOCH), \
             mock.patch.object(identity.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, raw, raw)), \
             self.assertRaisesRegex(ValueError, "^identity-outside-refused$"):
            backend.command(["fixture"])

    def test_cleanup_removes_secret_and_package_files_even_when_scan_refuses(self):
        backend = identity.LiveBackend({"ssh_key": "/key", "known_hosts": "/hosts", "host": "fixture.invalid"}, {"deadline_unix": 1})
        backend.root = Path(tempfile.mkdtemp())
        backend.package_root = Path(tempfile.mkdtemp())
        (backend.root / "source.json").write_text("fixture secret")
        with mock.patch.object(backend, "scan", side_effect=ValueError("fixture leak")), self.assertRaises(ValueError):
            backend.cleanup()
        self.assertFalse(backend.root.exists())
        self.assertFalse(backend.package_root.exists())

    def test_tls_timeout_and_reset_have_distinct_results_without_network(self):
        backend = mock.Mock()
        backend.timeout.return_value = 1
        connection = identity.TLSConnection.__new__(identity.TLSConnection)
        connection.backend, connection.sock = backend, mock.Mock()
        connection.sock.sendall.side_effect = socket.timeout("fixture timeout")
        with self.assertRaises(socket.timeout):
            connection.request()
        connection.sock.sendall.side_effect = ConnectionResetError("fixture reset")
        with self.assertRaises(identity.ClosedTransport):
            connection.request()

    def test_wrong_client_listener_fails_before_any_traffic_or_ready_receipt(self):
        manifest, request, state = inputs()
        bound = identity.binding(manifest, request, state)
        backend = identity.LiveBackend({"ssh_key": "/key", "known_hosts": "/hosts", "host": "fixture.invalid"}, bound)
        config = {"inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
                  "outbounds": [{"type": "vless", "uuid": "11111111-1111-4111-8111-111111111111", "server": "192.0.2.1"}]}
        with tempfile.TemporaryDirectory() as directory:
            backend.root, backend.binary = Path(directory), "/verified/fixture/sing-box"
            process = mock.Mock(pid=1234)
            process.poll.return_value = None
            with mock.patch.object(backend, "state", return_value=state), \
                 mock.patch.object(backend, "fetch", return_value=identity.canonical(config)), \
                 mock.patch.object(backend, "command", return_value=b""), \
                 mock.patch.object(backend, "timeout", return_value=1), \
                 mock.patch.object(backend, "listener", return_value=b'LISTEN 0 10 127.0.0.1:2080 users:(("fixture",pid=9876,fd=3))'), \
                 mock.patch.object(identity.subprocess, "Popen", return_value=process), \
                 mock.patch.object(identity.time, "monotonic", side_effect=[0, 0, 0, 11]), \
                 mock.patch.object(identity.time, "sleep"), self.assertRaises(ValueError):
                backend.start_client()
            self.assertTrue((backend.root / "source.json").exists())
            self.assertEqual((backend.root / "source.json").stat().st_mode & 0o777, 0o600)

    def test_replacement_must_change_only_uuid_in_the_confirmed_configuration(self):
        backend = identity.LiveBackend({"ssh_key": "/key", "known_hosts": "/hosts", "host": "fixture.invalid"}, {"deadline_unix": 1})
        config = {"inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
                  "outbounds": [{"type": "vless", "uuid": "11111111-1111-4111-8111-111111111111", "server": "192.0.2.1"}]}
        backend.source = copy.deepcopy(config)
        for change in ({}, {"uuid": "22222222-2222-4222-8222-222222222222", "server": "192.0.2.2"}):
            candidate = copy.deepcopy(config)
            candidate["outbounds"][0].update(change)
            with mock.patch.object(backend, "state", return_value={"replacement_disclosure_confirmed": True}), \
                 mock.patch.object(backend, "fetch", return_value=identity.canonical(candidate)), self.assertRaises(ValueError):
                backend.start_client(replacement=True)


if __name__ == "__main__":
    unittest.main()
