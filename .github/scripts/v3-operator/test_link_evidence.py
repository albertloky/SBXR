import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


assembler = load("test_link_assembler", "assemble-evidence.py")
outside = load("test_link_outside_adapter", "link-outside.py")
runtime = load("test_link_runtime_adapter", "link-runtime.py")


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


class LinkFixture:
    def __init__(self, root, scenario, now=None):
        self.root = Path(root)
        self.scenario = scenario
        self.precommit = scenario == "link-precommit"
        self.now = int(time.time() if now is None else now)
        self.t = {name: stamp(self.now + offset) for name, offset in {
            "not_before": -240, "prepared": -220, "started": -210, "entry_started": -205,
            "controller_started": -200, "old_initial": -198, "ready": -197,
            "preflight": -191, "route_started": -196, "route": -195, "action": -190, "target": -180,
            "challenge": -179, "ack": -178, "quiesced": -175, "closed": -174,
            "committed": -172, "interrupted": -170, "recovery": -160, "recovered": -150,
            "finalized": -149, "old_final": -145, "new_final": -144, "cleanup": -140,
            "last_connection": -130, "entry_checks": -125, "completed": -120,
            "proof": -110}.items()}
        self.paths = {}
        self.documents = {}

    def write(self, name, raw, mode=0o600):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.parent != self.root:
            path.parent.chmod(0o700)
        path.write_bytes(raw)
        path.chmod(mode)
        self.paths[name] = path
        return path

    def document(self, name, value, newline=False):
        self.documents[name] = value
        return self.write(name, canon(value) + (b"\n" if newline else b""))

    def replace(self, name, mutate, newline=None):
        value = copy.deepcopy(self.documents[name])
        mutate(value)
        if newline is None:
            newline = self.paths[name].read_bytes().endswith(b"\n")
        self.documents[name] = value
        self.paths[name].write_bytes(canon(value) + (b"\n" if newline else b""))

    def build(self, authority=None, validator=None):
        required = ["baseline-clean", "baseline-refusal", "baseline-precommit", "baseline-postcommit",
                    "baseline-drift", "baseline-removal", "identity-absent", "enable-schema1",
                    "link-precommit", "link-postcommit"]
        candidate = {"commit": "a" * 40, "release_identity": {"commit": "a" * 40,
                     "release_index_sha256": "b" * 64, "repository": "owner/repo", "tag": "v9.0.0"},
                     "sequence": 900, "tag": "v9.0.0"}
        packages = {"snap": {"name": "snapd"}, "certbot": {"name": "certbot"},
                    "karing": {"name": "karing"}}
        attempt = {"attempt_id": "attempt-1", "evidence_policy": assembler.POLICY,
                   "outside_runner_id": "runner-1", "packages": packages,
                   "required_scenarios": required, "runner": {"architecture": "amd64"},
                   "scenario_limit_seconds": 1800, "schema": "sbxr-v3-qualification-attempt-v3",
                   "started_at": stamp(self.now - 1000), "validation_limit_seconds": 300,
                   "vps_id": "vps-1", "vps_identity_sha256": "c" * 64}
        manifest = {"mode": "v3", "releases": [candidate], "schema": "sbxr-qualification-manifest-v3",
                    "source_state": "v3-subscription-clean", "v3_attempt": attempt}
        if authority is not None:
            manifest = copy.deepcopy(authority["manifest"])
            attempt = manifest["v3_attempt"]
            candidate = manifest["releases"][0]
            packages = attempt["packages"]
            required = attempt["required_scenarios"]
        manifest_raw = canon(manifest)
        manifest_sha = sha(manifest_raw)
        request = {"deadline_unix": self.now + 30, "not_before": self.t["not_before"],
                   "qualification_manifest_sha256": manifest_sha, "scenario_id": self.scenario,
                   "scenario_limit_seconds": 1800}
        request_raw = canon(request)
        request_sha = sha(request_raw)
        self.manifest_sha, self.request_sha = manifest_sha, request_sha

        prefix, previous = [], manifest_sha
        prefix_count = assembler.SCENARIO_INDEX[self.scenario]
        if authority is not None:
            prefix = copy.deepcopy(authority["prefix"])
        else:
            for index in range(prefix_count):
                start = stamp(self.now - 600 + index * 35)
                completed = stamp(self.now - 590 + index * 35)
                validated = stamp(self.now - 585 + index * 35)
                item = {"attempt_id": "attempt-1", "candidate": candidate, "completed_at": completed,
                        "operation_id": f"operation-{index + 1}", "packages_after": packages,
                        "packages_before": packages, "prior_scenario_sha256": previous,
                        "scenario_id": required[index], "schema": "sbxr-v3-scenario-evidence-v3",
                        "started_at": start, "validated_at": validated, "vps_id": "vps-1",
                        "vps_identity_sha256": "c" * 64}
                prefix.append(item)
                previous = sha(canon(item))
        prefix_raw = canon(prefix)

        token_old, token_new = "A" * 43, "B" * 43
        certs = [str(number) * 64 for number in (1, 2, 3, 4)]
        source = {"link_id": "a" * 32, "credential_sha256": sha(token_old.encode()),
                  "certificate_generation": 7, "certificate_sha256": certs}
        target = {"link_id": "b" * 32, "credential_sha256": sha(token_new.encode()),
                  "certificate_generation": 7, "certificate_sha256": certs}
        config = {"outbounds": [{"type": "vless", "server": "192.0.2.10"}]}
        config_sha = sha(canon(config))
        disclosure_binding = {"scenario_id": self.scenario, "request_sha256": request_sha,
            "qualification_manifest_sha256": manifest_sha, "deadline_unix": request["deadline_unix"],
            "not_before": request["not_before"]}
        initial = {"link": "https://192.0.2.10:8443/s/" + token_old,
                   "certificate_der_sha256": "d" * 64, "configuration": config,
                   "binding": disclosure_binding}
        final = copy.deepcopy(initial)
        if not self.precommit:
            final["link"] = "https://192.0.2.10:8443/s/" + token_new
        initial_raw, final_raw = canon(initial), canon(final)

        initial_hash = outside.hashes(initial)
        bound_public = {"scenario_id": self.scenario, "request_sha256": request_sha,
                        "qualification_manifest_sha256": manifest_sha,
                        "deadline_unix": request["deadline_unix"]}
        ready = dict(bound_public, schema="sbxr-v4-link-outside-ready-v1", started_at=self.t["started"],
            old_initial_at=self.t["old_initial"], ready_at=self.t["ready"],
            old_link_sha256=initial_hash["link"], configuration_sha256=initial_hash["configuration"],
            certificate_der_sha256=initial_hash["certificate"], initial_disclosure_sha256=sha(initial_raw),
            facts={"artifact_matches": True, "old_initial_200": True, "outside_route_distinct": True,
                   "trusted_tls": True})
        ready_raw = canon(ready)
        target_record_sha = "e" * 64
        challenge = dict(bound_public, schema="sbxr-v4-link-outside-challenge-v1", nonce="f" * 64,
            challenged_at=self.t["challenge"], ready_sha256=sha(ready_raw),
            initial_disclosure_sha256=sha(initial_raw), transition_record_sha256=target_record_sha)
        challenge_raw = canon(challenge)
        ack = dict(bound_public, schema="sbxr-v4-link-outside-ack-v1", challenge_sha256=sha(challenge_raw),
            connection_id="9" * 32, tls_established_at=self.t["challenge"],
            partial_request_sent_at=self.t["ack"], pending_ready_at=self.t["ack"],
            old_link_sha256=initial_hash["link"])
        ack_raw = canon(ack)
        closed = dict(bound_public, schema="sbxr-v4-link-outside-closed-v1", challenge_sha256=sha(challenge_raw),
            ack_sha256=sha(ack_raw), connection_id=ack["connection_id"],
            partial_request_sent_at=ack["partial_request_sent_at"], pending_ready_at=ack["pending_ready_at"],
            closed_at=self.t["closed"], closure_kind="eof", pending_elapsed_milliseconds=900,
            server_deadline_seconds=5, old_link_sha256=initial_hash["link"])
        closed_raw = canon(closed)

        source_process = {"pid": 100, "start_tick": 1000, "executable_device": 10,
                          "executable_inode": 20, "cgroup": "/system.slice/sbxr-subscription.service",
                          "serving_state_sha256": sha(runtime.serving_state_bytes(source))}
        proxy_process = {"pid": 200, "start_tick": 2000, "executable_device": 11,
                         "executable_inode": 21}
        selected = source if self.precommit else target
        recovered_process = dict(source_process, pid=101, start_tick=1001,
                                 serving_state_sha256=sha(runtime.serving_state_bytes(selected)))
        quiescent = {"active_state": "inactive", "main_pid": 0, "source_process_absent": True,
            "owned_processes_and_descendants_absent": True, "cgroup_state": "absent",
            "listener_8443_absent": True, "accepted_sockets_8443_absent": True,
            "unowned_kernel_time_wait_sockets": 1, "proxy_process": proxy_process,
            "configuration_sha256": config_sha}
        controller_runtime = {
            "initial": {"source_process": source_process, "proxy_process": proxy_process,
                        "configuration_sha256": config_sha, "staging_empty": True},
            "target_prepared": {"source_process": source_process,
                "target_state_sha256": sha(runtime.serving_state_bytes(target)),
                "target_credential_sha256": target["credential_sha256"],
                "source_still_running": True, "target_staged_only": True},
            "quiescent": quiescent,
            "recovered": {"subscription_process": recovered_process, "proxy_process": proxy_process,
                "configuration_sha256": config_sha, "selected_authority_sha256": sha(canon(selected)),
                "staging_empty": True}}
        if not self.precommit:
            controller_runtime["committed"] = dict(quiescent, observed_at=self.t["committed"],
                target_state_sha256=sha(runtime.serving_state_bytes(target)),
                target_credential_sha256=target["credential_sha256"], target_staged_only=True,
                serving_material="source", source_state_sha256=sha(runtime.serving_state_bytes(source)),
                source_credential_sha256=source["credential_sha256"])
        handoff = {"ready_sha256": sha(ready_raw), "ready_at": ready["ready_at"],
            "challenge_sha256": sha(challenge_raw), "challenged_at": challenge["challenged_at"],
            "ack_sha256": sha(ack_raw), "pending_ready_at": ack["pending_ready_at"],
            "connection_id": ack["connection_id"], "closed_sha256": sha(closed_raw),
            "closed_at": closed["closed_at"], "closure_kind": closed["closure_kind"],
            "pending_elapsed_milliseconds": closed["pending_elapsed_milliseconds"],
            "old_link_sha256": ready["old_link_sha256"], "configuration_sha256": ready["configuration_sha256"],
            "certificate_der_sha256": ready["certificate_der_sha256"]}
        controller = {"schema": "sbxr-v4-link-transition-controller-v1", "scenario": self.scenario,
            "phase": "recovered", "qualification_manifest_sha256": manifest_sha,
            "request_sha256": request_sha, "started_at": self.t["controller_started"],
            "action_started_at": self.t["action"], "target_prepared_at": self.t["target"],
            "quiesced_at": self.t["quiesced"], "interrupted_at": self.t["interrupted"],
            "recovery_started_at": self.t["recovery"], "recovered_at": self.t["recovered"],
            "initial_record_sha256": "1" * 64, "interrupted_record_sha256": "2" * 64,
            "final_record_sha256": "3" * 64, "target_record_sha256": target_record_sha,
            "field": "subscription_rotation.checkpoint",
            "checkpoint": "stop authorized" if self.precommit else "committed",
            "boundary_path": "/var/lib/sbxr/.proxy-ownership.json.next" if self.precommit else
                             "/var/lib/sbxr/subscription-token",
            "direction": "cleanup" if self.precommit else "forward",
            "result_code": "PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-CLEANED-UP" if self.precommit else
                           "PROXY-INSTALLATION-SUBSCRIPTION-LINK-ROTATED",
            "boundary_process": {"pid": 300, "start_tick": 3000, "executable_device": 12,
                "executable_inode": 22, "cgroup": f"/system.slice/sbxr-v4-{self.scenario}-300.service"},
            "source": source, "target": target,
            "source_target_comparison": runtime.comparison(source, target, "source",
                                            "source" if self.precommit else "target",
                                            "source" if self.precommit else "target"),
            "outside_handoff": handoff, "runtime": controller_runtime}
        controller_raw = canon(controller) + b"\n"
        finalize = dict(bound_public, schema="sbxr-v4-link-outside-finalize-v1",
            challenge_sha256=sha(challenge_raw), closed_sha256=sha(closed_raw),
            final_disclosure_sha256=sha(final_raw), recovered_transition_sha256=sha(controller_raw),
            recovered_at=self.t["recovered"], finalized_at=self.t["finalized"])
        finalize_raw = canon(finalize)
        final_hash = outside.hashes(final)
        result = dict(bound_public, schema="sbxr-v4-link-outside-result-v1", ready_sha256=sha(ready_raw),
            challenge_sha256=sha(challenge_raw), ack_sha256=sha(ack_raw), closed_sha256=sha(closed_raw),
            finalize_sha256=sha(finalize_raw), final_disclosure_sha256=sha(final_raw),
            started_at=ready["started_at"], old_initial_at=ready["old_initial_at"],
            pending_ready_at=ack["pending_ready_at"], closed_at=closed["closed_at"],
            old_final_at=self.t["old_final"], new_final_at=None if self.precommit else self.t["new_final"],
            cleanup_at=self.t["cleanup"], old_link_sha256=initial_hash["link"],
            new_link_sha256=None if self.precommit else final_hash["link"],
            configuration_sha256=initial_hash["configuration"],
            certificate_der_sha256=initial_hash["certificate"],
            facts={"old_final_200": self.precommit, "new_final_200": not self.precommit,
                   "old_final_404": not self.precommit, "same_configuration": True,
                   "same_certificate": True, "same_old_link": self.precommit,
                   "trusted_tls": True, "runner_cleanup_complete": True})
        result_raw = canon(result)

        state = {"schema": "sbxr-v4-link-entry-v1", "scenario_id": self.scenario,
            "qualification_manifest_sha256": manifest_sha, "request_sha256": request_sha,
            "started_at": self.t["started"], "entry_started_at": self.t["entry_started"],
            "completed_at": self.t["completed"], "initial_disclosure_sha256": sha(initial_raw),
            "final_disclosure_sha256": sha(final_raw), "controller_receipt_sha256": sha(controller_raw),
            "outside_receipt_sha256": sha(result_raw)}

        trace = (canon({"check": 1, "connection_id": "8" * 32, "request_sha256": request_sha,
                 "same_connection": True, "schema": "sbxr-v3-connection-probe-v1",
                 "time": self.t["started"]}) + b"\n" +
                 canon({"check": 2, "connection_id": "8" * 32, "request_sha256": request_sha,
                 "same_connection": True, "schema": "sbxr-v3-connection-probe-v1",
                 "time": self.t["last_connection"]}) + b"\n")
        summary = {"action_spanned": True, "checks": 2, "same_connection": True,
                   "trace_sha256": sha(trace)}

        capture = b"bounded retained operator capture\n"
        entry_events = {}
        early = {"preflight_completed_at": self.t["preflight"],
                 "running_proved_at": self.t["old_initial"]}
        rules = assembler.timing.scenario_rules(self.scenario)
        operator_rows = []
        for rule in rules:
            for anchor in rule.not_before:
                if anchor.source == "entry":
                    observed = early.get(anchor.event, self.t["entry_checks"])
                    entry_events[anchor.event] = observed
                    operator_rows.append({"capture_sha256": sha(capture), "check": rule.check,
                        "event": anchor.event, "observed_at": observed, "result": "observed"})
        operator = {"capture_sha256": sha(capture), "observations": operator_rows,
            "qualification_manifest_sha256": manifest_sha, "request_sha256": request_sha,
            "scenario_id": self.scenario, "schema": assembler.OPERATOR_SCHEMA}
        route = {"check": "supported-effective-route-inspected", "completed_at": self.t["route"],
            "effective_exec_verified": True, "owned_artifacts_sha256": {},
            "qualification_manifest_sha256": manifest_sha, "record_sha256": "6" * 64,
            "request_sha256": request_sha, "route": "official-snap", "scenario_id": self.scenario,
            "schema": "sbxr-v4-effective-route-v1", "started_at": self.t["route_started"],
            "timer_calendar_verified": True}

        source_events = {"entry": entry_events, "route": {"completed_at": route["completed_at"]},
            "controller": {key: controller[key] for key in ("action_started_at", "target_prepared_at",
                "quiesced_at", "interrupted_at", "recovery_started_at", "recovered_at")},
            "outside": {"old_initial_at": result["old_initial_at"], "closed_at": result["closed_at"],
                        "old_final_at": result["old_final_at"]},
            "connection": {"last_at": self.t["last_connection"]}}
        if result["new_final_at"] is not None:
            source_events["outside"]["new_final_at"] = result["new_final_at"]
        proof_rows = []
        for rule in rules:
            earliest = max(assembler.instant(source_events[a.source][a.event], "fixture")
                           for a in rule.not_before)
            proof_rows.append({"check": rule.check,
                "observed_at": stamp(earliest.epoch_second + (1 if earliest.nanosecond else 0)),
                "result": "observed"})
        proof = {"completed_at": self.t["proof"], "link_id": "",
                 "observations": proof_rows, "operation_id": f"operation-{prefix_count + 1}",
                 "scenario_id": self.scenario, "schema": assembler.LINK_PROOF_SCHEMA}

        boundary = copy.deepcopy(authority["boundary"]) if authority is not None else {"fixture": "boundary"}
        boundary_raw = canon(boundary)
        validator_body = b'''#!/usr/bin/env python3
import hashlib,json,sys
raw=sys.stdin.buffer.read(); facts=json.loads(raw)
value={"facts_sha256":hashlib.sha256(raw).hexdigest(),"outcome":"accepted","prior_decision_sha256":facts["prior_decision_sha256"],"records":[],"schema":"sbxr-release-qualification-decision-v1","stage":"v3-scenario-result"}
sys.stdout.write(json.dumps(value,sort_keys=True,separators=(",",":")))
'''
        if validator is None:
            validator_path = self.write("validator", validator_body, 0o700)
        else:
            validator_path = Path(validator)
            if not validator_path.is_absolute():
                raise ValueError("external validator path must be absolute")
        validator_sha = sha(validator_path.read_bytes())
        preparation = {"accepted_prior_prefix_sha256": sha(prefix_raw), "prepared_at": self.t["prepared"],
            "qualification_boundary_facts_sha256": sha(boundary_raw),
            "qualification_manifest_sha256": manifest_sha, "request_sha256": request_sha,
            "scenario_id": self.scenario, "schema": assembler.PREPARATION_SCHEMA,
            "validator_sha256": validator_sha, "verifications": [
                {"artifact_sha256": manifest_sha, "check": "fresh-signed-manifest",
                 "observed_at": stamp(self.now - 223), "result": "verified"},
                {"artifact_sha256": sha(boundary_raw), "check": "qualification-boundary",
                 "observed_at": stamp(self.now - 222), "result": "verified"},
                {"artifact_sha256": validator_sha, "check": "pinned-validator",
                 "observed_at": stamp(self.now - 221), "result": "verified"}]}

        common = (("manifest", manifest, False), ("boundary", boundary, False),
                  ("request", request, False), ("prefix", prefix, False),
                  ("preparation", preparation, True), ("operator", operator, True),
                  ("route", route, True), ("state", state, True), ("controller", controller, True),
                  ("summary", summary, True), ("proof", proof, True))
        for name, value, newline in common:
            self.document(name, value, newline)
        self.write("capture", capture)
        self.write("trace", trace)
        outside_dir = self.root / "outside"
        outside_dir.mkdir(mode=0o700)
        for name, value in (("initial", initial), ("final", final), ("ready", ready),
                            ("challenge", challenge), ("ack", ack), ("closed", closed),
                            ("finalize", finalize), ("result", result)):
            self.document("outside/" + f"link-{self.scenario}-{name}.json", value)

        self.output = self.root / "output"
        self.command = [sys.executable, str(HERE / "assemble-evidence.py"), self.scenario,
            "--manifest", str(self.paths["manifest"]), "--boundary", str(self.paths["boundary"]),
            "--request", str(self.paths["request"]), "--accepted-prior-prefix", str(self.paths["prefix"]),
            "--preparation-receipt", str(self.paths["preparation"]),
            "--operator-observations", str(self.paths["operator"]), "--operator-capture", str(self.paths["capture"]),
            "--effective-route", str(self.paths["route"]), "--state", str(self.paths["state"]),
            "--proof", str(self.paths["proof"]), "--validator", str(validator_path),
            "--validator-sha256", validator_sha, "--output", str(self.output),
            "--controller-receipt", str(self.paths["controller"]), "--outside-directory", str(outside_dir),
            "--connection-observation", str(self.paths["trace"]), "--connection-summary", str(self.paths["summary"])]

    def run(self):
        return subprocess.run(self.command, capture_output=True, text=True)


class LinkEvidenceTests(unittest.TestCase):
    def fixture(self, scenario):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        root.chmod(0o700)
        fixture = LinkFixture(root, scenario)
        fixture.build()
        return temporary, fixture

    def test_full_precommit_and_postcommit_assembly_preserves_wire_result(self):
        for scenario in ("link-precommit", "link-postcommit"):
            with self.subTest(scenario=scenario):
                temporary, fixture = self.fixture(scenario)
                with temporary:
                    result = fixture.run()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    facts = json.loads(fixture.output.read_bytes())
                    assembled = facts["detailed_evidence"]["scenarios"][-1]
                    self.assertEqual(assembled["scenario_id"], scenario)
                    self.assertEqual(assembled["boundary"], "before-commitment" if fixture.precommit else "after-commitment")
                    self.assertEqual(assembled["recovery_direction"], "rollback" if fixture.precommit else "forward")
                    self.assertEqual([row["record"] for row in assembled["evidence"]], fixture.documents["proof"]["observations"])

    def test_completed_scenario_uses_validation_grace_without_extending_operations(self):
        for scenario in ("link-precommit", "link-postcommit"):
            for delay, accepted in ((60, True), (250, False)):
                with self.subTest(scenario=scenario, delay=delay), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    root.chmod(0o700)
                    fixture = LinkFixture(root, scenario, now=int(time.time()) - delay)
                    fixture.build()
                    self.assertLess(fixture.documents['request']['deadline_unix'], time.time())
                    result = fixture.run()
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    self.assertEqual(fixture.output.exists(), accepted)
                    if not accepted:
                        self.assertIn('validation time lies outside signed limit', result.stderr)

    def test_fixture_accepts_authority_bytes_and_external_validator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed_root, replay_root = root / "seed", root / "replay"
            seed_root.mkdir(mode=0o700)
            replay_root.mkdir(mode=0o700)
            evaluation = int(time.time())
            seed = LinkFixture(seed_root, "link-precommit", now=evaluation)
            seed.build()
            authority = {key: copy.deepcopy(seed.documents[key])
                         for key in ("manifest", "boundary", "prefix")}
            replay = LinkFixture(replay_root, "link-precommit", now=evaluation)
            replay.build(authority=authority, validator=seed.paths["validator"])
            result = replay.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(replay.documents["manifest"], authority["manifest"])
            self.assertEqual(replay.documents["prefix"], authority["prefix"])

    def test_tampered_retained_chain_is_refused(self):
        temporary, fixture = self.fixture("link-precommit")
        with temporary:
            fixture.replace("outside/link-link-precommit-ack.json",
                            lambda value: value.update(connection_id="7" * 32))
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("complete current-request producer chain refused", result.stderr)

    def test_wrong_controller_boundary_and_direction_are_refused(self):
        for key, value in (("checkpoint", "committed"), ("direction", "forward")):
            with self.subTest(key=key):
                temporary, fixture = self.fixture("link-precommit")
                with temporary:
                    fixture.replace("controller", lambda document: document.update({key: value}), newline=True)
                    result = fixture.run()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("boundary, or recovery result differs", result.stderr)

    def test_missing_or_misordered_closure_is_refused(self):
        for case in ("missing", "misordered"):
            with self.subTest(case=case):
                temporary, fixture = self.fixture("link-postcommit")
                with temporary:
                    path = fixture.paths["outside/link-link-postcommit-closed.json"]
                    if case == "missing":
                        path.unlink()
                    else:
                        fixture.replace("outside/link-link-postcommit-closed.json",
                            lambda value: value.update(closed_at=stamp(fixture.now - 181)))
                    result = fixture.run()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(fixture.output.exists())

    def test_outside_event_outside_action_window_is_refused(self):
        temporary, fixture = self.fixture("link-precommit")
        with temporary:
            fixture.replace("outside/link-link-precommit-ready.json",
                lambda value: value.update(old_initial_at=stamp(fixture.now - 189)))
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(fixture.output.exists())

    def test_wrong_disclosed_authority_is_refused(self):
        temporary, fixture = self.fixture("link-postcommit")
        with temporary:
            fixture.replace("outside/link-link-postcommit-final.json",
                lambda value: value.update(link="https://192.0.2.10:8443/s/" + "C" * 43))
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(fixture.output.exists())

    def test_wrong_connection_trace_or_summary_is_refused(self):
        for case in ("trace", "summary"):
            with self.subTest(case=case):
                temporary, fixture = self.fixture("link-precommit")
                with temporary:
                    if case == "trace":
                        fixture.paths["trace"].write_bytes(fixture.paths["trace"].read_bytes().replace(b'"check":2', b'"check":3'))
                    else:
                        fixture.replace("summary", lambda value: value.update(checks=3), newline=True)
                    result = fixture.run()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("link proxy connection", result.stderr)


if __name__ == "__main__":
    unittest.main()
