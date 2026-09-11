#!/usr/bin/env python3
import importlib.util
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import io
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = load("managed_evidence", "managed-evidence.py")
timing = load("managed_timing", "evidence-timing.py")
renewal = load("managed_renewal_outside", "renewal-outside.py")


COMMON = "fresh-disposable-vps-preflight unchanged-candidate-bytes initial-state-proved boundary-observed final-state-proved original-ssh-continuity capture-coverage-complete exact-secrets-absent prohibited-patterns-absent supported-effective-route-inspected"
FAMILY = "proxy-and-traffic-unchanged client-identity-unchanged unchanged-link"
EXTRA = {
    "managed-renewal": "supported-managed-attempt-interrupted recorder-unknown-or-failed reviewed-repair-targeted-production-replacement fault-retained-until-proof official-schedule-integration recorder-start recorder-outcome production-issuance canonical-publication accepted-activation outside-tls natural-timer-not-observed naturally-due-renewal-not-observed",
    "recorder-live": "live-attempt live-and-abandoned-distinguished live-not-completed",
    "recorder-locks": "lock-order-contention no-evidence-lock-held-during-child-or-whole-host-wait bounded-refusal",
    "snap-refresh": "supported-snap-refresh effective-generated-route-preserved recorder-and-hooks-verified planned-package-change-only",
    "unsupported-route": "new-or-renamed-route-detected problem-detected accounting-gap-explicit bypass-prevention-not-claimed historical-outcomes-unknown",
}


def populate_fixture(ctx):
    """Write a complete positive captured-source family for a real later.Context."""
    def instant(value): return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    def stamp(value): return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    entry, action_start = instant(ctx.state["entry_started_at"]), instant(ctx.state["action_started_at"])
    action_done, completed = instant(ctx.state["action_completed_at"]), instant(ctx.state["completed_at"])
    def between(left, right, fraction=.5): return left + (right-left)*fraction
    before_at, held_at = between(entry, action_start, .35), between(action_start, action_done, .1)
    final_at = between(action_done, completed, .35)
    outside_start, outside_initial = between(entry, action_start, .1), between(entry, action_start, .2)
    outside_final, outside_done = between(action_done, completed, .2), between(action_done, completed, .3)
    capture_end = between(action_done, completed, .8)
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    def write(name, value):
        path = ctx.directory / name
        path.write_bytes(canonical(value) + b"\n")
        path.chmod(0o600)
    def capture(name, helper, rows, started=entry, ended=capture_end):
        value = {"schema": "sbxr-v4-captured-source-v1", "scenario_id": ctx.scenario,
                 "qualification_manifest_sha256": ctx.manifest_sha, "request_sha256": ctx.request_sha,
                 "helper": helper, "started_at": stamp(started), "completed_at": stamp(ended),
                 "exit_code": 0, "events": [{"observed_at": stamp(at), "record": row} for at, row in rows]}
        write(name, value)
    number = {name: str(11+index) for index, name in enumerate(m.SCENARIOS)}[ctx.scenario]
    binding = {"scenario_id": ctx.scenario, "request_sha256": ctx.request_sha,
               "qualification_manifest_sha256": ctx.manifest_sha, "deadline_unix": ctx.request["deadline_unix"],
               "not_before": ctx.request["not_before"], "outside_runner_id": "runner-1"}
    configuration = {"inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
                     "outbounds": [{"type": "vless", "tag": "SBXR", "server": "203.0.113.7",
                                    "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}], "log": {}}
    link_value = "https://203.0.113.7:8443/s/" + "A"*43
    initial_disclosure = {"link": link_value, "certificate_der_sha256": "6"*64,
                          "configuration": configuration,
                          "binding": {key: value for key, value in binding.items() if key != "outside_runner_id"}}
    final_disclosure = dict(initial_disclosure)
    if ctx.scenario == "managed-renewal": final_disclosure["certificate_der_sha256"] = "7"*64
    initial_raw, final_raw = canonical(initial_disclosure) + b"\n", canonical(final_disclosure) + b"\n"
    write(number + "-subscription-before.json", initial_disclosure)
    write(number + "-subscription-final.json", final_disclosure)
    config_sha, link_sha = sha(canonical(configuration)), sha(link_value.encode())
    route = {key: (["8"*64, "9"*64] if key == "hooks_sha256" else "8"*64) for key in m.ROUTE_KEYS}
    packages = ctx.manifest["v3_attempt"]["packages"]
    final_packages = ctx.manifest["v3_attempt"].get("after_snap_refresh", packages) if ctx.scenario == "snap-refresh" else packages
    history_before = {"schema": 1, "recorder_id": "1"*32, "established_at": stamp(entry), "attempts": []}
    lineage4 = "../../archive/sbxr-subscription/cert4.pem"
    lineage5 = "../../archive/sbxr-subscription/cert5.pem"
    def attempt(identifier, exit_code, started, ended, invocation="snap-certbot-renew-v1", after=lineage4, outcome="no-op"):
        return {"attempt_id": identifier, "invocation": invocation, "started_at": stamp(started),
                "boot_id": "boot-1", "recorder_pid": 21, "process_tick": 22, "lineage_before": lineage4,
                "completion": {"exit_code": exit_code, "completed_at": stamp(ended), "owned_outcome": outcome, "lineage_after": after}}
    history_final = json.loads(json.dumps(history_before))
    history_interrupted = history_repaired = None
    if ctx.scenario == "managed-renewal":
        history_interrupted = json.loads(json.dumps(history_before))
        history_interrupted["attempts"] = [attempt("f"*32, 1, held_at, between(action_start, action_done, .2))]
        history_repaired = json.loads(json.dumps(history_interrupted))
        history_repaired["attempts"].append(attempt("a"*32, 0, between(action_start, action_done, .4),
            between(action_start, action_done, .6), "snap-certbot-certonly-v1", lineage5, "renewed"))
        history_final["established_at"] = stamp(between(action_start, action_done, .7))
    elif ctx.scenario in ("recorder-live", "recorder-locks"):
        history_final["attempts"] = [attempt("f"*32, 0, held_at, between(action_start, action_done, .2))]
    before_history, final_history = sha(canonical(history_before)), sha(canonical(history_final))
    base = {"schema": "sbxr-v4-managed-snapshot-v1", "scenario_id": ctx.scenario,
            "qualification_manifest_sha256": ctx.manifest_sha, "request_sha256": ctx.request_sha,
            "status": "Running", "proxy_configuration_sha256": config_sha, "client_identity_sha256": "2"*64,
            "link_id": "3"*32, "link_sha256": link_sha, "subscription_artifact_sha256": config_sha,
            "certificate_generation": 4, "certificate_sha256": ["6"*64]*4, "certificate_der_sha256": "6"*64, "ownership_sha256": "5"*64,
            "route": route, "unrelated_packages_sha256": "c"*64, "unrelated_lineages_sha256": "d"*64,
            "active_package_work": False, "active_certbot": False, "writer_active": False,
            "local_activation_accepted": True, "bounded_refusal": None}
    before = dict(base, phase="before", observed_at=stamp(before_at), packages=packages, renewal_history_sha256=before_history)
    final = dict(base, phase="final", observed_at=stamp(final_at), packages=final_packages, renewal_history_sha256=final_history)
    if ctx.scenario == "managed-renewal":
        final.update(certificate_generation=5, certificate_sha256=["7"*64]*4, certificate_der_sha256="7"*64)
    if ctx.scenario == "recorder-locks":
        final["bounded_refusal"] = {"active_state": "failed", "exec_main_status": 125, "certbot_child": False}
    capture(number+"-managed-before.json", "managed-evidence", [(before_at, before)], entry, between(entry, action_start, .45))
    capture(number+"-managed-final.json", "managed-evidence", [(final_at, final)], action_done, between(action_done, completed, .45))
    before_envelope = {"schema": "sbxr-v4-renewal-history-source-v1", "source_sha256": before_history, "history": history_before}
    final_envelope = {"schema": "sbxr-v4-renewal-history-source-v1", "source_sha256": final_history, "history": history_final}
    capture(number+"-renewal-before.json", "managed-evidence", [(before_at, before_envelope)], entry, between(entry, action_start, .45))
    capture(number+"-renewal-final.json", "managed-evidence", [(final_at, final_envelope)], action_done, between(action_done, completed, .45))
    if ctx.scenario == "managed-renewal":
        interrupted_sha, repaired_sha = sha(canonical(history_interrupted)), sha(canonical(history_repaired))
        capture("11-renewal-interrupted.json", "managed-evidence", [(between(action_start, action_done, .25),
            {"schema": "sbxr-v4-renewal-history-source-v1", "source_sha256": interrupted_sha, "history": history_interrupted})],
            action_start, between(action_start, action_done, .3))
        capture("11-renewal-repaired.json", "managed-evidence", [(between(action_start, action_done, .65),
            {"schema": "sbxr-v4-renewal-history-source-v1", "source_sha256": repaired_sha, "history": history_repaired})],
            between(action_start, action_done, .62), between(action_start, action_done, .68))
    ready = renewal.ready_receipt(binding, initial_raw, initial_disclosure, stamp(outside_start), stamp(outside_initial),
                                  stamp(between(outside_initial, action_start, .25)))
    ready_raw = canonical(ready) + b"\n"
    outside_receipt = {**{key: binding[key] for key in renewal.BOUND_KEYS},
        "schema": "sbxr-v4-renewal-outside-v1", "ready_sha256": sha(ready_raw),
        "started_at": stamp(outside_start), "initial_at": stamp(outside_initial), "ready_at": ready["ready_at"],
        "action_completed_at": ctx.state["action_completed_at"], "final_at": stamp(outside_final),
        "completed_at": stamp(outside_done),
        "initial_disclosure_sha256": sha(initial_raw), "final_disclosure_sha256": sha(final_raw),
        "link_sha256": link_sha, "configuration_sha256": config_sha,
        "initial_certificate_der_sha256": initial_disclosure["certificate_der_sha256"],
        "final_certificate_der_sha256": final_disclosure["certificate_der_sha256"],
        "facts": {"artifact_fields_and_name": True, "outside_route_distinct": True,
                  "runner_cleanup_complete": True, "trusted_outside_tls": True,
                  "unchanged_link_and_configuration": True}}
    write(number+"-outside-ready.json", ready)
    write(number+"-outside-result.json", outside_receipt)
    trace_rows = []
    for index, at in enumerate((between(entry, action_start, .8), between(action_done, completed, .1)), 1):
        trace_rows.append((at, {"check": index, "connection_id": "e"*32, "request_sha256": ctx.request_sha,
                               "same_connection": True, "schema": "sbxr-v3-connection-probe-v1", "time": stamp(at)}))
    capture(number+"-proxy-trace.json", "connection-probe", trace_rows, between(entry, action_start, .6), between(action_done, completed, .15))
    if ctx.scenario in ("managed-renewal", "recorder-live"):
        held = {"state": "held", "attempt_id": "f"*32, "receipt_sha256": "1"*64, "egress_denied": True}
        end_state = "interrupted" if ctx.scenario == "managed-renewal" else "completed"
        end = {"state": end_state, "receipt_sha256": final_history if ctx.scenario == "recorder-live" else interrupted_sha, "no_ca_egress": True}
        capture(number+"-managed.json", "managed-hold", [(held_at, held), (between(action_start, action_done, .25), end)], before_at, between(action_start, action_done, .35))
        if ctx.scenario == "managed-renewal":
            capture("11-repair-boundary.json", "syscall-gate", [
                (between(action_start, action_done, .3), {"state": "armed"}),
                (between(action_start, action_done, .62), {"state": "boundary-held", "boundary": "after-close",
                 "path": "/var/lib/sbxr/.renewal-attempts.json.next", "record_sha256": repaired_sha, "boundary_index": 0}),
                (between(action_start, action_done, .68), {"state": "released"})],
                between(action_start, action_done, .28), between(action_start, action_done, .69))
    elif ctx.scenario == "recorder-locks":
        held = {"state": "boundary-held", "mode": "admission", "writer": {"lock_state": "unlocked"},
                "admission": {"lock_state": "locked"}, "whole_host": {"lock_state": "unlocked"}}
        capture("13-admission.json", "recorder-boundary", [(held_at, held), (between(action_start, action_done, .15), {"state": "completed", "receipt_sha256": final_history, "no_ca_egress": True})], before_at, between(action_start, action_done, .2))
        wait_held = between(action_start, action_done, .35)
        wait_before_at = between(action_start, action_done, .4)
        wait_observed = between(action_start, action_done, .5)
        wait_final_at = between(action_start, action_done, .6)
        wait_released = between(action_start, action_done, .65)
        capture("13-whole-host.json", "hold-flock", [(wait_held, {"state": "held", "pid": 22, "sha256": "3"*64}),
                                                       (wait_released, {"state": "released"})],
                between(action_start, action_done, .3), between(action_start, action_done, .7))
        wait_envelope = {"schema": "sbxr-v4-renewal-history-source-v1", "source_sha256": final_history, "history": history_final}
        capture("13-wait-renewal-before.json", "managed-evidence", [(wait_before_at, wait_envelope)], wait_held, wait_observed)
        capture("13-whole-host-wait.json", "observations", [(wait_observed, {
            "schema": "sbxr-v4-lock-observation-v1", "lock_api": "flock", "observations": [
                {"path": "/var/lib/sbxr/renewal-writer.lock", "state": "present", "kind": "file", "nlink": 1,
                 "lock_state": "unlocked", "holders": []},
                {"path": "/run/lock/sbxr.lock", "state": "present", "kind": "file", "nlink": 1,
                 "lock_state": "locked", "holders": [{"mode": "WRITE", "pid": 22}]},
            ]})], wait_before_at, wait_final_at)
        capture("13-wait-renewal-final.json", "managed-evidence", [(wait_final_at, wait_envelope)], wait_observed, wait_released)
    elif ctx.scenario == "unsupported-route":
        unit = {"device": 1, "inode": 2, "uid": 0, "gid": 0, "mode": "0644", "size": 9, "sha256": "4"*64}
        timer = {"enabled": "enabled", "active": "active", "persistent": "no"}
        inject_at = between(action_start, action_done, .1)
        restore_at = between(action_start, action_done, .8)
        capture("15-route-inject.json", "route-control", [(inject_at, {"schema": "sbxr-v4-route-control-v1", "unit": unit, "timer": timer})], action_start, between(action_start, action_done, .2))
        capture("15-route-restore.json", "route-control", [(restore_at, {"schema": "sbxr-v4-route-control-v1", "restored": True, "unit": unit, "timer": timer})], between(action_start, action_done, .7), between(action_start, action_done, .9))


class API:
    class Refusal(ValueError): pass
    SHA256 = timing.SHA256

    @staticmethod
    def exact(value, keys, label):
        if not isinstance(value, dict) or set(value) != set(keys):
            raise API.Refusal(label)
        return value
    @staticmethod
    def before(left, right): return timing.parse_instant(left, "left") <= timing.parse_instant(right, "right")


class ManagedEvidence(unittest.TestCase):
    def test_populate_fixture_passes_real_context_adapters(self):
        assembler = load("managed_fixture_assembler", "assemble-evidence.py")
        later = load("managed_fixture_context", "scenario-sources.py")
        packages = {name: {"name": name, "version": "1", "architecture": "amd64", "size": 1,
                           "sha256": digit*64, "repository": "fixture"}
                    for name, digit in (("snap", "1"), ("certbot", "2"), ("karing", "3"))}
        after = {name: dict(value) for name, value in packages.items()}
        after["certbot"] = dict(after["certbot"], version="2", sha256="4"*64)
        for scenario in m.SCENARIOS:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as folder:
                directory = Path(folder); directory.chmod(0o700)
                manifest = {"schema": "sbxr-qualification-manifest-v3", "mode": "v3", "v3_attempt": {
                    "evidence_policy": "repair-issuance-bounded-v4", "scenario_limit_seconds": 1800,
                    "required_scenarios": list(m.SCENARIOS), "packages": packages, "after_snap_refresh": after,
                    "outside_runner_id": "runner-1"}}
                manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
                request = {"scenario_id": scenario, "qualification_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                           "scenario_limit_seconds": 1800, "not_before": "2030-01-01T00:00:00Z", "deadline_unix": 1893457800}
                request_raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                state = {"started_at": "2030-01-01T00:00:01Z", "entry_started_at": "2030-01-01T00:00:02Z",
                         "action_started_at": "2030-01-01T00:02:00Z", "action_completed_at": "2030-01-01T00:08:00Z",
                         "completed_at": "2030-01-01T00:10:00Z"}
                context = later.Context(assembler, scenario, manifest, manifest_raw, hashlib.sha256(manifest_raw).hexdigest(),
                                        request, request_raw, hashlib.sha256(request_raw).hexdigest(), state, directory)
                populate_fixture(context)
                sources = m.sources(context)
                expected = {"before", "final", "history_before", "history_final", "outside", "connection"}
                if scenario in ("managed-renewal", "recorder-live", "recorder-locks"): expected.add("operator")
                if scenario == "managed-renewal": expected.update(("history_interrupted", "history_repaired", "repair_boundary"))
                if scenario == "recorder-locks": expected.update(("whole_host", "during_wait", "wait_history_before", "wait_history_final"))
                if scenario == "unsupported-route": expected.update(("route_inject", "route_restore"))
                self.assertEqual(set(sources), expected)

    def test_rules_exactly_match_go_order_and_all_have_real_anchors(self):
        for scenario in m.SCENARIOS:
            with self.subTest(scenario=scenario):
                rules = m.rules(timing, scenario)
                expected = (COMMON + " " + FAMILY + " " + EXTRA[scenario]).split()
                self.assertEqual([rule.check for rule in rules], expected)
                self.assertEqual(len(rules), len({rule.check for rule in rules}))
                self.assertTrue(all(rule.required_sources and rule.not_before and rule.not_after for rule in rules))

    def test_operator_capture_refuses_labels_without_actual_helper_facts(self):
        class Context:
            api = API()
            scenario = "managed-renewal"
            def capture(self, filename, helper):
                return ({"events": [{"observed_at": "2030-01-01T00:00:01Z", "record": {"state": "held"}},
                                    {"observed_at": "2030-01-01T00:00:02Z", "record": {"state": "interrupted"}}]}, b"capture")
            def source(self, name, raw, events): return timing.EventSource(name, "managed-renewal", "a"*64, "b"*64, raw, "c"*64, events)
        with self.assertRaisesRegex(API.Refusal, "receipt and no-egress"):
            m._operator_sources(Context(), "11")

    def test_snapshot_refuses_missing_hashes_and_untyped_activity(self):
        base = {key: None for key in m.SNAPSHOT_KEYS}
        base.update(schema="sbxr-v4-managed-snapshot-v1", scenario_id="snap-refresh",
                    qualification_manifest_sha256="a"*64, request_sha256="b"*64, phase="before",
                    observed_at="2030-01-01T00:00:01Z", status="Running", packages={}, link_id="link-1",
                    certificate_generation=1, certificate_sha256=["c"*64]*4, certificate_der_sha256="c"*64,
                    route={key: (["d"*64, "e"*64] if key == "hooks_sha256" else "d"*64) for key in m.ROUTE_KEYS},
                    active_package_work=False, active_certbot=False, writer_active=False, local_activation_accepted=True)
        for key in ("proxy_configuration_sha256", "client_identity_sha256", "link_sha256", "subscription_artifact_sha256", "certificate_der_sha256",
                    "ownership_sha256", "renewal_history_sha256", "unrelated_packages_sha256", "unrelated_lineages_sha256"):
            base[key] = "f"*64
        class Context:
            api = API(); scenario="snap-refresh"; manifest_sha="a"*64; request_sha="b"*64
            def capture(self, filename, helper):
                return ({"started_at": "2030-01-01T00:00:00Z", "completed_at": "2030-01-01T00:00:02Z",
                         "events": [{"observed_at": base["observed_at"], "record": base}]}, b"capture")
            def source(self, name, raw, events): return timing.EventSource(name, self.scenario, self.manifest_sha, self.request_sha, raw, "c"*64, events)
        value, _ = m._snapshot(Context(), "14-managed-before.json", "before")
        self.assertEqual(value, base)
        base["writer_active"] = "false"
        with self.assertRaisesRegex(API.Refusal, "typed activity"):
            m._snapshot(Context(), "14-managed-before.json", "before")

    def test_refuses_unknown_scenario(self):
        with self.assertRaises(timing.EvidenceTimingRefusal):
            m.rules(timing, "label-only")

    def test_history_producer_hashes_exact_protected_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "history.json"
            raw = b'{"schema":1,"recorder_id":"r","established_at":"2030-01-01T00:00:00Z","attempts":[]}\n'
            source.write_bytes(raw); source.chmod(0o600)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(m.main(["history", "--source", str(source)]), 0)
            value = json.loads(output.getvalue())
            self.assertEqual(value["source_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(value["history"]["recorder_id"], "r")

    def test_history_refuses_exit_zero_with_incomplete_owned_outcome(self):
        history = {"schema": 1, "recorder_id": "1"*32, "established_at": "2030-01-01T00:00:00Z", "attempts": [{
            "attempt_id": "2"*32, "invocation": "snap-certbot-renew-v1", "started_at": "2030-01-01T00:00:01Z",
            "boot_id": "boot", "recorder_pid": 21, "process_tick": 22,
            "lineage_before": "../../archive/sbxr-subscription/cert4.pem",
            "completion": {"exit_code": 0, "completed_at": "2030-01-01T00:00:02Z", "owned_outcome": "incomplete",
                           "lineage_after": "../../archive/sbxr-subscription/cert4.pem"}}]}
        record = {"schema": "sbxr-v4-renewal-history-source-v1", "source_sha256": "3"*64, "history": history}
        class Context:
            api = API()
            def capture(self, filename, helper):
                return ({"events": [{"observed_at": "2030-01-01T00:00:03Z", "record": record}]}, b"capture")
            def source(self, name, raw, events):
                return timing.EventSource(name, "recorder-live", "a"*64, "b"*64, raw, "c"*64, events)
        with self.assertRaisesRegex(API.Refusal, "completion differs"):
            m._history(Context(), "12", "final")

    def test_recorder_lock_observation_refuses_writer_locked_during_wait(self):
        records = {
            "13-admission.json": [
                {"state": "boundary-held", "mode": "admission", "writer": {"lock_state": "unlocked"},
                 "admission": {"lock_state": "locked"}, "whole_host": {"lock_state": "unlocked"}},
                {"state": "completed", "no_ca_egress": True}],
            "13-whole-host.json": [{"state": "held", "pid": 22, "sha256": "3"*64}, {"state": "released"}],
            "13-whole-host-wait.json": [{"schema": "sbxr-v4-lock-observation-v1", "lock_api": "flock", "observations": [
                {"path": "/var/lib/sbxr/renewal-writer.lock", "state": "present", "kind": "file", "nlink": 1,
                 "lock_state": "locked", "holders": [{"mode": "WRITE", "pid": 90}]},
                {"path": "/run/lock/sbxr.lock", "state": "present", "kind": "file", "nlink": 1,
                 "lock_state": "locked", "holders": [{"mode": "WRITE", "pid": 22}]}]}],
        }
        class Context:
            api = API(); scenario = "recorder-locks"
            state = {"action_started_at": "2030-01-01T00:00:00Z", "action_completed_at": "2030-01-01T00:00:10Z"}
            def capture(self, filename, helper):
                times = (["2030-01-01T00:00:01Z", "2030-01-01T00:00:09Z"] if filename != "13-whole-host-wait.json"
                         else ["2030-01-01T00:00:05Z"])
                return ({"events": [{"observed_at": at, "record": row} for at, row in zip(times, records[filename])]}, b"capture")
            def source(self, name, raw, events): return timing.EventSource(name, self.scenario, "a"*64, "b"*64, raw, "c"*64, events)
        with self.assertRaisesRegex(API.Refusal, "writer-unlocked"):
            m._operator_sources(Context(), "13")

    def test_runtime_snapshot_derives_bound_file_route_and_package_facts(self):
        scenario = "snap-refresh"
        packages = {name: {"name": name} for name in ("snap", "certbot", "karing")}
        after = {name: dict(value) for name, value in packages.items()}; after["certbot"] = {"name": "certbot", "version": "2"}
        manifest = {"v3_attempt": {"packages": packages, "after_snap_refresh": after}}
        manifest_raw = json.dumps(manifest, separators=(",", ":")).encode()
        request = {"scenario_id": scenario, "qualification_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                   "deadline_unix": 1893457800, "not_before": "2030-01-01T00:00:00Z"}
        request_raw = json.dumps(request, separators=(",", ":")).encode()
        config = {"inbounds": [{"type": "vless", "users": [{"uuid": "00000000-0000-4000-8000-000000000001"}]}], "outbounds": []}
        config_raw = json.dumps(config, separators=(",", ":")).encode()
        token = b"A"*43 + b"\n"
        cert_bodies = [b"cert", b"chain", b"fullchain", b"private"]
        cert_hashes = [hashlib.sha256(value).hexdigest() for value in cert_bodies]
        serving = {"link_id": "1"*32, "credential_sha256": hashlib.sha256(token.rstrip()).hexdigest(),
                   "certificate_generation": 4, "certificate_sha256": cert_hashes}
        ownership = {"phase": "Running", "configuration_sha256": hashlib.sha256(config_raw).hexdigest(),
                     "public_ipv4": "203.0.113.7", "serving": serving}
        disclosure = {"link": "https://203.0.113.7:8443/s/" + "A"*43, "certificate_der_sha256": "2"*64,
                      "configuration": config, "binding": {"scenario_id": scenario,
                      "request_sha256": hashlib.sha256(request_raw).hexdigest(),
                      "qualification_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
                      "deadline_unix": request["deadline_unix"], "not_before": request["not_before"]}}
        history_raw = b'{"schema":1,"recorder_id":"r","established_at":"2030-01-01T00:00:00Z","attempts":[]}'
        def private(path):
            name = str(path)
            if name.endswith("request"): return request_raw
            if name.endswith("manifest"): return manifest_raw
            return json.dumps(disclosure, separators=(",", ":")).encode()
        def file(path, mode):
            name = str(path)
            if name.endswith("proxy-ownership.json"): return json.dumps(ownership, separators=(",", ":")).encode()
            if name.endswith("subscription-serving.json"): return json.dumps({"schema": 1, "serving": serving}, separators=(",", ":")).encode()
            if name.endswith("renewal-attempts.json"): return history_raw
            if name.endswith("config.json"): return config_raw
            if name.endswith("subscription-token"): return token
            for prefix, body in zip(("cert4.pem", "chain4.pem", "fullchain4.pem", "privkey4.pem"), cert_bodies):
                if Path(name).name == prefix: return body
            return (name + str(mode)).encode()
        def command(args, check=True):
            if args[:2] == ["systemctl", "is-active"]: return "active\n" if args[2] in ("sing-box.service", "sbxr-subscription.service") else "inactive\n"
            if args[:2] == ["snap", "list"]: return "Name Version\ncertbot 2\ncore24 1\n"
            if args[:2] == ["dpkg-query", "-W"]: return "snapd\t1\tamd64\n"
            return "route\n"
        with patch.dict(os.environ, {"SBXR_QUALIFICATION_REQUEST": "/authority/request", "SBXR_QUALIFICATION_MANIFEST": "/authority/manifest"}), \
             patch.object(m, "_private", side_effect=private), patch.object(m, "_file", side_effect=file), \
             patch.object(m, "_command", side_effect=command), patch.object(m, "_tree_digest", return_value="3"*64), \
             patch.object(m.ssl, "PEM_cert_to_DER_cert", return_value=b"certificate-der"), \
             patch.object(m.subprocess, "run", return_value=SimpleNamespace(returncode=1)), \
             patch.object(m.sys, "platform", "linux"), patch.object(m.os, "geteuid", return_value=0):
            value = m._runtime_snapshot("final", Path("/private/subscription"))
        self.assertEqual(value["packages"], after)
        self.assertEqual(value["certificate_sha256"], cert_hashes)
        self.assertEqual(value["certificate_der_sha256"], hashlib.sha256(b"certificate-der").hexdigest())
        self.assertEqual(value["renewal_history_sha256"], hashlib.sha256(history_raw).hexdigest())
        self.assertTrue(value["local_activation_accepted"])


if __name__ == "__main__": unittest.main()
