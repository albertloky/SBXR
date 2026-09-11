#!/usr/bin/env python3
"""Outside-runner producer/checker for identity scenarios 16--18.

The producer keeps one TLS request on the old Client Identity alive before the
reviewed action starts.  Its EOF/reset is evidence of session termination; a
fresh request is then used for refusal/restoration and the final selected
configuration is exercised separately.  Retained documents contain only
digests, process identity and timestamps.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import signal
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("identity_outside_base", HERE / "identity-outside.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

SCHEMA = "sbxr-v4-identity-transition-outside-v1"
SCENARIOS = ("identity-precommit", "identity-postcommit", "identity-unavailable")


def require(value):
    if not value:
        raise ValueError("identity-transition-outside-refused")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def binding(manifest_raw, request_raw, state):
    manifest, request = base.decode(manifest_raw), base.decode(request_raw)
    scenario = request.get("scenario_id")
    require(scenario in SCENARIOS and request.get("qualification_manifest_sha256") == sha(manifest_raw))
    require(request.get("scenario_limit_seconds") == 1800 and isinstance(request.get("deadline_unix"), int))
    require(manifest.get("schema") == "sbxr-qualification-manifest-v3" and manifest.get("mode") == "v3")
    attempt = manifest.get("v3_attempt", {})
    require(attempt.get("evidence_policy") == "repair-issuance-bounded-v4")
    require(re.fullmatch(r"runner-[0-9]+", attempt.get("outside_runner_id", "")))
    require(state.get("schema") in ("sbxr-v4-scenario-entry-v1", "sbxr-v4-identity-transition-entry-v1") and
            state.get("scenario_id") == scenario)
    require(state.get("qualification_manifest_sha256") == sha(manifest_raw) and state.get("request_sha256") == sha(request_raw))
    require(state["started_at"] == request["not_before"] and
            0 < request["deadline_unix"] - base.timestamp(request["not_before"]) <= request["scenario_limit_seconds"])
    return {"schema": SCHEMA, "scenario_id": scenario,
            "qualification_manifest_sha256": sha(manifest_raw), "request_sha256": sha(request_raw),
            "outside_runner_id": attempt["outside_runner_id"], "deadline_unix": request["deadline_unix"],
            "started_at": state["started_at"]}


def check(document, bound, state, ready=False, current=None):
    common = set(bound) | {"connection_id", "source_configuration_sha256", "noncredential_sha256",
                           "link_sha256", "old_client", "old_established_at", "ready_at"}
    if bound["scenario_id"] == "identity-unavailable":
        common |= {"subscription_outside_failed_at"}
    require(set(document) == common if ready else set(document) == common | {
        "ready_sha256", "closed_sha256", "old_terminated_at", "fresh_old_checked_at", "target_healthy_at",
        "selected_configuration_sha256", "selected_client", "final_traffic_at", "cleanup_at", "facts"})
    require(all(document.get(k) == v for k, v in bound.items()))
    require(re.fullmatch(r"[0-9a-f]{32}", document.get("connection_id", "")))
    for key in ("source_configuration_sha256", "noncredential_sha256", "link_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", document.get(key, "")))
    process = document.get("old_client", {})
    require(set(process) == {"pid", "start_tick", "listener_owned", "confirmed_disclosure"} and
            process["pid"] > 1 and process["start_tick"] > 0 and process["listener_owned"] is True and
            process["confirmed_disclosure"] is True)
    times = [state["entry_started_at"], document["old_established_at"], document["ready_at"]]
    if bound["scenario_id"] == "identity-unavailable":
        require(base.timestamp(state["entry_started_at"]) <= base.timestamp(document["subscription_outside_failed_at"]) <=
                base.timestamp(document["ready_at"]))
    if not ready:
        facts = document["facts"]
        expected = {"established_old_session_terminated": True, "outside_target_healthy": True,
                    "fresh_old_refused": True,
                    "source_restored": bound["scenario_id"] == "identity-precommit",
                    "replacement_traffic": bound["scenario_id"] != "identity-precommit",
                    "unchanged_link_and_noncredential_fields": True, "runner_cleanup_complete": True}
        require(facts == expected)
        require(document["selected_configuration_sha256"] == document["source_configuration_sha256"]
                if bound["scenario_id"] == "identity-precommit"
                else document["selected_configuration_sha256"] != document["source_configuration_sha256"])
        require(document["selected_client"] is None if bound["scenario_id"] == "identity-precommit"
                else document["selected_client"] != process)
        times += [document[k] for k in ("old_terminated_at", "fresh_old_checked_at", "target_healthy_at",
                                        "final_traffic_at", "cleanup_at")]
    require(all(base.timestamp(a) <= base.timestamp(b) for a, b in zip(times, times[1:])))
    require(base.timestamp(times[-1]) <= min(bound["deadline_unix"], bound["deadline_unix"] if current is None else current))
    return document


def check_chain(manifest_raw, request_raw, state_raw, ready_raw, closed_raw, result_raw):
    state = base.decode(state_raw)
    bound = binding(manifest_raw, request_raw, state)
    ready, closed, result = base.decode(ready_raw), base.decode(closed_raw), base.decode(result_raw)
    check(ready, bound, state, ready=True, current=base.timestamp(ready["ready_at"]))
    require(closed == {"schema": "sbxr-v4-identity-transition-closed-v1", "scenario_id": bound["scenario_id"],
        "qualification_manifest_sha256": bound["qualification_manifest_sha256"], "request_sha256": bound["request_sha256"],
        "ready_sha256": sha(ready_raw), "connection_id": ready["connection_id"],
        "old_terminated_at": result["old_terminated_at"], "fresh_old_checked_at": result["fresh_old_checked_at"],
        "target_healthy_at": result["target_healthy_at"], "fresh_old_refused": True})
    require(result.get("ready_sha256") == sha(ready_raw))
    require(result.get("closed_sha256") == sha(closed_raw))
    require(all(result.get(key) == value for key, value in ready.items()))
    check(result, bound, state, current=base.timestamp(result["cleanup_at"]))
    return result


class LiveBackend(base.LiveBackend):
    def __init__(self, options, bound, scenario):
        super().__init__(options, bound)
        self.scenario = scenario

    def prepare(self):
        manifest_raw = self.remote_read(self.options['remote_manifest'])
        require(sha(manifest_raw) == self.bound['qualification_manifest_sha256'] and
                base.decode(manifest_raw).get('v3_attempt', {}).get('proxy_package') == base.PACKAGE)
        super().prepare()

    def fetch(self, name):
        aliases = {"07-state.json": f"{self.scenario}-entry.json",
                   "07-source-client.json": f"{self.scenario}-source-client.json",
                   "07-replacement-client.json": f"{self.scenario}-selected-client.json"}
        return self.remote_read(self.options["remote_state_dir"] + "/" + aliases.get(name, name))

    def publish(self, name, document):
        aliases = {"07-outside-started.json": f"{self.scenario}-outside-started.json"}
        return super().publish(aliases.get(name, name), document)

    def state(self):
        require(sha(self.remote_read(self.options["remote_request"])) == self.bound["request_sha256"])
        value = base.decode(self.fetch("07-state.json"))
        value["source_disclosure_confirmed"] = True
        value["replacement_disclosure_confirmed"] = self.scenario != "identity-precommit"
        return value

    def exists(self, name):
        path = self.options['remote_state_dir'] + '/' + name
        program = 'import os,sys; print(int(os.path.lexists(sys.argv[1])))'
        return self.command(self.remote + ['python3 -c ' + base.shlex.quote(program) + ' ' + base.shlex.quote(path)]).strip() == b'1'

    def start_client(self, replacement=False):
        if replacement:
            while not self.exists(self.scenario + '-selected-client.json'):
                self.state()
                self.pause()
        return super().start_client(replacement)

    def trigger(self):
        path = self.options["remote_state_dir"] + f"/{self.scenario}-action.json"
        try:
            return base.decode(self.remote_read(path))
        except Exception:
            return None

    def final_controller(self):
        path = self.options["remote_state_dir"] + f"/transition-{self.scenario}.json"
        try:
            value = base.decode(self.remote_read(path))
            return value if value.get("phase") in ("recovered", "rotated") else None
        except Exception:
            return None

    def subscription_unavailable(self):
        server = self.source["outbounds"][0]["server"]
        sock = base.socket.socket(base.socket.AF_INET, base.socket.SOCK_STREAM)
        sock.settimeout(self.timeout())
        try:
            try:
                sock.connect((server, 8443))
            except OSError:
                return self.clock()
            raise ValueError("outside-subscription-remains-reachable")
        finally:
            sock.close()

    def repair_subscription(self):
        while not self.exists('18-subscription-final.json'):
            self.state()
            self.pause()
        value = self.fetch('18-subscription-final.json')
        request_raw = self.remote_read(self.options['remote_request'])
        require(sha(request_raw) == self.bound['request_sha256'])
        request = base.decode(request_raw)
        spec = importlib.util.spec_from_file_location('identity_repair_outside', HERE / 'identity-repair-outside.py')
        repair = importlib.util.module_from_spec(spec); spec.loader.exec_module(repair)
        server = self.source['outbounds'][0]['server']
        direct = self.command(['curl', '-4', '-fsS', '--noproxy', '*', '--max-time', str(int(self.timeout())),
                               'https://api.ipify.org']).strip()
        require(str(base.ipaddress.ip_address(direct.decode())).encode() == direct and direct != server.encode())
        receipt = repair.produce(value, dict(self.bound, not_before=request['not_before']), self.state()['link_sha256'])
        self.publish(self.scenario + '-repair-outside.json', receipt)


def produce(backend, bound, state):
    persistent = None
    try:
        backend.prepare()
        old_process = backend.start_client()
        backend.routes()
        persistent = backend.connect(); persistent.request()
        subscription_failed_at = backend.subscription_unavailable() if bound["scenario_id"] == "identity-unavailable" else None
        ready = dict(bound, connection_id=secrets.token_hex(16),
                     source_configuration_sha256=state["source_configuration_sha256"],
                     noncredential_sha256=state["noncredential_sha256"], link_sha256=state["link_sha256"],
                     old_client=old_process, old_established_at=backend.clock(), ready_at=backend.clock())
        if subscription_failed_at is not None:
            ready["subscription_outside_failed_at"] = subscription_failed_at
        ready_raw = base.canonical(ready)
        backend.publish(f"{bound['scenario_id']}-outside-ready.json", ready)
        trigger = backend.trigger()
        while trigger is None:
            backend.client_alive(); persistent.request(); backend.pause()
            trigger = backend.trigger()
        require(trigger.get("schema") == "sbxr-v4-identity-transition-action-v1" and
                trigger.get("scenario_id") == bound["scenario_id"] and
                trigger.get("request_sha256") == bound["request_sha256"] and
                trigger.get("ready_sha256") == sha(ready_raw) and
                trigger.get("source_configuration_sha256") == state["source_configuration_sha256"] and
                re.fullmatch(r"[0-9a-f]{64}", trigger.get("target_configuration_sha256", "")) and
                trigger["target_configuration_sha256"] != trigger["source_configuration_sha256"])
        while True:
            try:
                persistent.request()
            except base.ClosedTransport:
                terminated = backend.clock(); break
            backend.pause()
        persistent.close(); persistent = None
        refused = False
        backend.client_alive()
        try:
            fresh = backend.connect(); fresh.request(); fresh.close()
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, base.ssl.SSLEOFError,
                base.ClosedTransport, base.http.client.RemoteDisconnected):
            refused = True
        checked = backend.clock()
        direct = backend.connect(proxy=False); direct.request(); direct.close()
        healthy = backend.clock()
        require(refused)
        closed = {"schema": "sbxr-v4-identity-transition-closed-v1", "scenario_id": bound["scenario_id"],
            "qualification_manifest_sha256": bound["qualification_manifest_sha256"], "request_sha256": bound["request_sha256"],
            "ready_sha256": sha(ready_raw), "connection_id": ready["connection_id"],
            "old_terminated_at": terminated, "fresh_old_checked_at": checked,
            "target_healthy_at": healthy, "fresh_old_refused": True}
        closed_raw = base.canonical(closed)
        backend.publish(f"{bound['scenario_id']}-outside-closed.json", closed)
        scenario = bound["scenario_id"]
        controller = backend.final_controller()
        while controller is None:
            backend.pause(); controller = backend.final_controller()
        if scenario == "identity-precommit":
            final = backend.connect(); final.request(); final.close()
            selected_process = None
            selected_sha = state["source_configuration_sha256"]
        else:
            require(refused)
            backend.stop_client()
            selected_process = backend.start_client(replacement=True)
            final = backend.connect(); final.request(); final.close(); backend.routes()
            selected_sha = trigger["target_configuration_sha256"]
        final_at = backend.clock()
    finally:
        try:
            if persistent:
                persistent.close()
        finally:
            backend.cleanup()
    result = dict(ready, ready_sha256=sha(ready_raw), closed_sha256=sha(closed_raw), old_terminated_at=terminated,
                  fresh_old_checked_at=checked, target_healthy_at=healthy,
                  selected_configuration_sha256=selected_sha, selected_client=selected_process,
                  final_traffic_at=final_at, cleanup_at=backend.clock(), facts={
                    "established_old_session_terminated": True, "outside_target_healthy": True,
                    "fresh_old_refused": True,
                    "source_restored": scenario == "identity-precommit",
                    "replacement_traffic": scenario != "identity-precommit",
                    "unchanged_link_and_noncredential_fields": True, "runner_cleanup_complete": True})
    check(result, bound, backend.state(), current=base.timestamp(result["cleanup_at"]))
    backend.publish(f"{scenario}-outside-result.json", result)
    if scenario == 'identity-unavailable':
        backend.repair_subscription()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run"); run.add_argument("--config", required=True); run.add_argument("--scenario", choices=SCENARIOS, required=True)
    check_parser = sub.add_parser("check-chain")
    for key in ("manifest", "request", "state", "ready", "closed", "result"):
        check_parser.add_argument("--" + key, required=True)
    args = parser.parse_args(argv)
    if args.command == "check-chain":
        raws = [base.read_private(getattr(args, key)) for key in ("manifest", "request", "state", "ready", "closed", "result")]
        check_chain(*raws); print('{"identity_transition_outside_verified":true}'); return
    options = base.decode(base.read_private(args.config))
    require(set(options) == {"host", "ssh_key", "known_hosts", "remote_state_dir", "remote_request",
                             "remote_manifest", "manifest", "request", "outside_runner_id"})
    manifest_raw, request_raw = base.read_private(options["manifest"]), base.read_private(options["request"])
    request = base.decode(request_raw); scenario = args.scenario
    require(request.get("scenario_id") == scenario)
    backend = LiveBackend(options, {"deadline_unix": request["deadline_unix"]}, scenario)
    state = base.decode(backend.fetch("07-state.json")); bound = binding(manifest_raw, request_raw, state); backend.bound = bound
    result = produce(backend, bound, state); print(base.canonical(result).decode())


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise RuntimeError('interrupted')
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(number, interrupted)
    try:
        main()
    except Exception:
        print('{"identity_transition_outside_failed":true}', file=sys.stderr)
        raise SystemExit(1)
