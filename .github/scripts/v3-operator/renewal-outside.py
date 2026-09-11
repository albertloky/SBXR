#!/usr/bin/env python3
"""Produce a collector-owned outside HTTPS witness for managed scenarios 11--15."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("sbxr_link_outside", HERE / "link-outside.py")
link = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(link)
IDENTITY_SPEC = importlib.util.spec_from_file_location("sbxr_identity_outside", HERE / "identity-outside.py")
identity = importlib.util.module_from_spec(IDENTITY_SPEC)
IDENTITY_SPEC.loader.exec_module(identity)
SCENARIOS = ("managed-renewal", "recorder-live", "recorder-locks", "snap-refresh", "unsupported-route")
NUMBERS = {scenario: str(11 + index) for index, scenario in enumerate(SCENARIOS)}
BOUND_KEYS = link.BOUND_KEYS | {"outside_runner_id"}


class OutsideHTTPSProbe(link.HTTPSProbe):
    pass


class ManagedClientBackend(identity.LiveBackend):
    """Identity runner lifecycle adapted to one disclosed managed configuration."""

    def prepare_client(self):
        link.require(sys.platform == "linux" and platform.machine() == "x86_64")
        release = Path("/etc/os-release").read_text()
        link.require('ID=ubuntu\n' in release and 'VERSION_ID="24.04"' in release and
                     self.command(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).strip() == b"yes" and
                     self.command(["findmnt", "-no", "FSTYPE", "-T", "/dev/shm"]).strip() == b"tmpfs" and
                     self.options["outside_runner_id"] == self.bound["outside_runner_id"] and not self.listener() and
                     getattr(self, "proxy_package", None) == identity.PACKAGE and
                     hashlib.sha256(self.remote_read(self.options["remote_manifest"])).hexdigest() ==
                     self.bound["qualification_manifest_sha256"])
        self.root = Path(tempfile.mkdtemp(prefix="sbxr-managed-", dir="/dev/shm"))
        self.package_root = Path(tempfile.mkdtemp(prefix="sbxr-managed-package-"))
        key, deb = self.root / "key", self.root / "client.deb"
        self.command(["curl", "-fsSL", "--max-time", str(int(self.timeout())),
                      "https://sing-box.app/gpg.key", "-o", str(key)])
        link.require(hashlib.sha256(key.read_bytes()).hexdigest() == identity.PACKAGE["signing_key_sha256"])
        self.command(["curl", "-fsSL", "--max-time", str(int(self.timeout())),
                      "https://deb.sagernet.org/files/ver_qb4px/sing-box_1.13.19_linux_amd64.deb", "-o", str(deb)])
        link.require(deb.stat().st_size == identity.PACKAGE["size"] and
                     hashlib.sha256(deb.read_bytes()).hexdigest() == identity.PACKAGE["sha256"])
        self.command(["dpkg-deb", "-x", str(deb), str(self.package_root)])
        self.binary = str(self.package_root / "usr/bin/sing-box")

    def start_disclosed_client(self, raw):
        config = link.decode(raw)
        link.require(config.get("inbounds") == [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
                                                  "listen_port": 2080}] and len(config.get("outbounds", [])) == 1)
        outbound = config["outbounds"][0]
        link.require(outbound.get("type") == "vless" and
                     re.fullmatch(r"[0-9a-fA-F-]{36}", outbound.get("uuid", "")) is not None)
        self.source = config
        self.uuids.append(outbound["uuid"])
        path, log = self.root / "source.json", self.root / "source.log"
        identity.write_new(path, raw)
        self.command([self.binary, "check", "-c", str(path)])
        with open(log, "xb") as output:
            self.client = subprocess.Popen([self.binary, "run", "-c", str(path)], stdin=subprocess.DEVNULL,
                                           stdout=output, stderr=output, start_new_session=True)
        until = min(time.monotonic() + 10, time.monotonic() + self.timeout())
        while time.monotonic() < until:
            link.require(self.client.poll() is None)
            if b"pid=" + str(self.client.pid).encode() + b"," in self.listener():
                self.scan()
                return
            time.sleep(.1)
        raise link.Refused("managed-client-not-ready")

    def exists(self, name):
        path = self.options["remote_state_dir"] + "/" + name
        program = "import os,sys;print(int(os.path.lexists(sys.argv[1])))"
        return self.command(self.remote + ["python3 -c " + identity.shlex.quote(program) + " " +
                            identity.shlex.quote(path)]).strip() == b"1"

    def wait(self, name):
        while not self.exists(name):
            self.unchanged()
            self.pause()
        self.unchanged()
        return self.fetch(name)

    def unchanged(self):
        link.require(hashlib.sha256(self.remote_read(self.options["remote_request"])).hexdigest() ==
                     self.bound["request_sha256"] and
                     hashlib.sha256(self.remote_read(self.options["remote_manifest"])).hexdigest() ==
                     self.bound["qualification_manifest_sha256"])


def public_bound(bound):
    return {key: bound[key] for key in BOUND_KEYS}


def check_bound(document, bound):
    link.require(all(document.get(key) == bound[key] for key in BOUND_KEYS))


def binding(manifest_raw, request_raw):
    manifest, request = link.decode(manifest_raw), link.decode(request_raw)
    manifest_sha = link.digest(manifest_raw)
    scenario = request.get("scenario_id")
    link.require(scenario in SCENARIOS and request.get("qualification_manifest_sha256") == manifest_sha)
    link.require(type(request.get("deadline_unix")) is int and type(request.get("scenario_limit_seconds")) is int and
                 request["scenario_limit_seconds"] > 0)
    not_before = link.timestamp(request.get("not_before"))
    link.require(0 < request["deadline_unix"] - not_before <= request["scenario_limit_seconds"])
    attempt = manifest.get("v3_attempt")
    link.require(manifest.get("schema") == "sbxr-qualification-manifest-v3" and manifest.get("mode") == "v3" and
                 isinstance(attempt, dict) and attempt.get("evidence_policy") == "repair-issuance-bounded-v4" and
                 request["scenario_limit_seconds"] == attempt.get("scenario_limit_seconds") and
                 scenario in attempt.get("required_scenarios", []) and
                 link.re.fullmatch(r"runner-[0-9]+", attempt.get("outside_runner_id", "")) is not None)
    return {"scenario_id": scenario, "request_sha256": link.digest(request_raw),
            "qualification_manifest_sha256": manifest_sha, "deadline_unix": request["deadline_unix"],
            "not_before": request["not_before"], "outside_runner_id": attempt["outside_runner_id"]}


def disclosure(raw, bound):
    return link.observation(raw, bound)


def ready_receipt(bound, initial_raw, initial, started, initial_at, ready_at=None):
    values = link.hashes(initial)
    return {**public_bound(bound), "schema": "sbxr-v4-renewal-outside-ready-v1", "started_at": started,
            "initial_at": initial_at, "ready_at": ready_at or link.now(),
            "initial_disclosure_sha256": link.digest(initial_raw), "link_sha256": values["link"],
            "configuration_sha256": values["configuration"], "initial_certificate_der_sha256": values["certificate"],
            "facts": {"artifact_fields_and_name": True, "outside_route_distinct": True, "trusted_outside_tls": True}}


def check_ready(value, bound, initial_raw, initial, current=None):
    keys = BOUND_KEYS | {"schema", "started_at", "initial_at", "ready_at", "initial_disclosure_sha256",
                         "link_sha256", "configuration_sha256", "initial_certificate_der_sha256", "facts"}
    link.require(isinstance(value, dict) and set(value) == keys)
    check_bound(value, bound)
    hashes = link.hashes(initial)
    link.require(value["schema"] == "sbxr-v4-renewal-outside-ready-v1" and
                 value["initial_disclosure_sha256"] == link.digest(initial_raw) and
                 value["link_sha256"] == hashes["link"] and value["configuration_sha256"] == hashes["configuration"] and
                 value["initial_certificate_der_sha256"] == hashes["certificate"] and
                 value["facts"] == {"artifact_fields_and_name": True, "outside_route_distinct": True,
                                    "trusted_outside_tls": True})
    times = [link.timestamp(value[key]) for key in ("started_at", "initial_at", "ready_at")]
    link.require(link.timestamp(bound["not_before"]) <= times[0] <= times[1] <= times[2] <=
                 (time.time() if current is None else current) <= bound["deadline_unix"])
    return value


def check_action_complete(raw, bound, ready):
    value = link.decode(raw)
    keys = {"schema", "scenario_id", "qualification_manifest_sha256", "request_sha256", "started_at",
            "entry_started_at", "action_started_at", "action_completed_at"}
    link.require(set(value) == keys and value["schema"] == "sbxr-v4-scenario-entry-v1" and
                 value["scenario_id"] == bound["scenario_id"] and
                 value["qualification_manifest_sha256"] == bound["qualification_manifest_sha256"] and
                 value["request_sha256"] == bound["request_sha256"] and
                 value["started_at"] == bound["not_before"])
    times = [link.timestamp(value[key]) for key in
             ("started_at", "entry_started_at", "action_started_at", "action_completed_at")]
    link.require(link.timestamp(bound["not_before"]) <= times[0] <= times[1] <= times[2] <= times[3] <=
                 bound["deadline_unix"] and link.timestamp(ready["ready_at"]) <= times[2])
    return value


def check(receipt, manifest_raw, request_raw, initial_raw, final_raw, ready_raw):
    bound = binding(manifest_raw, request_raw)
    initial, final = disclosure(initial_raw, bound), disclosure(final_raw, bound)
    ih, fh = link.hashes(initial), link.hashes(final)
    ready = check_ready(link.decode(ready_raw), bound, initial_raw, initial,
                        current=link.timestamp(receipt.get("completed_at")))
    keys = BOUND_KEYS | {"schema", "ready_sha256", "started_at", "initial_at", "ready_at",
                         "action_completed_at", "final_at", "completed_at", "initial_disclosure_sha256",
                         "final_disclosure_sha256", "link_sha256", "configuration_sha256",
                         "initial_certificate_der_sha256", "final_certificate_der_sha256", "facts"}
    link.require(isinstance(receipt, dict) and set(receipt) == keys)
    check_bound(receipt, bound)
    link.require(receipt["schema"] == "sbxr-v4-renewal-outside-v1" and
                 receipt["ready_sha256"] == link.digest(ready_raw) and receipt["started_at"] == ready["started_at"] and
                 receipt["initial_at"] == ready["initial_at"] and receipt["ready_at"] == ready["ready_at"] and
                 receipt["initial_disclosure_sha256"] == link.digest(initial_raw) and
                 receipt["final_disclosure_sha256"] == link.digest(final_raw) and
                 receipt["link_sha256"] == ih["link"] == fh["link"] and
                 receipt["configuration_sha256"] == ih["configuration"] == fh["configuration"] and
                 receipt["initial_certificate_der_sha256"] == ih["certificate"] and
                 receipt["final_certificate_der_sha256"] == fh["certificate"] and
                 receipt["facts"] == {"artifact_fields_and_name": True, "outside_route_distinct": True,
                                      "runner_cleanup_complete": True, "trusted_outside_tls": True,
                                      "unchanged_link_and_configuration": True})
    times = [link.timestamp(receipt[key]) for key in
             ("started_at", "initial_at", "ready_at", "action_completed_at", "final_at", "completed_at")]
    link.require(link.timestamp(bound["not_before"]) <= times[0] and times == sorted(times) and
                 times[-1] <= bound["deadline_unix"])
    return receipt


def _result(bound, initial_raw, final_raw, ready, action_completed_at, final_at):
    initial, final = disclosure(initial_raw, bound), disclosure(final_raw, bound)
    ih, fh = link.hashes(initial), link.hashes(final)
    link.require(ih["link"] == fh["link"] and ih["configuration"] == fh["configuration"])
    ready_raw = link.canonical(ready)
    return {**public_bound(bound), "schema": "sbxr-v4-renewal-outside-v1",
            "ready_sha256": link.digest(ready_raw), "started_at": ready["started_at"],
            "initial_at": ready["initial_at"], "ready_at": ready["ready_at"],
            "action_completed_at": action_completed_at, "final_at": final_at, "completed_at": link.now(),
            "initial_disclosure_sha256": link.digest(initial_raw), "final_disclosure_sha256": link.digest(final_raw),
            "link_sha256": ih["link"], "configuration_sha256": ih["configuration"],
            "initial_certificate_der_sha256": ih["certificate"], "final_certificate_der_sha256": fh["certificate"],
            "facts": {"artifact_fields_and_name": True, "outside_route_distinct": True,
                      "runner_cleanup_complete": True, "trusted_outside_tls": True,
                      "unchanged_link_and_configuration": True}}


def trace_row(bound, connection_id, number, at):
    return {"check": number, "connection_id": connection_id, "request_sha256": bound["request_sha256"],
            "same_connection": True, "schema": "sbxr-v3-connection-probe-v1", "time": at}


def trace_envelope(bound, started_at, completed_at, rows):
    link.require(len(rows) >= 2)
    return {"schema": "sbxr-v4-captured-source-v1", "scenario_id": bound["scenario_id"],
            "qualification_manifest_sha256": bound["qualification_manifest_sha256"],
            "request_sha256": bound["request_sha256"], "helper": "connection-probe",
            "started_at": started_at, "completed_at": completed_at, "exit_code": 0,
            "events": [{"observed_at": row["time"], "record": row} for row in rows]}


def check_trace(value, bound, action):
    keys = {"schema", "scenario_id", "qualification_manifest_sha256", "request_sha256", "helper",
            "started_at", "completed_at", "exit_code", "events"}
    link.require(isinstance(value, dict) and set(value) == keys and value["schema"] == "sbxr-v4-captured-source-v1" and
                 value["scenario_id"] == bound["scenario_id"] and
                 value["qualification_manifest_sha256"] == bound["qualification_manifest_sha256"] and
                 value["request_sha256"] == bound["request_sha256"] and value["helper"] == "connection-probe" and
                 value["exit_code"] == 0 and isinstance(value["events"], list) and 2 <= len(value["events"]) <= 10000)
    connection_id = value["events"][0].get("record", {}).get("connection_id")
    link.require(re.fullmatch(r"[0-9a-f]{32}", connection_id or "") is not None)
    times = []
    for number, event in enumerate(value["events"], 1):
        row = event.get("record") if isinstance(event, dict) else None
        expected = trace_row(bound, connection_id, number, row.get("time") if isinstance(row, dict) else None)
        link.require(set(event) == {"observed_at", "record"} and row == expected and event["observed_at"] == row["time"])
        times.append(link.timestamp(row["time"]))
    link.require(link.timestamp(value["started_at"]) <= times[0] and times == sorted(times) and
                 times[0] <= link.timestamp(action["action_started_at"]) <=
                 link.timestamp(action["action_completed_at"]) <= times[-1] <=
                 link.timestamp(value["completed_at"]) <= bound["deadline_unix"])
    return value


def produce(manifest_raw, request_raw, initial_raw, final_raw, probe=None, action_completed_at=None):
    """Pure producer retained for fixtures; live collection uses ``produce_live``."""
    bound = binding(manifest_raw, request_raw)
    initial, final = disclosure(initial_raw, bound), disclosure(final_raw, bound)
    probe = probe or OutsideHTTPSProbe()
    started, initial_at = link.now(), probe.complete(initial, 200, 12)
    ready = ready_receipt(bound, initial_raw, initial, started, initial_at)
    action_completed_at = action_completed_at or link.now()
    final_at = probe.complete(final, 200, 12)
    receipt = _result(bound, initial_raw, final_raw, ready, action_completed_at, final_at)
    return check(receipt, manifest_raw, request_raw, initial_raw, final_raw, link.canonical(ready)), ready


def produce_live(backend, bound):
    number = NUMBERS[bound["scenario_id"]]
    backend.unchanged()
    initial_raw = backend.fetch(number + "-subscription-before.json")
    initial = disclosure(initial_raw, bound)
    connection = None
    rows = []
    trace_started = backend.clock()
    try:
        backend.prepare_client()
        backend.start_disclosed_client(link.canonical(initial["configuration"]))
        backend.routes()  # Direct public IP differs from the VPS and proxied egress equals it.
        connection = backend.connect()
        connection_id = identity.secrets.token_hex(16)
        connection.request()
        rows.append(trace_row(bound, connection_id, 1, backend.clock()))
        started = backend.clock()
        initial_at = backend.probe.complete(initial, 200, backend.timeout())
        ready = ready_receipt(bound, initial_raw, initial, started, initial_at, backend.clock())
        check_ready(ready, bound, initial_raw, initial)
        ready_raw = link.canonical(ready)
        backend.publish(number + "-outside-ready.json", ready)
        action_name = "scenario-" + bound["scenario_id"] + "-action-complete.json"
        while not backend.exists(action_name):
            backend.unchanged()
            backend.client_alive()
            backend.pause()
            connection.request()
            rows.append(trace_row(bound, connection_id, len(rows) + 1, backend.clock()))
        backend.unchanged()
        action = check_action_complete(backend.fetch(action_name), bound, ready)
        connection.request()
        rows.append(trace_row(bound, connection_id, len(rows) + 1, backend.clock()))
        final_raw = backend.wait(number + "-subscription-final.json")
        backend.unchanged()
        final_at = backend.probe.complete(disclosure(final_raw, bound), 200, backend.timeout())
        connection.request()
        rows.append(trace_row(bound, connection_id, len(rows) + 1, backend.clock()))
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            backend.cleanup()
    trace_completed = backend.clock()
    trace = trace_envelope(bound, trace_started, trace_completed, rows)
    check_trace(trace, bound, action)
    backend.publish(number + "-proxy-trace.json", trace)
    receipt = _result(bound, initial_raw, final_raw, ready, action["action_completed_at"], final_at)
    check(receipt, backend.manifest_raw, backend.request_raw, initial_raw, final_raw, ready_raw)
    backend.publish(number + "-outside-result.json", receipt)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--config", required=True)
    run.add_argument("--scenario", choices=SCENARIOS, required=True)
    for name in ("check-ready", "check-result"):
        item = commands.add_parser(name)
        for argument in ("manifest", "request", "initial", "receipt"):
            item.add_argument("--" + argument, required=True)
        if name == "check-result":
            item.add_argument("--final", required=True)
            item.add_argument("--ready", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.command == "run":
        options = link.decode(link.read_private(args.config))
        expected = {"host", "ssh_key", "known_hosts", "remote_state_dir", "remote_request", "remote_manifest",
                    "manifest", "request", "outside_runner_id"}
        link.require(set(options) == expected and all(isinstance(value, str) and value for value in options.values()))
        link.require(link.re.fullmatch(r"[a-zA-Z0-9.-]+", options["host"]) is not None and
                     not options["host"].startswith("-") and
                     all(value.startswith("/") for key, value in options.items() if key not in ("host", "outside_runner_id")))
        link.require(sys.platform == "linux" and platform.machine() == "x86_64" and
                     'ID=ubuntu\n' in Path("/etc/os-release").read_text() and
                     'VERSION_ID="24.04"' in Path("/etc/os-release").read_text())
        manifest_raw, request_raw = link.read_private(options["manifest"]), link.read_private(options["request"])
        bound = binding(manifest_raw, request_raw)
        link.require(time.time() < bound["deadline_unix"] and bound["scenario_id"] == args.scenario and
                     bound["outside_runner_id"] == options["outside_runner_id"])
        backend = ManagedClientBackend(options, bound)
        backend.manifest_raw, backend.request_raw = manifest_raw, request_raw
        backend.proxy_package = link.decode(manifest_raw)["v3_attempt"].get("proxy_package")
        backend.probe = OutsideHTTPSProbe()
        remaining = bound["deadline_unix"] - time.time()
        link.require(remaining > 0)
        signal.setitimer(signal.ITIMER_REAL, remaining)
        try:
            result = produce_live(backend, bound)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        print(link.canonical(result).decode())
    else:
        manifest_raw, request_raw = link.read_private(args.manifest), link.read_private(args.request)
        bound = binding(manifest_raw, request_raw)
        initial_raw = link.read_private(args.initial)
        if args.command == "check-ready":
            check_ready(link.decode(link.read_private(args.receipt)), bound, initial_raw, disclosure(initial_raw, bound))
        else:
            check(link.decode(link.read_private(args.receipt)), manifest_raw, request_raw, initial_raw,
                  link.read_private(args.final), link.read_private(args.ready))
        print('{"renewal_outside_verified":true}')
    return 0


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise RuntimeError("interrupted")
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(number, interrupted)
    try:
        raise SystemExit(main())
    except Exception:
        print('{"renewal_outside_refused":true}', file=sys.stderr)
        raise SystemExit(1)
