#!/usr/bin/env python3
"""Outside witness for subscription-link precommit and postcommit recovery.

The live runner reads secret-bearing observations only through protected files.
Receipts contain hashes and timing facts, never a link or client configuration.
"""
import argparse
import ctypes
import datetime as dt
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse


HERE = Path(__file__).resolve().parent
check_spec = importlib.util.spec_from_file_location("subscription_check", HERE / "check-subscription.py")
subscription = importlib.util.module_from_spec(check_spec)
check_spec.loader.exec_module(subscription)

SCENARIOS = ("link-precommit", "link-postcommit")
BOUND_KEYS = {"scenario_id", "request_sha256", "qualification_manifest_sha256", "deadline_unix"}
HEX64 = re.compile(r"[0-9a-f]{64}")
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")


class Refused(Exception):
    pass


def require(condition):
    if not condition:
        raise Refused("link-outside-refused")


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    require(0 < len(raw) <= 1_000_000)
    value = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(value, dict))
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def timestamp(value):
    require(isinstance(value, str) and STAMP.fullmatch(value) is not None)
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def read_private(path, uid=None):
    path = os.fspath(path)
    before = os.lstat(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
                info.st_nlink == 1 and info.st_uid == (os.getuid() if uid is None else uid) and
                0 < info.st_size <= 1_000_000)
        raw = os.read(fd, 1_000_001)
        after = os.lstat(path)
        require((before.st_dev, before.st_ino) == (info.st_dev, info.st_ino) ==
                (after.st_dev, after.st_ino) and len(raw) == info.st_size)
        return raw
    finally:
        os.close(fd)


def atomic_write_new(path, raw):
    path = os.fspath(path)
    directory = os.path.dirname(path)
    parent = os.lstat(directory)
    require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700 and
            parent.st_uid == os.getuid())
    fd, temporary = tempfile.mkstemp(prefix=".link-outside-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        if sys.platform == "linux":
            libc = ctypes.CDLL(None, use_errno=True)
            rename = libc.renameat2
            rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            rename.restype = ctypes.c_int
            require(rename(-100, os.fsencode(temporary), -100, os.fsencode(path), 1) == 0)
        else:  # Local checker/test portability; live production is Linux-only.
            os.link(temporary, path, follow_symlinks=False)
        parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def binding(manifest_raw, request_raw):
    manifest, request = decode(manifest_raw), decode(request_raw)
    manifest_sha = digest(manifest_raw)
    scenario = request.get("scenario_id")
    require(scenario in SCENARIOS and request.get("qualification_manifest_sha256") == manifest_sha)
    require(type(request.get("deadline_unix")) is int and
            type(request.get("scenario_limit_seconds")) is int and request["scenario_limit_seconds"] > 0)
    not_before = timestamp(request.get("not_before"))
    require(0 < request["deadline_unix"] - not_before <= request["scenario_limit_seconds"])
    attempt = manifest.get("v3_attempt")
    require(manifest.get("schema") == "sbxr-qualification-manifest-v3" and manifest.get("mode") == "v3" and
            isinstance(attempt, dict) and attempt.get("evidence_policy") == "repair-issuance-bounded-v4" and
            type(attempt.get("scenario_limit_seconds")) is int and
            request["scenario_limit_seconds"] == attempt["scenario_limit_seconds"] and
            re.fullmatch(r"runner-[0-9]+", attempt.get("outside_runner_id", "")) is not None and
            scenario in attempt.get("required_scenarios", []))
    return {"scenario_id": scenario, "request_sha256": digest(request_raw),
            "qualification_manifest_sha256": manifest_sha, "deadline_unix": request["deadline_unix"],
            "not_before": request["not_before"], "outside_runner_id": attempt["outside_runner_id"]}


def public_bound(bound):
    return {key: bound[key] for key in BOUND_KEYS}


def check_bound(document, bound):
    require(all(document.get(key) == bound[key] for key in BOUND_KEYS))


def observation(raw, bound):
    value = decode(raw)
    require(set(value) == {"link", "certificate_der_sha256", "configuration", "binding"})
    expected = {"scenario_id": bound["scenario_id"], "request_sha256": bound["request_sha256"],
                "qualification_manifest_sha256": bound["qualification_manifest_sha256"],
                "deadline_unix": bound["deadline_unix"], "not_before": bound["not_before"]}
    require(value["binding"] == expected and HEX64.fullmatch(value["certificate_der_sha256"] or "") is not None)
    link = urllib.parse.urlsplit(value["link"])
    require(link.scheme == "https" and link.port == 8443 and link.username is None and link.password is None and
            not link.query and not link.fragment and subscription.SUBSCRIPTION_PATH.fullmatch(link.path) is not None and
            str(ipaddress.IPv4Address(link.hostname)) == link.hostname)
    return value


def hashes(value):
    return {"link": digest(value["link"].encode()), "configuration": digest(canonical(value["configuration"])),
            "certificate": value["certificate_der_sha256"]}


class HTTPSProbe:
    def __init__(self, context=None):
        self.context = context or ssl.create_default_context()

    def connect(self, value, timeout):
        link = urllib.parse.urlsplit(value["link"])
        raw = socket.create_connection((link.hostname, 8443), timeout=timeout)
        try:
            tls = self.context.wrap_socket(raw, server_hostname=link.hostname)
            require(digest(tls.getpeercert(binary_form=True)) == value["certificate_der_sha256"])
            return tls, link
        except BaseException:
            raw.close()
            raise

    def complete(self, value, expected, timeout):
        tls, link = self.connect(value, timeout)
        with tls:
            tls.sendall(("GET " + link.path + " HTTP/1.1\r\nHost: " + link.netloc +
                         "\r\nConnection: close\r\n\r\n").encode("ascii"))
            response = http.client.HTTPResponse(tls)
            response.begin()
            body = response.read(65537)
            require(response.status == expected and len(body) <= 65536)
            if expected == 200:
                require(subscription.fields_match(body, value["configuration"]))
        return now()

    def pending(self, value, timeout):
        started = time.monotonic()
        tls, link = self.connect(value, timeout)
        established = now()
        tls.sendall(("GET " + link.path + " HTTP/1.1\r\nHost: " + link.netloc +
                     "\r\nConnection: close\r\nX-SBXR-Pending: 1\r\n").encode("ascii"))
        return tls, started, established, now()

    @staticmethod
    def closure(tls, started, timeout):
        tls.settimeout(timeout)
        kind = None
        try:
            data = tls.recv(1)
            require(data == b"")
            kind = "eof"
        except (ConnectionResetError, BrokenPipeError):
            kind = "reset"
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
            kind = "ssl-eof"
        finally:
            tls.close()
        elapsed = int((time.monotonic() - started) * 1000)
        require(kind is not None and 0 <= elapsed < 5000)
        return kind, elapsed, now()


READY_KEYS = BOUND_KEYS | {"schema", "started_at", "old_initial_at", "ready_at", "old_link_sha256",
                           "configuration_sha256", "certificate_der_sha256", "initial_disclosure_sha256", "facts"}
ACK_KEYS = BOUND_KEYS | {"schema", "challenge_sha256", "connection_id", "tls_established_at",
                         "partial_request_sent_at", "pending_ready_at", "old_link_sha256"}
CLOSED_KEYS = BOUND_KEYS | {"schema", "challenge_sha256", "ack_sha256", "connection_id",
                            "partial_request_sent_at", "pending_ready_at", "closed_at", "closure_kind",
                            "pending_elapsed_milliseconds", "server_deadline_seconds", "old_link_sha256"}


def check_ready(document, bound, initial_raw=None, current=None):
    check_bound(document, bound)
    require(set(document) == READY_KEYS and document["schema"] == "sbxr-v4-link-outside-ready-v1" and
            document["facts"] == {"artifact_matches": True, "old_initial_200": True,
                                  "outside_route_distinct": True, "trusted_tls": True})
    require(all(HEX64.fullmatch(document[key] or "") for key in ("old_link_sha256", "configuration_sha256",
                                                                  "certificate_der_sha256", "initial_disclosure_sha256")))
    times = [timestamp(document[key]) for key in ("started_at", "old_initial_at", "ready_at")]
    require(timestamp(bound["not_before"]) <= times[0] <= times[1] <= times[2] <=
            (time.time() if current is None else current) <= bound["deadline_unix"])
    if initial_raw is not None:
        require(document["initial_disclosure_sha256"] == digest(initial_raw))
        initial_hash = hashes(observation(initial_raw, bound))
        require(document["old_link_sha256"] == initial_hash["link"] and
                document["configuration_sha256"] == initial_hash["configuration"] and
                document["certificate_der_sha256"] == initial_hash["certificate"])
    return document


def check_challenge(document, bound, ready_raw):
    check_bound(document, bound)
    require(set(document) == BOUND_KEYS | {"schema", "nonce", "challenged_at", "ready_sha256",
                                           "initial_disclosure_sha256", "transition_record_sha256"} and
            document["schema"] == "sbxr-v4-link-outside-challenge-v1" and
            re.fullmatch(r"[0-9a-f]{64}", document["nonce"] or "") is not None and
            all(HEX64.fullmatch(document[key] or "") for key in ("ready_sha256", "initial_disclosure_sha256",
                                                                  "transition_record_sha256")) and
            document["ready_sha256"] == digest(ready_raw))
    ready = decode(ready_raw)
    require(document["initial_disclosure_sha256"] == ready["initial_disclosure_sha256"] and
            timestamp(ready["ready_at"]) <= timestamp(document["challenged_at"]) <= bound["deadline_unix"])
    return document


def check_ack(document, bound, ready_raw, challenge_raw, current=None):
    check_bound(document, bound)
    challenge = check_challenge(decode(challenge_raw), bound, ready_raw)
    require(set(document) == ACK_KEYS and document["schema"] == "sbxr-v4-link-outside-ack-v1" and
            document["challenge_sha256"] == digest(challenge_raw) and
            re.fullmatch(r"[0-9a-f]{32}", document["connection_id"] or "") is not None and
            HEX64.fullmatch(document["old_link_sha256"] or "") is not None)
    ready = decode(ready_raw)
    require(document["old_link_sha256"] == ready["old_link_sha256"])
    times = [timestamp(challenge["challenged_at"])] + [timestamp(document[key]) for key in
             ("tls_established_at", "partial_request_sent_at", "pending_ready_at")]
    require(times == sorted(times) and times[-1] <= (time.time() if current is None else current) <= bound["deadline_unix"])
    return document


def check_closed(document, bound, ready_raw, challenge_raw, ack_raw):
    check_bound(document, bound)
    ack = check_ack(decode(ack_raw), bound, ready_raw, challenge_raw, current=timestamp(document["closed_at"]))
    require(set(document) == CLOSED_KEYS and document["schema"] == "sbxr-v4-link-outside-closed-v1" and
            document["challenge_sha256"] == digest(challenge_raw) and document["ack_sha256"] == digest(ack_raw) and
            document["connection_id"] == ack["connection_id"] and document["old_link_sha256"] == ack["old_link_sha256"] and
            document["partial_request_sent_at"] == ack["partial_request_sent_at"] and
            document["pending_ready_at"] == ack["pending_ready_at"] and
            document["closure_kind"] in ("eof", "reset", "ssl-eof") and
            type(document["pending_elapsed_milliseconds"]) is int and
            0 <= document["pending_elapsed_milliseconds"] < 5000 and document["server_deadline_seconds"] == 5 and
            timestamp(document["pending_ready_at"]) <= timestamp(document["closed_at"]) <= bound["deadline_unix"])
    return document


def check_finalize(document, bound, challenge_raw, closed_raw, final_raw):
    check_bound(document, bound)
    keys = BOUND_KEYS | {"schema", "challenge_sha256", "closed_sha256", "final_disclosure_sha256",
                         "recovered_transition_sha256", "recovered_at", "finalized_at"}
    require(set(document) == keys and document["schema"] == "sbxr-v4-link-outside-finalize-v1" and
            document["challenge_sha256"] == digest(challenge_raw) and document["closed_sha256"] == digest(closed_raw) and
            document["final_disclosure_sha256"] == digest(final_raw) and
            HEX64.fullmatch(document["recovered_transition_sha256"] or "") is not None and
            timestamp(decode(closed_raw)["closed_at"]) <= timestamp(document["recovered_at"]) <=
            timestamp(document["finalized_at"]) <= bound["deadline_unix"])
    return document


def check_result(document, bound, handoffs, initial_raw, final_raw):
    check_bound(document, bound)
    ready_raw, challenge_raw, ack_raw, closed_raw, finalize_raw = [handoffs[key] for key in
        ("ready", "challenge", "ack", "closed", "finalize")]
    ready = check_ready(decode(ready_raw), bound, initial_raw, current=timestamp(document["cleanup_at"]))
    check_closed(decode(closed_raw), bound, ready_raw, challenge_raw, ack_raw)
    check_finalize(decode(finalize_raw), bound, challenge_raw, closed_raw, final_raw)
    keys = BOUND_KEYS | {"schema", "ready_sha256", "challenge_sha256", "ack_sha256", "closed_sha256",
                         "finalize_sha256", "final_disclosure_sha256", "started_at", "old_initial_at",
                         "pending_ready_at", "closed_at", "old_final_at", "new_final_at", "cleanup_at",
                         "old_link_sha256", "new_link_sha256", "configuration_sha256",
                         "certificate_der_sha256", "facts"}
    require(set(document) == keys and document["schema"] == "sbxr-v4-link-outside-result-v1")
    for key, raw in (("ready_sha256", ready_raw), ("challenge_sha256", challenge_raw), ("ack_sha256", ack_raw),
                     ("closed_sha256", closed_raw), ("finalize_sha256", finalize_raw),
                     ("final_disclosure_sha256", final_raw)):
        require(document[key] == digest(raw))
    closed, final = decode(closed_raw), observation(final_raw, bound)
    require(document["started_at"] == ready["started_at"] and document["old_initial_at"] == ready["old_initial_at"] and
            document["pending_ready_at"] == closed["pending_ready_at"] and document["closed_at"] == closed["closed_at"] and
            document["old_link_sha256"] == ready["old_link_sha256"] and
            document["configuration_sha256"] == ready["configuration_sha256"] and
            document["certificate_der_sha256"] == ready["certificate_der_sha256"])
    final_hash = hashes(final)
    require(final_hash["configuration"] == ready["configuration_sha256"] and
            final_hash["certificate"] == ready["certificate_der_sha256"])
    times = [timestamp(document[key]) for key in ("started_at", "old_initial_at", "pending_ready_at", "closed_at",
                                                   "old_final_at")]
    if bound["scenario_id"] == "link-precommit":
        require(document["new_final_at"] is None and document["new_link_sha256"] is None and
                final_hash["link"] == ready["old_link_sha256"] and
                document["facts"] == {"old_final_200": True, "new_final_200": False, "old_final_404": False,
                                      "same_configuration": True, "same_certificate": True,
                                      "same_old_link": True, "trusted_tls": True, "runner_cleanup_complete": True})
    else:
        times.append(timestamp(document["new_final_at"]))
        require(document["new_link_sha256"] == final_hash["link"] and final_hash["link"] != ready["old_link_sha256"] and
                document["facts"] == {"old_final_200": False, "new_final_200": True, "old_final_404": True,
                                      "same_configuration": True, "same_certificate": True,
                                      "same_old_link": False, "trusted_tls": True, "runner_cleanup_complete": True})
    times.append(timestamp(document["cleanup_at"]))
    require(times == sorted(times) and times[-1] <= bound["deadline_unix"])
    return document


def check_chain(manifest_raw, request_raw, result_raw, handoffs, initial_raw, final_raw):
    """Validate an explicitly supplied chain; no directory layout is assumed."""
    bound = binding(manifest_raw, request_raw)
    return check_result(decode(result_raw), bound, handoffs, initial_raw, final_raw)


class LiveBackend:
    def __init__(self, options, bound):
        self.options, self.bound = options, bound
        self.remote = ["ssh", "-i", options["ssh_key"], "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                       "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + options["known_hosts"],
                       "-o", "ConnectTimeout=10", "root@" + options["host"]]
        self.probe = HTTPSProbe()

    def timeout(self):
        remaining = self.bound["deadline_unix"] - time.time()
        require(remaining > 0)
        return min(12, remaining)

    def command(self, args, data=None):
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=self.timeout(), check=False)
        require(result.returncode == 0)
        return result.stdout

    def remote_read(self, path):
        program = "import os,stat,sys;p=sys.argv[1];a=os.lstat(p);f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);s=os.fstat(f);assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==384 and s.st_uid==0 and s.st_nlink==1 and 0<s.st_size<=1000000;b=os.read(f,1000001);z=os.lstat(p);assert (a.st_dev,a.st_ino)==(s.st_dev,s.st_ino)==(z.st_dev,z.st_ino) and len(b)==s.st_size;sys.stdout.buffer.write(b)"
        return self.command(self.remote + ["python3 -c " + shlex.quote(program) + " " + shlex.quote(path)])

    def exists(self, name):
        path = self.options["remote_state_dir"] + "/" + name
        program = "import os,sys;print(int(os.path.lexists(sys.argv[1])))"
        return self.command(self.remote + ["python3 -c " + shlex.quote(program) + " " + shlex.quote(path)]).strip() == b"1"

    def fetch(self, name):
        return self.remote_read(self.options["remote_state_dir"] + "/" + name)

    def publish(self, name, document):
        program = """import ctypes,os,stat,sys,tempfile
p=sys.argv[1];d=os.path.dirname(p);s=os.lstat(d);assert stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==448 and s.st_uid==0
f,t=tempfile.mkstemp(prefix='.link-outside-',dir=d)
try:
 os.fchmod(f,384);b=sys.stdin.buffer.read(1000001);assert 0<len(b)<=1000000 and os.write(f,b)==len(b);os.fsync(f);os.close(f);f=-1
 c=ctypes.CDLL(None,use_errno=True);r=c.renameat2;r.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];r.restype=ctypes.c_int;assert r(-100,os.fsencode(t),-100,os.fsencode(p),1)==0
 q=os.open(d,os.O_RDONLY|os.O_DIRECTORY);os.fsync(q);os.close(q)
finally:
 if f>=0: os.close(f)
 if os.path.lexists(t): os.unlink(t)
"""
        self.command(self.remote + ["python3 -c " + shlex.quote(program) + " " +
                                    shlex.quote(self.options["remote_state_dir"] + "/" + name)], canonical(document))

    def wait(self, name):
        while not self.exists(name):
            require(time.time() < self.bound["deadline_unix"])
            time.sleep(.1)
        return self.fetch(name)

    def unchanged(self):
        require(digest(self.remote_read(self.options["remote_request"])) == self.bound["request_sha256"] and
                digest(self.remote_read(self.options["remote_manifest"])) == self.bound["qualification_manifest_sha256"])

    def outside_route(self, server):
        raw = self.command(["curl", "-4", "-fsS", "--noproxy", "*", "--max-time", str(int(self.timeout())),
                            "https://api.ipify.org"]).strip()
        direct = str(ipaddress.ip_address(raw.decode())).encode()
        require(direct == raw and direct != server.encode())


def produce(backend, bound):
    scenario = bound["scenario_id"]
    prefix = "link-" + scenario
    backend.unchanged()
    initial_raw = backend.fetch(prefix + "-initial.json")
    initial = observation(initial_raw, bound)
    initial_hash = hashes(initial)
    backend.outside_route(urllib.parse.urlsplit(initial["link"]).hostname)
    started = now()
    old_initial = backend.probe.complete(initial, 200, backend.timeout())
    ready = dict(public_bound(bound), schema="sbxr-v4-link-outside-ready-v1", started_at=started,
                 old_initial_at=old_initial, ready_at=now(), old_link_sha256=initial_hash["link"],
                 configuration_sha256=initial_hash["configuration"], certificate_der_sha256=initial_hash["certificate"],
                 initial_disclosure_sha256=digest(initial_raw), facts={"artifact_matches": True, "old_initial_200": True,
                 "outside_route_distinct": True, "trusted_tls": True})
    check_ready(ready, bound, initial_raw)
    ready_raw = canonical(ready)
    backend.publish(prefix + "-ready.json", ready)
    challenge_raw = backend.wait(prefix + "-challenge.json")
    check_challenge(decode(challenge_raw), bound, ready_raw)
    backend.unchanged()
    tls = None
    try:
        tls, pending_started, established, sent = backend.probe.pending(initial, min(4.9, backend.timeout()))
        ack = dict(public_bound(bound), schema="sbxr-v4-link-outside-ack-v1", challenge_sha256=digest(challenge_raw),
                   connection_id=secrets.token_hex(16), tls_established_at=established, partial_request_sent_at=sent,
                   pending_ready_at=now(), old_link_sha256=initial_hash["link"])
        ack_raw = canonical(ack)
        check_ack(ack, bound, ready_raw, challenge_raw)
        backend.publish(prefix + "-ack.json", ack)
        kind, elapsed, closed_at = backend.probe.closure(tls, pending_started, min(5, backend.timeout()))
    finally:
        if tls is not None:
            tls.close()
    closed = dict(public_bound(bound), schema="sbxr-v4-link-outside-closed-v1", challenge_sha256=digest(challenge_raw),
                  ack_sha256=digest(ack_raw), connection_id=ack["connection_id"],
                  partial_request_sent_at=sent, pending_ready_at=ack["pending_ready_at"], closed_at=closed_at,
                  closure_kind=kind, pending_elapsed_milliseconds=elapsed, server_deadline_seconds=5,
                  old_link_sha256=initial_hash["link"])
    closed_raw = canonical(closed)
    check_closed(closed, bound, ready_raw, challenge_raw, ack_raw)
    backend.publish(prefix + "-closed.json", closed)
    finalize_raw = backend.wait(prefix + "-finalize.json")
    final_raw = backend.fetch(prefix + "-final.json")
    check_finalize(decode(finalize_raw), bound, challenge_raw, closed_raw, final_raw)
    backend.unchanged()
    final = observation(final_raw, bound)
    final_hash = hashes(final)
    require(final_hash["configuration"] == initial_hash["configuration"] and
            final_hash["certificate"] == initial_hash["certificate"])
    if scenario == "link-precommit":
        require(final_hash["link"] == initial_hash["link"])
        old_final, new_final, new_link = backend.probe.complete(final, 200, backend.timeout()), None, None
        facts = {"old_final_200": True, "new_final_200": False, "old_final_404": False,
                 "same_configuration": True, "same_certificate": True, "same_old_link": True,
                 "trusted_tls": True, "runner_cleanup_complete": True}
    else:
        require(final_hash["link"] != initial_hash["link"])
        old_final = backend.probe.complete(initial, 404, backend.timeout())
        new_final = backend.probe.complete(final, 200, backend.timeout())
        new_link = final_hash["link"]
        facts = {"old_final_200": False, "new_final_200": True, "old_final_404": True,
                 "same_configuration": True, "same_certificate": True, "same_old_link": False,
                 "trusted_tls": True, "runner_cleanup_complete": True}
    result = dict(public_bound(bound), schema="sbxr-v4-link-outside-result-v1", ready_sha256=digest(ready_raw),
                  challenge_sha256=digest(challenge_raw), ack_sha256=digest(ack_raw), closed_sha256=digest(closed_raw),
                  finalize_sha256=digest(finalize_raw), final_disclosure_sha256=digest(final_raw), started_at=started,
                  old_initial_at=old_initial, pending_ready_at=ack["pending_ready_at"], closed_at=closed_at,
                  old_final_at=old_final, new_final_at=new_final, cleanup_at=now(), old_link_sha256=initial_hash["link"],
                  new_link_sha256=new_link, configuration_sha256=initial_hash["configuration"],
                  certificate_der_sha256=initial_hash["certificate"], facts=facts)
    check_result(result, bound, {"ready": ready_raw, "challenge": challenge_raw, "ack": ack_raw,
                 "closed": closed_raw, "finalize": finalize_raw}, initial_raw, final_raw)
    backend.publish(prefix + "-result.json", result)
    return result


def checker(args, bound):
    receipt_raw = read_private(args.receipt)
    receipt = decode(receipt_raw)
    base = Path(args.receipt).parent
    scenario = bound["scenario_id"]
    prefix = "link-" + scenario
    read = lambda suffix: read_private(base / (prefix + "-" + suffix + ".json"))
    if args.command == "check-ready":
        check_ready(receipt, bound, read("initial"))
    elif args.command == "check-ack":
        check_ack(receipt, bound, read("ready"), read("challenge"))
    elif args.command == "check-closed":
        check_closed(receipt, bound, read("ready"), read("challenge"), read("ack"))
    else:
        check_result(receipt, bound, {key: read(key) for key in ("ready", "challenge", "ack", "closed", "finalize")},
                     read("initial"), read("final"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--config", required=True)
    run.add_argument("--scenario", choices=SCENARIOS, required=True)
    for name in ("check-ready", "check-ack", "check-closed", "check-result"):
        item = commands.add_parser(name)
        item.add_argument("--manifest", required=True)
        item.add_argument("--request", required=True)
        item.add_argument("--receipt", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.command == "run":
        options = decode(read_private(args.config))
        expected = {"host", "ssh_key", "known_hosts", "remote_state_dir", "remote_request", "remote_manifest",
                    "manifest", "request", "outside_runner_id"}
        require(set(options) == expected and all(isinstance(value, str) and value for value in options.values()))
        require(re.fullmatch(r"[a-zA-Z0-9.-]+", options["host"]) is not None and not options["host"].startswith("-") and
                all(value.startswith("/") for key, value in options.items() if key not in ("host", "outside_runner_id")))
        require(sys.platform == "linux" and platform.machine() == "x86_64" and
                'ID=ubuntu\n' in Path("/etc/os-release").read_text() and
                'VERSION_ID="24.04"' in Path("/etc/os-release").read_text())
        manifest_raw, request_raw = read_private(options["manifest"]), read_private(options["request"])
        bound = binding(manifest_raw, request_raw)
        require(time.time() < bound["deadline_unix"])
        require(bound["scenario_id"] == args.scenario and bound["outside_runner_id"] == options["outside_runner_id"])
        backend = LiveBackend(options, bound)
        require(backend.command(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).strip() == b"yes")
        result = produce(backend, bound)
        print(canonical(result).decode())
    else:
        bound = binding(read_private(args.manifest), read_private(args.request))
        require(time.time() < bound["deadline_unix"])
        checker(args, bound)
        print('{"link_outside_verified":true}')


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"link_outside_failed":true}', file=sys.stderr)
        raise SystemExit(1)
