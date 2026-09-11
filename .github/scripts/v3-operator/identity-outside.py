#!/usr/bin/env python3
"""One-shot outside Client Identity proof and its remote ready/result checker.

Run on the attested Ubuntu amd64 outside runner with a protected --config file.
Only paths and non-secret transport facts belong in that file. Configuration
disclosures travel over strict SSH into a unique tmpfs directory. No subprocess
output or exception text is forwarded to the terminal. The public rotation is
performed separately by 07-identity-absent-rotate.sh after the ready receipt.
"""
import argparse
import copy
import ctypes
import datetime as dt
import hashlib
import http.client
import ipaddress
import inspect
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time

SCHEMA = "sbxr-v4-identity-outside-v1"
PACKAGE = {"architecture": "amd64", "name": "sing-box", "repository": "https://deb.sagernet.org/",
           "sha256": "fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf",
           "signing_key_sha256": "803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1",
           "size": 24597120, "version": "1.13.19"}
FACTS = {"same_old_connection": True, "old_transport_closed": True,
         "fresh_old_connection_refused": True, "target_healthy": True,
         "manual_replacement_configuration": True, "replacement_traffic": True,
         "outside_routes_differ": True, "egress_matched": True,
         "runner_cleanup_complete": True}
FAILURE_PHASES = {"input", "setup", "tls-health", "old-session-closure", "state-wait",
                  "old-session-refusal", "replacement", "cleanup"}


def failure_kind(error):
    """Return a fixed category; exception text and type names are never diagnostics."""
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "timeout-error"
    if isinstance(error, ssl.SSLError):
        return "tls-error"
    if isinstance(error, http.client.HTTPException):
        return "http-error"
    if isinstance(error, subprocess.SubprocessError):
        return "subprocess-error"
    if isinstance(error, ConnectionError):
        return "connection-error"
    if isinstance(error, OSError):
        return "os-error"
    if isinstance(error, (ValueError, KeyError, TypeError, AssertionError)):
        return "validation-error"
    if isinstance(error, RuntimeError):
        return "runtime-error"
    return "unexpected-error"


def mark_failure(error, phase):
    error.identity_outside_phase = phase if phase in FAILURE_PHASES else "input"
    return error


def failure_diagnostic(error, phase=None):
    selected = phase if phase in FAILURE_PHASES else getattr(error, "identity_outside_phase", "input")
    if selected not in FAILURE_PHASES:
        selected = "input"
    return {"exception_kind": failure_kind(error), "identity_outside_failed": True, "phase": selected}


def require(condition):
    if not condition:
        raise ValueError("identity-outside-refused")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    require(0 < len(raw) <= 1_000_000)
    return json.loads(raw, object_pairs_hook=unique)


def read_private(path, uid=None):
    before = os.lstat(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1 and info.st_uid == (os.getuid() if uid is None else uid)
                and 0 < info.st_size <= 1_000_000)
        raw = os.read(fd, 1_000_001)
        after = os.lstat(path)
        require((before.st_dev, before.st_ino) == (info.st_dev, info.st_ino) == (after.st_dev, after.st_ino)
                and len(raw) == info.st_size)
        return raw
    finally:
        os.close(fd)


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)


def atomic_write_new(path, value):
    """Linux atomic no-replace publication; no empty, partial or two-link window."""
    path = os.fspath(path)
    directory = os.path.dirname(path)
    parent = os.lstat(directory)
    if not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700 or parent.st_uid != os.getuid():
        raise ValueError("private-directory-required")
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    fd, temporary = tempfile.mkstemp(prefix=".identity-publish-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        if rename(-100, os.fsencode(temporary), -100, os.fsencode(path), 1) != 0:
            raise OSError(ctypes.get_errno(), "atomic-publication-refused")
        parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def timestamp(value):
    require(isinstance(value, str) and bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value)))
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def binding(manifest_raw, request_raw, state):
    manifest, request = decode(manifest_raw), decode(request_raw)
    digest = hashlib.sha256(manifest_raw).hexdigest()
    require(request["qualification_manifest_sha256"] == digest and request["scenario_id"] == "identity-absent")
    require(type(request["deadline_unix"]) is int and type(request["scenario_limit_seconds"]) is int
            and request["scenario_limit_seconds"] == 1800)
    started = timestamp(state["started_at"])
    require(timestamp(request["not_before"]) <= started <= request["deadline_unix"]
            and request["deadline_unix"] - started <= 1800)
    attempt = manifest["v3_attempt"]
    require(manifest["schema"] == "sbxr-qualification-manifest-v3" and manifest["mode"] == "v3"
            and attempt["evidence_policy"] == "repair-issuance-bounded-v4" and attempt["proxy_package"] == PACKAGE)
    require(re.fullmatch(r"runner-[0-9]+", attempt["outside_runner_id"]) is not None)
    return {"schema": SCHEMA, "scenario_id": "identity-absent", "request_sha256": hashlib.sha256(request_raw).hexdigest(),
            "qualification_manifest_sha256": digest, "deadline_unix": request["deadline_unix"],
            "outside_runner_id": attempt["outside_runner_id"], "started_at": state["started_at"]}


def check(document, bound, state, ready=False, current=None):
    require(all(document.get(key) == value for key, value in bound.items()))
    base = set(bound) | {"connection_id", "old_established_at", "ready_at", "ready"}
    require(document.get("ready") is True and isinstance(document.get("connection_id"), str)
            and re.fullmatch(r"[0-9a-f]{32}", document["connection_id"]) is not None)
    times = [timestamp(bound["started_at"]), timestamp(state["setup_at"]),
             timestamp(document["old_established_at"]), timestamp(document["ready_at"])]
    if ready:
        require(set(document) == base)
        # The fresh challenge, rather than this initial receipt, proves liveness.
        require(times[-1] <= (time.time() if current is None else current) <= bound["deadline_unix"])
    else:
        require(set(document) == base | {"old_terminated_at", "old_refused_at", "target_healthy_at",
                                       "replacement_at", "cleanup_at", "facts", "rotation_ready_at", "rotation_challenge_sha256",
                                       "old_client", "replacement_client"})
        require(set(document["facts"]) == set(FACTS) and all(value is True for value in document["facts"].values()))
        for name in ("old_client", "replacement_client"):
            process = document[name]
            require(set(process) == {"pid", "start_tick", "listener_owned", "confirmed_disclosure"}
                    and type(process["pid"]) is int and process["pid"] > 1
                    and type(process["start_tick"]) is int and process["start_tick"] > 0
                    and process["listener_owned"] is True and process["confirmed_disclosure"] is True)
        require(document["old_client"]["pid"] != document["replacement_client"]["pid"])
        require(re.fullmatch(r"[0-9a-f]{64}", document["rotation_challenge_sha256"]) is not None)
        rotation_start, rotation_end = timestamp(state["rotation_started_at"]), timestamp(state["rotation_completed_at"])
        require(times[-1] <= timestamp(document["rotation_ready_at"]) <= rotation_start <= rotation_end)
        terminated = timestamp(document["old_terminated_at"])
        require(rotation_start <= terminated)
        times += [terminated, timestamp(document["old_refused_at"]), timestamp(document["target_healthy_at"]),
                  timestamp(document["replacement_at"]), timestamp(document["cleanup_at"])]
        require(rotation_end <= timestamp(document["old_refused_at"]))
        require(state.get("replacement_disclosure_confirmed") is True)
    require(times == sorted(times) and times[-1] <= bound["deadline_unix"])
    return document


def check_rotation_ack(ack, challenge, bound, current):
    require(set(challenge) == set(bound) | {"nonce", "challenged_at"}
            and all(challenge.get(key) == value for key, value in bound.items())
            and re.fullmatch(r"[0-9a-f]{32}", challenge["nonce"]) is not None)
    require(set(ack) == set(challenge) | {"alive_at", "connection_id"}
            and all(ack.get(key) == value for key, value in challenge.items())
            and re.fullmatch(r"[0-9a-f]{32}", ack["connection_id"]) is not None)
    require(timestamp(challenge["challenged_at"]) <= timestamp(ack["alive_at"]) <= current
            and current - timestamp(ack["alive_at"]) <= 5 and current <= bound["deadline_unix"])


class ClosedTransport(Exception):
    """An observed EOF/reset, distinct from a timeout or an HTTP target error."""


class TLSConnection:
    def __init__(self, backend, proxy=True):
        self.backend = backend
        self.sock = None
        raw = socket.create_connection(("127.0.0.1", 2080) if proxy else ("httpbingo.org", 443), timeout=backend.timeout())
        try:
            if proxy:
                raw.sendall(b"CONNECT httpbingo.org:443 HTTP/1.1\r\nHost: httpbingo.org:443\r\n\r\n")
                header = bytearray()
                while not header.endswith(b"\r\n\r\n"):
                    part = raw.recv(1)
                    require(part and len(header) < 4096)
                    header.extend(part)
                require(header.split(b"\r\n", 1)[0].split()[1] == b"200")
            self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname="httpbingo.org")
        except BaseException:
            raw.close()
            raise

    def request(self):
        self.sock.settimeout(self.backend.timeout())
        try:
            self.sock.sendall(b"GET /status/200 HTTP/1.1\r\nHost: httpbingo.org\r\nUser-Agent: sbxr-qualification\r\nConnection: keep-alive\r\n\r\n")
            response = http.client.HTTPResponse(self.sock)
            response.begin()
            body = response.read(4097)
            require(response.status == 200 and not response.will_close and len(body) <= 4096)
            response.close()
        except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError, http.client.RemoteDisconnected) as error:
            raise ClosedTransport() from error

    def close(self):
        if self.sock:
            self.sock.close()


class LiveBackend:
    def __init__(self, options, bound):
        self.options, self.bound = options, bound
        self.root = None
        self.package_root = None
        self.client = None
        self.uuids = []
        self.source = None
        self.cleaning = False
        self.remote = ["ssh", "-i", options["ssh_key"], "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                       "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + options["known_hosts"],
                       "-o", "ConnectTimeout=10", "root@" + options["host"]]

    def timeout(self):
        if self.cleaning:
            return 5
        remaining = self.bound["deadline_unix"] - time.time()
        require(remaining > 0)
        return min(12, remaining)

    def command(self, args, data=None):
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=self.timeout(), check=False)
        require(result.returncode == 0)
        return result.stdout

    def remote_read(self, path):
        # No shell expansion of owner paths; root metadata is checked before read.
        program = "import os,stat,sys; p=sys.argv[1]; before=os.lstat(p); f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); s=os.fstat(f); assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==384 and s.st_uid==0 and s.st_nlink==1 and 0<s.st_size<=1000000; b=os.read(f,1000001); after=os.lstat(p); assert (before.st_dev,before.st_ino)==(s.st_dev,s.st_ino)==(after.st_dev,after.st_ino) and len(b)==s.st_size; sys.stdout.buffer.write(b)"
        return self.command(self.remote + ["python3 -c " + shlex.quote(program) + " " + shlex.quote(path)])

    def fetch(self, name):
        return self.remote_read(self.options["remote_state_dir"] + "/" + name)

    def challenge(self):
        path = self.options["remote_state_dir"] + "/07-outside-rotation-request.json"
        exists = self.command(self.remote + ["python3 -c " + shlex.quote("import os,sys; print(int(os.path.lexists(sys.argv[1])))") + " " + shlex.quote(path)])
        return decode(self.remote_read(path)) if exists.strip() == b"1" else None

    def state(self):
        # Revalidate the exact current request on every coordinated state read.
        require(hashlib.sha256(self.remote_read(self.options["remote_request"])).hexdigest() == self.bound["request_sha256"])
        return decode(self.fetch("07-state.json"))

    def publish(self, name, document):
        program = ("import ctypes,os,stat,sys,tempfile\n" + inspect.getsource(atomic_write_new)
                   + "\nassert os.getuid()==0\nb=sys.stdin.buffer.read(1000001)\nassert 0<len(b)<=1000000\natomic_write_new(sys.argv[1],b)\n")
        self.command(self.remote + ["python3 -c " + shlex.quote(program) + " " + shlex.quote(self.options["remote_state_dir"] + "/" + name)], canonical(document))

    def prepare(self):
        require(sys.platform == "linux" and platform.machine() == "x86_64")
        release = Path("/etc/os-release").read_text()
        require('ID=ubuntu\n' in release and 'VERSION_ID="24.04"' in release)
        require(self.command(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).strip() == b"yes")
        require(self.command(["findmnt", "-no", "FSTYPE", "-T", "/dev/shm"]).strip() == b"tmpfs")
        require(self.options["outside_runner_id"] == self.bound["outside_runner_id"])
        self.root = Path(tempfile.mkdtemp(prefix="sbxr-identity-", dir="/dev/shm"))
        self.package_root = Path(tempfile.mkdtemp(prefix="sbxr-identity-package-"))
        require(not self.listener())
        require(hashlib.sha256(self.remote_read(self.options["remote_manifest"])).hexdigest() == self.bound["qualification_manifest_sha256"])
        self.publish("07-outside-started.json", self.bound)
        key, deb = self.root / "key", self.root / "client.deb"
        self.command(["curl", "-fsSL", "--max-time", str(int(self.timeout())), "https://sing-box.app/gpg.key", "-o", str(key)])
        require(hashlib.sha256(key.read_bytes()).hexdigest() == PACKAGE["signing_key_sha256"])
        self.command(["curl", "-fsSL", "--max-time", str(int(self.timeout())), "https://deb.sagernet.org/files/ver_qb4px/sing-box_1.13.19_linux_amd64.deb", "-o", str(deb)])
        require(deb.stat().st_size == PACKAGE["size"] and hashlib.sha256(deb.read_bytes()).hexdigest() == PACKAGE["sha256"])
        self.command(["dpkg-deb", "-x", str(deb), str(self.package_root)])
        self.binary = str(self.package_root / "usr/bin/sing-box")

    def listener(self):
        return self.command(["ss", "-H", "-ltnp", "sport = :2080"]).strip()

    def scan(self):
        if self.root:
            for path in self.root.glob("*.log"):
                raw = path.read_bytes()
                require(not any(value.encode() in raw for value in self.uuids))
                require(not re.search(rb"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|Authorization:|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", raw))

    def start_client(self, replacement=False):
        require(self.state().get("replacement_disclosure_confirmed" if replacement else "source_disclosure_confirmed") is True)
        raw = self.fetch("07-replacement-client.json" if replacement else "07-source-client.json")
        config = decode(raw)
        require(config["inbounds"] == [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}]
                and len(config["outbounds"]) == 1)
        outbound = config["outbounds"][0]
        require(outbound["type"] == "vless" and isinstance(outbound["uuid"], str)
                and re.fullmatch(r"[0-9a-fA-F-]{36}", outbound["uuid"]) is not None)
        self.uuids.append(outbound["uuid"])
        if replacement:
            old, new = copy.deepcopy(self.source), copy.deepcopy(config)
            require(old["outbounds"][0].pop("uuid") != new["outbounds"][0].pop("uuid") and old == new)
        else:
            self.source = config
        path = self.root / ("replacement.json" if replacement else "source.json")
        write_new(path, raw)
        self.command([self.binary, "check", "-c", str(path)])
        log = self.root / ("replacement.log" if replacement else "source.log")
        with open(log, "xb") as output:
            self.client = subprocess.Popen([self.binary, "run", "-c", str(path)], stdin=subprocess.DEVNULL,
                                           stdout=output, stderr=output, start_new_session=True)
        until = min(time.monotonic() + 10, time.monotonic() + self.timeout())
        while time.monotonic() < until:
            require(self.client.poll() is None)
            if b"pid=" + str(self.client.pid).encode() + b"," in self.listener():
                self.scan()
                tick = int(Path(f"/proc/{self.client.pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
                return {"pid": self.client.pid, "start_tick": tick, "listener_owned": True, "confirmed_disclosure": True}
            time.sleep(.1)
        raise ValueError("client-not-ready")

    def client_alive(self):
        require(self.client is not None and self.client.poll() is None)

    def stop_client(self):
        if self.client:
            group = self.client.pid
            try:
                os.killpg(group, signal.SIGTERM)
            except ProcessLookupError:
                pass
            forced = False
            try:
                self.client.wait(timeout=5)
            except subprocess.TimeoutExpired:
                forced = True
                os.killpg(group, signal.SIGKILL)
                self.client.wait(timeout=5)
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                pass
            else:
                raise ValueError("client-descendants-remain")
            self.client = None
            require(not self.listener())
            self.scan()
            require(not forced)

    def connect(self, proxy=True):
        self.client_alive()
        return TLSConnection(self, proxy)

    def routes(self):
        direct = self.command(["curl", "-fsS", "--noproxy", "*", "--max-time", str(int(self.timeout())), "https://api.ipify.org"]).strip()
        proxied = self.command(["curl", "-fsS", "--proxy", "socks5h://127.0.0.1:2080", "--noproxy", "", "--max-time", str(int(self.timeout())), "https://api.ipify.org"]).strip()
        # The disclosed server address is the supported setup's public IPv4.
        server = str(ipaddress.ip_address(self.source["outbounds"][0]["server"])).encode()
        require(str(ipaddress.ip_address(direct.decode())).encode() == direct and direct != server and proxied == server)

    def clock(self):
        self.timeout()
        return now()

    def pause(self):
        time.sleep(min(1, self.timeout()))

    def cleanup(self):
        # Cleanup has its own bounded process waits; it cannot produce a pass
        # after the scenario deadline, which clock/check still enforce.
        signal.setitimer(signal.ITIMER_REAL, 0)
        self.cleaning = True
        try:
            try:
                self.stop_client()
                self.scan()
            finally:
                if self.root:
                    shutil.rmtree(self.root)
                    require(not self.root.exists())
                if self.package_root:
                    shutil.rmtree(self.package_root)
                    require(not self.package_root.exists())
        finally:
            self.cleaning = False


def produce(backend, bound, state):
    """Dependency seam for deterministic producer tests; CLI always uses LiveBackend."""
    connection = None
    document = None
    phase = "setup"
    try:
        backend.prepare()
        old_process = backend.start_client()
        backend.routes()
        phase = "tls-health"
        connection = backend.connect()
        connection.request()  # One real TLS connection, never replaced after this point.
        established = backend.clock()
        document = dict(bound, connection_id=secrets.token_hex(16), old_established_at=established,
                        ready_at=backend.clock(), ready=True)
        backend.publish("07-outside-ready.json", document)
        acknowledged = False
        phase = "old-session-closure"
        while True:
            backend.client_alive()
            backend.pause()
            challenge = backend.challenge() if not acknowledged else None
            try:
                connection.request()
            except ClosedTransport:
                require(acknowledged)
                document["old_terminated_at"] = backend.clock()
                break
            if challenge:
                ack = dict(challenge, connection_id=document["connection_id"], alive_at=backend.clock())
                check_rotation_ack(ack, challenge, bound, timestamp(ack["alive_at"]))
                backend.publish("07-outside-rotation-ready.json", ack)
                document["rotation_ready_at"] = ack["alive_at"]
                document["rotation_challenge_sha256"] = hashlib.sha256(canonical(challenge)).hexdigest()
                acknowledged = True
        connection.close()
        connection = None
        # The product may close sessions before public action completion.
        phase = "state-wait"
        while True:
            state = backend.state()
            if "rotation_completed_at" in state:
                break
            backend.pause()
        require(timestamp(document["old_terminated_at"]) >= timestamp(state["rotation_started_at"]))
        require(state.get("replacement_disclosure_confirmed") is True)
        backend.client_alive()
        # A fresh connection with the unchanged old config must fail. HTTP errors
        # and success are not revocation evidence. No second attempt is allowed.
        phase = "old-session-refusal"
        old = None
        refused = False
        try:
            old = backend.connect()
            old.request()
        except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError, ClosedTransport, http.client.RemoteDisconnected):
            refused = True
        finally:
            if old:
                old.close()
        require(refused)
        backend.client_alive()
        document["old_refused_at"] = backend.clock()
        phase = "tls-health"
        healthy = backend.connect(proxy=False)
        try:
            healthy.request()
        finally:
            healthy.close()
        document["target_healthy_at"] = backend.clock()
        phase = "replacement"
        backend.stop_client()
        new_process = backend.start_client(replacement=True)
        replacement = backend.connect()
        try:
            replacement.request()
        finally:
            replacement.close()
        backend.routes()
        document["replacement_at"] = backend.clock()
    except Exception as error:
        mark_failure(error, phase)
        raise
    finally:
        close_error = None
        try:
            if connection:
                connection.close()
        except Exception as error:
            mark_failure(error, "cleanup")
            close_error = error
        try:
            backend.cleanup()
        except Exception as error:
            mark_failure(error, "cleanup")
            raise
        if close_error:
            raise close_error
    try:
        document["cleanup_at"] = backend.clock()
        document["facts"] = FACTS.copy()
        document["old_client"] = old_process
        document["replacement_client"] = new_process
        check(document, bound, state, current=timestamp(document["cleanup_at"]))
        backend.publish("07-outside.json", document)
    except Exception as error:
        mark_failure(error, "cleanup")
        raise
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--config", required=True, help="mode-0600 JSON containing transport paths only")
    for name in ("check-ready", "check-result", "request-rotation", "wait-rotation"):
        item = commands.add_parser(name)
        for flag in ("manifest", "request", "state", "receipt"):
            item.add_argument("--" + flag, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.command == "run":
        options = decode(read_private(args.config))
        require(set(options) == {"host", "ssh_key", "known_hosts", "remote_state_dir", "remote_request", "remote_manifest", "manifest", "request", "outside_runner_id"})
        require(all(isinstance(value, str) and value for value in options.values()))
        require(re.fullmatch(r"[a-zA-Z0-9.-]+", options["host"]) is not None and not options["host"].startswith("-"))
        require(all(value.startswith("/") for key, value in options.items() if key not in ("host", "outside_runner_id")))
        manifest_raw, request_raw = read_private(options["manifest"]), read_private(options["request"])
        # Initial transport timeout is still capped by the original request.
        backend = LiveBackend(options, {"deadline_unix": decode(request_raw)["deadline_unix"]})
        state = decode(backend.fetch("07-state.json"))
        bound = binding(manifest_raw, request_raw, state)
        backend.bound = bound
        remaining = bound["deadline_unix"] - time.time()
        require(remaining > 0)
        signal.setitimer(signal.ITIMER_REAL, remaining)
        try:
            result = produce(backend, bound, state)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        print(canonical(result).decode())
        return
    else:
        state = decode(read_private(args.state))
        bound = binding(read_private(args.manifest), read_private(args.request), state)
        if args.command == "request-rotation":
            challenge = dict(bound, nonce=secrets.token_hex(16), challenged_at=now())
            require(time.time() <= bound["deadline_unix"])
            atomic_write_new(Path(args.receipt).with_name("07-outside-rotation-request.json"), canonical(challenge))
        elif args.command == "wait-rotation":
            challenge = decode(read_private(Path(args.receipt).with_name("07-outside-rotation-request.json")))
            until = min(time.monotonic() + 10, time.monotonic() + bound["deadline_unix"] - time.time())
            while not Path(args.receipt).exists() and time.monotonic() < until:
                time.sleep(.1)
            ack = decode(read_private(args.receipt))
            check_rotation_ack(ack, challenge, bound, time.time())
            ready = decode(read_private(Path(args.receipt).with_name("07-outside-ready.json")))
            require(ready["connection_id"] == ack["connection_id"])
        else:
            document = decode(read_private(args.receipt))
            check(document, bound, state, ready=args.command == "check-ready")
            if args.command == "check-result":
                challenge = decode(read_private(Path(args.receipt).with_name("07-outside-rotation-request.json")))
                ack = decode(read_private(Path(args.receipt).with_name("07-outside-rotation-ready.json")))
                check_rotation_ack(ack, challenge, bound, timestamp(state["rotation_started_at"]))
                require(document["rotation_ready_at"] == ack["alive_at"] and document["connection_id"] == ack["connection_id"]
                        and document["rotation_challenge_sha256"] == hashlib.sha256(canonical(challenge)).hexdigest())
    print('{"identity_outside_verified":true}')


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise RuntimeError("interrupted")
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(number, interrupted)
    try:
        main()
    except Exception as error:
        print(canonical(failure_diagnostic(error)).decode(), file=sys.stderr)
        raise SystemExit(1)
