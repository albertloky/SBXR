#!/usr/bin/env python3
"""Receive one authenticated diagnostic disclosure privately. Run only with Owner approval."""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode
from uuid import UUID

HERE = Path(__file__).resolve().parent
MAX_OUTPUT = 65536
CAP = 120
STOP_ALLOWANCE = 10
CLIENT_CAP = 300


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load("disclosure-diagnostic")
restoration = load("diagnostic-restoration")


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(raw, host, label):
    begin = b"----- BEGIN SBXR CLIENT CONFIGURATION -----"
    end = b"----- END SBXR CLIENT CONFIGURATION -----"
    result = b"Code: PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED"
    lines = raw.splitlines()
    require(len(raw) <= MAX_OUTPUT and lines.count(begin) == lines.count(end) == 1 and result in lines,
            "incomplete disclosure")
    first, last = lines.index(begin), lines.index(end)
    require(first < last, "frame order")
    data = json.loads(b"\n".join(lines[first+1:last]), object_pairs_hook=collector.pairs)
    n, = data["outbounds"]
    tls = n["tls"]
    uid = UUID(n["uuid"])
    require(str(uid) == n["uuid"] and uid.version == 4, "client identity")
    public = tls["reality"]["public_key"]
    key = base64.urlsafe_b64decode(public + "=")
    require(len(key) == 32 and base64.urlsafe_b64encode(key).decode().rstrip("=") == public, "public key")
    sid = tls["reality"]["short_id"]
    sni = tls["server_name"]
    require(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", sni)
            and re.fullmatch(r"[0-9a-f]{8}", sid), "REALITY fields")
    require(str(ipaddress.IPv4Address(host)) == host and re.fullmatch(r"SBXR-[0-9a-f]{16}", label),
            "host or label")
    expected = {"log":{"level":"warn","timestamp":True},
                "inbounds":[{"listen":"127.0.0.1","listen_port":2080,"tag":"mixed-in","type":"mixed"}],
                "outbounds":[{"flow":"xtls-rprx-vision","server":host,"server_port":443,"tag":"vless-out",
                             "type":"vless","uuid":str(uid),"tls":{"enabled":True,"server_name":sni,
                             "reality":{"enabled":True,"public_key":public,"short_id":sid},
                             "utls":{"enabled":True,"fingerprint":"chrome"}}}]}
    require(collector.canonical(data) == collector.canonical(expected), "unexpected Standard configuration")
    query = urlencode([("encryption","none"),("flow","xtls-rprx-vision"),("security","reality"),
                       ("sni",sni),("fp","chrome"),("pbk",public),("sid",sid),("type","tcp")])
    return f"vless://{uid}@{host}:443?{query}#{label}\n".encode()


def private_directory(path):
    require(path.is_absolute() and path.resolve(strict=True) == path, "canonical directory required")
    collector.directory(path)


def collect(command, program, cutoff):
    # The SSH input contains reviewed script bytes and public run pins. Only its
    # output contains a credential. No transcript ever reaches an operator log.
    end = time.monotonic() + CAP
    def remaining():
        left = min(end - time.monotonic(), cutoff - STOP_ALLOWANCE - time.time())
        require(left > 0, "operator deadline")
        return left
    with tempfile.TemporaryFile() as code:
        code.write(program)
        code.seek(0)
        remaining()
        with subprocess.Popen(command, stdin=code, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child:
            try:
                body = bytearray()
                with selectors.DefaultSelector() as sel:
                    sel.register(child.stdout, selectors.EVENT_READ)
                    while True:
                        require(sel.select(remaining()), "disclosure timeout")
                        chunk = os.read(child.stdout.fileno(), min(8192, MAX_OUTPUT+1-len(body)))
                        if not chunk:
                            break
                        body.extend(chunk)
                        require(len(body) <= MAX_OUTPUT, "oversize disclosure")
                require(child.wait(timeout=remaining()) == 0, "producer refused")
                remaining()
                return body
            finally:
                if child.poll() is None:
                    child.kill()  # Fixed direct ssh process. Remote supervision is separate.
                child.wait(timeout=STOP_ALLOWANCE)
                child.stdout.close()


def record_file(directory, node, receipt):
    fd = os.open(directory/"node.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        info = os.fstat(out.fileno())
        receipt.update(device=info.st_dev, inode=info.st_ino, sha256=sha(node))
        receipt_raw = collector.canonical(receipt)
        try:
            # Retain ownership evidence before the first credential byte is written.
            receipt_fd = os.open(directory/"receipt.json", os.O_WRONLY | os.O_EXCL | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(receipt_fd, "wb") as rec:
                rec.write(receipt_raw)
                rec.flush()
                os.fsync(rec.fileno())
            # The outer operator supervisor retains this cleanup-only pin even
            # if the process stops before the final success acknowledgement.
            print("cleanup_receipt_sha256=" + sha(receipt_raw), file=sys.stderr, flush=True)
            out.write(node)
            out.flush()
            os.fsync(out.fileno())
            require(collector.read(directory/"node.txt") == node, "file verification")
        except BaseException:
            other = (directory/"node.txt").lstat()
            if os.path.samestat(info, other) and other.st_nlink == 1:
                (directory/"node.txt").unlink()
            raise
    return sha(receipt_raw)


def receive(root, attempt, manifest_sha, request_sha, host, cutoff, command, program):
    private_directory(root)
    require(re.fullmatch(r"run-[1-9][0-9]*-attempt-[1-9][0-9]*", attempt)
            and all(re.fullmatch("[0-9a-f]{64}", x) for x in (manifest_sha, request_sha)), "run pins")
    require(time.time()+CAP+STOP_ALLOWANCE+CLIENT_CAP < cutoff, "insufficient operation time")
    directory = root / ("karing-" + attempt)
    directory.mkdir(mode=0o700)  # One disclosure attempt, including failures.
    label = "SBXR-" + request_sha[:16]
    raw = collect(command, program, cutoff)
    node = wire(raw, host, label)
    client_until = int(time.time()) + CLIENT_CAP
    require(client_until + STOP_ALLOWANCE < cutoff, "publication cutoff")
    pin = record_file(directory, node, dict(attempt_id=attempt, manifest_sha256=manifest_sha,
                      request_sha256=request_sha, label=label, client_until_unix=client_until))
    return {"receipt_sha256":pin, "client_until_unix":client_until}


def discard(directory, receipt_pin):
    private_directory(directory)
    raw = collector.read(directory/"receipt.json")
    require(sha(raw) == receipt_pin, "wrong receipt")
    receipt = json.loads(raw, object_pairs_hook=collector.pairs)
    require(directory.name == "karing-" + receipt["attempt_id"], "wrong directory")
    path = directory/"node.txt"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return "absent"
    with os.fdopen(fd,"rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_dev == receipt["device"]
                and info.st_ino == receipt["inode"] and info.st_size <= 4096, "identity changed")
        require(sha(stream.read(4097)) == receipt["sha256"] and os.path.samestat(info, path.lstat()),
                "contents or name changed")
        path.unlink()  # Parent is private and the approved operator is its sole writer.
    return "removed"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    subs = p.add_subparsers(dest="action", required=True)
    create = subs.add_parser("receive")
    for key in ("manifest", "request", "run-directory", "identity", "known-hosts"):
        create.add_argument("--"+key, type=Path, required=True)
    for key in ("manifest-sha256", "request-sha256", "host"):
        create.add_argument("--"+key, required=True)
    create.add_argument("--port", type=int, required=True)
    create.add_argument("--runtime-deadline", type=int, required=True)
    create.add_argument("--finish-by", type=int, required=True)
    drop = subs.add_parser("discard")
    drop.add_argument("--directory", type=Path, required=True)
    drop.add_argument("--receipt-sha256", required=True)
    args = p.parse_args()
    if args.action == "discard":
        print(discard(args.directory, args.receipt_sha256))
        return
    raw = collector.read(args.manifest)
    request_raw = collector.read(args.request)
    require(sha(raw) == args.manifest_sha256 and sha(request_raw) == args.request_sha256, "binding changed")
    attempt = json.loads(raw, object_pairs_hook=collector.pairs)["v3_attempt"]
    q = json.loads(request_raw, object_pairs_hook=collector.pairs)
    window, run = attempt["diagnostic"], attempt["attempt_id"]
    remote = "/root/sbxr-diagnostic-" + run
    restoration.validate_request(q, raw, args.manifest_sha256, remote+"/request.json",
                                 remote+"/observation-draft.json", window)
    require(window.get("mode") == "karing-one-node", "signed mode required")
    cutoff = restoration.operation_cutoff(q, args.runtime_deadline, args.finish_by)
    require(window["start_unix"] <= time.time(), "early start")
    command, program = load("diagnostic-karing-producer").command(
        args.host, args.port, args.identity, args.known_hosts, run, args.manifest_sha256,
        args.request_sha256, cutoff)
    result = receive(args.run_directory, run, args.manifest_sha256, args.request_sha256,
                  args.host, cutoff, command, program)
    print(json.dumps(result, separators=(",",":")))


if __name__ == "__main__":
    def interrupt(*_):
        raise KeyboardInterrupt
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupt)
    try:
        main()
    except (KeyboardInterrupt, OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, subprocess.SubprocessError):
        print("Karing diagnostic refused or interrupted; inspect the run directory before cleanup.", file=sys.stderr)
        sys.exit(1)
