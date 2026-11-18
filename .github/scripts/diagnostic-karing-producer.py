"""Construct one direct SSH disclosure. The receiving caller owns all I/O and timing."""
import hashlib
import ipaddress
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent

# The SSH command starts this program at /. Its inputs are the checkout's
# reviewed modules and the caller's authenticated, non-secret run bindings.
REMOTE = r'''
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time


def load(name):
    namespace = {"__name__": name}
    exec(compile(sources[name], name, "exec"), namespace)
    return namespace


def disclose():
    collector = load("disclosure-diagnostic.py")
    binding = load("diagnostic-restoration.py")
    menu = load("v3-menu-session.py")
    transport = Path("root/sbxr-qualification-v3")
    manifest = transport / "qualification-manifest.json"
    directory = Path("root/sbxr-diagnostic-" + attempt)
    request = directory / "request.json"
    draft = directory / "observation-draft.json"
    recorder = directory / "mvp-observe.py"
    executable = Path("usr/local/bin/sbxr").absolute()

    collector["directory"](directory)
    manifest_raw = collector["read"](manifest)
    request_raw = collector["read"](request)
    if hashlib.sha256(request_raw).hexdigest() != request_sha:
        raise ValueError("request identity")
    declaration = json.loads(manifest_raw, object_pairs_hook=collector["pairs"])["v3_attempt"]
    window = declaration["diagnostic"]
    if declaration["attempt_id"] != attempt or window.get("mode") != "karing-one-node":
        raise ValueError("signed disclosure scope")
    q = json.loads(request_raw, object_pairs_hook=collector["pairs"])
    binding["validate_request"](q, manifest_raw, manifest_sha, "/" + str(request), "/" + str(draft), window)
    fd = os.open("etc/machine-id", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("machine identity file")
        machine = stream.read(65)
    if not 0 < len(machine) <= 64 or hashlib.sha256(machine).hexdigest() != declaration["vps_identity_sha256"]:
        raise ValueError("signed machine identity")

    os.environ.update(SBXR_QUALIFICATION_REQUEST=str(request.absolute()),
                      SBXR_QUALIFICATION_DRAFT=str(draft.absolute()),
                      SBXR_QUALIFICATION_CLOCK=str(recorder.absolute()),
                      SBXR_QUALIFICATION_CLOCK_SHA256=clock_sha)
    # Source the whole reviewed library through an anonymous pipe. Only call
    # its read-only identity check with this diagnostic's explicit paths.
    subprocess.run(["bash", "--noprofile", "--norc", "-c",
                    'set -eu -o pipefail; source /dev/stdin; exact_candidate "$@"',
                    "sbxr-candidate-check", str(manifest), str(request),
                    "var/lib/sbxr/installed.json", str(executable)],
                   input=sources["v3-packaged-live.sh"], stdout=subprocess.DEVNULL,
                   check=True, timeout=10)

    recorder_end = menu["qualification_deadline"](str(request.absolute()))
    runtime_end = menu["cleanup_runtime_deadline"](str(transport.absolute() / "runtime-deadline"))
    # cutoff already excludes the local restoration reserve. The remote runtime
    # and request must independently leave the full 25 minutes for restoration.
    server_end = min(recorder_end, binding["operation_cutoff"](q, runtime_end, window["finish_unix"]))
    if cutoff > server_end:
        raise ValueError("caller must share the earlier server cutoff")
    if time.time() + 90 + 15 >= cutoff:
        raise ValueError("disclosure and supervision do not fit")
    if collector["read"](request) != request_raw or collector["read"](manifest) != manifest_raw:
        raise ValueError("run bindings changed")
    sys.argv = ["v3-menu-session.py", "disclose", "Show client configuration",
                "PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED",
                "--executable", str(executable), "--timeout", "90"]
    # Let the menu driver cancel and reap its child on backpressure as well
    # as disconnect. A blocking stdout write would hold it past its deadline.
    os.set_blocking(sys.stdout.fileno(), False)
    return menu["main"]()


try:
    status = disclose()
except Exception:
    print("One-node disclosure refused", file=sys.stderr)
    status = 1
raise SystemExit(status)
'''


def command(host, port, identity, known_hosts, attempt_id, manifest_sha256, request_sha256, cutoff):
    """Return argv and stdin bytes. cutoff is the absolute ordinary-work cutoff."""
    if not isinstance(host, str) or str(ipaddress.IPv4Address(host)) != host:
        raise ValueError("expected an exact IPv4 address")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("SSH port")
    if (not re.fullmatch(r"run-[1-9][0-9]*-attempt-[1-9][0-9]*", attempt_id) or
            any(not re.fullmatch(r"[0-9a-f]{64}", pin) for pin in (manifest_sha256, request_sha256))):
        raise ValueError("diagnostic identity")
    if type(cutoff) is not int or cutoff <= 0:
        raise ValueError("ordinary-work cutoff")
    # OpenSSH expands tokens and parses its own quoted filenames even with
    # shell=False. Accept plain absolute paths, including ordinary spaces.
    for path in (identity, known_hosts):
        if not re.fullmatch(r"/[a-zA-Z0-9._ /-]+", os.fspath(path)) or ".." in Path(path).parts:
            raise ValueError("SSH identity and host pin require explicit local paths")
    argv = ["/usr/bin/ssh", "-F", "/dev/null", "-4", "-T", "-a", "-x", "-p", str(port),
            "-o", f'IdentityFile="{identity}"', "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none", "-o", "ClearAllForwardings=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", f'UserKnownHostsFile="{known_hosts}"', "-o", "UpdateHostKeys=no",
            "-o", "ConnectTimeout=10", "root@" + host,
            "cd / && exec /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin "
            "LC_ALL=C /usr/bin/python3 -I -B -"]
    names = ("disclosure-diagnostic.py", "diagnostic-restoration.py", "v3-packaged-live.sh", "v3-menu-session.py")
    sources = {name: (HERE / name).read_bytes() for name in names}
    clock_sha = hashlib.sha256((HERE / "mvp-observe.py").read_bytes()).hexdigest()
    inputs = dict(sources=sources, attempt=attempt_id, manifest_sha=manifest_sha256,
                  request_sha=request_sha256, cutoff=cutoff, clock_sha=clock_sha)
    header = "".join(f"{name} = {value!r}\n" for name, value in inputs.items())
    return argv, (header + REMOTE).encode()
