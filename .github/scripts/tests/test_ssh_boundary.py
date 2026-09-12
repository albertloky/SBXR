#!/usr/bin/env python3
"""Linux-only real-SSH boundaries for the V3 operator scripts."""

import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


CASE_TOTAL = 11
CONFIG = '{"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}],"outbounds":[{"type":"vless","uuid":"11111111-1111-4111-8111-111111111111"}]}'


class Refused(Exception):
    pass


def run(command, *, cwd=None, env=None, data=None, timeout=20, ok=True):
    result = subprocess.run(command, cwd=cwd, env=env, input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout)
    if ok != (result.returncode == 0):
        raise Refused("unexpected-command-status")
    return result


def write(path, content, mode=0o600):
    Path(path).write_bytes(content if isinstance(content, bytes) else content.encode())
    os.chmod(path, mode)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fake_product(path):
    source = f'''#!/usr/bin/env python3
import os, signal, sys, time
menu = "SBXR V3\\nProxy status: Running\\nCode: PROXY-INSTALLATION-SETUP-COMPLETE\\n1. View details\\n2. Rotate Client Identity\\n3. Show client configuration\\n0. Exit"
print(menu, flush=True)
choice = sys.stdin.readline().strip()
if choice == "0": raise SystemExit(0)
if choice != "3": raise SystemExit(2)
if os.environ.get("FIXTURE_MODE") == "slow":
    child = os.fork()
    if child == 0:
        os.setsid()
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        marker = os.environ["FIXTURE_DESCENDANT"]
        with open(marker + ".pending", "w") as stream: stream.write(str(os.getpid()))
        os.replace(marker + ".pending", marker)
        while True: time.sleep(1)
    while True: time.sleep(1)
print("Show client configuration? [y/N]", flush=True)
if sys.stdin.readline().strip() != "y": raise SystemExit(3)
print("----- BEGIN SBXR CLIENT CONFIGURATION -----", flush=True)
print({CONFIG!r}, flush=True)
print("----- END SBXR CLIENT CONFIGURATION -----", flush=True)
print("Press Enter to preserve this configuration in terminal scrollback and return to the menu.", flush=True)
sys.stdin.readline()
print("Code: PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED", flush=True)
print(menu, flush=True)
sys.stdin.readline()
'''
    write(path, source, 0o700)


def ssh_base(port, key, known):
    return ["/usr/bin/ssh", "-p", str(port), "-F", "/dev/null", "-T",
            "-i", str(key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}",
            "-o", "ConnectTimeout=5", "root@127.0.0.1"]


def remote(base, command, *, data=None, ok=True, timeout=20):
    options = ["-n"] if data is None else []
    return run(base[:-1] + options + base[-1:] + [command],
               data=data, ok=ok, timeout=timeout)


def clean_results(base):
    remote(base, "rm -f /root/sbxr-qualification-evidence/result.tmp /root/sbxr-qualification-evidence/result.json")


def inside(root):
    if os.getpid() != 1:
        raise Refused("inside-not-pid-one")
    root = Path(root)
    (root / "pid-namespace-inode").write_text(str(os.stat("/proc/self/ns/pid").st_ino))
    run(["mount", "--make-rprivate", "/"])
    run(["mount", "-t", "tmpfs", "-o", "mode=0700", "tmpfs", "/root"])
    run(["mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/run"])
    Path("/run/sshd").mkdir(mode=0o755)
    Path("/root/.ssh").mkdir(mode=0o700)
    evidence = Path("/root/sbxr-qualification-evidence")
    evidence.mkdir(mode=0o700)
    work = root / "work"
    work.mkdir(mode=0o700)
    foreign = root / "foreign"
    foreign.mkdir(mode=0o700)
    keys = root / "keys"
    keys.mkdir(mode=0o700)
    client = keys / "client"
    host = keys / "host"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(client)])
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host)])
    write("/root/.ssh/authorized_keys", (client.with_suffix(".pub")).read_bytes())
    port = free_port()
    config = root / "sshd_config"
    write(config, f'''Port {port}
ListenAddress 127.0.0.1
HostKey {host}
PidFile {root / "sshd.pid"}
AuthorizedKeysFile /root/.ssh/authorized_keys
PermitRootLogin yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
StrictModes yes
LogLevel ERROR
''')
    sshd_path = shutil.which("sshd") or "/usr/sbin/sshd"
    sshd_log = open(root / "sshd.stderr", "wb")
    daemon = subprocess.Popen([sshd_path, "-D", "-e", "-f", str(config)],
                              stdout=subprocess.DEVNULL, stderr=sshd_log,
                              start_new_session=True)
    known = keys / "known_hosts"
    fields = host.with_suffix(".pub").read_text().split()
    write(known, f"[127.0.0.1]:{port} {fields[0]} {fields[1]}\n")
    base = ssh_base(port, client, known)
    try:
        for _ in range(60):
            if daemon.poll() is not None:
                raise Refused("sshd-start")
            trial = subprocess.run(base + ["true"], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
            if trial.returncode == 0:
                break
            time.sleep(0.05)
        else:
            raise Refused("sshd-ready")

        source = root / "source"
        module_bytes = (source / "v3-packaged-live.sh").read_bytes()
        staged = work / "v3-packaged-live.sh"
        driver = work / "v3-menu-session.py"
        collector = work / "v3-recurring-evidence.sh"
        product = work / "sbxr-fixture"
        fake_product(product)
        staged_bytes = module_bytes.replace(b"/usr/local/bin/sbxr", str(product).encode())
        if staged_bytes == module_bytes:
            raise Refused("fixture-substitution")
        write(staged, staged_bytes, 0o700)
        shutil.copyfile(source / "v3-menu-session.py", driver)
        os.chmod(driver, 0o700)
        shutil.copyfile(source / "v3-recurring-evidence.sh", collector)
        os.chmod(collector, 0o700)

        request = evidence / "request.json"
        now = int(time.time())
        write(request, json.dumps({"deadline_unix": now + 30}, separators=(",", ":")))
        command = (f"cd {foreign} && SBXR_EXECUTABLE={product} "
                   f"SBXR_QUALIFICATION_REQUEST={request} /usr/bin/bash {staged} "
                   "remote-outside-disclose v3.fixture 1 deadbeef 1")
        result = remote(base, command)
        if result.stdout != (CONFIG + "\n").encode():
            raise Refused("staged-disclosure-bytes")

        historical = (f"cd {foreign} && SBXR_EXECUTABLE={product} "
                      f"SBXR_QUALIFICATION_REQUEST={request} /usr/bin/bash -s "
                      "remote-outside-disclose v3.fixture 1 deadbeef 1")
        result = remote(base, historical, data=staged_bytes, ok=False)
        if result.stdout:
            raise Refused("streamed-disclosure-output")

        driver_saved = work / "driver.saved"
        driver.rename(driver_saved)
        try:
            result = remote(base, command, ok=False)
            if result.stdout:
                raise Refused("missing-driver-output")
        finally:
            driver_saved.rename(driver)

        write(request, '{"deadline_unix":1}')
        result = remote(base, command, ok=False)
        if result.stdout:
            raise Refused("expired-request-output")

        descendant = work / "descendant.pid"
        write(request, json.dumps({"deadline_unix": int(time.time()) + 3}))
        slow = (f"cd {foreign} && FIXTURE_MODE=slow FIXTURE_DESCENDANT={descendant} "
                f"SBXR_EXECUTABLE={product} SBXR_QUALIFICATION_REQUEST={request} "
                f"/usr/bin/bash {staged} remote-outside-disclose v3.fixture 1 deadbeef 1")
        result = remote(base, slow, ok=False, timeout=12)
        if (result.stdout or not descendant.exists() or
                b"SBXR_MENU_SESSION_REFUSED phase=output-deadline" not in result.stderr):
            raise Refused("deadline-cleanup-shape")
        escaped = int(descendant.read_text())
        try:
            os.kill(escaped, 0)
        except ProcessLookupError:
            pass
        else:
            raise Refused("deadline-descendant-live")

        manifest = root / "manifest.json"
        manifest_doc = {"schema": "fixture-manifest"}
        manifest_bytes = json.dumps(manifest_doc, separators=(",", ":")).encode()
        write(manifest, manifest_bytes)
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        request_doc = {"qualification_manifest_sha256": manifest_sha,
                       "scenario_id": "baseline-clean",
                       "deadline_unix": int(time.time()) + 60}
        request_bytes = json.dumps(request_doc, separators=(",", ":")).encode()
        write(request, request_bytes)
        facts = root / "facts.json"
        facts_doc = {"schema": "sbxr-release-qualification-facts-v1",
                     "qualification_manifest": manifest_doc,
                     "stage": "v3-scenario-failure",
                     "failure": {"scenario_id": "baseline-clean"},
                     "payload": "x" * (2 * 1024 * 1024)}
        facts_bytes = json.dumps(facts_doc, separators=(",", ":")).encode()
        write(facts, facts_bytes)

        wrapper_dir = root / "bin"
        wrapper_dir.mkdir(mode=0o700)
        wrapper = wrapper_dir / "ssh"
        wrapper_source = r'''#!/usr/bin/env bash
set -euo pipefail
real=(/usr/bin/ssh -p "$SSH_TEST_PORT" -F /dev/null)
last=${!#}
if [[ "$last" == *'temporary='* ]]; then
  case ${SSH_TEST_FAULT:-} in
    drop) exec "${real[@]}" "$@" </dev/null ;;
    truncate) head -c 1024 | "${real[@]}" "$@"; exit ${PIPESTATUS[1]} ;;
    change)
      before=("${@:1:$#-1}")
      "${real[@]}" -n "${before[@]}" "printf '%s' '$SSH_CHANGED_REQUEST_B64' | base64 -d > /root/sbxr-qualification-evidence/request.next; chmod 0600 /root/sbxr-qualification-evidence/request.next; mv -T /root/sbxr-qualification-evidence/request.next /root/sbxr-qualification-evidence/request.json"
      exec "${real[@]}" "$@"
      ;;
  esac
fi
exec "${real[@]}" "$@"
'''
        write(wrapper, wrapper_source, 0o700)
        submit = ["/usr/bin/bash", str(collector), "submit", "127.0.0.1",
                  str(client), str(known), str(manifest), str(facts)]
        submit_env = os.environ.copy()
        submit_env["PATH"] = str(wrapper_dir) + ":" + submit_env["PATH"]
        submit_env["SSH_TEST_PORT"] = str(port)
        result = run(submit, cwd=foreign, env=submit_env, timeout=30)
        published = evidence / "result.json"
        if published.read_bytes() != facts_bytes:
            raise Refused("submit-byte-preservation")

        result = run(submit, cwd=foreign, env=submit_env, timeout=30, ok=False)
        if published.read_bytes() != facts_bytes:
            raise Refused("duplicate-result-changed")

        clean_results(base)
        wrong = dict(facts_doc)
        wrong["failure"] = {"scenario_id": "other"}
        write(facts, json.dumps(wrong, separators=(",", ":")))
        run(submit, cwd=foreign, env=submit_env, timeout=30, ok=False)
        if published.exists() or (evidence / "result.tmp").exists():
            raise Refused("wrong-scenario-published")
        write(facts, facts_bytes)

        for fault in ("drop", "truncate"):
            clean_results(base)
            fault_env = submit_env.copy()
            fault_env["SSH_TEST_FAULT"] = fault
            run(submit, cwd=foreign, env=fault_env, timeout=30, ok=False)
            # A refused partial upload remains private for failure diagnosis.
            # Prove the injected bytes reached the receiver, without publication.
            expected = b"" if fault == "drop" else facts_bytes[:1024]
            if published.exists() or (evidence / "result.tmp").read_bytes() != expected:
                raise Refused(fault + "-published")

        clean_results(base)
        changed = dict(request_doc)
        changed["deadline_unix"] += 1
        changed_bytes = json.dumps(changed, separators=(",", ":")).encode()
        fault_env = submit_env.copy()
        fault_env["SSH_TEST_FAULT"] = "change"
        fault_env["SSH_CHANGED_REQUEST_B64"] = base64.b64encode(changed_bytes).decode()
        run(submit, cwd=foreign, env=fault_env, timeout=30, ok=False)
        if (published.exists() or (evidence / "result.tmp").exists() or
                request.read_bytes() != changed_bytes):
            raise Refused("changed-request-boundary")

        print(f"SSH_BOUNDARY_CASES_PASSED count={CASE_TOTAL}")
    finally:
        if daemon.poll() is None:
            os.killpg(daemon.pid, signal.SIGTERM)
            try:
                daemon.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(daemon.pid, signal.SIGKILL)
                daemon.wait(timeout=2)
        sshd_log.close()


def outer():
    if sys.platform != "linux" or os.geteuid() != 0:
        print("SSH_BOUNDARY_SKIPPED requires-linux-root")
        return 0
    required = ("unshare", "mount", "ssh", "sshd", "ssh-keygen", "jq", "sha256sum")
    if any(shutil.which(tool) is None for tool in required):
        print("SSH_BOUNDARY_SKIPPED missing-tool")
        return 0
    script = Path(__file__).resolve()
    source_dir = script.parent.parent
    with tempfile.TemporaryDirectory(prefix="sbxr-v3-ssh-boundary-", dir="/tmp") as name:
        root = Path(name)
        copied = root / "source"
        copied.mkdir(mode=0o700)
        for filename in ("v3-packaged-live.sh", "v3-menu-session.py",
                         "v3-recurring-evidence.sh"):
            shutil.copyfile(source_dir / filename, copied / filename)
        command = ["unshare", "--mount", "--pid", "--fork", "--mount-proc",
                   "--kill-child=KILL", sys.executable, str(script), "--inside", name]
        parent_pid = os.getpid()
        def bind_parent_lifetime():
            # A forced death of this runner must also stop unshare, whose
            # --kill-child then kills the namespace init and its descendants.
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "parent-death signal")
            if os.getppid() != parent_pid:
                os.kill(os.getpid(), signal.SIGKILL)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, preexec_fn=bind_parent_lifetime)
        old_handlers = {}
        def interrupted(_signum, _frame):
            raise KeyboardInterrupt
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            old_handlers[signum] = signal.signal(signum, interrupted)
        timed_out = False
        try:
            stdout, _stderr = process.communicate(timeout=105)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, _stderr = process.communicate(timeout=5)
            timed_out = True
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)
            raise
        finally:
            for signum, handler in old_handlers.items():
                signal.signal(signum, handler)
        namespace_marker = root / "pid-namespace-inode"
        namespace_live = False
        if namespace_marker.exists():
            inode = int(namespace_marker.read_text())
            for entry in Path("/proc").glob("[0-9]*/ns/pid"):
                try:
                    if entry.stat().st_ino == inode:
                        namespace_live = True
                        break
                except (FileNotFoundError, PermissionError):
                    continue
        if namespace_live:
            print("SSH_BOUNDARY_REFUSED case=namespace-live", file=sys.stderr)
            return 1
        if timed_out:
            print("SSH_BOUNDARY_REFUSED case=namespace-timeout", file=sys.stderr)
            return 1
        if process.returncode or stdout != f"SSH_BOUNDARY_CASES_PASSED count={CASE_TOTAL}\n".encode():
            diagnostic = "inside"
            for line in _stderr.decode("ascii", "ignore").splitlines()[-8:]:
                if line.startswith("SSH_BOUNDARY_REFUSED case="):
                    candidate = line.removeprefix("SSH_BOUNDARY_REFUSED case=")
                    if candidate.replace("-", "").isalnum():
                        diagnostic = candidate
            print("SSH_BOUNDARY_REFUSED case=" + diagnostic, file=sys.stderr)
            return 1
        sys.stdout.buffer.write(stdout)
    return 0


def main():
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "--inside":
            inside(sys.argv[2])
            return 0
        if len(sys.argv) != 1:
            raise Refused("arguments")
        return outer()
    except Refused as error:
        reason = str(error)
        if not reason or not reason.replace("-", "").isalnum():
            reason = "fixture"
        print("SSH_BOUNDARY_REFUSED case=" + reason, file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError, ValueError):
        print("SSH_BOUNDARY_REFUSED case=fixture", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("SSH_BOUNDARY_REFUSED case=interrupted", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
