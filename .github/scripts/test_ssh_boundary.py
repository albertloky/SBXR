#!/usr/bin/env python3
"""Linux-only real-SSH boundaries for the V3 operator scripts."""

import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


CASE_TOTAL = 25
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
menu = "SBXR V3\\nProxy status: Running\\nCode: PROXY-INSTALLATION-SETUP-COMPLETE\\n1. View details\\n2. Rotate Client Identity\\n3. Show client configuration\\n4. Replace subscription certificate\\n0. Exit"
print(menu, flush=True)
choice = sys.stdin.readline().strip()
if choice == "0": raise SystemExit(0)
if choice == "4":
    print("Replace subscription certificate? [y/N]", flush=True)
    if sys.stdin.readline().strip() != "y": raise SystemExit(4)
    print("Code: PROXY-INSTALLATION-SUBSCRIPTION-CERTIFICATE-REPLACED", flush=True)
    print(menu, flush=True)
    if sys.stdin.readline().strip() != "0": raise SystemExit(5)
    raise SystemExit(0)
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


def recorder_handoff(base, source):
    """Replay the current documented streamed recorder call, not a mock SSH."""
    examples = re.findall(r"<!-- mvp-incremental-observer-ssh -->\n```sh\n(.*?)\n```",
                          (source / 'ordinary-recurring-live.md').read_text(), re.DOTALL)
    if len(examples) != 1:
        raise Refused('recorder-handoff-example')
    repository = source / 'recorder-checkout'
    scripts = repository / '.github/scripts'
    scripts.mkdir(parents=True)
    write(scripts / 'mvp-observe.py', (source / 'mvp-observe.py').read_bytes())
    prefix = ('set -euo pipefail\nssh_options=(' + shlex.join(base[1:-1]) + ')\n'
              'acceptance_host=' + shlex.quote(base[-1]) + '\n')
    definition = examples[0].split('mvp_observe start\n')[0]
    request = Path('/root/sbxr-qualification-evidence/request.json')
    draft = Path('/root/mvp-observation-draft.json')
    output = Path('/root/sbxr-qualification-evidence/observation.json')
    now = int(time.time())
    value = dict(scenario_id='source-v3.1.81-precommit',
                 not_before=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now)),
                 deadline_unix=now+30, scenario_limit_seconds=1800,
                 qualification_manifest_sha256='a'*64,
                 required_checks=['checkpoint-fixture', 'cleanup-fixture'])
    write(request, json.dumps(value))

    def observe(command, ok=True):
        return run(['bash', '-c', prefix + definition + command], cwd=repository, ok=ok)

    # Four boundary cases: complete flow, incomplete refusal, changed-request
    # refusal, and no re-publication after the collector consumes its output.
    run(['bash', '-c', prefix + examples[0]], cwd=repository)
    observe('mvp_observe observe --check checkpoint-fixture')
    observe('mvp_observe finish --output ' + str(output), ok=False)
    if output.exists():
        raise Refused('recorder-incomplete-published')
    original = request.read_bytes()
    write(request, original + b'\n')
    observe('mvp_observe status', ok=False)
    write(request, original)
    observe('mvp_observe observe --check cleanup-fixture')
    observe('mvp_observe finish --output ' + str(output))
    result = json.loads(output.read_bytes())
    if (result['scenario_id'] != value['scenario_id'] or
            [item['check'] for item in result['checks']] != value['required_checks'] or
            any(item['result'] != 'observed' for item in result['checks']) or
            output.stat().st_mode & 0o777 != 0o600):
        raise Refused('recorder-publication-shape')
    output.unlink()
    observe('mvp_observe finish --output ' + str(output), ok=False)
    if output.exists():
        raise Refused('recorder-republished')
    draft.unlink()
    request.unlink()


def candidate_handoff(base, source):
    """Execute the documented command with real SSH and unchanged helper bytes."""
    examples = re.findall(
        r"<!-- mvp-exact-candidate-ssh -->\n```sh\n(.*?)\n```",
        (source / "mvp-live-acceptance.md").read_text(), re.DOTALL)
    if len(examples) != 1:
        raise Refused("candidate-handoff-example")
    repository = source / "operator-checkout"
    scripts = repository / ".github" / "scripts"
    scripts.mkdir(parents=True)
    module = scripts / "v3-packaged-live.sh"
    original = (source / "v3-packaged-live.sh").read_bytes()
    write(module, original)
    # Only this namespace sees these mounts. Use the helper's actual default
    # paths, not source-text substitutions or an alternative identity check.
    run(["mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/var/lib"])
    run(["mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/usr/local/bin"])
    transport = Path("/root/sbxr-qualification-v3")
    transport.mkdir(mode=0o700)
    installed_dir = Path("/var/lib/sbxr")
    installed_dir.mkdir(mode=0o700)
    manifest = transport / "qualification-manifest.json"
    request = Path("/root/sbxr-qualification-evidence/request.json")
    installed = installed_dir / "installed.json"
    executable = Path("/usr/local/bin/sbxr")
    write(executable, "#!/bin/sh\ntouch /run/product-was-executed\nexit 9\n", 0o700)
    candidate = {"tag": "v3.1.50", "commit": "1" * 40, "sequence": 131,
                 "release_identity": {"repository": "albertloky/SBXR",
                                      "tag": "v3.1.50", "commit": "1" * 40,
                                      "release_index_sha256": "2" * 64}}
    write(manifest, json.dumps({"mode": "v3", "schema": "sbxr-qualification-manifest-v3",
                               "source_state": "v3-subscription-clean",
                               "releases": [candidate]}))
    write(request, json.dumps({"qualification_manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()}))
    record = dict(candidate["release_identity"], sequence=131, architecture="amd64",
                  executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest())
    write(installed, json.dumps(record))
    paths = [manifest, request, installed, executable]
    baseline = {p: p.read_bytes() for p in paths}
    # The exact documented shell command gets only authenticated connection
    # options. The server's login directory is unrelated to this local checkout.
    prefix = ("set -euo pipefail\nssh_options=(" + shlex.join(base[1:-1]) + ")\n"
              "acceptance_host=" + shlex.quote(base[-1]) + "\n")
    command = ["bash", "-c", prefix + examples[0] + "\nprintf 'identity-accepted\\n'"]
    missing = "/run/sbxr-qualification/v3-packaged-live.sh"
    if os.path.lexists(missing):
        raise Refused("candidate-legacy-helper-present")
    old = remote(base, "bash " + missing + " remote-exact-candidate", ok=False)
    if old.returncode != 127:
        raise Refused("candidate-original-failure-not-reproduced")

    def check(valid):
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode)
                  for p in paths if p.exists()}
        result = run(command, cwd=repository, ok=valid)
        if result.stdout != (b"identity-accepted\n" if valid else b""):
            raise Refused("candidate-handoff-continuation")
        if before != {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode)
                      for p in paths if p.exists()} or Path("/run/product-was-executed").exists():
            raise Refused("candidate-handoff-mutated-host")
        if os.path.lexists(missing) or sorted(p.name for p in transport.iterdir()) != [manifest.name]:
            raise Refused("candidate-handoff-staged-helper")

    check(True)
    for path in (manifest, request, installed, executable):
        changed = baseline[path] + b"changed"
        if path == installed:
            changed = json.dumps(dict(record, sequence=130)).encode()
        elif path == request:
            changed = json.dumps({"qualification_manifest_sha256": "0" * 64}).encode()
        write(path, changed)
        check(False)
        write(path, baseline[path], 0o700 if path == executable else 0o600)
    request.unlink()
    check(False)
    write(request, baseline[request])
    module.unlink()
    check(False)  # Local redirection refuses before the SSH command starts.
    write(module, b"")
    check(False)  # A dropped stream must not report a successful identity check.
    write(module, original)
    for path in paths:
        path.unlink()
    transport.rmdir()
    installed_dir.rmdir()


def inside(root):
    if os.getpid() != 1:
        raise Refused("inside-not-pid-one")
    root = Path(root).resolve()
    (root / "pid-namespace-inode").write_text(str(os.stat("/proc/self/ns/pid").st_ino))
    run(["mount", "--make-rprivate", "/"])
    # Keep a workspace TMPDIR under /root visible after isolating the SSH home.
    # The bind uses the same directory; fixtures remain in the caller's workspace.
    fixture_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY) if root.is_relative_to("/root") else None
    try:
        run(["mount", "-t", "tmpfs", "-o", "mode=0700", "tmpfs", "/root"])
        if fixture_fd is not None:
            root.mkdir(parents=True)
            run(["mount", "--no-canonicalize", "--bind", f"/proc/1/fd/{fixture_fd}", str(root)])
    finally:
        if fixture_fd is not None:
            os.close(fixture_fd)
    run(["mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/run"])
    Path("/run/sshd").mkdir(mode=0o755)
    # UsePAM=no key authentication still checks the root account's lock state.
    # Supply only a synthetic, non-expired, password-disabled record inside this
    # private mount namespace; never unlock or copy the host's shadow records.
    shadow = root / "shadow"
    write(shadow, "root:*:20000:0:99999:7:::\n")
    run(["mount", "--bind", str(shadow), "/etc/shadow"])
    run(["mount", "-o", "remount,bind,ro", "/etc/shadow"])
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
        candidate_handoff(base, source)
        recorder_handoff(base, source)
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

        replacement = (f"cd {foreign} && SBXR_EXECUTABLE={product} "
                       f"SBXR_QUALIFICATION_REQUEST={request} python3 {driver} action "
                       "'Replace subscription certificate' "
                       "PROXY-INSTALLATION-SUBSCRIPTION-CERTIFICATE-REPLACED --confirmation yes")
        result = remote(base, replacement)
        if (b"Replace subscription certificate? [y/N]" not in result.stdout or
                b"Code: PROXY-INSTALLATION-SUBSCRIPTION-CERTIFICATE-REPLACED" not in result.stdout):
            raise Refused("replacement-menu-ssh-boundary")

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
    source_dir = script.parent
    with tempfile.TemporaryDirectory(prefix="sbxr-v3-ssh-boundary-") as name:
        root = Path(name)
        copied = root / "source"
        copied.mkdir(mode=0o700)
        for filename in ("v3-packaged-live.sh", "v3-menu-session.py",
                         "v3-recurring-evidence.sh", "mvp-observe.py"):
            shutil.copyfile(source_dir / filename, copied / filename)
        shutil.copyfile(source_dir.parents[1] / "docs/acceptance/mvp-live-acceptance.md",
                        copied / "mvp-live-acceptance.md")
        shutil.copyfile(source_dir.parents[1] / "docs/acceptance/ordinary-recurring-live.md",
                        copied / "ordinary-recurring-live.md")
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
