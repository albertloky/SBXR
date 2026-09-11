#!/usr/bin/env python3
"""Hold a reviewed Complete removal across the real renewal-admission race.

The coordinator runs the installed zero-argument menu, stops at its exact
Complete removal confirmation, then starts recorder-boundary.py in admission
mode.  Only after that helper proves the actual recorder, receipt and shared
admission lock does this process submit REMOVE SBXR.  The public action must
refuse without publishing removal commitment or changing the owned inventory.
The recorder is then released and the candidate is checked healthy.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent
EXECUTABLE = Path("/usr/local/bin/sbxr")
SCENARIO = "remove-admission-race"
CONFIRMATION_PROMPT = "Type REMOVE SBXR to confirm Complete removal. Any other input cancels."
EXPECTED_PLAN = {
    "Complete removal deletes SBXR, proxy credentials, and every proved V3-owned resource from this VPS.",
    "Exact confirmation required: REMOVE SBXR",
}
MAX_LINE = 16384
MAX_OUTPUT = 1024 * 1024


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


managed = load_module("admission_race_managed_hold", HERE / "managed-hold.py")


def unique(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate coordinator event key")
        value[key] = item
    return value


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class LineStream:
    """Read bounded binary pipe lines without blocking past the deadline."""

    def __init__(self, stream):
        self.stream = stream
        self.buffer = bytearray()
        self.consumed = 0

    def line(self, deadline: float) -> str:
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.stream], [], [], remaining)[0]:
                raise TimeoutError("coordinator output deadline")
            block = os.read(self.stream.fileno(), 4096)
            if not block:
                raise ValueError("coordinated process closed before expected output")
            self.buffer.extend(block)
            self.consumed += len(block)
            if self.consumed > MAX_OUTPUT or len(self.buffer) > MAX_LINE:
                raise ValueError("coordinated output bound exceeded")
        raw, _, remainder = self.buffer.partition(b"\n")
        self.buffer = bytearray(remainder)
        try:
            return raw.rstrip(b"\r").decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("coordinated output encoding refused") from error


def write_input(process, value: bytes) -> None:
    process.stdin.write(value)
    process.stdin.flush()


def prepare_removal(process, deadline: float, reader) -> dict:
    action = None
    consumed = 0
    while True:
        line = reader(process.stdout, deadline)
        consumed += len(line) + 1
        if consumed > MAX_OUTPUT:
            raise ValueError("menu output bound exceeded")
        match = re.fullmatch(r"([1-9][0-9]*)\. (.+)", line)
        if match and match.group(2) == "Complete removal":
            if action is not None:
                raise ValueError("duplicate Complete removal action")
            action = match.group(1)
        if line == "0. Exit":
            if action is None:
                raise ValueError("Complete removal is not offered")
            write_input(process, (action + "\n").encode())
            break
    plan = set()
    while True:
        line = reader(process.stdout, deadline)
        consumed += len(line) + 1
        if consumed > MAX_OUTPUT:
            raise ValueError("menu output bound exceeded")
        if line in EXPECTED_PLAN:
            plan.add(line)
        if line == CONFIRMATION_PROMPT:
            if plan != EXPECTED_PLAN:
                raise ValueError("Complete removal plan is incomplete")
            return {"action_number": int(action), "prepared_at": now()}


def complete_refusal(process, deadline: float, reader) -> dict:
    write_input(process, b"REMOVE SBXR\n")
    failed_check = None
    code = None
    removal_committed = False
    consumed = 0
    while True:
        line = reader(process.stdout, deadline)
        consumed += len(line) + 1
        if consumed > MAX_OUTPUT:
            raise ValueError("menu output bound exceeded")
        if line.startswith("Failed safety check: "):
            failed_check = line.removeprefix("Failed safety check: ")
        if line == "Progress: Removal committed":
            removal_committed = True
        if line.startswith("Code: "):
            code = line.removeprefix("Code: ")
        if code is not None and line == "0. Exit":
            write_input(process, b"0\n")
            break
    if code != "PROXY-INSTALLATION-ACTION-REFUSED" or not failed_check or removal_committed:
        raise ValueError("public Complete removal did not refuse before commitment")
    return {"code": code, "failed_check": failed_check,
            "removal_commitment_absent": True, "refused_at": now()}


def event(process, deadline: float, reader) -> dict:
    value = json.loads(reader(process.stdout, deadline), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("coordinator event shape refused")
    return value


def validate_held(value: dict) -> None:
    pid = value.get("recorder_pid")
    boundary = value.get("actual_boundary")
    admission = value.get("admission")
    if (value.get("state") != "boundary-held" or value.get("mode") != "admission" or
            not isinstance(pid, int) or pid <= 1 or not isinstance(value.get("process_tick"), int) or
            not re.fullmatch(r"[0-9a-f]{32}", value.get("attempt_id", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", value.get("receipt_sha256", "")) or
            value.get("writer", {}).get("lock_state") != "unlocked" or
            value.get("whole_host", {}).get("lock_state") != "unlocked" or
            not isinstance(admission, dict) or admission.get("lock_state") != "locked" or
            {"mode": "READ", "pid": pid} not in admission.get("holders", []) or
            not isinstance(boundary, dict) or boundary.get("state") != "boundary-held" or
            boundary.get("boundary") != "after-close" or
            boundary.get("path") != "/run/lock/sbxr.lock" or boundary.get("pid") != pid):
        raise ValueError("actual recorder admission boundary refused")


def validate_final(value: dict) -> None:
    if (value.get("state") != "completed" or value.get("no_ca_egress") is not True or
            not re.fullmatch(r"[0-9a-f]{64}", value.get("receipt_sha256", ""))):
        raise ValueError("recorder admission completion refused")


def evidence_directory() -> Path:
    path = Path(os.environ["SBXR_OPERATOR_EVIDENCE_DIR"])
    info = path.lstat()
    if (not path.is_absolute() or path.is_symlink() or not stat.S_ISDIR(info.st_mode) or
            info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("protected evidence directory refused")
    return path


def write_exclusive(path: Path, value: dict) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError("evidence file protection refused")


SNAPSHOT_SCRIPT = r'''
set -euo pipefail
umask 077
source "$1"
operator_expect_scenario remove-admission-race
operator_exact_candidate
prove_running
{
  protected_inventory
  for path in \
    /etc/systemd/system/sbxr-subscription.service \
    /etc/systemd/system/sbxr-subscription.socket \
    /etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf \
    /etc/letsencrypt/live/sbxr-subscription \
    /etc/letsencrypt/archive/sbxr-subscription \
    /etc/letsencrypt/renewal/sbxr-subscription.conf; do
    if test -e "$path" || test -L "$path"; then
      stat -c '%n %F %a %u %g %h %s' "$path"
      if test -d "$path"; then
        find "$path" -xdev -printf '%p %y %m %U %G %n %s %l\n' | sort
        find "$path" -xdev -type f -print0 | sort -z | xargs -0 -r sha256sum
      elif test -f "$path"; then
        sha256sum "$path"
      fi
    else
      printf '%s absent\n' "$path"
    fi
  done
  for unit in sing-box.service sbxr-subscription.service sbxr-subscription.socket \
    snap.certbot.renew.service snap.certbot.renew.timer; do
    systemctl show "$unit" -p LoadState -p ActiveState -p SubState -p UnitFileState \
      -p MainPID -p ExecMainStatus
  done
  iptables-save -t filter | grep -F 'sbxr-subscription' || true
  ss -H -lntp 'sport = :443'
  ss -H -lntp 'sport = :8443'
} | sha256sum | cut -d' ' -f1
'''


def owned_snapshot() -> str:
    value = subprocess.check_output([
        "/bin/bash", "--noprofile", "--norc", "-c", SNAPSHOT_SCRIPT,
        "admission-race-snapshot", str(HERE / "operator-support.sh")],
        text=True, timeout=30).strip()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("owned inventory digest refused")
    return value


HEALTH_SCRIPT = r'''
set -euo pipefail
source "$1"
operator_expect_scenario remove-admission-race
operator_exact_candidate
prove_running
test "$(systemctl show snap.certbot.renew.service -p ActiveState --value)" = inactive
test ! -e /sys/fs/cgroup/system.slice/snap.certbot.renew.service
scan_journal
scan_transport_captures
'''


def final_health() -> None:
    subprocess.run([
        "/bin/bash", "--noprofile", "--norc", "-c", HEALTH_SCRIPT,
        "admission-race-health", str(HERE / "operator-support.sh")],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)


def timer_state() -> tuple[str, str]:
    return managed.show(managed.TIMER, "ActiveState"), managed.show(managed.TIMER, "UnitFileState")


def stop_timer(initial: tuple[str, str]) -> None:
    if initial != ("active", "enabled"):
        raise ValueError("official Certbot timer must initially be active and enabled")
    subprocess.run(["systemctl", "stop", managed.TIMER], check=True, timeout=30)
    if timer_state() != ("inactive", "enabled") or managed.show(managed.UNIT, "ActiveState") != "inactive":
        raise ValueError("official Certbot timer did not stop cleanly")


def pre_stop_preflight(interpreter: str, digest: str, timeout: int) -> tuple[bytes, bytes, int]:
    request_raw = managed.protected_bytes(Path(os.environ["SBXR_QUALIFICATION_REQUEST"]), 0o600)
    manifest_raw = managed.protected_bytes(Path(os.environ["SBXR_QUALIFICATION_MANIFEST"]), 0o600)
    request = json.loads(request_raw, object_pairs_hook=unique)
    manifest = json.loads(manifest_raw, object_pairs_hook=unique)
    if (request.get("scenario_id") != SCENARIO or type(request.get("deadline_unix")) is not int or
            request["deadline_unix"] - time.time() < timeout or
            request.get("qualification_manifest_sha256") != hashlib.sha256(manifest_raw).hexdigest() or
            manifest.get("schema") != "sbxr-qualification-manifest-v3" or manifest.get("mode") != "v3"):
        raise ValueError("current request and manifest binding refused")
    attempt = manifest.get("v3_attempt", {})
    scenarios = attempt.get("required_scenarios")
    if (attempt.get("evidence_policy") != "repair-issuance-bounded-v4" or
            not isinstance(scenarios, list) or SCENARIO not in scenarios or "snap-refresh" not in scenarios):
        raise ValueError("current attempt authority refused")
    phase = "after-snap-refresh" if scenarios.index(SCENARIO) > scenarios.index("snap-refresh") else "initial"
    subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c",
        'set -euo pipefail; source "$1"; operator_expect_scenario "$2"; preflight "$3"; operator_exact_candidate',
        "admission-race-pre-stop", str(HERE / "operator-support.sh"), SCENARIO, phase],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(30, timeout))
    return request_raw, manifest_raw, request["deadline_unix"]


def menu_identity(unit: str) -> dict:
    pid = int(managed.show(unit, "MainPID"))
    if pid <= 1:
        raise ValueError("public menu PID refused")
    expected = EXECUTABLE.stat()
    actual = Path("/proc/%d/exe" % pid).stat()
    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
        raise ValueError("public menu executable refused")
    fields = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
    cgroup = "/system.slice/" + unit
    if "0::" + cgroup not in Path("/proc/%d/cgroup" % pid).read_text().splitlines():
        raise ValueError("public menu cgroup refused")
    return {"pid": pid, "start_tick": int(fields[19]),
            "executable_device": actual.st_dev, "executable_inode": actual.st_ino,
            "cgroup": cgroup, "unit": unit}


def restore_timer(initial: tuple[str, str]) -> None:
    if initial != ("active", "enabled"):
        raise ValueError("unsupported timer restoration state")
    subprocess.run(["systemctl", "start", managed.TIMER], check=True, timeout=30)
    if timer_state() != initial or managed.show(managed.UNIT, "ActiveState") != "inactive":
        raise ValueError("official Certbot timer restoration refused")


def launch_menu(unit: str):
    return subprocess.Popen([
        "systemd-run", "--quiet", "--pipe", "--wait", "--collect",
        "--service-type=exec", "--unit=" + unit, str(EXECUTABLE)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=0)


def launch_boundary(interpreter: str, digest: str, timeout: int):
    return subprocess.Popen([
        sys.executable, str(HERE / "recorder-boundary.py"), "admission",
        interpreter, digest, "--timeout", str(timeout)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0)


def wait_menu_identity(menu, unit: str, deadline: float) -> dict:
    """Wait for systemd-run to create the actual service before binding it."""
    while time.monotonic() < deadline:
        if menu.poll() is not None:
            raise ValueError("public menu exited before service readiness")
        try:
            pid = managed.show(unit, "MainPID")
            active = managed.show(unit, "ActiveState")
        except subprocess.CalledProcessError:
            pid, active = "", ""
        if pid.isdecimal() and int(pid) > 1 and active == "active":
            return menu_identity(unit)
        if active == "failed":
            raise ValueError("public menu service failed before readiness")
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    raise TimeoutError("public menu service readiness deadline")


def stop_process(process, unit: str | None = None) -> None:
    if process is None:
        return
    if process.poll() is None and unit:
        subprocess.run(["systemctl", "stop", unit], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=40)
    if process.poll() is None:
        try:
            process.stdin.close()
        except Exception:
            pass
    try:
        process.wait(timeout=40)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run(interpreter: str, digest: str, timeout: int) -> dict:
    if (sys.platform != "linux" or os.geteuid() != 0 or not 20 <= timeout <= 120 or
            os.environ.get("SBXR_OPERATOR_REHEARSAL") or os.environ.get("SBXR_OPERATOR_REHEARSAL_HOOK")):
        raise ValueError("live Linux root and timeout 20..120 required")
    if not os.environ.get("STARTED_AT") or os.environ.get("STARTED_AT") != os.environ.get("SCENARIO_START"):
        raise ValueError("original scenario start binding refused")
    output = evidence_directory()
    timer_initial = None
    timer_restore_needed = False
    menu = boundary = None
    boundary_held = boundary_released = False
    unit = "sbxr-v4-remove-admission-race-%d.service" % os.getpid()
    try:
        request_raw, manifest_raw, pre_stop_deadline = pre_stop_preflight(interpreter, digest, timeout)
        observed_timer = timer_state()
        if observed_timer != ("active", "enabled"):
            raise ValueError("official Certbot timer must initially be active and enabled")
        timer_initial = observed_timer
        timer_restore_needed = True
        stop_timer(timer_initial)
        _, _, _, _, original_deadline = managed.preflight(
            interpreter, digest, timeout, {SCENARIO})
        if (original_deadline != pre_stop_deadline or
                managed.protected_bytes(Path(os.environ["SBXR_QUALIFICATION_REQUEST"]), 0o600) != request_raw or
                managed.protected_bytes(Path(os.environ["SBXR_QUALIFICATION_MANIFEST"]), 0o600) != manifest_raw):
            raise ValueError("authority changed across timer stop")
        authority_deadline = time.monotonic() + min(timeout, original_deadline - time.time())

        menu = launch_menu(unit)
        prepared_menu = wait_menu_identity(menu, unit, authority_deadline)
        menu_stream = LineStream(menu.stdout)
        menu_reader = lambda _stream, deadline: menu_stream.line(deadline)
        prepared = prepare_removal(menu, authority_deadline, menu_reader)

        remaining = int(min(timeout, original_deadline - time.time(), authority_deadline - time.monotonic()))
        if remaining < 5:
            raise TimeoutError("insufficient original scenario deadline")
        boundary = launch_boundary(interpreter, digest, remaining)
        boundary_stream = LineStream(boundary.stdout)
        boundary_reader = lambda _stream, deadline: boundary_stream.line(deadline)
        held = event(boundary, authority_deadline, boundary_reader)
        validate_held(held)
        held_menu = menu_identity(unit)
        if held_menu != prepared_menu:
            raise ValueError("public menu process changed before confirmation")
        boundary_held = True
        held_record = {**held, "menu_before_prepared": prepared_menu,
                       "menu_after_boundary": held_menu}
        write_exclusive(output / "22-admission-held.json", held_record)

        before = owned_snapshot()
        refused = complete_refusal(menu, authority_deadline, menu_reader)
        if menu.wait(timeout=max(1, authority_deadline - time.monotonic())) != 0:
            raise ValueError("public menu did not exit cleanly after refusal")
        after = owned_snapshot()
        if after != before:
            raise ValueError("owned resources changed during removal refusal")
        refusal = {
            "schema": "sbxr-v4-removal-admission-refusal-v1",
            "scenario": SCENARIO,
            "qualification_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "request_sha256": hashlib.sha256(request_raw).hexdigest(),
            "owned_inventory_before_sha256": before,
            "owned_inventory_after_sha256": after,
            **prepared, **refused,
        }
        write_exclusive(output / "22-removal-refusal.json", refusal)

        write_input(boundary, b"release\n")
        boundary_released = True
        final = event(boundary, authority_deadline, boundary_reader)
        validate_final(final)
        if boundary.wait(timeout=max(1, authority_deadline - time.monotonic())) != 0:
            raise ValueError("recorder admission coordinator failed")
        if boundary.stderr.read():
            raise ValueError("recorder admission coordinator wrote stderr")
        write_exclusive(output / "22-admission-final.json", final)
        final_health()
        if (managed.protected_bytes(Path(os.environ["SBXR_QUALIFICATION_REQUEST"]), 0o600) != request_raw or
                managed.protected_bytes(Path(os.environ["SBXR_QUALIFICATION_MANIFEST"]), 0o600) != manifest_raw):
            raise ValueError("authority changed before final result")
        result = {
            "schema": "sbxr-v4-admission-race-operator-v1", "scenario": SCENARIO,
            "prepared_public_removal": True, "actual_admission_boundary": True,
            "removal_refused_before_commitment": True,
            "owned_resources_preserved": True, "recorder_completed": True,
            "healthy_running": True, "completed_at": now(),
            "request_sha256": hashlib.sha256(request_raw).hexdigest(),
            "qualification_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        }
    finally:
        if boundary is not None and boundary.poll() is None:
            try:
                if boundary_held and not boundary_released:
                    write_input(boundary, b"release\n")
                    boundary_released = True
                    event(boundary, time.monotonic() + 40, boundary_reader)
                else:
                    boundary.stdin.close()
            except Exception:
                pass
        stop_process(boundary)
        stop_process(menu, unit)
        if timer_restore_needed:
            restore_timer(timer_initial)
    if timer_state() != timer_initial:
        raise ValueError("official Certbot timer final state mismatch")
    if (managed.protected_bytes(Path(os.environ["SBXR_QUALIFICATION_REQUEST"]), 0o600) != request_raw or
            managed.protected_bytes(Path(os.environ["SBXR_QUALIFICATION_MANIFEST"]), 0o600) != manifest_raw):
        raise ValueError("authority changed before result publication")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interpreter")
    parser.add_argument("sha256")
    parser.add_argument("--timeout", type=int, default=90)
    options = parser.parse_args()
    try:
        print(json.dumps(run(options.interpreter, options.sha256, options.timeout),
                         sort_keys=True, separators=(",", ":")))
    except Exception as error:
        print(json.dumps({"state": "refused", "error_type": type(error).__name__},
                         sort_keys=True, separators=(",", ":")))
        raise SystemExit(1)
