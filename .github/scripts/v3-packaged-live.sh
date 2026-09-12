#!/usr/bin/env bash
menu_number_from() {
  local output=$1 label=$2
  sed -n "s/^\([1-9][0-9]*\)\. $label$/\1/p" <<<"$output"
}

menu_session_driver() {
  local module_dir
  module_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
  python3 "$module_dir/v3-menu-session.py" "$@"
}

menu_session_action() {
  local label=$1 input=$2 expected=$3 confirmation=none
  case "$input" in
    y) confirmation=yes ;;
    'REMOVE SBXR') confirmation=remove ;;
    '') ;;
    *) return 1 ;;
  esac
  menu_session_driver action "$label" "${expected#Code: }" --confirmation "$confirmation"
}

menu_session_details() {
  menu_session_driver details 'View details'
}

scan_vps_capture() {
  local capture=$1 content private_key client_uuid
  content="$(<"$capture")"
  if test -e /etc/sing-box/config.json && jq -e '.inbounds[0].tls.reality.private_key and .inbounds[0].users[0].uuid' /etc/sing-box/config.json >/dev/null 2>&1; then
    private_key="$(jq -er '.inbounds[0].tls.reality.private_key' /etc/sing-box/config.json)"
    client_uuid="$(jq -er '.inbounds[0].users[0].uuid' /etc/sing-box/config.json)"
    if grep -F -- "$private_key" <<<"$content" >/dev/null; then return 1; fi
    if grep -F -- "$client_uuid" <<<"$content" >/dev/null; then return 1; fi
  fi
  if test -n "${KNOWN_PRIVATE_KEY:-}" && grep -F -- "$KNOWN_PRIVATE_KEY" <<<"$content" >/dev/null; then return 1; fi
  if test -n "${KNOWN_CLIENT_UUID:-}" && grep -F -- "$KNOWN_CLIENT_UUID" <<<"$content" >/dev/null; then return 1; fi
  if grep -Eq 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization: Bearer ' <<<"$content"; then return 1; fi
}

protected_inventory() {
  {
    for path in /usr/local/bin/sbxr /var/lib/sbxr/installed.json /var/lib/sbxr/proxy-ownership.json /var/lib/sbxr/proxy-ownership.finalizing.json /etc/sing-box/config.json /etc/apt/sources.list.d/sagernet.sources /etc/apt/keyrings/sagernet.asc /lib/systemd/system/sing-box.service /usr/lib/systemd/system/sing-box.service; do
      if test -e "$path"; then stat -c "$path %a %u %g %s" "$path"; sha256sum "$path"; else printf '%s absent\n' "$path"; fi
    done
    for directory in /var/lib/sbxr /etc/sing-box /var/lib/sing-box; do
      if test -d "$directory"; then
        find "$directory" -xdev -printf '%p %m %U %G %s %y\n' | sort
        find "$directory" -xdev -type f -print0 | sort -z | xargs -0 -r sha256sum
      else
        printf '%s absent\n' "$directory"
      fi
    done
    dpkg-query -W -f='package ${Status} ${Version} ${Architecture}\n' sing-box 2>/dev/null || printf 'package absent\n'
    if apt-mark showhold | grep -Fx sing-box >/dev/null; then printf 'hold present\n'; else printf 'hold absent\n'; fi
    if systemctl is-enabled sing-box.service >/dev/null 2>&1; then printf 'enabled yes\n'; else printf 'enabled no\n'; fi
    if systemctl is-active sing-box.service >/dev/null 2>&1; then printf 'active yes\n'; else printf 'active no\n'; fi
    (ss -H -ltnp 'sport = :443' | grep -F sing-box || true) | sha256sum
    if getent passwd sing-box >/dev/null; then getent passwd sing-box | sha256sum; else printf 'user absent\n'; fi
    if getent group sing-box >/dev/null; then getent group sing-box | sha256sum; else printf 'group absent\n'; fi
  } | sha256sum | cut -d' ' -f1
}

run_action() {
  local label=$1 input=$2 expected=$3 output
  output="$(menu_session_action "$label" "$input" "$expected")" || return 1
  scan_vps_capture <(printf '%s' "$output") || return 1
  LAST_ACTION_OUTPUT=$output
  # Ignore the initial menu and the separate lifecycle status in later frames.
  test "$(awk '
    /^0\. Exit$/ {action=1; next}
    !action {next}
    /^SBXR V3$/ {lifecycle=0; next}
    /^Software Lifecycle:/ {lifecycle=1; next}
    /^Code: / && !lifecycle {code=$0}
    END {print code}
  ' <<<"$output")" = "$expected" || return 1
}

view_details() {
  local expected=$1 output
  output="$(menu_session_details)" || return 1
  scan_vps_capture <(printf '%s' "$output")
  test "$(grep -Fxc "$expected" <<<"$output")" -eq 1
}

prove_status() {
  printf '0\n' | /usr/local/bin/sbxr | grep -F "Proxy status: $1" >/dev/null
}

interrupt_at() {
  local WORK=${WORK:-/run/sbxr-qualification}
  local label=$1 confirmation=$2 event=$3 number=$4 timeout_seconds=${5:-900}
  local output="$WORK/output-$number" status=0 scan_status=0
  test ! -e "$output" && test ! -L "$output" || return 1
  # Keep this controller in the packaged module: historical and flat operator
  # bundles both distribute this file. It owns only the menu it starts.
  python3 - "${SBXR_EXECUTABLE:-/usr/local/bin/sbxr}" "$output" "$event" \
    "$label" "$confirmation" "$timeout_seconds" "${SBXR_QUALIFICATION_REQUEST:-}" \
    "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/v3-menu-session.py" <<'PY' || status=$?
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

executable, output, event, action, confirmation, seconds, request, driver_path = sys.argv[1:]
process = None
driver = None
reason = 'controller-error'
observed = False
interrupted = False
cleaned = True
returncode = None
received_signal = None


def control_signal(signum, frame):
    # Do not unwind Popen between fork and assignment of the owned process.
    global received_signal
    received_signal = signum


def cleanup():
    # The session leader remains unreaped until after signaling, so its PGID
    # cannot be recycled. Subreaper adoption also covers descendants that leave
    # the process group; only this dedicated controller's children are reaped.
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, signal.SIG_IGN)
    if process is None:
        return None
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    until = time.monotonic() + 5
    code = process.wait(timeout=max(0.01, until - time.monotonic()))
    children = Path('/proc/self/task') / str(os.getpid()) / 'children'
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return code
        if pid:
            continue
        # A reparented child cannot have its PID reused until we reap it.
        # Killing each adopted child causes its remaining descendants to be
        # adopted here in turn, including children in another session.
        for child in children.read_text().split():
            try:
                os.kill(int(child), signal.SIGKILL)
            except ProcessLookupError:
                pass
        if time.monotonic() >= until:
            raise TimeoutError('descendant cleanup incomplete')
        time.sleep(0.01)


try:
    if sys.platform != 'linux' or not seconds.isdecimal() or not 0 < int(seconds) <= 1800:
        raise ValueError('invalid interruption timeout or runtime')
    remaining = float(seconds)
    if request:
        document = json.loads(Path(request).read_bytes())
        deadline = document['deadline_unix']
        if type(deadline) is not int:
            raise ValueError('invalid collector deadline')
        remaining = min(remaining, deadline - time.time())
    if remaining <= 0:
        reason = 'deadline-expired-before-start'
        raise TimeoutError(reason)
    deadline = time.monotonic() + remaining
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'subreaper unavailable')
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, control_signal)
    if received_signal is not None:
        raise InterruptedError('controller interrupted')
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as capture:
        spec = importlib.util.spec_from_file_location('sbxr_menu_session', driver_path)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        session = driver.MenuSession(executable, capture, deadline,
                                     lambda: received_signal is not None)
        process = session.process
        if received_signal is not None:
            raise InterruptedError('controller interrupted')
        session.choose(action)
        if confirmation == 'y':
            prompt = driver.PROMPTS.get(action)
            if prompt is None:
                raise ValueError('unsupported confirmation contract')
            session.expect_prompt(prompt)
            session.write('y\n')
        elif confirmation == 'REMOVE SBXR' and action == 'Complete removal':
            session.expect_prompt(driver.REMOVAL_PROMPT)
            session.write('REMOVE SBXR\n')
        else:
            raise ValueError('unsupported interruption confirmation')
        target = 'Progress: ' + event
        while True:
            if received_signal is not None:
                raise InterruptedError('controller interrupted')
            line = session.stream.line(deadline)
            if line is None:
                reason = 'menu-exited-before-boundary'
                break
            if line == target:
                if received_signal is not None:
                    raise InterruptedError('controller interrupted')
                if session.stream.owner_exited():
                    reason = 'menu-exited-before-boundary'
                    break
                observed = True
                os.kill(process.pid, signal.SIGSTOP)
                if received_signal is not None:
                    raise InterruptedError('controller interrupted')
                interrupted = True
                reason = 'boundary-observed'
                break
except InterruptedError:
    reason = 'controller-interrupted'
except Exception as error:
    if driver is not None and isinstance(error, driver.ProtocolError):
        if error.phase == 'output-deadline':
            reason = 'deadline-before-boundary'
        elif error.phase.startswith('exit-') or error.phase == 'owner-exited':
            reason = 'menu-exited-before-boundary'
        elif error.phase.startswith('label-'):
            reason = 'menu-action-unavailable-before-boundary'
        elif error.phase in ('prompt-mismatch', 'action-refused'):
            reason = 'confirmation-refused-before-boundary'
    # Output may contain protected values. Retain it only for the caller's
    # existing secret scan, and report no command/output/exception details.
    pass
finally:
    try:
        returncode = cleanup()
    except Exception:
        cleaned = False
    if process is not None and process.stdin is not None:
        try:
            process.stdin.close()
        except BrokenPipeError:
            pass

if received_signal is not None:
    reason = 'controller-interrupted'
passed = (observed and interrupted and cleaned and received_signal is None
          and returncode == -signal.SIGKILL)
print('INTERRUPTION_RESULT reason=%s descendants_reaped=%s' % (reason, str(cleaned).lower()))
sys.exit(0 if passed else 1)
PY
  if test -f "$output"; then
    scan_vps_capture "$output" || scan_status=$?
    rm -f -- "$output"
  fi
  test "$status" -eq 0 && test "$scan_status" -eq 0
}

install_candidate() {
  local WORK=${WORK:-/run/sbxr-qualification}
  local output=$WORK/install-output
  curl -fsS https://github.com/albertloky/SBXR/releases/latest/download/install.sh | /usr/bin/setsid --wait /usr/bin/bash >"$output" 2>&1
  scan_vps_capture "$output"
  rm -f "$output"
  test -x /usr/local/bin/sbxr
  jq -e --arg tag "$TAG" --arg commit "$COMMIT" --arg index "$INDEX" --argjson sequence "$SEQUENCE" '.repository == "albertloky/SBXR" and .tag == $tag and .commit == $commit and .release_index_sha256 == $index and .sequence == $sequence and .architecture == "amd64"' /var/lib/sbxr/installed.json >/dev/null
}

# The recurring collector's request binds the already attested manifest bytes.
# Read that identity on every call: split SSH steps cannot inherit shell state.
# Optional paths allow the same boundary to be exercised without a live host.
exact_candidate() {
  local manifest=${1:-/root/sbxr-qualification-v3/qualification-manifest.json}
  local request=${2:-/root/sbxr-qualification-evidence/request.json}
  local installed=${3:-/var/lib/sbxr/installed.json}
  local executable=${4:-/usr/local/bin/sbxr}
  local digest candidate executable_digest path
  for path in "$manifest" "$request" "$installed" "$executable"; do
    test -f "$path" && test ! -L "$path" || return 1
  done
  digest=$(sha256sum "$manifest" | cut -d' ' -f1) || return 1
  jq -e --arg digest "$digest" '.qualification_manifest_sha256 == $digest' "$request" >/dev/null || return 1
  candidate=$(jq -ce '
    select(.mode == "v3" and
      (.schema == "sbxr-qualification-manifest-v2" or .schema == "sbxr-qualification-manifest-v3") and
      (.source_state == "v3-recurring" or .source_state == "v3-subscription-clean") and
      (.releases | length) == 1) | .releases[0] |
    select(.release_identity.repository == "albertloky/SBXR" and
      .tag == .release_identity.tag and .commit == .release_identity.commit and
      (.tag | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")) and
      (.commit | test("^[0-9a-f]{40}$")) and
      (.release_identity.release_index_sha256 | test("^[0-9a-f]{64}$")) and
      (.sequence | type == "number" and . > 0 and . == floor))' "$manifest") || return 1
  executable_digest=$(sha256sum "$executable" | cut -d' ' -f1) || return 1
  jq -e --argjson candidate "$candidate" --arg executable "$executable_digest" '
    .repository == $candidate.release_identity.repository and
    .tag == $candidate.tag and .commit == $candidate.commit and
    .sequence == $candidate.sequence and
    .release_index_sha256 == $candidate.release_identity.release_index_sha256 and
    .architecture == "amd64" and .executable_sha256 == $executable' "$installed" >/dev/null
}

prove_not_set_up() {
  printf '0\n' | /usr/local/bin/sbxr | grep -F 'Proxy status: Not set up' >/dev/null
  test ! -e /var/lib/sbxr/proxy-ownership.json
  test ! -e /var/lib/sbxr/proxy-ownership.finalizing.json
  test ! -e /etc/sing-box/config.json
  test ! -e /var/lib/sing-box
  ! dpkg-query -W sing-box >/dev/null 2>&1
}

prove_running() {
  local output
  output="$(printf '0\n' | /usr/local/bin/sbxr)"
  grep -F 'Proxy status: Running' <<<"$output" >/dev/null
  grep -F 'Code: PROXY-INSTALLATION-SETUP-COMPLETE' <<<"$output" >/dev/null
}

prove_not_installed() {
  local code output
  for path in /usr/local/bin/sbxr /var/lib/sbxr/installed.json /var/lib/sbxr/proxy-ownership.json /var/lib/sbxr/proxy-ownership.finalizing.json /etc/sing-box/config.json /var/lib/sing-box /etc/apt/sources.list.d/sagernet.sources /etc/apt/keyrings/sagernet.asc /lib/systemd/system/sing-box.service /usr/lib/systemd/system/sing-box.service; do
    test ! -e "$path" || return 1
  done
  if dpkg-query -W sing-box >/dev/null 2>&1; then return 1; else code=$?; fi
  test "$code" -eq 1 || return 1
  output="$(apt-mark showhold)" || return 1
  if grep -Fx sing-box <<<"$output" >/dev/null; then return 1; fi
  if output="$(systemctl list-unit-files sing-box.service --no-legend 2>&1)"; then return 1; else code=$?; fi
  test "$code" -eq 1 && test -z "$output" || return 1
  output="$(ss -H -ltnp 'sport = :443')" || return 1
  if grep -F sing-box <<<"$output" >/dev/null; then return 1; fi
  if getent passwd sing-box >/dev/null; then return 1; else code=$?; fi
  test "$code" -eq 2 || return 1
  if getent group sing-box >/dev/null; then return 1; else code=$?; fi
  test "$code" -eq 2 || return 1
}

remote_failure_safety() {
  install_candidate
  prove_not_set_up

  install -d -m 0700 /etc/sing-box
  install -m 0600 /dev/null /etc/sing-box/config.json
  prove_status 'Problem detected'
  view_details 'Detected mismatch: /etc/sing-box is present'
  conflict_before="$(protected_inventory)"
  run_action 'Start setup' '' 'Code: PROXY-INSTALLATION-ACTION-REFUSED'
  test "$(protected_inventory)" = "$conflict_before"
  test ! -e /var/lib/sbxr/proxy-ownership.json
  rm -f /etc/sing-box/config.json
  rmdir /etc/sing-box
  prove_not_set_up
  clean_footprint_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  interrupt_at 'Start setup' y 'Validate configuration' before-activation
  prove_status 'Setup incomplete'
  run_action 'Finish cleanup' y 'Code: PROXY-INSTALLATION-SETUP-CLEANED-UP'
  prove_not_set_up
  before_activation_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  interrupt_at 'Start setup' y 'Activation committed' after-activation
  prove_status 'Setup incomplete'
  run_action 'Finish setup' y 'Code: PROXY-INSTALLATION-SETUP-COMPLETE'
  prove_running
  after_activation_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  chmod 0600 /etc/sing-box/config.json
  drift_before="$(protected_inventory)"
  run_action 'Complete removal' 'REMOVE SBXR' 'Code: PROXY-INSTALLATION-ACTION-REFUSED'
  prove_status 'Problem detected'
  view_details 'Detected mismatch: the protected configuration identity does not match'
  test "$(protected_inventory)" = "$drift_before"
  chmod 0640 /etc/sing-box/config.json
  prove_running
  ownership_drift_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  KNOWN_PRIVATE_KEY="$(jq -er '.inbounds[0].tls.reality.private_key' /etc/sing-box/config.json)"
  KNOWN_CLIENT_UUID="$(jq -er '.inbounds[0].users[0].uuid' /etc/sing-box/config.json)"
  interrupt_at 'Complete removal' 'REMOVE SBXR' 'Removal committed' after-removal
  prove_status 'Removal incomplete'
  run_action 'Finish removal' '' 'Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED'
  prove_not_installed
  after_removal_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  jq -cnS --arg clean "$clean_footprint_completed_at" --arg before "$before_activation_completed_at" --arg after "$after_activation_completed_at" --arg drift "$ownership_drift_completed_at" --arg removal "$after_removal_completed_at" '{after_activation_completed_at:$after,after_removal_completed_at:$removal,before_activation_completed_at:$before,clean_footprint_completed_at:$clean,ownership_drift_completed_at:$drift}'
}

remote_setup_and_disclose() {
  install_candidate
  prove_not_set_up
  run_action 'Start setup' y 'Code: PROXY-INSTALLATION-SETUP-COMPLETE'
  prove_running
  local details
  details="$(menu_session_details)" || return 1
  scan_vps_capture <(printf '%s' "$details")
  for fact in 'Release Identity:' 'Proxy Package Identity:' 'Ownership Record:' 'Packaged validation result:' 'systemd unit provenance' 'Service enabled:' 'Service active:' 'Expected public listener ownership:' 'Package hold:' 'Selected destination:' 'Client Identity: Present'; do
    grep -F "$fact" <<<"$details" >/dev/null
  done
  remote_outside_disclose
}

remote_remove() {
  prove_running
  KNOWN_PRIVATE_KEY="$(jq -er '.inbounds[0].tls.reality.private_key' /etc/sing-box/config.json)"
  KNOWN_CLIENT_UUID="$(jq -er '.inbounds[0].users[0].uuid' /etc/sing-box/config.json)"
  run_action 'Complete removal' 'REMOVE SBXR' 'Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED'
  prove_not_installed
}

remote_outside_disclose() {
  prove_running || return 1
  menu_session_driver disclose 'Show client configuration' \
    PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED | awk '
    /^----- BEGIN SBXR CLIENT CONFIGURATION -----$/ {inside=1; next}
    /^----- END SBXR CLIENT CONFIGURATION -----$/ {inside=0; complete=1; next}
    inside {print}
    END {if (!complete) exit 1}
  '
}

seal_failure_evidence() {
  local evidence=$1 marker=$2
  rm -f "$marker"
  scan_vps_capture "$evidence" || return 1
  install -m 0600 /dev/null "$marker"
}

remote_failure_cleanup() {
  local WORK=${WORK:-/run/sbxr-qualification}
  local action after before details details_number evidence evidence_safe input expected output status
  evidence=$WORK/failure-cleanup-evidence.txt
  evidence_safe=$WORK/failure-cleanup-evidence.safe
  rm -f "$evidence_safe"
  install -m 0600 /dev/null "$evidence"
  for _ in 1 2 3; do
    if test ! -x /usr/local/bin/sbxr; then
      if prove_not_installed; then
        printf 'Public interface: Not installed\nFinal absence: Verified\n' >>"$evidence"
        seal_failure_evidence "$evidence" "$evidence_safe"
        return
      fi
      printf 'Public interface: Not installed\nFinal absence: Inspection failed or a protected resource remains\n' >>"$evidence"
      seal_failure_evidence "$evidence" "$evidence_safe"
      return 1
    fi
    if output="$(printf '0\n' | /usr/local/bin/sbxr)"; then
      scan_vps_capture <(printf '%s' "$output") || return 1
    else
      status=$?
      if scan_vps_capture <(printf '%s' "$output"); then
        printf 'Public inspection: Failed (%s)\n%s\n' "$status" "$output" >>"$evidence"
      else
        printf 'Public inspection: Failed (%s); rejected secret-bearing output was not retained\n' "$status" >>"$evidence"
      fi
      seal_failure_evidence "$evidence" "$evidence_safe"
      return 1
    fi
    printf '%s\n' "$output" >>"$evidence"
    details_number="$(menu_number_from "$output" 'View details')"
    if test -n "$details_number"; then
      details="$(menu_session_details)" || return 1
      scan_vps_capture <(printf '%s' "$details") || return 1
      printf '%s\n' "$details" >>"$evidence"
      seal_failure_evidence "$evidence" "$evidence_safe" || return 1
    fi
    if test -e /etc/sing-box/config.json && jq -e '.inbounds[0].tls.reality.private_key and .inbounds[0].users[0].uuid' /etc/sing-box/config.json >/dev/null 2>&1; then
      KNOWN_PRIVATE_KEY="$(jq -er '.inbounds[0].tls.reality.private_key' /etc/sing-box/config.json)"
      KNOWN_CLIENT_UUID="$(jq -er '.inbounds[0].users[0].uuid' /etc/sing-box/config.json)"
    fi
    before="$(protected_inventory)" || return 1
    if test -n "$(menu_number_from "$output" 'Finish cleanup')"; then
      action='Finish cleanup' input=y expected='Code: PROXY-INSTALLATION-SETUP-CLEANED-UP'
    elif test -n "$(menu_number_from "$output" 'Finish setup')"; then
      action='Finish setup' input=y expected='Code: PROXY-INSTALLATION-SETUP-COMPLETE'
    elif test -n "$(menu_number_from "$output" 'Finish removal')"; then
      action='Finish removal' input='' expected='Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED'
    elif test -n "$(menu_number_from "$output" 'Complete removal')"; then
      action='Complete removal' input='REMOVE SBXR' expected='Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED'
    else
      after="$(protected_inventory)" || return 1
      printf 'Legal finishing action: Absent\nProtected inventory before: %s\nProtected inventory after: %s\nRetention: %s\n' "$before" "$after" "$(if test "$before" = "$after"; then printf Verified; else printf Changed; fi)" >>"$evidence"
      seal_failure_evidence "$evidence" "$evidence_safe"
      test "$before" = "$after" || return 1
      return 1
    fi
    LAST_ACTION_OUTPUT=
    if run_action "$action" "$input" "$expected"; then
      after="$(protected_inventory)" || return 1
      printf 'Legal finishing action: %s\n%s\nAction result: Accepted\nProtected inventory before: %s\nProtected inventory after: %s\n' "$action" "$LAST_ACTION_OUTPUT" "$before" "$after" >>"$evidence"
    else
      after="$(protected_inventory)" || return 1
      printf 'Legal finishing action: %s\n%s\nAction result: Refused or failed\nProtected inventory before: %s\nProtected inventory after: %s\n' "$action" "${LAST_ACTION_OUTPUT:-No action output}" "$before" "$after" >>"$evidence"
      seal_failure_evidence "$evidence" "$evidence_safe"
      return 1
    fi
    seal_failure_evidence "$evidence" "$evidence_safe"
  done
  if prove_not_installed; then
    printf 'Final absence: Verified\n' >>"$evidence"
    seal_failure_evidence "$evidence" "$evidence_safe"
    return
  fi
  printf 'Final absence: Inspection failed or a protected resource remains\n' >>"$evidence"
  seal_failure_evidence "$evidence" "$evidence_safe"
  return 1
}

remote_secret_safe() {
  local WORK=${WORK:-/run/sbxr-qualification}
  local private_key client_uuid
  private_key="$(jq -er '.inbounds[0].tls.reality.private_key' /etc/sing-box/config.json)"
  client_uuid="$(jq -er '.inbounds[0].users[0].uuid' /etc/sing-box/config.json)"
  if grep -RF -- "$private_key" "$WORK/qualification-manifest.json" "$WORK/gateway.log" >/dev/null 2>&1; then return 1; fi
  if grep -RF -- "$client_uuid" "$WORK/qualification-manifest.json" "$WORK/gateway.log" >/dev/null 2>&1; then return 1; fi
  if grep -Eq 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization: Bearer ' "$WORK/qualification-manifest.json" "$WORK/gateway.log"; then return 1; fi
}

# Operator helpers source this module directly; never extract/eval its text.
if test "${BASH_SOURCE[0]}" != "$0"; then return; fi

set -euo pipefail
umask 077
PACKAGE_SHA256=fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf
PACKAGE_SIZE=24597120
WORK=/run/sbxr-qualification

if [[ ${1:-} == remote-exact-candidate ]]; then
  test "$#" -eq 1
  exact_candidate
  exit
fi

if [[ ${1:-} == remote-* ]]; then
  mode=$1
  TAG=$2 SEQUENCE=$3 COMMIT=$4 INDEX=$5
  case "$mode" in
    remote-failure-safety) remote_failure_safety ;;
    remote-setup-and-disclose) remote_setup_and_disclose ;;
    remote-secret-safe) remote_secret_safe ;;
    remote-remove) remote_remove ;;
    remote-failure-cleanup) remote_failure_cleanup ;;
    remote-outside-disclose) remote_outside_disclose ;;
    *) exit 1 ;;
  esac
  exit
fi

outside_probe=false
if [[ ${1:-} == outside-probe ]]; then
  test "$#" -eq 7
  outside_probe=true
  shift
  scenario=$5 deadline=$6
  case "$scenario" in baseline-clean|baseline-postcommit) ;; *) exit 1 ;; esac
  [[ "$deadline" =~ ^[0-9]{10}$ ]]
  test "$(date +%s)" -lt "$deadline"
else
  test $# -eq 4
fi

host=$1 key=$2 known_hosts=$3 manifest=$4
test "$(jq -r '.mode' "$manifest")" = v3
if test "$outside_probe" = true; then
  jq -e '.source_state == "v3-recurring" or .source_state == "v3-subscription-clean"' "$manifest" >/dev/null
else
  test "$(jq -r '.source_state' "$manifest")" = v3-clean
fi
test "$(jq '.releases | length' "$manifest")" -eq 1
release="$(jq -c '.releases[0]' "$manifest")"
tag="$(jq -r .tag <<<"$release")"
sequence="$(jq -r .sequence <<<"$release")"
commit="$(jq -r .commit <<<"$release")"
index="$(jq -r .release_identity.release_index_sha256 <<<"$release")"
ssh_options=(-i "$key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ConnectTimeout=15)
remote=(ssh "${ssh_options[@]}" "root@$host")
client_config=/dev/shm/sbxr-v3-client.json
client_root=${RUNNER_TEMP:?}/sbxr-v3-client
client_deb=/dev/shm/sing-box.deb
client_log=/dev/shm/sbxr-v3-client.log
workflow_capture=/dev/shm/sbxr-v3-workflow.log
# Refuse collisions before installing a cleanup trap or writing any file.
for path in "$client_config" "$client_root" "$client_deb" "$client_log" "$workflow_capture" /dev/shm/sagernet.asc; do
  if test -e "$path" || test -L "$path"; then exit 1; fi
done
test "$(findmnt -no FSTYPE -T /dev/shm)" = tmpfs
runner_stage=initialization
runner_stage_evidence=handoff/failure-evidence/runner-stage.txt
rm -f "$runner_stage_evidence"
cleanup() {
  status=$?
  set +e
  if test -n "${client_pid:-}"; then kill "$client_pid" 2>/dev/null; wait "$client_pid" 2>/dev/null; fi
  if test -e "$workflow_capture"; then
    if grep -Eq 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization: Bearer |[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}' "$workflow_capture"; then status=1; fi
    if test -n "${client_uuid:-}" && grep -F -- "$client_uuid" "$workflow_capture" >/dev/null; then status=1; fi
  fi
  if test "$status" -ne 0; then
    case "$runner_stage" in
      initialization|remote-failure-safety|remote-setup-and-disclose|validate-client-configuration|download-client-signing-key|download-client-package|verify-client-package|start-outside-client|measure-direct-route|measure-proxied-route|measure-vps-route|compare-routes|cleanup-outside-client|verify-remote-secret-safety|complete-remote-removal|write-evidence) ;;
      *) runner_stage=unknown ;;
    esac
    mkdir -p "$(dirname "$runner_stage_evidence")"
    printf 'Runner stage: %s\n' "$runner_stage" >"$runner_stage_evidence"
  fi
  rm -rf "$client_config" "$client_root" "$client_deb" "$client_log" "$workflow_capture" /dev/shm/sagernet.asc
  test ! -e "$client_root" || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' TERM INT HUP
exec 3>&1
exec >"$workflow_capture" 2>&1

scan_runner_capture() {
  if grep -F -- "$client_uuid" "$client_log" >/dev/null; then return 1; fi
  if grep -Eq 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization: Bearer |[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}' "$client_log"; then return 1; fi
}

journey_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
runner_stage=remote-failure-safety
if test "$outside_probe" = true; then
  runner_stage=remote-setup-and-disclose
  "${remote[@]}" "/usr/bin/bash -s remote-outside-disclose '$tag' '$sequence' '$commit' '$index'" < "$0" >"$client_config"
else
  failure_times="$("${remote[@]}" "TAG=$tag SEQUENCE=$sequence COMMIT=$commit INDEX=$index /usr/bin/bash $WORK/v3-packaged-live.sh remote-failure-safety '$tag' '$sequence' '$commit' '$index'")"
  jq -e 'keys == ["after_activation_completed_at","after_removal_completed_at","before_activation_completed_at","clean_footprint_completed_at","ownership_drift_completed_at"]' <<<"$failure_times" >/dev/null
  runner_stage=remote-setup-and-disclose
  "${remote[@]}" "TAG=$tag SEQUENCE=$sequence COMMIT=$commit INDEX=$index /usr/bin/bash $WORK/v3-packaged-live.sh remote-setup-and-disclose '$tag' '$sequence' '$commit' '$index'" >"$client_config"
fi
uninterrupted_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
runner_stage=validate-client-configuration
chmod 0600 "$client_config"
jq -e '.inbounds == [{type:"mixed",tag:"mixed-in",listen:"127.0.0.1",listen_port:2080}] and (.outbounds | length) == 1' "$client_config" >/dev/null
test "$(findmnt -no FSTYPE -T "$client_config")" = tmpfs
test "$(stat -c %a "$client_config")" = 600
client_uuid="$(jq -er '.outbounds[0].uuid' "$client_config")"

runner_stage=download-client-signing-key
curl -fsSL https://sing-box.app/gpg.key -o /dev/shm/sagernet.asc
test "$(sha256sum /dev/shm/sagernet.asc | cut -d' ' -f1)" = 803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1
runner_stage=download-client-package
curl -fsSL --retry 3 --retry-all-errors https://deb.sagernet.org/files/ver_qb4px/sing-box_1.13.19_linux_amd64.deb -o "$client_deb"
test "$(stat -c %s "$client_deb")" -eq "$PACKAGE_SIZE"
test "$(sha256sum "$client_deb" | cut -d' ' -f1)" = "$PACKAGE_SHA256"
runner_stage=verify-client-package
mkdir -m 0700 "$client_root"
dpkg-deb -x "$client_deb" "$client_root"
"$client_root/usr/bin/sing-box" check -c "$client_config" >/dev/null 2>"$client_log"
scan_runner_capture
runner_stage=start-outside-client
"$client_root/usr/bin/sing-box" run -c "$client_config" >/dev/null 2>"$client_log" &
client_pid=$!
for _ in $(seq 1 100); do ss -H -ltn 'sport = :2080' | grep -F '127.0.0.1:2080' >/dev/null && break; kill -0 "$client_pid"; sleep .1; done
runner_stage=measure-direct-route
direct="$(curl -fsS https://api.ipify.org)"
runner_stage=measure-proxied-route
proxied="$(curl -fsS --proxy socks5h://127.0.0.1:2080 https://api.ipify.org)"
runner_stage=measure-vps-route
vps="$("${remote[@]}" curl -fsS https://api.ipify.org)"
runner_stage=compare-routes
test "$direct" != "$vps"
test "$proxied" = "$vps"
runner_stage=cleanup-outside-client
kill "$client_pid"
wait "$client_pid" 2>/dev/null || true
unset client_pid
scan_runner_capture
rm -rf "$client_config" "$client_root" "$client_deb" "$client_log" /dev/shm/sagernet.asc
if ss -H -ltn 'sport = :2080' | grep -F '127.0.0.1:2080' >/dev/null; then exit 1; fi
if pgrep -x sing-box >/dev/null; then exit 1; fi
test ! -e "$client_config"
test ! -e "$client_root"
test ! -e "$client_deb"
test ! -e "$client_log"
test ! -e /dev/shm/sagernet.asc
test ! -e /dev/shm/sagernet.sources
runner_cleanup_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if test "$outside_probe" = true; then
  test "$(date +%s)" -le "$deadline"
  # Scan before publishing a reply; the EXIT trap scans again on every exit.
  if grep -Eq 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization: Bearer |[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}' "$workflow_capture" || grep -F -- "$client_uuid" "$workflow_capture" >/dev/null; then exit 1; fi
  jq -cnS --arg scenario "$scenario" --arg started "$journey_started_at" --arg completed "$runner_cleanup_completed_at" '{completed_at:$completed,observation:{egress_matched:true,outside_routes_differ:true,runner_cleanup_complete:true},scenario_id:$scenario,schema:"sbxr-v3-outside-probe-reply-v1",started_at:$started}' >&3
  exit
fi

runner_stage=verify-remote-secret-safety
"${remote[@]}" "/usr/bin/bash $WORK/v3-packaged-live.sh remote-secret-safe '$tag' '$sequence' '$commit' '$index'"
runner_stage=complete-remote-removal
"${remote[@]}" "/usr/bin/bash $WORK/v3-packaged-live.sh remote-remove '$tag' '$sequence' '$commit' '$index'"
complete_removal_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
observed_at="$complete_removal_completed_at"
manifest_sha256="$(sha256sum "$manifest" | cut -d' ' -f1)"
runner_stage=write-evidence
jq -cnS --arg observed_at "$observed_at" --arg manifest_sha256 "$manifest_sha256" --arg package_sha256 "$PACKAGE_SHA256" --argjson package_size "$PACKAGE_SIZE" --argjson failure_times "$failure_times" --arg journey_started_at "$journey_started_at" --arg uninterrupted_completed_at "$uninterrupted_completed_at" --arg runner_cleanup_completed_at "$runner_cleanup_completed_at" --arg complete_removal_completed_at "$complete_removal_completed_at" '{failure_cases:[{final_state:"Not set up",finishing_action:"Remove qualification conflict",name:"clean-footprint-refusal",post_death_status:"Not set up",trigger_event:"Detected mismatch: /etc/sing-box is present"},{final_state:"Not set up",finishing_action:"Finish cleanup",name:"before-activation-commitment",post_death_status:"Setup incomplete",trigger_event:"Validate configuration"},{final_state:"Running",finishing_action:"Finish setup",name:"after-activation-commitment",post_death_status:"Setup incomplete",trigger_event:"Activation committed"},{final_state:"Running",finishing_action:"Restore recorded metadata",name:"ownership-drift-removal-refusal",post_death_status:"Problem detected",trigger_event:"Detected mismatch: the protected configuration identity does not match"},{final_state:"Not installed",finishing_action:"Finish removal",name:"after-removal-commitment",post_death_status:"Removal incomplete",trigger_event:"Removal committed"}],observed_at:$observed_at,outside_client_package:{architecture:"amd64",name:"sing-box",repository:"https://deb.sagernet.org/",sha256:$package_sha256,signing_key_sha256:"803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1",size:$package_size,version:"1.13.19"},proxy_package:{architecture:"amd64",name:"sing-box",repository:"https://deb.sagernet.org/",sha256:$package_sha256,signing_key_sha256:"803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1",size:$package_size,version:"1.13.19"},qualification_manifest_sha256:$manifest_sha256,schema:"sbxr-v3-packaged-live-evidence-v1",secret_scan:{exact_secrets_absent:true,prohibited_patterns_absent:true,retained_evidence:true,runner_capture:true,vps_capture:true,workflow_output:true},stage_times:($failure_times+{complete_removal_completed_at:$complete_removal_completed_at,journey_started_at:$journey_started_at,runner_cleanup_completed_at:$runner_cleanup_completed_at,uninterrupted_completed_at:$uninterrupted_completed_at}),uninterrupted:{clean_installation:true,details_complete:true,disclosure_bounded:true,egress_matched:true,final_absence_complete:true,installed_identity:true,not_set_up:true,outside_routes_differ:true,removal_result:"SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED",runner_configuration_absent:true,runner_file_mode:"0600",runner_listener_absent:true,runner_memory_backed:true,runner_process_absent:true,running:true,setup_confirmed:true,setup_result:"PROXY-INSTALLATION-SETUP-COMPLETE",setup_reviewed:true}}' | tr -d '\n' > handoff/v3-packaged-live-evidence.json
! grep -F -- "$client_uuid" handoff/v3-packaged-live-evidence.json >/dev/null
