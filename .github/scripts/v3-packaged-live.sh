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
    for path in /usr/local/bin/sbxr /var/lib/sbxr/installed.json /var/lib/sbxr/proxy-ownership.json /var/lib/sbxr/proxy-ownership.finalizing.json /etc/sing-box/config.json /etc/apt/sources.list.d/sagernet.sources /etc/apt/keyrings/sagernet.asc /etc/systemd/system/sbxr-mutation-lock.service /etc/systemd/system/sbxr-mutation-lock.service.sbxr-next /etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service /lib/systemd/system/sing-box.service /usr/lib/systemd/system/sing-box.service; do
      if test -e "$path" || test -L "$path"; then stat -c "$path %a %u %g %s" "$path"; sha256sum "$path"; else printf '%s absent\n' "$path"; fi
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
  local label=$1 input=$2 expected=$3 output status=0
  LAST_ACTION_OUTPUT=
  output="$(menu_session_action "$label" "$input" "$expected")" || status=$?
  # A refused menu still contains the safety check and correction. Scan those
  # bytes before retaining or reporting them, including on driver failure.
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
  ' <<<"$output")" = "$expected" || status=1
  if test "$status" -ne 0; then
    printf '%s\n' "$output" | awk '
      !action {
        if ($0 == "SBXR V3" ||
            $0 ~ /^(Proxy status:|Subscription status:|Software Lifecycle:|Code:|[0-9]+\. )/) {
          initial = initial $0 ORS
        }
        if ($0 == "0. Exit") action=1
        next
      }
      /^(Failed safety check:|Correction:|Result:|Code:)/ {
        details = details $0 ORS
      }
      END {
        if (details != "") printf "%s", details
        else printf "%s", initial
      }
    '
  fi
  return "$status"
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
  test ! -e /etc/systemd/system/sbxr-mutation-lock.service && test ! -L /etc/systemd/system/sbxr-mutation-lock.service
  test ! -e /etc/systemd/system/sbxr-mutation-lock.service.sbxr-next && test ! -L /etc/systemd/system/sbxr-mutation-lock.service.sbxr-next
  test ! -e /etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service && test ! -L /etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service
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
  for path in /usr/local/bin/sbxr /var/lib/sbxr/installed.json /var/lib/sbxr/proxy-ownership.json /var/lib/sbxr/proxy-ownership.finalizing.json /etc/sing-box/config.json /var/lib/sing-box /etc/apt/sources.list.d/sagernet.sources /etc/apt/keyrings/sagernet.asc /etc/systemd/system/sbxr-mutation-lock.service /etc/systemd/system/sbxr-mutation-lock.service.sbxr-next /etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service /lib/systemd/system/sing-box.service /usr/lib/systemd/system/sing-box.service; do
    { test ! -e "$path" && test ! -L "$path"; } || return 1
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
    remote-setup-and-disclose) remote_setup_and_disclose ;;
    remote-secret-safe) remote_secret_safe ;;
    remote-remove) remote_remove ;;
    remote-failure-cleanup) remote_failure_cleanup ;;
    remote-outside-disclose) remote_outside_disclose ;;
    *) exit 1 ;;
  esac
  exit
fi

exit 1
