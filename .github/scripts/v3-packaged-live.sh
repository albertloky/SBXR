#!/usr/bin/env bash
set -euo pipefail
umask 077

PACKAGE_SHA256=fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf
PACKAGE_SIZE=24597120
WORK=/run/sbxr-qualification

menu_number() {
  local label=$1 output
  output="$(printf '0\n' | /usr/local/bin/sbxr)"
  menu_number_from "$output" "$label"
}

menu_number_from() {
  local output=$1 label=$2
  sed -n "s/^\([1-9][0-9]*\)\. $label$/\1/p" <<<"$output"
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
  local label=$1 input=$2 expected=$3 number output
  number="$(menu_number "$label")"
  test -n "$number" || return 1
  output="$(printf '%s\n' "$number" "$input" 0 | /usr/local/bin/sbxr)" || return 1
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
  output="$(printf '%s\n\n0\n' "$(menu_number 'View details')" | /usr/local/bin/sbxr)"
  scan_vps_capture <(printf '%s' "$output")
  test "$(grep -Fxc "$expected" <<<"$output")" -eq 1
}

prove_status() {
  printf '0\n' | /usr/local/bin/sbxr | grep -F "Proxy status: $1" >/dev/null
}

interrupt_at() {
  local label=$1 confirmation=$2 event=$3 number=$4 event_observed=false interrupted=false scan_status=0 wait_status=0
  local fifo="$WORK/input-$number" output="$WORK/output-$number" action
  action="$(menu_number "$label")"
  test -n "$action"
  mkfifo "$fifo"
  exec 3<>"$fifo"
  /usr/local/bin/sbxr <"$fifo" >"$output" &
  local process=$!
  printf '%s\n%s\n' "$action" "$confirmation" >&3
  for _ in $(seq 1 6000); do
    if grep -F "Progress: $event" "$output" >/dev/null; then event_observed=true; break; fi
    if ! kill -0 "$process" 2>/dev/null; then break; fi
    sleep .01
  done
  if test "$event_observed" = true && kill -0 "$process" 2>/dev/null; then
    if kill -SIGSTOP "$process" 2>/dev/null && kill -SIGKILL "$process" 2>/dev/null; then interrupted=true; fi
  elif kill -0 "$process" 2>/dev/null; then
    kill -SIGKILL "$process" 2>/dev/null || true
  fi
  if test "$interrupted" != true && kill -0 "$process" 2>/dev/null; then
    kill -SIGCONT "$process" 2>/dev/null || true
    kill -SIGKILL "$process" 2>/dev/null || true
  fi
  wait "$process" 2>/dev/null || wait_status=$?
  if test "$wait_status" -eq "$((128 + $(kill -l STOP)))"; then
    wait_status=0
    wait "$process" 2>/dev/null || wait_status=$?
  fi
  exec 3>&-
  scan_vps_capture "$output" || scan_status=$?
  rm -f "$fifo" "$output"
  test "$scan_status" -eq 0
  test "$event_observed" = true
  test "$interrupted" = true
  test "$wait_status" -eq 137
}

install_candidate() {
  local output=$WORK/install-output
  curl -fsS https://github.com/albertloky/SBXR/releases/latest/download/install.sh | bash >"$output" 2>&1
  scan_vps_capture "$output"
  rm -f "$output"
  test -x /usr/local/bin/sbxr
  jq -e --arg tag "$TAG" --arg commit "$COMMIT" --arg index "$INDEX" --argjson sequence "$SEQUENCE" '.repository == "albertloky/SBXR" and .tag == $tag and .commit == $commit and .release_index_sha256 == $index and .sequence == $sequence and .architecture == "amd64"' /var/lib/sbxr/installed.json >/dev/null
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
  details="$(printf '%s\n\n0\n' "$(menu_number 'View details')" | /usr/local/bin/sbxr)"
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
  prove_running
  printf '%s\ny\n\n0\n' "$(menu_number 'Show client configuration')" | /usr/local/bin/sbxr | awk '
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
      details="$(printf '%s\n\n0\n' "$details_number" | /usr/local/bin/sbxr)" || return 1
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
  local private_key client_uuid
  private_key="$(jq -er '.inbounds[0].tls.reality.private_key' /etc/sing-box/config.json)"
  client_uuid="$(jq -er '.inbounds[0].users[0].uuid' /etc/sing-box/config.json)"
  if grep -RF -- "$private_key" "$WORK/qualification-manifest.json" "$WORK/gateway.log" >/dev/null 2>&1; then return 1; fi
  if grep -RF -- "$client_uuid" "$WORK/qualification-manifest.json" "$WORK/gateway.log" >/dev/null 2>&1; then return 1; fi
  if grep -Eq 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization: Bearer ' "$WORK/qualification-manifest.json" "$WORK/gateway.log"; then return 1; fi
}

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
