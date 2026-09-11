#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
operator_expect_scenario lifecycle-menu
test "$SCENARIO_START" = "$STARTED_AT"
test "$SBXR_EXECUTABLE" = /usr/local/bin/sbxr
test "$SBXR_INSTALLED_RECORD" = /var/lib/sbxr/installed.json
preflight after-snap-refresh
operator_exact_candidate
prove_running
remember_secrets

entry_started_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
manifest_sha=$(sha256sum "$SBXR_QUALIFICATION_MANIFEST" | awk '{print $1}')
request_sha=$(sha256sum "$SBXR_QUALIFICATION_REQUEST" | awk '{print $1}')

first_frame=$(printf '0\n' | /usr/local/bin/sbxr)
scan_vps_capture <(printf %s "$first_frame")
printf '%s\n' "$first_frame" > "${SBXR_OPERATOR_EVIDENCE_DIR}/19-first-frame.txt"
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/19-first-frame.txt"
scan_retained_capture "${SBXR_OPERATOR_EVIDENCE_DIR}/19-first-frame.txt"
for label in Check Update Recover; do
  number=$(menu_number_from "$first_frame" "$label")
  test -n "$number"
done

before=$(protected_inventory)
action_started_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
check_number=$(menu_number_from "$first_frame" Check)
check_output=$(printf '%s\n0\n' "$check_number" | /usr/local/bin/sbxr)
scan_vps_capture <(printf %s "$check_output")
grep -F 'Progress: Checking the qualified latest release' <<<"$check_output" >/dev/null
grep -F 'Software Lifecycle: Ready' <<<"$check_output" >/dev/null
grep -F 'Code: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT' <<<"$check_output" >/dev/null
test "$(protected_inventory)" = "$before"
printf '%s\n' "$check_output" > "${SBXR_OPERATOR_EVIDENCE_DIR}/19-check.txt"
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/19-check.txt"

update_frame=$(printf '0\n' | /usr/local/bin/sbxr)
update_number=$(menu_number_from "$update_frame" Update)
test -n "$update_number"
update_output=$(printf '%s\n0\n' "$update_number" | /usr/local/bin/sbxr)
scan_vps_capture <(printf %s "$update_output")
grep -F 'Progress: Checking the qualified latest release' <<<"$update_output" >/dev/null
grep -F 'Software Lifecycle: Ready' <<<"$update_output" >/dev/null
grep -F 'Code: SOFTWARE-LIFECYCLE-UPDATE-ALREADY-CURRENT' <<<"$update_output" >/dev/null
! grep -F 'Update SBXR? [y/N]' <<<"$update_output" >/dev/null
test "$(protected_inventory)" = "$before"
printf '%s\n' "$update_output" > "${SBXR_OPERATOR_EVIDENCE_DIR}/19-update.txt"
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/19-update.txt"

recover_frame=$(printf '0\n' | /usr/local/bin/sbxr)
recover_number=$(menu_number_from "$recover_frame" Recover)
test -n "$recover_number"
recover_output=$(printf '%s\n0\n' "$recover_number" | /usr/local/bin/sbxr)
scan_vps_capture <(printf %s "$recover_output")
grep -F 'Software Lifecycle: Ready' <<<"$recover_output" >/dev/null
grep -F 'No recovery is available. If a change is in progress, wait for it to finish.' <<<"$recover_output" >/dev/null
! grep -F 'Recover SBXR? [y/N]' <<<"$recover_output" >/dev/null
test "$(protected_inventory)" = "$before"
printf '%s\n' "$recover_output" > "${SBXR_OPERATOR_EVIDENCE_DIR}/19-recover.txt"
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/19-recover.txt"
scan_retained_capture "${SBXR_OPERATOR_EVIDENCE_DIR}/19-check.txt" \
  "${SBXR_OPERATOR_EVIDENCE_DIR}/19-update.txt" \
  "${SBXR_OPERATOR_EVIDENCE_DIR}/19-recover.txt"
action_completed_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)

operator_exact_candidate
prove_running
scan_journal
scan_transport_captures
completed_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
jq -cnS --arg started "$STARTED_AT" --arg entry "$entry_started_at" \
  --arg action_started "$action_started_at" --arg action_completed "$action_completed_at" \
  --arg completed "$completed_at" --arg manifest "$manifest_sha" --arg request "$request_sha" \
  '{action_completed_at:$action_completed,action_started_at:$action_started,completed_at:$completed,entry_started_at:$entry,qualification_manifest_sha256:$manifest,request_sha256:$request,scenario_id:"lifecycle-menu",schema:"sbxr-v4-scenario-entry-v1",started_at:$started}' \
  | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/19-state.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/19-state.json"
jq -cnS --arg started "$action_started_at" --arg completed "$action_completed_at" \
  --arg first "$(sha256sum "${SBXR_OPERATOR_EVIDENCE_DIR}/19-first-frame.txt" | awk '{print $1}')" \
  --arg check "$(sha256sum "${SBXR_OPERATOR_EVIDENCE_DIR}/19-check.txt" | awk '{print $1}')" \
  --arg update "$(sha256sum "${SBXR_OPERATOR_EVIDENCE_DIR}/19-update.txt" | awk '{print $1}')" \
  --arg recover "$(sha256sum "${SBXR_OPERATOR_EVIDENCE_DIR}/19-recover.txt" | awk '{print $1}')" \
  --arg inventory "$before" \
  '{action_completed_at:$completed,action_started_at:$started,check_output_sha256:$check,first_frame_sha256:$first,inventory_before_and_after:$inventory,recover_output_sha256:$recover,schema:"sbxr-v4-lifecycle-menu-result-v1",update_output_sha256:$update}'
