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
check_number=$(menu_number_from "$first_frame" Check)
check_output=$(printf '%s\n0\n' "$check_number" | /usr/local/bin/sbxr)
scan_vps_capture <(printf %s "$check_output")
grep -F 'Progress: Checking the qualified latest release' <<<"$check_output" >/dev/null
grep -F 'Software Lifecycle: Ready' <<<"$check_output" >/dev/null
grep -F 'Code: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT' <<<"$check_output" >/dev/null
test "$(protected_inventory)" = "$before"

update_frame=$(printf '0\n' | /usr/local/bin/sbxr)
update_number=$(menu_number_from "$update_frame" Update)
test -n "$update_number"
update_output=$(printf '%s\n0\n' "$update_number" | /usr/local/bin/sbxr)
scan_vps_capture <(printf %s "$update_output")
grep -F 'Progress: Checking the qualified latest release' <<<"$update_output" >/dev/null
grep -F 'Software Lifecycle: Ready' <<<"$update_output" >/dev/null
grep -F 'Code: SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT' <<<"$update_output" >/dev/null
! grep -F 'Update SBXR? [y/N]' <<<"$update_output" >/dev/null
test "$(protected_inventory)" = "$before"

recover_frame=$(printf '0\n' | /usr/local/bin/sbxr)
recover_number=$(menu_number_from "$recover_frame" Recover)
test -n "$recover_number"
recover_output=$(printf '%s\n0\n' "$recover_number" | /usr/local/bin/sbxr)
scan_vps_capture <(printf %s "$recover_output")
grep -F 'Software Lifecycle: Ready' <<<"$recover_output" >/dev/null
grep -F 'No recovery is available. If a change is in progress, wait for it to finish.' <<<"$recover_output" >/dev/null
! grep -F 'Recover SBXR? [y/N]' <<<"$recover_output" >/dev/null
test "$(protected_inventory)" = "$before"

operator_exact_candidate
prove_running
scan_journal
scan_transport_captures
completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -cnS --arg started "$STARTED_AT" --arg completed "$completed_at" '{completed_at:$completed,started_at:$started}' | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/19-state.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/19-state.json"
printf 'LIFECYCLE_MENU_OK started=%s completed=%s\n' "$STARTED_AT" "$completed_at"
