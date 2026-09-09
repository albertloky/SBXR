#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
operator_expect_scenario baseline-removal
test "$SCENARIO_START" = "$STARTED_AT"
preflight
operator_exact_candidate
prove_running
remember_secrets
initial_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
interrupt_at 'Complete removal' 'REMOVE SBXR' 'Removal committed' after-removal
prove_status 'Removal incomplete'
boundary_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_action 'Finish removal' '' 'Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED'
prove_not_installed
recovery_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
scan_journal
scan_transport_captures
completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -cnS --arg started "$STARTED_AT" --arg initial "$initial_at" --arg boundary "$boundary_at" --arg recovery "$recovery_at" --arg completed "$completed_at" '{boundary_at:$boundary,completed_at:$completed,initial_at:$initial,recovery_at:$recovery,started_at:$started}' | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/06-state.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/06-state.json"
printf 'BASELINE_REMOVAL_OK started=%s initial=%s boundary=%s recovery=%s completed=%s\n' "$STARTED_AT" "$initial_at" "$boundary_at" "$recovery_at" "$completed_at"
