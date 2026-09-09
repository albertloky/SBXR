#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
operator_expect_scenario baseline-drift
test "$SCENARIO_START" = "$STARTED_AT"
preflight
operator_exact_candidate
prove_running
remember_secrets
test "$(stat -c %a /etc/sing-box/config.json)" = 640
initial_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
chmod 0600 /etc/sing-box/config.json
drift_before=$(protected_inventory)
prove_status 'Problem detected'
view_details 'Detected mismatch: the protected configuration identity does not match'
drift_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_action 'Complete removal' 'REMOVE SBXR' 'Code: PROXY-INSTALLATION-ACTION-REFUSED'
test "$(protected_inventory)" = "$drift_before"
refusal_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
chmod 0640 /etc/sing-box/config.json
prove_running
operator_exact_candidate
restoration_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
scan_journal
scan_transport_captures
completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -cnS --arg started "$STARTED_AT" --arg initial "$initial_at" --arg drift "$drift_at" --arg refusal "$refusal_at" --arg restoration "$restoration_at" --arg completed "$completed_at" '{completed_at:$completed,drift_at:$drift,initial_at:$initial,refusal_at:$refusal,restoration_at:$restoration,started_at:$started}' | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/05-state.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/05-state.json"
printf 'BASELINE_DRIFT_OK started=%s initial=%s drift=%s refusal=%s restoration=%s completed=%s\n' "$STARTED_AT" "$initial_at" "$drift_at" "$refusal_at" "$restoration_at" "$completed_at"
