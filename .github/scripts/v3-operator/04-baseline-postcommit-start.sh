#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
operator_expect_scenario baseline-postcommit
test "$SCENARIO_START" = "$STARTED_AT"
preflight
prove_not_set_up
initial_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
interrupt_at 'Start setup' y 'Activation committed' after-activation
prove_status 'Setup incomplete'
boundary_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_action 'Finish setup' y 'Code: PROXY-INSTALLATION-SETUP-COMPLETE'
prove_running
remember_secrets
recovery_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -cnS --arg started "$STARTED_AT" --arg initial "$initial_at" --arg boundary "$boundary_at" --arg recovery "$recovery_at" '{boundary_at:$boundary,initial_at:$initial,recovery_at:$recovery,started_at:$started}' | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/04-state.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/04-state.json"
printf 'BASELINE_POSTCOMMIT_READY started=%s initial=%s boundary=%s recovery=%s\n' "$STARTED_AT" "$initial_at" "$boundary_at" "$recovery_at"
