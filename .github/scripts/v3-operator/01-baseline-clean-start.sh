#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
operator_expect_scenario baseline-clean
test "$SCENARIO_START" = "$STARTED_AT"
preflight
prove_not_installed
initial_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
load_candidate_identity
install_candidate
operator_exact_candidate
prove_not_set_up
install_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
action 'Start setup' y 'Code: PROXY-INSTALLATION-SETUP-COMPLETE'
prove_running
remember_secrets
setup_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -cnS --arg started "$STARTED_AT" --arg initial "$initial_at" --arg installed "$install_at" --arg setup "$setup_at" '{initial_at:$initial,install_at:$installed,setup_at:$setup,started_at:$started}' | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/01-state.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/01-state.json"
printf 'BASELINE_CLEAN_READY started=%s initial=%s installed=%s setup=%s\n' "$STARTED_AT" "$initial_at" "$install_at" "$setup_at"
