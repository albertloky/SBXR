#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
operator_expect_scenario baseline-refusal
test "$SCENARIO_START" = "$STARTED_AT"
preflight
prove_not_installed
load_candidate_identity
install_candidate
operator_exact_candidate
prove_not_set_up
initial_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
install -d -m 0700 /etc/sing-box
install -m 0600 /dev/null /etc/sing-box/config.json
prove_status 'Problem detected'
view_details 'Detected mismatch: /etc/sing-box is present'
conflict_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
conflict_before=$(protected_inventory)
run_action 'Start setup' '' 'Code: PROXY-INSTALLATION-ACTION-REFUSED'
test "$(protected_inventory)" = "$conflict_before"
test ! -e /var/lib/sbxr/proxy-ownership.json
refusal_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
rm -f /etc/sing-box/config.json
rmdir /etc/sing-box
prove_not_set_up
operator_exact_candidate
scan_journal
scan_transport_captures
completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -cnS --arg started "$STARTED_AT" --arg initial "$initial_at" --arg conflict "$conflict_at" --arg refusal "$refusal_at" --arg completed "$completed_at" '{completed_at:$completed,conflict_at:$conflict,initial_at:$initial,refusal_at:$refusal,started_at:$started}' | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/02-state.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/02-state.json"
printf 'BASELINE_REFUSAL_OK started=%s initial=%s conflict=%s refusal=%s completed=%s\n' "$STARTED_AT" "$initial_at" "$conflict_at" "$refusal_at" "$completed_at"
