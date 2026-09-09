#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
SCENARIO_START=$(jq -er .started_at "${SBXR_OPERATOR_STATE_DIR}/01-state.json")
evidence=$SBXR_OPERATOR_EVIDENCE_DIR
operator_expect_scenario baseline-clean
operator_manifest_digest >/dev/null
deadline=$(jq -er '.deadline_unix' "$SBXR_QUALIFICATION_REQUEST")
while test "$(date +%s)" -lt "$deadline" && test ! -e "$evidence/outside-reply-baseline-clean.json"; do sleep 2; done
reply="$evidence/outside-reply-baseline-clean.json"
test "$(stat -c '%U:%G:%a:%h:%F' "$reply")" = 'root:root:600:1:regular file'
jq -e '.schema=="sbxr-v3-outside-probe-reply-v1" and .scenario_id=="baseline-clean" and .observation=={egress_matched:true,outside_routes_differ:true,runner_cleanup_complete:true} and (.started_at|fromdateiso8601) <= (.completed_at|fromdateiso8601)' "$reply" >/dev/null
outside_at=$(jq -r .completed_at "$reply")
scan_retained_capture "$reply"
prove_running
operator_exact_candidate
remember_secrets
action 'Complete removal' 'REMOVE SBXR' 'Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED'
prove_not_installed
removal_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
scan_journal
scan_transport_captures
completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -cS --arg outside "$outside_at" --arg removal "$removal_at" --arg completed "$completed_at" '. + {outside_at:$outside,removal_at:$removal,completed_at:$completed}' "${SBXR_OPERATOR_STATE_DIR}/01-state.json" | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/01-state.next"
mv "${SBXR_OPERATOR_STATE_DIR}/01-state.next" "${SBXR_OPERATOR_STATE_DIR}/01-state.json"
printf 'BASELINE_CLEAN_OK outside=%s removal=%s completed=%s\n' "$outside_at" "$removal_at" "$completed_at"
