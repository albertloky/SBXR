#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
SCENARIO_START=$(jq -er .started_at "${SBXR_OPERATOR_STATE_DIR}/04-state.json")
evidence=$SBXR_OPERATOR_EVIDENCE_DIR
operator_expect_scenario baseline-postcommit
operator_manifest_digest >/dev/null
deadline=$(jq -er '.deadline_unix' "$SBXR_QUALIFICATION_REQUEST")
while test "$(date +%s)" -lt "$deadline" && test ! -e "$evidence/outside-reply-baseline-postcommit.json"; do sleep 2; done
reply="$evidence/outside-reply-baseline-postcommit.json"
test "$(stat -c '%U:%G:%a:%h:%F' "$reply")" = 'root:root:600:1:regular file'
jq -e '.schema=="sbxr-v3-outside-probe-reply-v1" and .scenario_id=="baseline-postcommit" and .observation=={egress_matched:true,outside_routes_differ:true,runner_cleanup_complete:true} and (.started_at|fromdateiso8601) <= (.completed_at|fromdateiso8601)' "$reply" >/dev/null
outside_at=$(jq -r .completed_at "$reply")
scan_retained_capture "$reply"
prove_running
operator_exact_candidate
remember_secrets
scan_journal
scan_transport_captures
completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -cS --arg outside "$outside_at" --arg completed "$completed_at" '. + {outside_at:$outside,completed_at:$completed}' "${SBXR_OPERATOR_STATE_DIR}/04-state.json" | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/04-state.next"
mv "${SBXR_OPERATOR_STATE_DIR}/04-state.next" "${SBXR_OPERATOR_STATE_DIR}/04-state.json"
printf 'BASELINE_POSTCOMMIT_OK outside=%s completed=%s\n' "$outside_at" "$completed_at"
