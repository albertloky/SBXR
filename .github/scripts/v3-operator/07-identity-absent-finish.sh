#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
SCENARIO_START=$(jq -er .started_at "${SBXR_OPERATOR_STATE_DIR}/07-state.json")
operator_expect_scenario identity-absent
preflight
test "$(stat -c '%U:%G:%a:%h:%F' "${SBXR_OPERATOR_STATE_DIR}/07-outside.json")" = 'root:root:600:1:regular file'
python3 "$operator_dir/identity-outside.py" check-result \
  --manifest "$SBXR_QUALIFICATION_MANIFEST" --request "$SBXR_QUALIFICATION_REQUEST" \
  --state "${SBXR_OPERATOR_STATE_DIR}/07-state.json" --receipt "${SBXR_OPERATOR_STATE_DIR}/07-outside.json" >/dev/null
test "$(stat -c '%U:%G:%a:%h:%F' "${SBXR_OPERATOR_STATE_DIR}/07-outside-collected.json")" = 'root:root:600:1:regular file'
cmp -s "${SBXR_OPERATOR_STATE_DIR}/07-outside-collected.json" \
  <(printf '{"receipt_sha256":"%s"}' "$(sha256sum "${SBXR_OPERATOR_STATE_DIR}/07-outside.json" | cut -d' ' -f1)")
scan_retained_capture "${SBXR_OPERATOR_STATE_DIR}/07-outside.json"
operator_exact_candidate
prove_running
jq -e '.schema==2 and .phase=="Running" and (.client_identity_rotation|not) and (.serving|not) and (.renewal|not) and (.subscription_resources|not)' /var/lib/sbxr/proxy-ownership.json >/dev/null
test "$(systemctl show sing-box.service -p MainPID --value)" = "$(jq -er .replacement_pid "${SBXR_OPERATOR_STATE_DIR}/07-state.json")"
test "$(awk '{print $22}' "/proc/$(jq -er .replacement_pid "${SBXR_OPERATOR_STATE_DIR}/07-state.json")/stat")" = "$(jq -er .replacement_tick "${SBXR_OPERATOR_STATE_DIR}/07-state.json")"
issuance_lines=$(zgrep -hF 'Certificate is saved at:' /var/log/letsencrypt/letsencrypt.log* 2>/dev/null | wc -l | tr -d ' ')
test "$issuance_lines" = "$(jq -er .issuance_lines_before "${SBXR_OPERATOR_STATE_DIR}/07-state.json")"
test ! -e /etc/letsencrypt/live/sbxr-subscription
test -z "$(ss -H -lnt 'sport = :8443')"
outside_established_at=$(jq -er .old_established_at "${SBXR_OPERATOR_STATE_DIR}/07-outside.json")
outside_terminated_at=$(jq -er .old_terminated_at "${SBXR_OPERATOR_STATE_DIR}/07-outside.json")
outside_refused_at=$(jq -er .old_refused_at "${SBXR_OPERATOR_STATE_DIR}/07-outside.json")
outside_replacement_at=$(jq -er .replacement_at "${SBXR_OPERATOR_STATE_DIR}/07-outside.json")
reviewed_removal_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
remember_secrets
action 'Complete removal' 'REMOVE SBXR' 'Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED'
prove_not_installed
absence_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
python3 "$operator_dir/assemble-evidence.py" retain-07 --state-directory "$SBXR_OPERATOR_STATE_DIR" >/dev/null
rm -f "${SBXR_OPERATOR_STATE_DIR}/07-source-server.json" "${SBXR_OPERATOR_STATE_DIR}/07-source-client.json" \
  "${SBXR_OPERATOR_STATE_DIR}/07-replacement-client.json" "${SBXR_OPERATOR_STATE_DIR}/07-source-noncredential.json" \
  "${SBXR_OPERATOR_STATE_DIR}/07-replacement-noncredential.json"
scan_journal
scan_transport_captures
completed_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
jq -cS --arg reviewed "$reviewed_removal_at" --arg absent "$absence_at" --arg completed "$completed_at" --arg established "$outside_established_at" --arg terminated "$outside_terminated_at" --arg refused "$outside_refused_at" --arg replacement "$outside_replacement_at" '. + {absence_at:$absent,completed_at:$completed,old_established_at:$established,old_refused_at:$refused,old_terminated_at:$terminated,replacement_at:$replacement,reviewed_removal_at:$reviewed}' "${SBXR_OPERATOR_STATE_DIR}/07-state.json" | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/07-state.next"
mv "${SBXR_OPERATOR_STATE_DIR}/07-state.next" "${SBXR_OPERATOR_STATE_DIR}/07-state.json"
printf 'IDENTITY_ABSENT_FINISHED reviewed_removal=%s absent=%s completed=%s\n' "$reviewed_removal_at" "$absence_at" "$completed_at"
