#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
SCENARIO_START=$(jq -er .started_at "${SBXR_OPERATOR_STATE_DIR}/07-state.json")
operator_expect_scenario identity-absent
preflight
operator_exact_candidate
prove_running
remember_secrets
source_pid=$(jq -er .source_pid "${SBXR_OPERATOR_STATE_DIR}/07-state.json")
source_tick=$(jq -er .source_tick "${SBXR_OPERATOR_STATE_DIR}/07-state.json")
test "$(awk '{print $22}' "/proc/$source_pid/stat")" = "$source_tick"
rotation_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
action 'Rotate Client Identity' y 'Code: PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATED'
rotation_completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
prove_running
operator_exact_candidate
jq -e '.schema==2 and .phase=="Running" and (.client_identity_rotation|not) and (.serving|not) and (.renewal|not) and (.subscription_resources|not)' /var/lib/sbxr/proxy-ownership.json >/dev/null
test ! -e "/proc/$source_pid"
test -z "$(pgrep -g "$(jq -er .source_group "${SBXR_OPERATOR_STATE_DIR}/07-state.json")" || true)"
replacement_pid=$(systemctl show sing-box.service -p MainPID --value)
test "$replacement_pid" -gt 1
test "$replacement_pid" != "$source_pid"
replacement_tick=$(awk '{print $22}' "/proc/$replacement_pid/stat")
remote_outside_disclose > "${SBXR_OPERATOR_STATE_DIR}/07-replacement-client.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/07-replacement-client.json"
source_uuid=$(jq -er '.outbounds[0].uuid' "${SBXR_OPERATOR_STATE_DIR}/07-source-client.json")
replacement_uuid=$(jq -er '.outbounds[0].uuid' "${SBXR_OPERATOR_STATE_DIR}/07-replacement-client.json")
test "$source_uuid" != "$replacement_uuid"
jq -S '(.outbounds[0] |= del(.uuid))' "${SBXR_OPERATOR_STATE_DIR}/07-source-client.json" > "${SBXR_OPERATOR_STATE_DIR}/07-source-noncredential.json"
jq -S '(.outbounds[0] |= del(.uuid))' "${SBXR_OPERATOR_STATE_DIR}/07-replacement-client.json" > "${SBXR_OPERATOR_STATE_DIR}/07-replacement-noncredential.json"
cmp "${SBXR_OPERATOR_STATE_DIR}/07-source-noncredential.json" "${SBXR_OPERATOR_STATE_DIR}/07-replacement-noncredential.json"
issuance_lines=$(zgrep -hF 'Certificate is saved at:' /var/log/letsencrypt/letsencrypt.log* 2>/dev/null | wc -l | tr -d ' ')
test "$issuance_lines" = "$(jq -er .issuance_lines_before "${SBXR_OPERATOR_STATE_DIR}/07-state.json")"
test ! -e /etc/letsencrypt/live/sbxr-subscription
test -z "$(ss -H -lnt 'sport = :8443')"
jq -cS --arg started "$rotation_started_at" --arg completed "$rotation_completed_at" --arg pid "$replacement_pid" --arg tick "$replacement_tick" '. + {replacement_pid:$pid,replacement_tick:$tick,rotation_completed_at:$completed,rotation_started_at:$started}' "${SBXR_OPERATOR_STATE_DIR}/07-state.json" | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/07-state.next"
mv "${SBXR_OPERATOR_STATE_DIR}/07-state.next" "${SBXR_OPERATOR_STATE_DIR}/07-state.json"
printf 'IDENTITY_ABSENT_ROTATED started=%s completed=%s replacement_pid=%s\n' "$rotation_started_at" "$rotation_completed_at" "$replacement_pid"
