#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
test "$SCENARIO_START" = "$STARTED_AT"
operator_expect_scenario identity-absent
for outside_file in 07-outside-started.json 07-outside-ready.json 07-outside-rotation-request.json 07-outside-rotation-ready.json 07-outside-collected.json 07-outside.json; do
  test ! -e "${SBXR_OPERATOR_STATE_DIR}/$outside_file"
  test ! -L "${SBXR_OPERATOR_STATE_DIR}/$outside_file"
done
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
operator_exact_candidate
remember_secrets
jq -e '.schema==1 and .phase=="Running" and (.serving|not) and (.renewal|not) and (.certificate_activation|not) and (.subscription_enablement|not) and (.subscription_rotation|not) and (.subscription_repair|not) and (.subscription_resources|not)' /var/lib/sbxr/proxy-ownership.json >/dev/null
test ! -e /var/lib/sbxr/subscription-token
test ! -e /var/lib/sbxr/subscription-renewal.json
test ! -e /etc/systemd/system/sbxr-subscription.service
test ! -e /etc/systemd/system/sbxr-subscription.socket
test ! -e /etc/letsencrypt/live/sbxr-subscription
test -z "$(ss -H -lnt 'sport = :8443')"
source_pid=$(systemctl show sing-box.service -p MainPID --value)
test "$source_pid" -gt 1
source_tick=$(awk '{print $22}' "/proc/$source_pid/stat")
source_group=$(ps -o pgid= -p "$source_pid" | tr -d ' ')
test "$source_group" -gt 1
cp /etc/sing-box/config.json "${SBXR_OPERATOR_STATE_DIR}/07-source-server.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/07-source-server.json"
remote_outside_disclose > "${SBXR_OPERATOR_STATE_DIR}/07-source-client.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/07-source-client.json"
source_uuid=$(jq -er '.inbounds[0].users[0].uuid' "${SBXR_OPERATOR_STATE_DIR}/07-source-server.json")
test "$source_uuid" = "$(jq -er '.outbounds[0].uuid' "${SBXR_OPERATOR_STATE_DIR}/07-source-client.json")"
issuance_lines=$(zgrep -hF 'Certificate is saved at:' /var/log/letsencrypt/letsencrypt.log* 2>/dev/null | wc -l | tr -d ' ')
setup_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -cnS --arg started "$STARTED_AT" --arg initial "$initial_at" --arg install "$install_at" --arg setup "$setup_at" --arg pid "$source_pid" --arg tick "$source_tick" --arg group "$source_group" --argjson issuance "$issuance_lines" '{initial_at:$initial,install_at:$install,issuance_lines_before:$issuance,setup_at:$setup,source_disclosure_confirmed:true,source_group:$group,source_pid:$pid,source_tick:$tick,started_at:$started}' | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/07-state.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/07-state.json"
test ! -e "${SBXR_OPERATOR_EVIDENCE_DIR}/identity-outside-request.json"
test ! -L "${SBXR_OPERATOR_EVIDENCE_DIR}/identity-outside-request.json"
jq -cnS --argjson deadline "$(jq -er .deadline_unix "$SBXR_QUALIFICATION_REQUEST")" \
  --arg digest "$(operator_manifest_digest)" --arg state "$SBXR_OPERATOR_STATE_DIR" --arg operator "$operator_dir" \
  '{deadline_unix:$deadline,operator_directory:$operator,qualification_manifest_sha256:$digest,request_id:"identity-1",scenario_id:"identity-absent",schema:"sbxr-v4-identity-outside-request-v1",state_directory:$state}' \
  | tr -d '\n' > "${SBXR_OPERATOR_EVIDENCE_DIR}/identity-outside-request.next"
mv "${SBXR_OPERATOR_EVIDENCE_DIR}/identity-outside-request.next" "${SBXR_OPERATOR_EVIDENCE_DIR}/identity-outside-request.json"
printf 'IDENTITY_ABSENT_READY started=%s initial=%s install=%s setup=%s source_pid=%s\n' "$STARTED_AT" "$initial_at" "$install_at" "$setup_at" "$source_pid"
