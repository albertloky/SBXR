#!/usr/bin/env bash
set -euo pipefail
umask 077

verify_subscription_token_identity() {
  local token_path=$1 authority_sha256=$2
  test "$(wc -c < "$token_path" | tr -d ' ')" -eq 44 &&
    test "$(tail -c 1 "$token_path" | od -An -tu1 | tr -d ' ')" = 10 &&
    test "$(head -c 43 "$token_path" | sha256sum | cut -d' ' -f1)" = "$authority_sha256"
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  return 0
fi

operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
operator_expect_scenario enable-schema1
state=${SBXR_OPERATOR_STATE_DIR}/08-private.json
test "$(stat -c '%U:%G:%a:%h:%F' "$state")" = 'root:root:600:1:regular file'
SCENARIO_START=$(jq -er .started_at "$state")
preflight
operator_exact_candidate
prove_running

case "${1:-}" in
  enable)
    test "$(sha256sum /var/lib/sbxr/proxy-ownership.json | cut -d' ' -f1)" = "$(jq -er .ownership_sha256 "$state")"
    test "$(systemctl show sing-box.service -p MainPID --value)" = "$(jq -er .proxy_pid "$state")"
    test "$(awk '{print $22}' "/proc/$(jq -er .proxy_pid "$state")/stat")" = "$(jq -er .proxy_start_tick "$state")"
    action_started=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
    action 'Enable subscription' y 'Code: PROXY-INSTALLATION-SUBSCRIPTION-ENABLED'
    action_completed=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
    link=$(printf '%s\n' "$LAST_ACTION_OUTPUT" | sed -n '/^https:\/\/[^[:space:]]*:8443\/s\/[A-Za-z0-9_-]\{43\}$/p')
    test "$(printf '%s\n' "$link" | wc -l | tr -d ' ')" -eq 1
    link_sha=$(printf %s "$link" | sha256sum | cut -d' ' -f1)
    remember_secrets
    next=${state}.next
    jq -cS --arg started "$action_started" --arg completed "$action_completed" --arg link "$link_sha" '. + {action_completed_at:$completed,action_started_at:$started,authoritative_link_sha256:$link}' "$state" | tr -d '\n' > "$next"
    chmod 0600 "$next"
    mv -T "$next" "$state"
    printf 'ENABLE_SCHEMA1_OUTSIDE_CHECK_REQUIRED action_started=%s action_completed=%s\n' "$action_started" "$action_completed"
    ;;
  verify)
    operator_require_file SBXR_ENABLE_SCHEMA1_CONNECTION_OBSERVATION
    operator_require_file SBXR_ENABLE_SCHEMA1_SUBSCRIPTION_OBSERVATION
    test "$(stat -c '%U:%G:%a:%h:%F' "$SBXR_ENABLE_SCHEMA1_CONNECTION_OBSERVATION")" = 'root:root:600:1:regular file'
    test "$(stat -c '%U:%G:%a:%h:%F' "$SBXR_ENABLE_SCHEMA1_SUBSCRIPTION_OBSERVATION")" = 'root:root:600:1:regular file'
    action_started=$(jq -er .action_started_at "$state")
    action_completed=$(jq -er .action_completed_at "$state")
    request_sha=$(sha256sum "$SBXR_QUALIFICATION_REQUEST" | cut -d' ' -f1)
    request_deadline=$(jq -er .deadline_unix "$SBXR_QUALIFICATION_REQUEST")
    python3 "$operator_dir/check-connection-observation.py" "$SBXR_ENABLE_SCHEMA1_CONNECTION_OBSERVATION" "$SCENARIO_START" "$action_started" "$action_completed" "$request_deadline" "$request_sha" > "${SBXR_OPERATOR_EVIDENCE_DIR}/08-connection-summary.json"
    chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/08-connection-summary.json"
    jq -e --arg link "$(jq -er .authoritative_link_sha256 "$state")" --arg manifest "$(operator_manifest_digest)" \
      --arg request "$request_sha" --arg action "$action_completed" \
      --argjson deadline "$request_deadline" '
      .schema == "sbxr-v4-subscription-check-v2" and .scenario_id == "enable-schema1" and
      .qualification_manifest_sha256 == $manifest and .request_sha256 == $request and
      .trusted_outside_tls == true and .expected_status == true and .artifact_fields_and_name == true and
      .link_sha256 == $link and (.configuration_sha256|test("^[0-9a-f]{64}$")) and
      (.certificate_der_sha256|test("^[0-9a-f]{64}$")) and .completed_at >= .started_at
    ' "$SBXR_ENABLE_SCHEMA1_SUBSCRIPTION_OBSERVATION" >/dev/null
    python3 -c 'import datetime,json,sys; d=json.load(open(sys.argv[1])); p=lambda v: datetime.datetime.fromisoformat(v.replace("Z","+00:00")); assert p(d["started_at"]) >= p(sys.argv[2]); assert p(d["completed_at"]) >= p(d["started_at"]); assert p(d["completed_at"]).timestamp() <= int(sys.argv[3])' "$SBXR_ENABLE_SCHEMA1_SUBSCRIPTION_OBSERVATION" "$action_completed" "$request_deadline"
    subscription_observed_at=$(jq -er .completed_at "$SBXR_ENABLE_SCHEMA1_SUBSCRIPTION_OBSERVATION")
    subscription_receipt_sha=$(sha256sum "$SBXR_ENABLE_SCHEMA1_SUBSCRIPTION_OBSERVATION" | cut -d' ' -f1)
    scan_retained_capture "$SBXR_ENABLE_SCHEMA1_CONNECTION_OBSERVATION" "$SBXR_ENABLE_SCHEMA1_SUBSCRIPTION_OBSERVATION" "${SBXR_OPERATOR_EVIDENCE_DIR}/08-connection-summary.json"
    remember_secrets
    verify_subscription_token_identity /var/lib/sbxr/subscription-token "$(jq -er .serving.credential_sha256 /var/lib/sbxr/proxy-ownership.json)"
    jq -e --argjson release "$(jq -c .release_identity "$state")" '
      .schema == 2 and .phase == "Running" and .unfinished_direction == "none" and
      (.subscription_enablement|not) and (.subscription_rotation|not) and
      (.subscription_repair|not) and (.client_identity_rotation|not) and
      (.serving.link_id|test("^[0-9a-f]{32}$")) and
      (.serving.credential_sha256|test("^[0-9a-f]{64}$")) and
      (.serving.certificate_generation|type == "number" and . >= 1) and
      (.serving.certificate_sha256|length == 4) and
      (.serving.certificate_sha256|all(test("^[0-9a-f]{64}$"))) and
      (.renewal.recorder_id|test("^[0-9a-f]{32}$")) and
      .renewal.lineage == "sbxr-subscription" and
      .renewal.invocation == "snap-certbot-renew-v1" and
      .renewal.public_ipv4 == .public_ipv4 and
      .subscription_resources.public_ipv4 == .public_ipv4 and
      (.subscription_resources.firewall_sha256|test("^[0-9a-f]{64}$")) and
      (.resource_creating_releases|length == (.permitted_resources|length)) and
      (.resource_creating_releases|all(. == $release))
    ' /var/lib/sbxr/proxy-ownership.json >/dev/null
    test "$(sha256sum /etc/sing-box/config.json | cut -d' ' -f1)" = "$(jq -er .config_sha256 "$state")"
    test "$(printf %s "$KNOWN_CLIENT_UUID" | sha256sum | cut -d' ' -f1)" = "$(jq -er .uuid_sha256 "$state")"
    test "$(printf %s "$KNOWN_PRIVATE_KEY" | sha256sum | cut -d' ' -f1)" = "$(jq -er .key_sha256 "$state")"
    test "$(systemctl show sing-box.service -p MainPID --value)" = "$(jq -er .proxy_pid "$state")"
    test "$(awk '{print $22}' "/proc/$(jq -er .proxy_pid "$state")/stat")" = "$(jq -er .proxy_start_tick "$state")"
    prove_running
    operator_exact_candidate
    scan_journal
    scan_transport_captures
    completed_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
    safe_state="${SBXR_OPERATOR_STATE_DIR}/08-safe-state.json"
    test ! -e "$safe_state"
    test ! -L "$safe_state"
    link_id=$(jq -er '.serving.link_id | select(test("^[0-9a-f]{32}$"))' /var/lib/sbxr/proxy-ownership.json)
    ownership_schema=$(jq -er '.schema | select(. == 2)' /var/lib/sbxr/proxy-ownership.json)
    ownership_phase=$(jq -er '.phase | select(. == "Running")' /var/lib/sbxr/proxy-ownership.json)
    jq -cnS \
      --arg scenario enable-schema1 --arg started "$SCENARIO_START" \
      --arg action_started "$action_started" --arg action_completed "$action_completed" \
      --arg completed "$completed_at" --arg manifest "$(operator_manifest_digest)" \
      --arg request "$(sha256sum "$SBXR_QUALIFICATION_REQUEST" | cut -d' ' -f1)" \
      --arg private "$(sha256sum "$state" | cut -d' ' -f1)" \
      --arg ownership "$(sha256sum /var/lib/sbxr/proxy-ownership.json | cut -d' ' -f1)" \
      --argjson ownership_schema "$ownership_schema" --arg ownership_phase "$ownership_phase" \
      --arg link_id "$link_id" --arg link_sha "$(jq -er .authoritative_link_sha256 "$state")" \
      --arg subscription_observed "$subscription_observed_at" --arg subscription_receipt "$subscription_receipt_sha" \
      '{action_completed_at:$action_completed,action_started_at:$action_started,authoritative_link_sha256:$link_sha,completed_at:$completed,final_state:$ownership_phase,initial_state:"Running",link_id:$link_id,ownership_record_sha256:$ownership,ownership_schema:$ownership_schema,private_state_sha256:$private,qualification_manifest_sha256:$manifest,request_sha256:$request,scenario_id:$scenario,schema:"sbxr-v4-enable-schema1-safe-state-v1",started_at:$started,subscription_observed_at:$subscription_observed,subscription_receipt_sha256:$subscription_receipt}' \
      | tr -d '\n' > "${safe_state}.next"
    chmod 0600 "${safe_state}.next"
    mv -T "${safe_state}.next" "$safe_state"
    printf 'ENABLE_SCHEMA1_OK started=%s action_started=%s action_completed=%s completed=%s\n' "$SCENARIO_START" "$action_started" "$action_completed" "$completed_at"
    ;;
  *) printf 'usage: %s enable|verify\n' "$0" >&2; exit 2 ;;
esac
