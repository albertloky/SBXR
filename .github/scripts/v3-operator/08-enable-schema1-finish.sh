#!/usr/bin/env bash
set -euo pipefail
umask 077
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
    action_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    action 'Enable subscription' y 'Code: PROXY-INSTALLATION-SUBSCRIPTION-ENABLED'
    action_completed=$(date -u +%Y-%m-%dT%H:%M:%SZ)
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
    jq -e --arg link "$(jq -er .authoritative_link_sha256 "$state")" '
      keys == ["artifact_fields_and_name","expected_status","link_sha256","schema","trusted_outside_tls"] and
      .schema == "sbxr-v3-subscription-check-v1" and .trusted_outside_tls == true and
      .expected_status == true and .artifact_fields_and_name == true and .link_sha256 == $link
    ' "$SBXR_ENABLE_SCHEMA1_SUBSCRIPTION_OBSERVATION" >/dev/null
    scan_retained_capture "$SBXR_ENABLE_SCHEMA1_CONNECTION_OBSERVATION" "$SBXR_ENABLE_SCHEMA1_SUBSCRIPTION_OBSERVATION" "${SBXR_OPERATOR_EVIDENCE_DIR}/08-connection-summary.json"
    remember_secrets
    token_sha=$(sha256sum /var/lib/sbxr/subscription-token | cut -d' ' -f1)
    test "$token_sha" = "$(jq -er .serving.credential_sha256 /var/lib/sbxr/proxy-ownership.json)"
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
    completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf 'ENABLE_SCHEMA1_OK started=%s action_started=%s action_completed=%s completed=%s\n' "$SCENARIO_START" "$action_started" "$action_completed" "$completed_at"
    ;;
  *) printf 'usage: %s enable|verify\n' "$0" >&2; exit 2 ;;
esac
