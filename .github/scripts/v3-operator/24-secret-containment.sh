#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
operator_expect_scenario secret-containment
test "$SCENARIO_START" = "$STARTED_AT"
operator_require_file SBXR_SECRET_CONTAINMENT_KNOWN_SECRETS
operator_require_file SBXR_SECRET_CONTAINMENT_SPEC
test "$SBXR_SECRET_CONTAINMENT_KNOWN_SECRETS" = "${SBXR_OPERATOR_STATE_DIR}/24-known-secrets.json"
test "$(stat -c '%U:%G:%a:%h:%F' "$SBXR_SECRET_CONTAINMENT_KNOWN_SECRETS")" = 'root:root:600:1:regular file'
test "$(stat -c '%U:%G:%a:%h:%F' "$SBXR_SECRET_CONTAINMENT_SPEC")" = 'root:root:600:1:regular file'

# Preserve the ordinary rehearsal stop before consuming the live-only attempt
# inventory. The live scanner validates its V2 schema and all root bindings.
preflight after-snap-refresh
operator_exact_candidate
prove_running
remember_secrets
entry_started_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
manifest_sha=$(sha256sum "$SBXR_QUALIFICATION_MANIFEST" | awk '{print $1}')
request_sha=$(sha256sum "$SBXR_QUALIFICATION_REQUEST" | awk '{print $1}')
action_started_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)

cleanup_inventory=false
cleanup() {
  local status=$?
  trap - EXIT
  if test "$cleanup_inventory" = true; then
    if python3 "$operator_dir/secret-containment.py" remove-inventory \
      --spec "$SBXR_SECRET_CONTAINMENT_SPEC" \
      > "${SBXR_OPERATOR_EVIDENCE_DIR}/24-removal.json"; then
      cleanup_inventory=false
      chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/24-removal.json"
    else
      status=1
    fi
  fi
  return "$status"
}
trap cleanup EXIT

python3 "$operator_dir/secret-containment.py" protection \
  --spec "$SBXR_SECRET_CONTAINMENT_SPEC" \
  > "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protection.json"
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protection.json"
cleanup_inventory=true

python3 "$operator_dir/sandbox-token-probe.py" \
  --unit sbxr-subscription.service \
  --fragment /etc/systemd/system/sbxr-subscription.service \
  --executable /usr/local/bin/sbxr --argument=--subscription-serving \
  --token /var/lib/sbxr/subscription-token \
  --staging /var/lib/sbxr/subscription-staging \
  > "${SBXR_OPERATOR_EVIDENCE_DIR}/24-sandbox.json"
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/24-sandbox.json"
jq -e '.schema == "sbxr-v3-sandbox-token-probe-v1" and
  .capabilities_zero == true and .no_new_privileges == true and
  .protected_reads_refused == 2' \
  "${SBXR_OPERATOR_EVIDENCE_DIR}/24-sandbox.json" >/dev/null

python3 "$operator_dir/protected-open-probe.py" \
  --spec "$SBXR_SECRET_CONTAINMENT_SPEC" --runtime-parent /run \
  > "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protected-open.json"
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protected-open.json"
jq -e '.schema == "sbxr-v4-protected-open-probe-v1" and
  .capabilities_zero == true and .no_new_privileges == true and
  .no_supplementary_groups == true and .private_runtime_empty == true and
  .metadata_unchanged == true and .account_removed == true and
  .runtime_removed == true and .protected_reads_refused == (.objects | length)' \
  "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protected-open.json" >/dev/null

python3 "$operator_dir/secret-containment.py" scan \
  --known-secrets "$SBXR_SECRET_CONTAINMENT_KNOWN_SECRETS" \
  --spec "$SBXR_SECRET_CONTAINMENT_SPEC" \
  > "${SBXR_OPERATOR_EVIDENCE_DIR}/24-scan.json"
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/24-scan.json"
jq -e '.schema == "sbxr-v4-secret-scan-result-v2" and
  .variants_absent == true and .prohibited_patterns_absent == true and
  .external_surface_attested == true and .external_client_cleanup_attested == true and
  ([.capture_files[]] | all(. > 0)) and .retained_inventory_files > 0 and
  .process_fields > 0 and .units == 4' \
  "${SBXR_OPERATOR_EVIDENCE_DIR}/24-scan.json" >/dev/null
scan_retained_capture "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protection.json" \
  "${SBXR_OPERATOR_EVIDENCE_DIR}/24-sandbox.json" \
  "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protected-open.json" \
  "${SBXR_OPERATOR_EVIDENCE_DIR}/24-scan.json"

python3 "$operator_dir/secret-containment.py" remove-inventory \
  --spec "$SBXR_SECRET_CONTAINMENT_SPEC" \
  > "${SBXR_OPERATOR_EVIDENCE_DIR}/24-removal.json"
cleanup_inventory=false
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/24-removal.json"
python3 "$operator_dir/secret-containment.py" cleanup \
  --spec "$SBXR_SECRET_CONTAINMENT_SPEC" \
  > "${SBXR_OPERATOR_EVIDENCE_DIR}/24-cleanup.json"
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/24-cleanup.json"
jq -e '.schema == "sbxr-v4-cleanup-result-v2" and
  .cleanup_paths_absent > 0 and
  (.cleanup_processes_absent | type == "number" and . >= 0 and . == floor)' \
  "${SBXR_OPERATOR_EVIDENCE_DIR}/24-cleanup.json" >/dev/null
scan_retained_capture "${SBXR_OPERATOR_EVIDENCE_DIR}/24-removal.json" \
  "${SBXR_OPERATOR_EVIDENCE_DIR}/24-cleanup.json"
action_completed_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)

operator_exact_candidate
prove_running
scan_journal
scan_transport_captures
completed_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
jq -cnS --arg started "$STARTED_AT" --arg entry "$entry_started_at" \
  --arg action_started "$action_started_at" --arg action_completed "$action_completed_at" \
  --arg completed "$completed_at" --arg manifest "$manifest_sha" --arg request "$request_sha" \
  '{action_completed_at:$action_completed,action_started_at:$action_started,completed_at:$completed,entry_started_at:$entry,qualification_manifest_sha256:$manifest,request_sha256:$request,scenario_id:"secret-containment",schema:"sbxr-v4-scenario-entry-v1",started_at:$started}' \
  | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/24-state.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/24-state.json"
jq -cnS --arg started "$action_started_at" --arg completed "$action_completed_at" \
  --arg protection "$(sha256sum "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protection.json" | awk '{print $1}')" \
  --arg sandbox "$(sha256sum "${SBXR_OPERATOR_EVIDENCE_DIR}/24-sandbox.json" | awk '{print $1}')" \
  --arg protected_open "$(sha256sum "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protected-open.json" | awk '{print $1}')" \
  --arg scan "$(sha256sum "${SBXR_OPERATOR_EVIDENCE_DIR}/24-scan.json" | awk '{print $1}')" \
  --arg removal "$(sha256sum "${SBXR_OPERATOR_EVIDENCE_DIR}/24-removal.json" | awk '{print $1}')" \
  --arg cleanup "$(sha256sum "${SBXR_OPERATOR_EVIDENCE_DIR}/24-cleanup.json" | awk '{print $1}')" \
  '{action_completed_at:$completed,action_started_at:$started,cleanup_sha256:$cleanup,protected_open_sha256:$protected_open,protection_sha256:$protection,removal_sha256:$removal,sandbox_sha256:$sandbox,scan_sha256:$scan,schema:"sbxr-v4-secret-containment-result-v1"}'
