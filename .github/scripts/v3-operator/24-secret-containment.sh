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
jq -e --arg secret "$SBXR_SECRET_CONTAINMENT_KNOWN_SECRETS" '.schema == "sbxr-v3-secret-containment-spec-v1" and (.cleanup_paths | index($secret)) != null' "$SBXR_SECRET_CONTAINMENT_SPEC" >/dev/null
preflight after-snap-refresh
operator_exact_candidate
prove_running
remember_secrets

python3 "$operator_dir/secret-containment.py" protection --spec "$SBXR_SECRET_CONTAINMENT_SPEC" > "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protection.json"
python3 "$operator_dir/sandbox-token-probe.py" \
  --unit sbxr-subscription.service \
  --fragment /etc/systemd/system/sbxr-subscription.service \
  --executable /usr/local/bin/sbxr --argument=--subscription-serving \
  --token /var/lib/sbxr/subscription-token \
  --staging /var/lib/sbxr/subscription-staging \
  > "${SBXR_OPERATOR_EVIDENCE_DIR}/24-sandbox.json"
python3 "$operator_dir/secret-containment.py" scan \
  --known-secrets "$SBXR_SECRET_CONTAINMENT_KNOWN_SECRETS" \
  --spec "$SBXR_SECRET_CONTAINMENT_SPEC" \
  > "${SBXR_OPERATOR_EVIDENCE_DIR}/24-scan.json"
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protection.json" "${SBXR_OPERATOR_EVIDENCE_DIR}/24-sandbox.json" "${SBXR_OPERATOR_EVIDENCE_DIR}/24-scan.json"
jq -e '.schema == "sbxr-v3-secret-scan-result-v1" and .variants_absent == true and .prohibited_patterns_absent == true and ([.capture_files[]] | all(. > 0)) and .process_fields > 0 and .units > 0' "${SBXR_OPERATOR_EVIDENCE_DIR}/24-scan.json" >/dev/null
jq -e '.schema == "sbxr-v3-sandbox-token-probe-v1" and .capabilities_zero == true and .no_new_privileges == true and .protected_reads_refused == 2' "${SBXR_OPERATOR_EVIDENCE_DIR}/24-sandbox.json" >/dev/null
scan_retained_capture "${SBXR_OPERATOR_EVIDENCE_DIR}/24-protection.json" "${SBXR_OPERATOR_EVIDENCE_DIR}/24-sandbox.json" "${SBXR_OPERATOR_EVIDENCE_DIR}/24-scan.json"

# This is the sole deletion performed here. The path is fixed inside the
# operator state directory and was required to be a protected one-link file.
rm -- "$SBXR_SECRET_CONTAINMENT_KNOWN_SECRETS"
python3 "$operator_dir/secret-containment.py" cleanup --spec "$SBXR_SECRET_CONTAINMENT_SPEC" > "${SBXR_OPERATOR_EVIDENCE_DIR}/24-cleanup.json"
chmod 0600 "${SBXR_OPERATOR_EVIDENCE_DIR}/24-cleanup.json"
scan_retained_capture "${SBXR_OPERATOR_EVIDENCE_DIR}/24-cleanup.json"
operator_exact_candidate
prove_running
scan_journal
scan_transport_captures
completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf 'SECRET_CONTAINMENT_OK started=%s completed=%s\n' "$STARTED_AT" "$completed_at"
