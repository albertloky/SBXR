#!/usr/bin/env bash
# Evidence handoff only. The operator uses unchanged packaged production paths.
set -euo pipefail
umask 077
test "$#" -eq 3
remote=(ssh -i "$2" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$3" -o ConnectTimeout=15 "root@$1")
manifest=handoff/qualification-manifest.json
boundary=handoff/qualification-boundary-facts.json
tool=handoff/sbxr-release
test "$(jq -r .schema "$manifest")" = sbxr-qualification-manifest-v2
test "$(jq -r .source_state "$manifest")" = v3-recurring
digest="$(sha256sum "$manifest" | cut -d' ' -f1)"
directory="$(mktemp -d)"
mkdir -m 0700 handoff/v3-scenarios
scenario=baseline-clean
operation=operation-1
reason=unexpected-failure

stop_attempt() {
  status=$?
  trap - EXIT
  if test "$status" -ne 0; then
    # Do not fetch raw output or run cleanup against an uncertain installation.
    "${remote[@]}" 'test ! -d /run/sbxr-qualification/v3-evidence || printf "%s\n" STOP > /run/sbxr-qualification/v3-evidence/request.json' || true
    mkdir -p handoff/failure-evidence
    if test "$reason" = failure-recorded; then
      cp "$directory/retained-failure.json" "$directory/failure.json"
    else
      jq -cnS --slurpfile m "$manifest" --slurpfile b "$boundary" --arg scenario "$scenario" --arg operation "$operation" --arg reason "$reason" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{failure:{actual_result:$reason,attempt_id:$m[0].v3_attempt.attempt_id,boundary:"unknown",candidate:$m[0].releases[0],expected_result:"expected-safety-and-final-state-proved",host_state:"Unknown",observed_at:$now,operation_id:$operation,scenario_id:$scenario,schema:"sbxr-v3-scenario-failure-v2",vps_id:$m[0].v3_attempt.vps_id},qualification_boundary_facts:$b[0],qualification_manifest:$m[0],qualification_manifest_attested:true,safety_cleanup:{host_state:"Unknown",status:"not-started"},schema:"sbxr-release-qualification-facts-v1",stage:"v3-scenario-failure"}' | tr -d '\n' > "$directory/failure.json"
    fi
    if "$tool" qualification < "$directory/failure.json" > "$directory/failure-decision.json" && jq -e '.outcome == "failed" and .stop_test_mutations and .burn_required' "$directory/failure-decision.json" >/dev/null; then
      cp "$directory/failure.json" "$directory/failure-decision.json" handoff/failure-evidence/
    fi
  fi
  # Only temporary files created by this collector; never product authority.
  rm -f "$directory/input.json" "$directory/decision.json" "$directory/failure.json" "$directory/failure-decision.json" "$directory/previous.json" "$directory/request.json" "$directory/final.json" "$directory/retained-failure.json"
  rmdir "$directory"
  exit "$status"
}
trap stop_attempt EXIT

"${remote[@]}" 'test ! -e /run/sbxr-qualification && install -d -m 0700 /run/sbxr-qualification/v3-evidence'
# Bind a non-secret, host-specific identity without publishing a machine ID.
actual_vps="$("${remote[@]}" 'test "$(. /etc/os-release; printf "%s:%s" "$ID" "$VERSION_ID")" = ubuntu:24.04 && test "$(uname -m)" = x86_64 && sha256sum /etc/machine-id' | cut -d' ' -f1)"
test "$actual_vps" = "$(jq -r .v3_attempt.vps_identity_sha256 "$manifest")"
printf '[]' > "$directory/previous.json"
index=0
while read -r scenario; do
  index=$((index + 1))
  operation="operation-$index"
  limit=1800
  if test "$scenario" = karing-final; then limit=7200; fi
  started="$(date +%s)"
  jq -cnS --arg scenario "$scenario" --arg digest "$digest" --argjson limit "$limit" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{not_before:$now,qualification_manifest_sha256:$digest,scenario_id:$scenario,scenario_limit_seconds:$limit}' > "$directory/request.json"
  "${remote[@]}" 'umask 077; test ! -e /run/sbxr-qualification/v3-evidence/result.json; cat > /run/sbxr-qualification/v3-evidence/request.json' < "$directory/request.json"
  while ! "${remote[@]}" 'test -f /run/sbxr-qualification/v3-evidence/result.json'; do
    if test "$(( $(date +%s) - started ))" -gt "$((limit + 300))"; then reason=timeout; exit 1; fi
    sleep 2
  done
  reason=evidence-refused
  "${remote[@]}" 'test "$(stat -c "%a:%u:%h:%F" /run/sbxr-qualification/v3-evidence/result.json)" = "600:0:1:regular file" && test "$(stat -c %s /run/sbxr-qualification/v3-evidence/result.json)" -le 16777216 && cat /run/sbxr-qualification/v3-evidence/result.json' > "$directory/input.json"
  # Validate the original bytes BEFORE jq: duplicate and unknown keys must not
  # disappear during normalization. Invalid input is never retained or echoed.
  "$tool" qualification < "$directory/input.json" > "$directory/decision.json"
  if jq -e '.stage == "v3-scenario-failure"' "$directory/input.json" >/dev/null; then
    jq -e --slurpfile m "$manifest" --arg scenario "$scenario" '.qualification_manifest == $m[0] and .failure.scenario_id == $scenario' "$directory/input.json" >/dev/null
    jq -e '.outcome == "failed" and .stop_test_mutations and .burn_required' "$directory/decision.json" >/dev/null
    cp "$directory/input.json" "$directory/retained-failure.json"
    reason=failure-recorded
    exit 1
  fi
  jq -e --arg digest "$digest" --arg scenario "$scenario" --argjson count "$index" --slurpfile previous "$directory/previous.json" '.stage == "v3-scenario-result" and .prior_decision_sha256 == $digest and (.detailed_evidence.scenarios | length) == $count and .detailed_evidence.scenarios[-1].scenario_id == $scenario and .detailed_evidence.scenarios[:-1] == $previous[0]' "$directory/input.json" >/dev/null
  jq -e '.outcome == "accepted" and .records == []' "$directory/decision.json" >/dev/null
  completed="$(date -u -d "$(jq -r '.detailed_evidence.scenarios[-1].completed_at' "$directory/input.json")" +%s)"
  recorded_start="$(date -u -d "$(jq -r '.detailed_evidence.scenarios[-1].started_at' "$directory/input.json")" +%s)"
  now="$(date +%s)"
  test "$recorded_start" -ge "$started"
  test "$completed" -le "$now"
  test "$((now - completed))" -le 300
  # Preserve all scenario times and the full prior prefix byte-for-byte in the
  # retained validated facts; no resubmission can replace an earlier pass.
  cp "$directory/input.json" "handoff/v3-scenarios/$index-facts.json"
  cp "$directory/decision.json" "handoff/v3-scenarios/$index-decision.json"
  jq -cS '.detailed_evidence.scenarios' "$directory/input.json" > "$directory/previous.json"
  "${remote[@]}" 'rm /run/sbxr-qualification/v3-evidence/result.json'
  reason=unexpected-failure
done < <(jq -r '.v3_attempt.required_scenarios[]' "$manifest")

"${remote[@]}" 'test ! -e /usr/local/bin/sbxr && test ! -e /var/lib/sbxr && rm /run/sbxr-qualification/v3-evidence/request.json && rmdir /run/sbxr-qualification/v3-evidence /run/sbxr-qualification'
# This is a new evaluation time, not a rewrite of a scenario timestamp.
jq -cS --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.stage = "v3-packaged-live-result" | .evaluation_time = $now' "$directory/input.json" | tr -d '\n' > "$directory/final.json"
"$tool" qualification < "$directory/final.json" > "$directory/decision.json"
jq -e '.outcome == "accepted" and (.records | length) == 1' "$directory/decision.json" >/dev/null
cp "$directory/final.json" handoff/v3-packaged-live-result-facts.json
cp "$directory/decision.json" handoff/v3-packaged-live-result-decision.json
jq -cS '.detailed_evidence' "$directory/input.json" | tr -d '\n' > handoff/v3-packaged-live-evidence.json
