#!/usr/bin/env bash
# Evidence handoff only. The operator uses unchanged packaged production paths.
set -euo pipefail
umask 077
outside_request_matches() {
  cmp -s "$1" <(printf '{"deadline_unix":%s,"qualification_manifest_sha256":"%s","request_id":"%s","scenario_id":"%s","schema":"sbxr-v3-outside-probe-request-v1"}' "$2" "$3" "$4" "$5")
}

# Publish original scenario facts through one owned interface. Reading the
# request deliberately uses ssh -n; publishing deliberately does not, because
# the facts are carried on stdin. The receiver proves the same active request
# and exact payload bytes before making result.json visible.
submit_result() {
  test "$#" -eq 5
  local submit_host=$1
  local submit_key=$2
  local submit_known_hosts=$3
  local submit_manifest=$4
  local submit_facts=$5
  local -a submit_remote=(ssh -T -i "$submit_key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$submit_known_hosts" -o ConnectTimeout=15)
  local submit_manifest_digest submit_request submit_request_digest submit_request_json submit_scenario submit_size submit_digest
  submit_manifest_digest="$(sha256sum "$submit_manifest" | cut -d' ' -f1)"
  submit_request="$("${submit_remote[@]}" -n "root@$submit_host" 'set -eu; request=/root/sbxr-qualification-evidence/request.json; test -f "$request"; test ! -L "$request"; test -O "$request"; test "$(find "$request" -prune -perm 0600 -links 1 -print)" = "$request"; sha256sum "$request" | cut -d" " -f1; cat "$request"')"
  submit_request_digest=${submit_request%%$'\n'*}
  submit_request_json=${submit_request#*$'\n'}
  test "$submit_request_digest" != "$submit_request_json"
  [[ "$submit_request_digest" =~ ^[0-9a-f]{64}$ ]]
  jq -e --arg digest "$submit_manifest_digest" '.qualification_manifest_sha256 == $digest and (.scenario_id | type == "string") and (.deadline_unix | type == "number")' <<<"$submit_request_json" >/dev/null
  submit_scenario="$(jq -r .scenario_id <<<"$submit_request_json")"
  jq -e --slurpfile m "$submit_manifest" --arg scenario "$submit_scenario" '
    .schema == "sbxr-release-qualification-facts-v1" and
    .qualification_manifest == $m[0] and
    ((.stage == "v3-scenario-failure" and .failure.scenario_id == $scenario) or
     (.stage == "v3-scenario-result" and .detailed_evidence.scenarios[-1].scenario_id == $scenario))
  ' "$submit_facts" >/dev/null
  submit_size="$(wc -c < "$submit_facts" | tr -d ' ')"
  test "$submit_size" -gt 0
  test "$submit_size" -le 16777216
  submit_digest="$(sha256sum "$submit_facts" | cut -d' ' -f1)"
  "${submit_remote[@]}" "root@$submit_host" "set -eu; directory=/root/sbxr-qualification-evidence; request=\"\$directory/request.json\"; temporary=\"\$directory/result.tmp\"; result=\"\$directory/result.json\"; test \"\$(sha256sum \"\$request\" | cut -d' ' -f1)\" = '$submit_request_digest'; test ! -e \"\$temporary\"; test ! -L \"\$temporary\"; test ! -e \"\$result\"; test ! -L \"\$result\"; umask 077; cat > \"\$temporary\"; test -f \"\$temporary\"; test ! -L \"\$temporary\"; test -O \"\$temporary\"; test \"\$(find \"\$temporary\" -prune -perm 0600 -links 1 -print)\" = \"\$temporary\"; test \"\$(wc -c < \"\$temporary\")\" -eq '$submit_size'; test \"\$(sha256sum \"\$temporary\" | cut -d' ' -f1)\" = '$submit_digest'; test \"\$(sha256sum \"\$request\" | cut -d' ' -f1)\" = '$submit_request_digest'; mv -T \"\$temporary\" \"\$result\"" < "$submit_facts"
}
if test "${1:-}" = submit; then
  test "$#" -eq 6
  submit_result "$2" "$3" "$4" "$5" "$6"
  exit 0
fi
test "$#" -eq 3
remote=(ssh -i "$2" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$3" -o ConnectTimeout=15 "root@$1")
manifest=handoff/qualification-manifest.json
boundary=handoff/qualification-boundary-facts.json
tool=handoff/sbxr-release
jq -e '(.schema == "sbxr-qualification-manifest-v2" or .schema == "sbxr-qualification-manifest-v3") and (.source_state == "v3-recurring" or .source_state == "v3-subscription-clean")' "$manifest" >/dev/null
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
    "${remote[@]}" 'test ! -d /root/sbxr-qualification-evidence || printf "%s\n" STOP > /root/sbxr-qualification-evidence/request.json' || true
    mkdir -p handoff/failure-evidence
    if test "$reason" = failure-recorded; then
      cp "$directory/retained-failure.json" "$directory/failure.json"
    else
      jq -cnS --slurpfile m "$manifest" --slurpfile b "$boundary" --arg scenario "$scenario" --arg operation "$operation" --arg reason "$reason" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{failure:{actual_result:$reason,attempt_id:$m[0].v3_attempt.attempt_id,boundary:"unknown",candidate:$m[0].releases[0],expected_result:"expected-safety-and-final-state-proved",host_state:"Unknown",observed_at:$now,operation_id:$operation,scenario_id:$scenario,schema:(if $m[0].schema == "sbxr-qualification-manifest-v3" then "sbxr-v3-scenario-failure-v3" else "sbxr-v3-scenario-failure-v2" end),vps_id:$m[0].v3_attempt.vps_id},qualification_boundary_facts:$b[0],qualification_manifest:$m[0],qualification_manifest_attested:true,safety_cleanup:{host_state:"Unknown",status:"not-started"},schema:"sbxr-release-qualification-facts-v1",stage:"v3-scenario-failure"}' | tr -d '\n' > "$directory/failure.json"
    fi
    if "$tool" qualification < "$directory/failure.json" > "$directory/failure-decision.json" && jq -e '.outcome == "failed" and .stop_test_mutations and .burn_required' "$directory/failure-decision.json" >/dev/null; then
      cp "$directory/failure.json" "$directory/failure-decision.json" handoff/failure-evidence/
    fi
  fi
  # Only temporary files created by this collector; never product authority.
  rm -f "$directory/input.json" "$directory/decision.json" "$directory/failure.json" "$directory/failure-decision.json" "$directory/previous.json" "$directory/request.json" "$directory/outside-request.json" "$directory/outside-reply.json" "$directory/final.json" "$directory/retained-failure.json"
  rmdir "$directory"
  exit "$status"
}
trap stop_attempt EXIT

# Bind a non-secret, host-specific identity without publishing a machine ID.
actual_vps="$("${remote[@]}" 'test "$(. /etc/os-release; printf "%s:%s" "$ID" "$VERSION_ID")" = ubuntu:24.04 && test "$(uname -m)" = x86_64 && sha256sum /etc/machine-id' | cut -d' ' -f1)"
test "$actual_vps" = "$(jq -r .v3_attempt.vps_identity_sha256 "$manifest")"
"${remote[@]}" 'test ! -e /root/sbxr-qualification-evidence && install -d -m 0700 /root/sbxr-qualification-evidence'
printf '[]' > "$directory/previous.json"
index=0
# Keep ssh's stdin separate, and retain the last scenario when read reaches EOF.
while IFS= read -r next_scenario <&3; do
  scenario=$next_scenario
  index=$((index + 1))
  operation="operation-$index"
  limit=1800
  if test "$scenario" = karing-final; then limit=7200; fi
  started="$(date +%s)"
  deadline=$((started + limit))
  outside_probe_required=false outside_probe_done=false
  if test "$scenario" = baseline-clean || test "$scenario" = baseline-postcommit; then outside_probe_required=true; fi
  jq -cnS --arg scenario "$scenario" --arg digest "$digest" --argjson limit "$limit" --argjson deadline "$deadline" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{deadline_unix:$deadline,not_before:$now,qualification_manifest_sha256:$digest,scenario_id:$scenario,scenario_limit_seconds:$limit}' > "$directory/request.json"
  "${remote[@]}" 'umask 077; test ! -e /root/sbxr-qualification-evidence/result.json; cat > /root/sbxr-qualification-evidence/request.json' < "$directory/request.json"
  while ! "${remote[@]}" 'test -f /root/sbxr-qualification-evidence/result.json'; do
    if "${remote[@]}" 'test -e /root/sbxr-qualification-evidence/outside-request.json || test -L /root/sbxr-qualification-evidence/outside-request.json'; then
      reason=evidence-refused
      test "$outside_probe_required" = true
      "${remote[@]}" 'test "$(stat -c "%a:%u:%h:%F" /root/sbxr-qualification-evidence/outside-request.json)" = "600:0:1:regular file" && test "$(stat -c %s /root/sbxr-qualification-evidence/outside-request.json)" -le 512 && cat /root/sbxr-qualification-evidence/outside-request.json' > "$directory/outside-request.json"
      # Fixed raw bytes reject duplicates, unknown keys, and normalization.
      request_id=probe-1
      if test "$scenario" = baseline-postcommit; then request_id=probe-2; fi
      outside_request_matches "$directory/outside-request.json" "$deadline" "$digest" "$request_id" "$scenario"
      test "$outside_probe_done" = false
      remaining=$((deadline - $(date +%s)))
      test "$remaining" -gt 0
      timeout --kill-after=5 "$remaining" bash .github/scripts/v3-packaged-live.sh outside-probe "$1" "$2" "$3" "$manifest" "$scenario" "$deadline" > "$directory/outside-reply.json"
      jq -e --arg scenario "$scenario" '.schema == "sbxr-v3-outside-probe-reply-v1" and .scenario_id == $scenario and .observation == {egress_matched:true,outside_routes_differ:true,runner_cleanup_complete:true}' "$directory/outside-reply.json" >/dev/null
      "${remote[@]}" "umask 077; test ! -e /root/sbxr-qualification-evidence/outside-reply-$scenario.json && test ! -L /root/sbxr-qualification-evidence/outside-reply-$scenario.json && test ! -e /root/sbxr-qualification-evidence/outside-reply-$scenario.tmp && test ! -L /root/sbxr-qualification-evidence/outside-reply-$scenario.tmp && cat > /root/sbxr-qualification-evidence/outside-reply-$scenario.tmp && mv -T /root/sbxr-qualification-evidence/outside-reply-$scenario.tmp /root/sbxr-qualification-evidence/outside-reply-$scenario.json && rm /root/sbxr-qualification-evidence/outside-request.json" < "$directory/outside-reply.json"
      outside_probe_done=true
    fi
    if test "$(( $(date +%s) - started ))" -gt "$((limit + 300))"; then reason=timeout; exit 1; fi
    sleep 2
  done
  reason=evidence-refused
  "${remote[@]}" 'test "$(stat -c "%a:%u:%h:%F" /root/sbxr-qualification-evidence/result.json)" = "600:0:1:regular file" && test "$(stat -c %s /root/sbxr-qualification-evidence/result.json)" -le 16777216 && cat /root/sbxr-qualification-evidence/result.json' > "$directory/input.json"
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
  if test "$outside_probe_required" = true && test "$outside_probe_done" != true; then exit 1; fi
  "${remote[@]}" 'test ! -e /root/sbxr-qualification-evidence/outside-request.json && test ! -L /root/sbxr-qualification-evidence/outside-request.json'
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
  "${remote[@]}" 'rm /root/sbxr-qualification-evidence/result.json'
  reason=unexpected-failure
done 3< <(jq -r '.v3_attempt.required_scenarios[]' "$manifest")

"${remote[@]}" 'test ! -e /usr/local/bin/sbxr && test ! -e /var/lib/sbxr && rm /root/sbxr-qualification-evidence/request.json /root/sbxr-qualification-evidence/outside-reply-baseline-clean.json /root/sbxr-qualification-evidence/outside-reply-baseline-postcommit.json && rmdir /root/sbxr-qualification-evidence'
# This is a new evaluation time, not a rewrite of a scenario timestamp.
jq -cS --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.stage = "v3-packaged-live-result" | .evaluation_time = $now' "$directory/input.json" | tr -d '\n' > "$directory/final.json"
"$tool" qualification < "$directory/final.json" > "$directory/decision.json"
jq -e '.outcome == "accepted" and (.records | length) == 1' "$directory/decision.json" >/dev/null
cp "$directory/final.json" handoff/v3-packaged-live-result-facts.json
cp "$directory/decision.json" handoff/v3-packaged-live-result-decision.json
jq -cS '.detailed_evidence' "$directory/input.json" | tr -d '\n' > handoff/v3-packaged-live-evidence.json
