#!/usr/bin/env bash
# Evidence handoff only. The operator uses unchanged packaged production paths.
set -euo pipefail
umask 077
outside_request_matches() {
  cmp -s "$1" <(printf '{"deadline_unix":%s,"qualification_manifest_sha256":"%s","request_id":"%s","scenario_id":"%s","schema":"sbxr-v3-outside-probe-request-v1"}' "$2" "$3" "$4" "$5")
}

identity_request_matches() {
  test "$#" -eq 4
  local request=$1 deadline=$2 manifest_digest=$3 scenario=$4
  identity_operator_directory=$(jq -er '.operator_directory | select(type == "string")' "$request")
  identity_state_directory=$(jq -er '.state_directory | select(type == "string")' "$request")
  test "$identity_operator_directory" = /run/sbxr-qualification
  test "$identity_state_directory" = /run/sbxr-qualification
  cmp -s "$request" <(printf '{"deadline_unix":%s,"operator_directory":"%s","qualification_manifest_sha256":"%s","request_id":"identity-1","scenario_id":"%s","schema":"sbxr-v4-identity-outside-request-v1","state_directory":"%s"}' \
    "$deadline" "$identity_operator_directory" "$manifest_digest" "$scenario" "$identity_state_directory")
}

identity_sources_match_commit() {
  test "$#" -eq 1
  local bound_commit=$1 path tracked=0
  test "${GITHUB_SHA:-}" = "$bound_commit"
  test "$(git rev-parse HEAD)" = "$bound_commit"
  test -z "$(git ls-files --others --exclude-standard -- .github/scripts/v3-operator .github/scripts/v3-recurring-evidence.sh .github/scripts/v3-packaged-live.sh)"
  while IFS= read -r path; do
    test -f "$path"
    git show "$bound_commit:$path" | cmp -s - "$path"
    tracked=$((tracked + 1))
  done < <(git ls-tree -r --name-only "$bound_commit" -- .github/scripts/v3-operator .github/scripts/v3-recurring-evidence.sh .github/scripts/v3-packaged-live.sh)
  test "$tracked" -gt 3
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
identity_pid=
identity_config=
identity_request_remote=

stop_attempt() {
  status=$?
  trap - EXIT
  if test -n "$identity_pid"; then
    kill "$identity_pid" 2>/dev/null || true
    wait "$identity_pid" 2>/dev/null || true
    identity_pid=
  fi
  if test -n "$identity_request_remote"; then
    if ! "${remote[@]}" "test ! -L '$identity_request_remote' && rm -f -- '$identity_request_remote'"; then
      status=1
    fi
  fi
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
  rm -f "$directory/input.json" "$directory/decision.json" "$directory/failure.json" "$directory/failure-decision.json" "$directory/previous.json" "$directory/request.json" "$directory/outside-request.json" "$directory/outside-reply.json" "$directory/final.json" "$directory/retained-failure.json" \
    "$directory/identity-config.json" "$directory/identity-request.json" "$directory/identity-request.next" "$directory/identity.stdout" "$directory/identity.stderr" "$directory/identity-check.stdout" "$directory/identity-check.stderr" \
    "$directory/07-state.json" "$directory/07-outside.json" "$directory/07-outside-rotation-request.json" "$directory/07-outside-rotation-ready.json" "$directory/07-outside-collected.json"
  rmdir "$directory"
  exit "$status"
}
trap stop_attempt EXIT

fetch_identity_file() {
  test "$#" -eq 2
  local remote_path=$1 local_path=$2
  "${remote[@]}" "test \"\$(stat -c '%a:%u:%h:%F' '$remote_path')\" = '600:0:1:regular file' && test \"\$(stat -c %s '$remote_path')\" -le 1000000 && cat '$remote_path'" > "$local_path"
}

collect_identity_driver() {
  local identity_status=0 receipt_digest
  wait "$identity_pid" || identity_status=$?
  identity_pid=
  if test "$identity_status" -ne 0; then
    if test "$identity_status" -eq 124; then reason=timeout; else reason=evidence-refused; fi
    test "$(<"$directory/identity.stderr")" = '{"identity_outside_failed":true}'
    return 1
  fi
  reason=evidence-refused
  fetch_identity_file "$identity_state_directory/07-state.json" "$directory/07-state.json"
  fetch_identity_file "$identity_state_directory/07-outside.json" "$directory/07-outside.json"
  fetch_identity_file "$identity_state_directory/07-outside-rotation-request.json" "$directory/07-outside-rotation-request.json"
  fetch_identity_file "$identity_state_directory/07-outside-rotation-ready.json" "$directory/07-outside-rotation-ready.json"
  cmp -s "$directory/identity.stdout" <(cat "$directory/07-outside.json"; printf '\n')
  test ! -s "$directory/identity.stderr"
  reason=evidence-refused
  python3 .github/scripts/v3-operator/identity-outside.py check-result \
    --manifest "$manifest_absolute" --request "$directory/request.json" \
    --state "$directory/07-state.json" --receipt "$directory/07-outside.json" \
    > "$directory/identity-check.stdout" 2> "$directory/identity-check.stderr"
  test "$(<"$directory/identity-check.stdout")" = '{"identity_outside_verified":true}'
  test ! -s "$directory/identity-check.stderr"
  receipt_digest=$(sha256sum "$directory/07-outside.json" | cut -d' ' -f1)
  printf '{"receipt_sha256":"%s"}' "$receipt_digest" > "$directory/07-outside-collected.json"
  reason=evidence-refused
  "${remote[@]}" "set -eu; marker='$identity_state_directory/07-outside-collected.json'; temporary='$identity_state_directory/07-outside-collected.next'; request='$identity_request_remote'; test ! -e \"\$marker\"; test ! -L \"\$marker\"; test ! -e \"\$temporary\"; test ! -L \"\$temporary\"; test ! -L \"\$request\"; umask 077; cat > \"\$temporary\"; test \"\$(stat -c '%a:%u:%h:%F' \"\$temporary\")\" = '600:0:1:regular file'; mv -T \"\$temporary\" \"\$marker\"; rm -- \"\$request\"" < "$directory/07-outside-collected.json"
  identity_request_remote=
  outside_identity_done=true
  reason=evidence-refused
}

# Bind a non-secret, host-specific identity without publishing a machine ID.
actual_vps="$("${remote[@]}" 'test "$(. /etc/os-release; printf "%s:%s" "$ID" "$VERSION_ID")" = ubuntu:24.04 && test "$(uname -m)" = x86_64 && sha256sum /etc/machine-id' | cut -d' ' -f1)"
test "$actual_vps" = "$(jq -r .v3_attempt.vps_identity_sha256 "$manifest")"
manifest_absolute=$(realpath "$manifest")
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
  outside_identity_required=false outside_identity_started=false outside_identity_done=false
  if test "$scenario" = baseline-clean || test "$scenario" = baseline-postcommit; then outside_probe_required=true; fi
  if test "$scenario" = identity-absent; then outside_identity_required=true; fi
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
    if "${remote[@]}" 'test -e /root/sbxr-qualification-evidence/identity-outside-request.json || test -L /root/sbxr-qualification-evidence/identity-outside-request.json'; then
      reason=evidence-refused
      test "$outside_identity_required" = true
      identity_request_remote=/root/sbxr-qualification-evidence/identity-outside-request.json
      "${remote[@]}" 'test "$(stat -c "%a:%u:%h:%F" /root/sbxr-qualification-evidence/identity-outside-request.json)" = "600:0:1:regular file" && test "$(stat -c %s /root/sbxr-qualification-evidence/identity-outside-request.json)" -le 1024 && cat /root/sbxr-qualification-evidence/identity-outside-request.json' > "$directory/identity-request.next"
      if test "$outside_identity_started" = true; then
        cmp -s "$directory/identity-request.next" "$directory/identity-request.json"
        rm "$directory/identity-request.next"
      else
        mv "$directory/identity-request.next" "$directory/identity-request.json"
        identity_request_matches "$directory/identity-request.json" "$deadline" "$digest" "$scenario"
        request_digest=$(sha256sum "$directory/request.json" | cut -d' ' -f1)
        bound_commit=$(jq -er '.workflow.commit | select(test("^[0-9a-f]{40}$"))' "$manifest")
        identity_sources_match_commit "$bound_commit"
        for source_pair in \
          ".github/scripts/v3-operator/identity-outside.py $identity_operator_directory/identity-outside.py" \
          ".github/scripts/v3-operator/operator-support.sh $identity_operator_directory/operator-support.sh" \
          ".github/scripts/v3-operator/07-identity-absent-start.sh $identity_operator_directory/07-identity-absent-start.sh" \
          ".github/scripts/v3-operator/07-identity-absent-rotate.sh $identity_operator_directory/07-identity-absent-rotate.sh" \
          ".github/scripts/v3-operator/07-identity-absent-finish.sh $identity_operator_directory/07-identity-absent-finish.sh" \
          ".github/scripts/v3-packaged-live.sh $identity_operator_directory/v3-packaged-live.sh"; do
          read -r local_source remote_source <<<"$source_pair"
          expected_source=$(sha256sum "$local_source" | cut -d' ' -f1)
          test "$("${remote[@]}" "test ! -L '$remote_source' && test -f '$remote_source' && sha256sum '$remote_source'" | cut -d' ' -f1)" = "$expected_source"
        done
        ssh_key_absolute=$(realpath "$2")
        known_hosts_absolute=$(realpath "$3")
        jq -cnS --arg host "$1" --arg key "$ssh_key_absolute" --arg known "$known_hosts_absolute" \
          --arg state "$identity_state_directory" --arg remote_request /root/sbxr-qualification-evidence/request.json \
          --arg remote_manifest /root/sbxr-qualification-v3/qualification-manifest.json \
          --arg manifest "$manifest_absolute" --arg request "$directory/request.json" \
          --arg runner "$(jq -er '.v3_attempt.outside_runner_id' "$manifest")" \
          '{host:$host,known_hosts:$known,manifest:$manifest,outside_runner_id:$runner,remote_manifest:$remote_manifest,remote_request:$remote_request,remote_state_dir:$state,request:$request,ssh_key:$key}' \
          | tr -d '\n' > "$directory/identity-config.json"
        chmod 0600 "$directory/identity-config.json"
        test "$(sha256sum "$directory/request.json" | cut -d' ' -f1)" = "$request_digest"
        remaining=$((deadline - $(date +%s)))
        test "$remaining" -gt 0
        reason=evidence-refused
        timeout --kill-after=5 "$remaining" python3 .github/scripts/v3-operator/identity-outside.py run \
          --config "$directory/identity-config.json" > "$directory/identity.stdout" 2> "$directory/identity.stderr" &
        identity_pid=$!
        outside_identity_started=true
      fi
    fi
    if test "$outside_identity_started" = true && test "$outside_identity_done" != true && ! kill -0 "$identity_pid" 2>/dev/null; then
      collect_identity_driver
    fi
    if test "$outside_identity_started" = true && test "$outside_identity_done" != true; then
      reason=evidence-refused
      "${remote[@]}" 'true'
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
  if test "$outside_identity_required" = true; then
    test "$outside_identity_started" = true
    while test "$outside_identity_done" != true; do
      if ! kill -0 "$identity_pid" 2>/dev/null; then collect_identity_driver; break; fi
      if test "$(date +%s)" -gt "$deadline"; then reason=timeout; exit 1; fi
      sleep 1
    done
  fi
  "${remote[@]}" 'test ! -e /root/sbxr-qualification-evidence/outside-request.json && test ! -L /root/sbxr-qualification-evidence/outside-request.json'
  "${remote[@]}" 'test ! -e /root/sbxr-qualification-evidence/identity-outside-request.json && test ! -L /root/sbxr-qualification-evidence/identity-outside-request.json'
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
  if test "$outside_identity_required" = true; then
    "${remote[@]}" 'for path in /run/sbxr-qualification/07-outside-started.json /run/sbxr-qualification/07-outside-ready.json /run/sbxr-qualification/07-outside-rotation-request.json /run/sbxr-qualification/07-outside-rotation-ready.json /run/sbxr-qualification/07-outside.json /run/sbxr-qualification/07-outside-collected.json; do test ! -e "$path" && test ! -L "$path"; done'
  fi
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
