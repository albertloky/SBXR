#!/usr/bin/env bash
# Collect ordinary live observations, including declared packaged upgrade checks.
set -euo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1

mvp_required_checks() {
  if jq -e '.v3_attempt.evidence_policy == "mvp-http-live-v1" or .v3_attempt.evidence_policy == "mvp-http-recurring-live-v1"' "$manifest" >/dev/null; then
    python3 .github/scripts/v3-mvp-evidence.py --checks "$manifest" "$1"
    return
  fi
  case "$1" in
    mvp-install) printf '%s' 'packaged-install reviewed-setup outside-proxy-traffic menu-status-and-lifecycle ssh-access-preserved' ;;
    mvp-subscription) printf '%s' 'trusted-outside-https one-correct-subscription-node wrong-token-refused private-files-and-logs-protected karing-import fresh-karing-node-latency manual-refresh selected-connection-preserved' ;;
    mvp-credentials) printf '%s' 'old-established-session-terminated old-proxy-credential-refused replacement-proxy-traffic same-link-refreshed-identity old-link-refused replacement-link-usable proxy-identity-unchanged-by-link-rotation fresh-karing-replacement-latency' ;;
    mvp-renewal) printf '%s' 'official-renewal-route certificate-replaced accepted-activation outside-trusted-tls proxy-traffic-preserved' ;;
    mvp-removal) printf '%s' 'restart-preserves-access reviewed-complete-removal owned-resources-absent outside-access-refused unrelated-resources-preserved test-client-and-secret-cleanup ssh-access-preserved' ;;
    source-*) python3 .github/scripts/v3-mvp-evidence.py --checks "$manifest" "$1" ;;
    *) return 1 ;;
  esac
}

# Publish original scenario facts through one owned interface. Reading the
# request deliberately uses ssh -n; publishing carries the facts on stdin.
submit_result() {
  test "$#" -eq 5
  local submit_host=$1 submit_key=$2 submit_known_hosts=$3 submit_manifest=$4 submit_facts=$5
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
manifest=handoff/qualification-manifest.json
boundary=handoff/qualification-boundary-facts.json
tool=handoff/sbxr-release
jq -e '(.schema == "sbxr-qualification-manifest-v2" or .schema == "sbxr-qualification-manifest-v3") and (.source_state == "v3-recurring" or .source_state == "v3-subscription-clean")' "$manifest" >/dev/null
if ! jq -e '.v3_attempt.evidence_policy == "mvp-live-v1" or .v3_attempt.evidence_policy == "mvp-recurring-live-v1" or .v3_attempt.evidence_policy == "mvp-http-live-v1" or .v3_attempt.evidence_policy == "mvp-http-recurring-live-v1"' "$manifest" >/dev/null; then
  printf '%s\n' 'The current checkout produces ordinary HTTPS or HTTP MVP evidence. Use Git revision 0859e96 to reproduce a historical v1-v4 qualification attempt.' >&2
  exit 2
fi
chmod 0600 "$manifest" "$boundary"
digest="$(sha256sum "$manifest" | cut -d' ' -f1)"
directory="$(mktemp -d)"
mkdir -m 0700 handoff/v3-scenarios
printf '[]' > "$directory/previous.json"
remote=(ssh -i "$2" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$3" -o ConnectTimeout=15 "root@$1")
scenario="$(jq -r '.v3_attempt.required_scenarios[0]' "$manifest")"
operation=operation-1
reason=unexpected-failure
mvp_observation_remote=

cleanup_mvp_observation() {
  if test -n "$mvp_observation_remote"; then
    if ! "${remote[@]}" "test ! -L '$mvp_observation_remote' && rm -f -- '$mvp_observation_remote'"; then return 1; fi
    mvp_observation_remote=
  fi
}

# Read one opened inode: the operator may atomically replace or retire its draft
# during this read. An already-unlinked inode is safe; extra hard links are not.
read_mvp_timing_draft() {
  "${remote[@]}" 'python3 - /root/mvp-observation-draft.json' > "$directory/mvp-timing-draft.json" <<'PYTHON'
import os, stat, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
except FileNotFoundError:
    raise SystemExit(0)
with os.fdopen(fd, "rb") as stream:
    info = os.fstat(stream.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink not in (0, 1)):
        raise SystemExit("Unsafe timing draft")
    body = stream.read(1000001)
    if not body or len(body) > 1000000:
        raise SystemExit("Invalid timing draft size")
    sys.stdout.buffer.write(body)
PYTHON
  if test ! -s "$directory/mvp-timing-draft.json"; then rm "$directory/mvp-timing-draft.json"; fi
}

# Timing transport helpers end.

stop_attempt() {
  status=$?
  trap - EXIT
  if ! cleanup_mvp_observation; then status=1; fi
  if test "$status" -ne 0; then
    # Do not fetch raw output or run product cleanup against uncertain state.
    "${remote[@]}" 'if test -e /root/sbxr-qualification-evidence || test -L /root/sbxr-qualification-evidence; then test -d /root/sbxr-qualification-evidence && test ! -L /root/sbxr-qualification-evidence && request=/root/sbxr-qualification-evidence/request.json && test -f "$request" && test ! -L "$request" && printf "%s\n" STOP > "$request"; fi' || true
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
  rm -f "$directory/input.json" "$directory/decision.json" "$directory/failure.json" "$directory/failure-decision.json" "$directory/previous.json" "$directory/request.json" "$directory/final.json" "$directory/retained-failure.json" "$directory/mvp-observation.json" "$directory/mvp-facts.json" "$directory/mvp-decision.json" "$directory/mvp-timing-draft.json" "$directory/request.next" "$directory/accepted-timing-draft.json"
  rmdir "$directory"
  exit "$status"
}
trap stop_attempt EXIT

actual_vps="$("${remote[@]}" 'test "$(. /etc/os-release; printf "%s:%s" "$ID" "$VERSION_ID")" = ubuntu:24.04 && test "$(uname -m)" = x86_64 && sha256sum /etc/machine-id' | cut -d' ' -f1)"
test "$actual_vps" = "$(jq -r .v3_attempt.vps_identity_sha256 "$manifest")"
"${remote[@]}" 'test ! -e /root/sbxr-qualification-evidence && test ! -L /root/sbxr-qualification-evidence && install -d -m 0700 /root/sbxr-qualification-evidence'

index=0
while IFS= read -r next_scenario <&3; do
  scenario=$next_scenario
  index=$((index + 1))
  operation="operation-$index"
  limit=1800
  if test "$scenario" = mvp-subscription; then limit=7200; fi
  started="$(date +%s)"
  deadline=$((started + limit))
  required_checks=$(mvp_required_checks "$scenario")
  jq -cnS --arg scenario "$scenario" --arg digest "$digest" --arg checks "$required_checks" --argjson limit "$limit" --argjson deadline "$deadline" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{deadline_unix:$deadline,not_before:$now,qualification_manifest_sha256:$digest,required_checks:($checks | split(" ")),scenario_id:$scenario,scenario_limit_seconds:$limit}' | tr -d '\n' > "$directory/request.json"
  if jq -e '.v3_attempt.karing_response_limit_seconds == 3600' "$manifest" >/dev/null; then
    jq -cS --slurpfile m "$manifest" '. + {karing_response_limit_seconds:3600,attended_finish_by:$m[0].v3_attempt.attended_finish_by}' "$directory/request.json" | tr -d '\n' > "$directory/request.next"
    mv "$directory/request.next" "$directory/request.json"
  fi
  "${remote[@]}" 'set -eu; umask 077; test ! -e /root/sbxr-qualification-evidence/result.json; test ! -L /root/sbxr-qualification-evidence/result.json; test ! -L /root/sbxr-qualification-evidence/request.json; cat > /root/sbxr-qualification-evidence/request.json' < "$directory/request.json"
  while ! "${remote[@]}" 'test -f /root/sbxr-qualification-evidence/result.json && test ! -L /root/sbxr-qualification-evidence/result.json'; do
    if "${remote[@]}" 'test -L /root/sbxr-qualification-evidence/result.json'; then reason=evidence-refused; exit 1; fi
    if "${remote[@]}" 'test -e /root/sbxr-qualification-evidence/observation.json || test -L /root/sbxr-qualification-evidence/observation.json'; then
      reason=evidence-refused
      test -z "$mvp_observation_remote"
      mvp_observation_remote=/root/sbxr-qualification-evidence/observation.json
      "${remote[@]}" "test ! -L '$mvp_observation_remote' && test \"\$(stat -c '%a:%u:%h:%F' '$mvp_observation_remote')\" = '600:0:1:regular file' && test \"\$(stat -c %s '$mvp_observation_remote')\" -le 1000000 && cat '$mvp_observation_remote'" > "$directory/mvp-observation.json"
      python3 .github/scripts/v3-mvp-evidence.py --manifest "$manifest" --boundary "$boundary" --request "$directory/request.json" --previous "$directory/previous.json" --observation "$directory/mvp-observation.json" --output "$directory/mvp-facts.json"
      "$tool" qualification < "$directory/mvp-facts.json" > "$directory/mvp-decision.json"
      jq -e '.outcome == "accepted" and .records == []' "$directory/mvp-decision.json" >/dev/null
      submit_result "$1" "$2" "$3" "$manifest" "$directory/mvp-facts.json"
      cleanup_mvp_observation
    fi
    active_deadline=$deadline
    if jq -e '.karing_response_limit_seconds == 3600' "$directory/request.json" >/dev/null; then
      # Read only private timing/check facts, never subscription URLs. The
      # recorder checks request identity and each prepared/notified handoff.
      read_mvp_timing_draft
      # The previous callback retires its sealed draft after seeing this request.
      # Ignore only its exact bytes, retained after the preceding Go acceptance.
      if test -f "$directory/accepted-timing-draft.json" && cmp -s "$directory/accepted-timing-draft.json" "$directory/mvp-timing-draft.json"; then
        rm "$directory/mvp-timing-draft.json"
      fi
      active_deadline=$(python3 .github/scripts/mvp-observe.py deadline --request "$directory/request.json" --draft "$directory/mvp-timing-draft.json")
    fi
    if test "$(date +%s)" -gt "$((active_deadline + 300))"; then reason=timeout; exit 1; fi
    sleep 2
  done

  reason=evidence-refused
  "${remote[@]}" 'test ! -L /root/sbxr-qualification-evidence/result.json && test "$(stat -c "%a:%u:%h:%F" /root/sbxr-qualification-evidence/result.json)" = "600:0:1:regular file" && test "$(stat -c %s /root/sbxr-qualification-evidence/result.json)" -le 16777216 && cat /root/sbxr-qualification-evidence/result.json' > "$directory/input.json"
  # Validate original bytes before jq so duplicate and unknown keys cannot disappear.
  "$tool" qualification < "$directory/input.json" > "$directory/decision.json"
  if jq -e '.stage == "v3-scenario-failure"' "$directory/input.json" >/dev/null; then
    jq -e --slurpfile m "$manifest" --arg scenario "$scenario" '.qualification_manifest == $m[0] and .failure.scenario_id == $scenario' "$directory/input.json" >/dev/null
    jq -e '.outcome == "failed" and .stop_test_mutations and .burn_required' "$directory/decision.json" >/dev/null
    cp "$directory/input.json" "$directory/retained-failure.json"
    reason=failure-recorded
    exit 1
  fi
  "${remote[@]}" 'test ! -e /root/sbxr-qualification-evidence/observation.json && test ! -L /root/sbxr-qualification-evidence/observation.json'
  jq -e --arg digest "$digest" --arg scenario "$scenario" --argjson count "$index" --slurpfile previous "$directory/previous.json" '.stage == "v3-scenario-result" and .prior_decision_sha256 == $digest and (.detailed_evidence.scenarios | length) == $count and .detailed_evidence.scenarios[-1].scenario_id == $scenario and .detailed_evidence.scenarios[:-1] == $previous[0]' "$directory/input.json" >/dev/null
  jq -e '.outcome == "accepted" and .records == []' "$directory/decision.json" >/dev/null
  completed="$(date -u -d "$(jq -r '.detailed_evidence.scenarios[-1].completed_at' "$directory/input.json")" +%s)"
  recorded_start="$(date -u -d "$(jq -r '.detailed_evidence.scenarios[-1].started_at' "$directory/input.json")" +%s)"
  now="$(date +%s)"
  test "$recorded_start" -ge "$started"
  test "$completed" -le "$now"
  test "$((now - completed))" -le 300
  cp "$directory/input.json" "handoff/v3-scenarios/$index-facts.json"
  cp "$directory/decision.json" "handoff/v3-scenarios/$index-decision.json"
  jq -cS '.detailed_evidence.scenarios' "$directory/input.json" > "$directory/previous.json"
  # Retain only a sealed draft matching this fully accepted scenario. Neither
  # unsealed drafts nor changed/replayed bytes can cross the next request.
  rm -f "$directory/accepted-timing-draft.json"
  if jq -e '.karing_response_limit_seconds == 3600' "$directory/request.json" >/dev/null; then
    read_mvp_timing_draft
    if test -f "$directory/mvp-timing-draft.json"; then
      python3 .github/scripts/mvp-observe.py deadline --request "$directory/request.json" --draft "$directory/mvp-timing-draft.json" >/dev/null
      jq -e --arg digest "$(sha256sum "$directory/request.json" | cut -d' ' -f1)" --slurpfile facts "$directory/input.json" '
        ($facts[0].detailed_evidence.scenarios[-1] | {scenario_id,started_at,completed_at,checks:[.evidence[].record]} +
          (if has("karing_handoffs") then {karing_handoffs} else {} end)) as $accepted |
        .request_sha256 == $digest and .observation.completed_at != null and .observation == $accepted
      ' "$directory/mvp-timing-draft.json" >/dev/null
      cp "$directory/mvp-timing-draft.json" "$directory/accepted-timing-draft.json"
    fi
  fi
  # Accepted timing retention ends.
  "${remote[@]}" 'rm /root/sbxr-qualification-evidence/result.json'
  rm -f "$directory/mvp-observation.json" "$directory/mvp-facts.json" "$directory/mvp-decision.json"
  reason=unexpected-failure
done 3< <(jq -r '.v3_attempt.required_scenarios[]' "$manifest")

"${remote[@]}" 'test ! -e /usr/local/bin/sbxr && test ! -L /usr/local/bin/sbxr && test ! -e /var/lib/sbxr && test ! -L /var/lib/sbxr && test -d /root/sbxr-qualification-evidence && test ! -L /root/sbxr-qualification-evidence && test -f /root/sbxr-qualification-evidence/request.json && test ! -L /root/sbxr-qualification-evidence/request.json && rm /root/sbxr-qualification-evidence/request.json && rmdir /root/sbxr-qualification-evidence'
jq -cS --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.stage = "v3-packaged-live-result" | .evaluation_time = $now' "$directory/input.json" | tr -d '\n' > "$directory/final.json"
"$tool" qualification < "$directory/final.json" > "$directory/decision.json"
jq -e '.outcome == "accepted" and (.records | length) == 1' "$directory/decision.json" >/dev/null
cp "$directory/final.json" handoff/v3-packaged-live-result-facts.json
cp "$directory/decision.json" handoff/v3-packaged-live-result-decision.json
jq -cS '.detailed_evidence' "$directory/input.json" | tr -d '\n' > handoff/v3-packaged-live-evidence.json
