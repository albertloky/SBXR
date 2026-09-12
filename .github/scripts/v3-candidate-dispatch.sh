#!/usr/bin/env bash
# Validate the complete preparation snapshot before submitting one V3 workflow.
set -euo pipefail
if test "$#" -ne 4 || { test "$1" != check && test "$1" != dispatch; }; then
  printf '%s\n' 'usage: v3-candidate-dispatch.sh check|dispatch TOOL PREFLIGHT_FACTS DECLARATION' >&2
  exit 2
fi
mode=$1 tool=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$3" "$work/preflight.json"
cp "$4" "$work/attempt.json"
# Do not normalize untrusted JSON before the validator sees duplicate keys.
{ printf '{"attempt":'; cat "$work/attempt.json"; printf ',"preflight":'; cat "$work/preflight.json"; printf '}'; } > "$work/request.json"
"$tool" qualification-declaration < "$work/request.json" > "$work/decision.json"
cat "$work/decision.json"
# Historical acceptance records remain readable, but this checkout no longer
# produces new v1-v4 live attempts. Reject after strict local validation and
# before the first GitHub request.
if ! jq -e '.evidence_policy == "mvp-live-v1"' "$work/attempt.json" >/dev/null; then
  printf '%s\n' 'The current checkout produces only mvp-live-v1 evidence. Use Git revision 0859e96 to reproduce a historical v1-v4 qualification attempt.' >&2
  exit 2
fi
if test "$mode" = check; then exit 0; fi
# Refuse a source change since the collected preflight snapshot.
current=$(gh api repos/albertloky/SBXR/git/ref/heads/main --jq .object.sha)
jq -e --arg current "$current" '.commit == $current and .remote_main == $current and .candidate.mode == "v3"' "$work/preflight.json" >/dev/null
jq -cn --slurpfile preflight "$work/preflight.json" --rawfile attempt "$work/attempt.json" \
  '{mode:"v3",a_tag:"",a_sequence:"0",b_tag:$preflight[0].candidate.b_tag,b_sequence:($preflight[0].candidate.b_sequence|tostring),v3_attempt:$attempt}' > "$work/inputs.json"
gh workflow run candidate.yml --repo albertloky/SBXR --ref main --json < "$work/inputs.json"
