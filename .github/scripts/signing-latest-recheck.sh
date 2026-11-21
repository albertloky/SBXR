#!/usr/bin/env bash
# The signing recheck keeps its existing trust/baseline assertion. Diagnostics
# retain only fixed categories and statuses, never raw verifier/input bytes.
set -euo pipefail
verifier_exit=0
baseline_comparison=not-started
diagnostics_dir="${RUNNER_TEMP:-.}"
report_exit() {
  local status="$1" outcome http_receipt
  trap - EXIT
  set +e
  if test ! -e current-source-verification.json; then
    outcome=missing
  elif test ! -s current-source-verification.json; then
    outcome=empty
  elif outcome="$(jq -ser 'if length == 1 then .[0].outcome else null end | select(. == "accepted" or . == "refused" or . == "unavailable")' current-source-verification.json 2>/dev/null)"; then
    :
  else
    outcome=invalid
  fi
  http_receipt="$(python3 -B "$(dirname "$0")/retain-public-http.py" \
    "$diagnostics_dir/signing-latest-http.raw" "$diagnostics_dir/signing-latest-http.json")" || http_receipt=unknown
  # A diagnostic write failure must not replace the original decision/status.
  jq -n --arg outcome "$outcome" --arg comparison "$baseline_comparison" --arg http_receipt "$http_receipt" \
    --argjson verifier_exit "$verifier_exit" --argjson status "$status" \
    '{schema:"sbxr-signing-latest-diagnostics-v2",http_receipt:$http_receipt,verifier_exit:$verifier_exit,verifier_outcome:$outcome,baseline_comparison:$comparison,exit_status:$status}' \
    | tee "$diagnostics_dir/signing-latest-diagnostics.json" >&2
  exit "$status"
}
trap 'report_exit "$?"' EXIT
if cargo run --locked --offline --release --manifest-path tooling/rust-package/Cargo.toml -- verify-public-latest \
  --http-diagnostics "$diagnostics_dir/signing-latest-http.raw" > current-source-verification.json; then
  verifier_exit=0
else
  verifier_exit=$?
  exit "$verifier_exit"
fi
baseline_comparison=not-completed
jq -e --slurpfile current current-source-verification.json '.latest_tag == $current[0].release_identity.tag and $current[0].outcome == "accepted" and any(.releases[]; .tag == $current[0].release_identity.tag and .commit == $current[0].release_identity.commit and .index.sha256 == $current[0].release_identity.release_index_sha256)' candidate-preflight-facts.json >/dev/null 2>&1
baseline_comparison=matched
