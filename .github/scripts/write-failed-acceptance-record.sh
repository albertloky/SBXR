#!/usr/bin/env bash
set -euo pipefail

release_json=$1
metadata=$2
record=$3
workflow=$4
code=$5
manifest=$6
failure_state=$7
tag="$(jq -r .tag "$release_json")"
commit="$(jq -r .commit "$release_json")"
index_sha256="$(jq -r .release_identity.release_index_sha256 "$release_json")"
role="$("$(dirname "$0")/release-role.sh" "$manifest" "$tag")"

source_record="$(jq -r .body "$metadata")"
if grep -Fx 'Status: Failed prerelease' <<<"$source_record" >/dev/null; then
  jq -j .body "$metadata" > "$record"
  source_canonical="$(sed -n '/^```json$/,/^```$/p' "$record" | sed '1d;$d')"
  jq -e --arg repository "$GITHUB_REPOSITORY" --arg tag "$tag" --arg commit "$commit" --arg index "$index_sha256" --arg code "$code" '.schema == "sbxr-acceptance-record-v1" and .release_identity == {repository:$repository,tag:$tag,commit:$commit,release_index_sha256:$index} and .stable_result_code == $code and .secret_safe_result == "Passed"' <<<"$source_canonical" >/dev/null
  exit 0
fi
if grep -Fx 'Status: Qualified' <<<"$source_record" >/dev/null; then
  source_canonical="$(sed -n '/^```json$/,/^```$/p' <<<"$source_record" | sed '1d;$d')"
  jq -e '.schema == "sbxr-acceptance-record-v1" and .secret_safe_result == "Passed"' <<<"$source_canonical" >/dev/null
  accepted_at="$(jq -r .accepted_at <<<"$source_canonical")"
  runner="$(jq -r .runner <<<"$source_canonical")"
  role="$(jq -r .qualification_role <<<"$source_canonical")"
  integrated="$(jq -r .stages.integrated_verification <<<"$source_canonical")"
  codex="$(jq -r .stages.codex_live_acceptance <<<"$source_canonical")"
  go_toolchain="$(grep -m1 '^Go toolchain: ' <<<"$source_record" | cut -d' ' -f3-)"
  public_verifier="$(grep -m1 '^Public verifier: ' <<<"$source_record" | cut -d' ' -f3-)"
  evidence="$(jq -c .evidence <<<"$source_canonical")"
else
  jq -e --arg workflow "$workflow" '.schema == "sbxr-candidate-failure-state-v1" and .workflow_run == $workflow and (.recorded_at | type == "string") and (.runner | type == "string") and (.software.go_toolchain | type == "string") and (.software.public_verifier | type == "string") and ([.stages.integrated_verification,.stages.codex_live_acceptance] | all(. == "Pending" or . == "Failed" or . == "Passed")) and (.evidence | type == "array" and length > 0)' "$failure_state" >/dev/null
  accepted_at="$(jq -r .recorded_at "$failure_state")"
  runner="$(jq -r .runner "$failure_state")"
  go_toolchain="$(jq -r .software.go_toolchain "$failure_state")"
  public_verifier="$(jq -r .software.public_verifier "$failure_state")"
  integrated="$(jq -r .stages.integrated_verification "$failure_state")"
  codex="$(jq -r .stages.codex_live_acceptance "$failure_state")"
  evidence="$(jq -c .evidence "$failure_state")"
fi

canonical="$(jq -cnS --arg repository "$GITHUB_REPOSITORY" --arg tag "$tag" --arg commit "$commit" --arg index "$index_sha256" --argjson sequence "$(jq .sequence "$release_json")" --arg workflow "$workflow" --arg accepted_at "$accepted_at" --arg runner "$runner" --arg go_toolchain "$go_toolchain" --arg public_verifier "$public_verifier" --arg role "$role" --arg code "$code" --arg integrated "$integrated" --arg codex "$codex" --argjson assets "$(jq .assets "$release_json")" --argjson evidence "$evidence" '{schema:"sbxr-acceptance-record-v1",release_identity:{repository:$repository,tag:$tag,commit:$commit,release_index_sha256:$index},sequence:$sequence,assets:$assets,workflow_run:$workflow,accepted_at:$accepted_at,runner:$runner,software:{go_toolchain:$go_toolchain,public_verifier:$public_verifier},stages:{module_verification:"Passed",seam_verification:"Passed",integrated_verification:$integrated,codex_live_acceptance:$codex,owner_acceptance:"Not required"},qualification_role:$role,stable_result_code:$code,secret_safe_result:"Passed",evidence:$evidence}' )"
{
  echo '# SBXR Installer-Updater Acceptance Record'
  echo 'Status: Failed prerelease'
  echo "Repository: $GITHUB_REPOSITORY"
  echo "Tag: $tag"
  echo "Commit: $commit"
  echo "Release index SHA-256: $index_sha256"
  echo "Sequence: $(jq -r .sequence "$release_json")"
  echo "Workflow evidence: $workflow"
  echo "Acceptance time: $accepted_at"
  echo "Runner: $runner"
  echo "Go toolchain: $go_toolchain"
  echo "Public verifier: $public_verifier"
  echo 'Secret-safe result: Passed'
  echo "Qualification role: $role"
  echo "Stable result code: $code"
  echo 'Module Verification: Passed'
  echo 'Seam Verification: Passed'
  echo "Integrated Verification: $integrated"
  echo "Codex Live Acceptance: $codex"
  echo 'Owner Acceptance: Not required'
  jq -r '.assets[] | "Asset: \(.name) \(.size) \(.sha256)"' "$release_json"
  echo '```json'
  echo "$canonical"
  echo '```'
} > "$record"
