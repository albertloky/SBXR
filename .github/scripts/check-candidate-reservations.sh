#!/usr/bin/env bash
# Read-only: preserve unknown and signed-unqualified authority; never mutate releases.
set -euo pipefail
test "$#" -le 1
test "$GITHUB_REPOSITORY" = albertloky/SBXR
allowed=${1:-'[]'}
go run ./cmd/sbxr-release candidate-reservations -policy > reservation-policy.json
jq -e 'length == 3' reservation-policy.json >/dev/null
gh api "repos/$GITHUB_REPOSITORY/releases?per_page=100" --paginate --slurp > reservation-release-pages.json
: > reservation-refs.jsonl
while IFS= read -r tag; do
  python3 .github/scripts/observe-github-resource.py "repos/$GITHUB_REPOSITORY/git/ref/tags/$tag" > reservation-tag.json
  python3 .github/scripts/observe-github-resource.py "repos/$GITHUB_REPOSITORY/git/ref/tags/release-burned/$tag" > reservation-burn.json
  jq -cnS --arg tag "$tag" --slurpfile release reservation-tag.json --slurpfile burn reservation-burn.json '{tag:$tag,release:$release[0],burn:$burn[0]}' >> reservation-refs.jsonl
done < <(jq -er '.[].tag' reservation-policy.json)
jq -ceS --slurpfile refs reservation-refs.jsonl --slurpfile policy reservation-policy.json '
  if type != "array" or length == 0 or any(.[]; type != "array") then error("release pages refused") else
  {refs:$refs,releases:[.[][] | . as $release | {assets:(if any($policy[0][]; .release_id == $release.id or .tag == $release.tag_name) then [.assets[] | {digest:(.digest | sub("^sha256:";"")),id,name,size}] | sort_by(.name) else [] end),body:(.body // ""),commit:.target_commitish,draft,id,immutable,prerelease,tag:.tag_name}]} end
' reservation-release-pages.json | tr -d '\n' > reservation-observations.json
go run ./cmd/sbxr-release candidate-reservations -allowed-draft-tags "$allowed" < reservation-observations.json
