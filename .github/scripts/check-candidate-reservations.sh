#!/usr/bin/env bash
# Read-only: never classifies unknown signing as unsigned or mutates a release.
set -euo pipefail
test "$#" -le 1
test "$GITHUB_REPOSITORY" = albertloky/SBXR
allowed=${1:-'[]'}
go run ./cmd/sbxr-release candidate-reservations -policy > reservation-policy.json
tag="$(jq -er 'select(length == 1) | .[0].tag' reservation-policy.json)"
gh api "repos/$GITHUB_REPOSITORY/releases?per_page=100" --paginate --slurp > reservation-release-pages.json
python3 .github/scripts/observe-github-resource.py "repos/$GITHUB_REPOSITORY/git/ref/tags/$tag" > reservation-tag.json
python3 .github/scripts/observe-github-resource.py "repos/$GITHUB_REPOSITORY/git/ref/tags/release-burned/$tag" > reservation-burn.json
jq -ceS --slurpfile tag reservation-tag.json --slurpfile burn reservation-burn.json --slurpfile policy reservation-policy.json '
  if type != "array" or length == 0 or any(.[]; type != "array") then error("release pages refused") else
  {burn:$burn[0],tag:$tag[0],releases:[.[][] | {assets:(if .id == $policy[0][0].release_id or .tag_name == $policy[0][0].tag then [.assets[] | {digest:(.digest | sub("^sha256:";"")),id,name,size}] | sort_by(.name) else [] end),body:(.body // ""),commit:.target_commitish,draft,id,immutable,prerelease,tag:.tag_name}]} end
' reservation-release-pages.json | tr -d '\n' > reservation-observations.json
go run ./cmd/sbxr-release candidate-reservations -allowed-draft-tags "$allowed" < reservation-observations.json
