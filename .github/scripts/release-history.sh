#!/usr/bin/env bash
# Collect every published release page. No network/decoding failure is absence.
set -euo pipefail
umask 077
test "$#" -eq 1
output="$1"
directory="$(mktemp -d)"
trap 'rm -rf "$directory"' EXIT
(
cd "$directory"
gh api "repos/$GITHUB_REPOSITORY/releases?per_page=100" --paginate --slurp | jq 'add' > releases.json
printf '[]' > release-facts.json
while read -r release; do
  assets="$(jq -cS '[.assets[] | {digest:((.digest // "") | sub("^sha256:";"")),id,name,size}] | sort_by(.name)' <<<"$release")"
  index_asset_id="$(jq -r '.assets[] | select(.name == "release-index.json") | .id' <<<"$release")"
  index=null
  sequence=null
  if test -n "$index_asset_id"; then
    gh api "repos/$GITHUB_REPOSITORY/releases/assets/$index_asset_id" -H 'Accept: application/octet-stream' > existing-index.json
    if jq -e '(.sequence | type) == "number" and .sequence > 0 and .sequence == (.sequence | floor)' existing-index.json >/dev/null 2>&1; then
      sequence="$(jq -c .sequence existing-index.json)"
    fi
    if jq -e '(.repository | type) == "string" and (.tag | type) == "string" and (.commit | type) == "string" and (.sequence | type) == "number" and .sequence > 0 and .sequence == (.sequence | floor)' existing-index.json >/dev/null 2>&1; then
      index="$(jq -cS --arg sha256 "$(sha256sum existing-index.json | cut -d' ' -f1)" '{commit,repository,schema,sequence,sha256:$sha256,tag} + (if .support == null then {} else {support:{contract:.support.contract,scope:.support.scope,sources:[.support.sources[] | {commit:.Commit,release_index_sha256:.IndexSHA256,repository:.Repository,tag:.Tag}]}} end)' existing-index.json)"
    fi
  fi
  jq -cS --argjson assets "$assets" --argjson index "$index" --argjson sequence "$sequence" '{assets:$assets,body:(.body // ""),commit:.target_commitish,draft:.draft,id:.id,immutable:(.immutable // false),index:$index,prerelease:.prerelease,sequence:$sequence,tag:.tag_name}' <<<"$release" > release-fact.json
  jq -cS --slurpfile fact release-fact.json '. + [$fact[0]] | sort_by(.id)' release-facts.json > release-facts.next
  mv release-facts.next release-facts.json
done < <(jq -c '.[] | select(.draft == false)' releases.json)
)
cp "$directory/release-facts.json" "$output"
