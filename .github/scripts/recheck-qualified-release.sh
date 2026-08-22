#!/usr/bin/env bash
set -euo pipefail

release_json=$1
directory=$2
metadata=$3
mode=${4:-complete}
tag="$(jq -r .tag "$release_json")"
commit="$(jq -r .commit "$release_json")"
release_id="$(jq -r .release_id "$release_json")"
index_sha256="$(jq -r .release_identity.release_index_sha256 "$release_json")"

mkdir -p -m 0700 "$directory"
gh api "repos/$GITHUB_REPOSITORY/releases/$release_id" > "$metadata"
jq -e --arg repository "$GITHUB_REPOSITORY" --arg tag "$tag" --arg commit "$commit" --arg index "$index_sha256" --arg mode "$mode" --argjson release_id "$release_id" '
  .id == $release_id and .tag_name == $tag and .target_commitish == $commit and
  (if $mode == "partial" then (.assets | length) <= 4 and all(.assets[]; .name as $name | ["install.sh","release-index.json","sbxr-linux-amd64.tar.gz","sbxr-linux-arm64.tar.gz"] | index($name))
   else (.assets | length) == 4 and (.assets | map(.name) | sort) == ["install.sh","release-index.json","sbxr-linux-amd64.tar.gz","sbxr-linux-arm64.tar.gz"] end) and
  ($release.release_identity == {repository:$repository,tag:$tag,commit:$commit,release_index_sha256:$index})
' --argjson release "$(cat "$release_json")" "$metadata" >/dev/null
while read -r asset; do
  name="$(jq -r .name <<<"$asset")"
  proof="$(jq -c --arg name "$name" '.assets[] | select(.name == $name)' "$release_json")"
  test -n "$proof"
  test "$(jq -r .size <<<"$asset")" -eq "$(jq -r .size <<<"$proof")"
  gh api "repos/$GITHUB_REPOSITORY/releases/assets/$(jq -r .id <<<"$asset")" -H 'Accept: application/octet-stream' > "$directory/$name"
  test "$(sha256sum "$directory/$name" | cut -d' ' -f1)" = "$(jq -r .sha256 <<<"$proof")"
done < <(jq -c '.assets[]' "$metadata")
if test -e "$directory/release-index.json"; then
  test "$(sha256sum "$directory/release-index.json" | cut -d' ' -f1)" = "$index_sha256"
else
  test "$mode" = partial
fi
