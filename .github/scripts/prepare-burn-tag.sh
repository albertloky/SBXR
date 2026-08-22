#!/usr/bin/env bash
set -euo pipefail

payload=$1
original_tag=$2
commit=$3
burn_tag="release-burned/$original_tag"

if git rev-parse -q --verify "refs/tags/$burn_tag" >/dev/null; then
  test "$(git rev-parse "$burn_tag^{commit}")" = "$commit"
  test "$(git tag -l --format='%(contents)' "$burn_tag")" = "$(cat "$payload")"
else
  git tag -a "$burn_tag" -F "$payload" "$commit"
  printf 'refs/tags/%s\n' "$burn_tag"
fi
