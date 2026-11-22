#!/usr/bin/env bash
# Read the same proof for stable preflight and explicit abandonment.
# A local result never sets or edits release metadata.
set -euo pipefail
umask 077
scripts="$(dirname "$0")"
repo=albertloky/SBXR
test "$#" -eq 2
test "$GITHUB_REPOSITORY" = "$repo"
run=$1
destination=$2
[[ "$run" =~ ^[1-9][0-9]*$ ]]
mkdir -m 0700 "$destination"
prefix="repos/$repo/actions/runs/$run"
gh api "$prefix" --method GET > "$destination/live-run.json"
gh api "$prefix/artifacts?per_page=100" --method GET --paginate --slurp |
  jq -e 'map(.artifacts|arrays) | add // []' > "$destination/artifacts.json"
count="$(jq '[.[]|select(.name=="fresh-qualification-window")]|length' "$destination/artifacts.json")"
if test "$count" = 0; then
  exit 0
fi
test "$count" = 1
jq -e '[.[]|select(.name=="fresh-qualification-window" and .expired==false)]|length==1'   "$destination/artifacts.json" >/dev/null
jq -e --arg name "installer-updater-acceptance-$run"   '[.[]|select(.name==$name and .expired==false)]|length==1' "$destination/artifacts.json" >/dev/null
gh run download "$run" -R "$repo" --name fresh-qualification-window --dir "$destination/window"
gh run download "$run" -R "$repo" --name "installer-updater-acceptance-$run" --dir "$destination/acceptance"
clock="$destination/window/fresh-window-decision.json"
mint="$destination/window/fresh-window-facts.json"
facts="$destination/acceptance/acceptance-vps-result-facts.json"
decision="$destination/acceptance/acceptance-vps-result-decision.json"
origin="$(jq -er '.window.origin.run_id|select(test("^[1-9][0-9]*$"))' "$clock")"
test "$origin" != "$run"
claim="fresh-qualification-use-$origin"
jq -e --arg name "$claim" '[.[]|select(.name==$name and .expired==false)]|length==1' "$destination/artifacts.json" >/dev/null
gh run download "$run" -R "$repo" --name "$claim" --dir "$destination/claim"
cmp "$clock" "$destination/claim/fresh-window-decision.json"
gh run download "$origin" -R "$repo" --name signed-qualification-manifest --dir "$destination/origin"
manifest="$destination/origin/qualification-manifest.json"
python3 -B "$scripts/qualification-window-authority.py" origin "$manifest" "$origin" > "$destination/origin-observation.json"
python3 -B "$scripts/qualification-window-authority.py" window "$clock" "$run"
python3 -B "$scripts/qualification-window-authority.py" completed "$run"
jq -e --slurpfile mint "$mint" --slurpfile clock "$clock" --slurpfile manifest "$manifest"   --slurpfile origin "$destination/origin-observation.json" '
    .fresh_window.window_facts == $mint[0] and .fresh_window.window_decision == $clock[0] and
    .qualification_manifest == $manifest[0] and $mint[0].origin == $origin[0]' "$facts" >/dev/null
go run ./cmd/sbxr-release qualification < "$facts" > "$destination/replayed-result.json"
cmp "$decision" "$destination/replayed-result.json"
gh api "repos/$repo/actions/runs/$origin" --method GET > "$destination/origin-run.json"
jq -cjS --arg sha "$(sha256sum "$clock" | cut -d' ' -f1)"   '{acceptance_conclusion:"success",origin_run:{conclusion,created_at,event,head_sha,id:(.id|tostring),path},
    origin_sign_conclusion:"success",run_attempt:1,window_attested:true,window_sha256:$sha}'   "$destination/origin-run.json" > "$destination/fresh-window-observation.json"
