#!/usr/bin/env bash
# Prepare and replay a fresh qualification window using the existing job roles.
# GitHub reads and local evidence only. No SSH or publication.
set -euo pipefail
umask 077
scripts="$(dirname "$0")"
repo=albertloky/SBXR
workflow=.github/workflows/candidate.yml
run_url="https://github.com/$repo/actions/runs/$GITHUB_RUN_ID"
test "$GITHUB_REPOSITORY" = "$repo"
test "$GITHUB_REF" = refs/heads/main
test "$GITHUB_RUN_ATTEMPT" = 1
[[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ && "$GITHUB_SHA" =~ ^[a-f0-9]{40}$ ]]
test "$#" -eq 1

recheck_clock() {
  jq -e --argjson now "$1" --argjson cutoff "$SECURITY_CUTOFF_UNIX" --arg run "$GITHUB_RUN_ID" '
    .window | .workflow.run_id == $run and .run_attempt == 1 and .finish_unix == $cutoff and
    .start_unix <= $now and $now + 1200 <= .test_until_unix and $now + 2760 <= .finish_unix
  ' fresh-window-decision.json >/dev/null
}

case "$1" in
  prepare)
    test -n "$FRESH_WINDOW"
    test "$FRESH_WINDOW" = "$(jq -cS . <<<"$FRESH_WINDOW")"
    jq -e 'keys == ["finish_unix","origin_run_id","start_unix","test_until_unix"] and
      (.origin_run_id | type == "string" and test("^[1-9][0-9]*$")) and
      all(.finish_unix,.start_unix,.test_until_unix; type == "number" and . == floor)' <<<"$FRESH_WINDOW" >/dev/null
    test "$(jq -r .finish_unix <<<"$FRESH_WINDOW")" = "$SECURITY_CUTOFF_UNIX"
    origin="$(jq -r .origin_run_id <<<"$FRESH_WINDOW")"
    test "$origin" != "$GITHUB_RUN_ID"
    mkdir -m 0700 fresh-source
    gh run download "$origin" -R "$repo" --name signed-qualification-manifest --dir fresh-source
    m=fresh-source/qualification-manifest.json
    jq -cer --arg repo "$repo" --arg run "$origin" --arg tag "$B_TAG" --argjson sequence "$B_SEQUENCE" '
      if .repository==$repo and .workflow.run_id==$run and (.releases|length)==1 and
        .releases[0].tag==$tag and .releases[0].sequence==$sequence and
        ($tag|test("^v[0-9]+[.][0-9]+[.][0-9]+$"))
      then .releases[0] else error("source release differs") end' "$m" > fresh-release.json
    git fetch --force --tags origin
    ancestor="$(jq -er '.workflow.commit|select(test("^[a-f0-9]{40}$"))' "$m")"
    git merge-base --is-ancestor "$ancestor" "$GITHUB_SHA"
    bash "$scripts/check-candidate-reservations.sh" "$(jq -c '[.tag]' fresh-release.json)" > fresh-source/current-reservations.json
    for ref in "$B_TAG" "release-burned/$B_TAG"; do
      python3 -B "$scripts/observe-github-resource.py" "repos/$repo/git/ref/tags/$ref" | jq -e '.state == "absent"' >/dev/null
    done
    bash "$scripts/recheck-qualified-release.sh" fresh-release.json fresh-download fresh-metadata.json
    jq -e '.draft == true and .immutable == false and .prerelease == false' fresh-metadata.json >/dev/null
    jq -cjS --slurpfile release fresh-release.json \
      '{draft,immutable,prerelease,release:$release[0],release_ref:"absent",burn_ref:"absent"}' \
      fresh-metadata.json > fresh-source/draft-observation.json
    for tag in $(git tag --list 'release-burned/*'); do
      git tag -l --format='%(contents)' "$tag"
    done | jq -csS 'sort_by(.original_tag)' > fresh-source/burned-identities.json
    ;;
  authorize)
    m=fresh-source/qualification-manifest.json
    origin="$(jq -er '.workflow.run_id|select(test("^[1-9][0-9]*$"))' "$m")"
    python3 -B "$scripts/qualification-window-authority.py" origin "$m" "$origin" > origin-observation.json
    gh api "repos/$repo/actions/runs/$GITHUB_RUN_ID/approvals" --method GET | jq -e '
      [.[]|select(.state=="approved" and (.environments|length)==1 and .environments[0].name=="acceptance-vps")] |
      length==1' >/dev/null
    # Use the same read-only sign credential and the original full-qualification
    # package check. A fresh observation must match the package in the manifest.
    gh api repos/KaringX/karing/releases/latest --method GET > fresh-karing-metadata.json
    jq -e --slurpfile manifest "$m" '
      $manifest[0].v3_attempt.packages.karing as $k |
      .draft==false and .prerelease==false and
      (.tag_name|ltrimstr("v"))==$k.version and
      any(.assets[]; .size==$k.size and .digest==("sha256:"+$k.sha256))' fresh-karing-metadata.json >/dev/null
    karing_checked="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    jq -cjS '.draft_verification_facts.construction_facts.preflight_facts' \
      fresh-source/qualification-boundary-facts.json > candidate-preflight-facts.json
    bash "$scripts/signing-latest-recheck.sh"
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    jq -cnS --arg now "$now" --arg karing_checked "$karing_checked" \
      --arg ref "$repo/$workflow@refs/heads/main" --arg path "$workflow" \
      --arg run_id "$GITHUB_RUN_ID" --arg url "$run_url" --arg commit "$GITHUB_SHA" \
      --arg digest "$(sha256sum "$m" | cut -d' ' -f1)" --argjson window "$FRESH_WINDOW" \
      --slurpfile draft fresh-source/draft-observation.json --slurpfile burned fresh-source/burned-identities.json \
      --slurpfile origin origin-observation.json --slurpfile manifest "$m" \
      --slurpfile boundary fresh-source/qualification-boundary-facts.json '
        {commit:$commit,path:$path,ref:$ref,run_id:$run_id,run_url:$url} as $workflow |
        {schema:"sbxr-release-qualification-facts-v1",stage:"qualification-window",observed_at:$now,
         approval:{environments:[{name:"acceptance-vps"}],state:"approved"},
         burned_identities:$burned[0],draft:$draft[0],origin:$origin[0],qualification_boundary_facts:$boundary[0],
         run_attempt:1,signed_manifest:$manifest[0],workflow:$workflow,
         window:($window|del(.origin_run_id)|. + {schema:"sbxr-qualification-window-v1",manifest_sha256:$digest,
           origin:$manifest[0].workflow,workflow:$workflow,release:$manifest[0].releases[0],run_attempt:1,karing_checked_at:$karing_checked})}' |
      tr -d '\n' > fresh-window-facts.json
    go run ./cmd/sbxr-release qualification < fresh-window-facts.json > fresh-window-decision.json
    test "$(jq -r .outcome fresh-window-decision.json)" = accepted
    ;;
  verify-live)
    m=handoff/qualification-manifest.json
    origin="$(jq -er '.workflow.run_id|select(test("^[1-9][0-9]*$"))' "$m")"
    python3 -B "$scripts/qualification-window-authority.py" origin "$m" "$origin" > origin-observation.json
    jq -e --slurpfile origin origin-observation.json --rawfile manifest "$m" \
      '.origin == $origin[0] and .signed_manifest == ($manifest | fromjson)' fresh-window-facts.json >/dev/null
    go run ./cmd/sbxr-release qualification < fresh-window-facts.json > fresh-window-replayed.json
    cmp fresh-window-replayed.json fresh-window-decision.json
    python3 -B "$scripts/qualification-window-authority.py" window-bundle fresh-window-decision.json "$GITHUB_RUN_ID" > handoff/fresh-window.bundle
    install -m 0600 fresh-window-decision.json handoff/fresh-window-decision.json
    # Both jobs use the same environment. The protected live job, its unique
    # successful sign dependency, and two reviews must all match this run.
    python3 -B "$scripts/qualification-window-authority.py" live "$GITHUB_RUN_ID"
    ;;
  admit)
    origin="$(jq -er '.window.origin.run_id|select(test("^[1-9][0-9]*$"))' fresh-window-decision.json)"
    claim="fresh-qualification-use-$origin"
    gh api "repos/$repo/actions/artifacts?name=$claim&per_page=100" --method GET --paginate --slurp |
      jq -e --arg claim "$claim" 'length > 0 and all(.[]; (.artifacts | type)=="array") and
        ([.[].artifacts[] | select(.name==$claim)]|length)==0' >/dev/null
    now="$(date +%s)"
    recheck_clock "$now"
    jq -cnS --arg now "$(date -u -d "@$now" +%Y-%m-%dT%H:%M:%SZ)" --arg signer "$repo/$workflow" \
      --slurpfile decision fresh-window-decision.json --slurpfile facts fresh-window-facts.json '
         {admitted_at:$now,attested:true,live_approved:true,live_job:"acceptance-vps",run_attempt:1,
          signer_workflow:$signer,window_decision:$decision[0],window_facts:$facts[0],workflow:$decision[0].window.workflow}' |
      tr -d '\n' > handoff/fresh-window-evidence.json
    ;;
  recheck-clock)
    recheck_clock "$(date +%s)"
    test "$(jq -cjS .window_decision handoff/fresh-window-evidence.json | sha256sum | cut -d' ' -f1)" = \
      "$(sha256sum fresh-window-decision.json | cut -d' ' -f1)"
    ;;
  record-restoration)
    raw=handoff/v3-packaged-live-result-facts.json
    jq -e --slurpfile proof handoff/fresh-window-evidence.json '.fresh_window==$proof[0]' "$raw" >/dev/null
    restored="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    jq -cjS --arg restored "$restored" \
      '.fresh_window.transport_restored_at=$restored | .evaluation_time=$restored' "$raw" > "$raw.next"
    mv "$raw.next" "$raw"
    ;;
  *)
    printf '%s\n' 'Unknown fresh qualification operation.' >&2
    exit 2
    ;;
esac
