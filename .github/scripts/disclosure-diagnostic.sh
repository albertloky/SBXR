#!/usr/bin/env bash
# Diagnostic-only collection; no qualification result or product cleanup.
set -euo pipefail
umask 077
test "$#" -eq 3
remote=(python3 .github/scripts/bounded-ssh.py 30 -i "$2" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$3" -o ConnectTimeout=15 "root@$1")
jq -e '.v3_attempt.diagnostic != null and .v3_attempt.required_scenarios == ["mvp-install"]' handoff/qualification-manifest.json >/dev/null
manifest_digest=$(sha256sum handoff/qualification-manifest.json | cut -d' ' -f1)
[[ "$manifest_digest" =~ ^[0-9a-f]{64}$ ]]
"${remote[@]}" "python3 - prepare --manifest-sha256 '$manifest_digest'" < .github/scripts/disclosure-diagnostic.py > handoff/diagnostic-handoff.json
binding=$(jq -er '.state_sha256 | select(test("^[0-9a-f]{64}$"))' handoff/diagnostic-handoff.json)
# No EXIT write to a request: an old or stopped run is never overwritten.
while true; do
  state=$("${remote[@]}" "python3 - status --manifest-sha256 '$manifest_digest' --state-sha256 '$binding'" < .github/scripts/disclosure-diagnostic.py)
  case "$state" in
    operator-finished) printf '%s\n' 'Diagnostic operator finished; no qualification result.'; break ;;
    waiting|restore-now) ;;
    *) exit 1 ;;
  esac
  sleep 5
done
