#!/usr/bin/env bash
# Secret-bearing stdout: connect only to a protected file or pipe.
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
scenario=${1:?link scenario required}
case "$scenario" in link-precommit|link-postcommit|managed-renewal|recorder-live|recorder-locks|snap-refresh|unsupported-route|identity-unavailable) ;; *) exit 1 ;; esac
operator_expect_scenario "$scenario"
operator_exact_candidate
prove_running
number=$(menu_number 'View details')
test -n "$number"
details=$(printf '%s\n\n0\n' "$number" | /usr/local/bin/sbxr)
link=$(printf '%s\n' "$details" | sed -n '/^https:\/\//p')
test "$(printf '%s\n' "$link" | wc -l | tr -d ' ')" -eq 1
certificate=$(openssl x509 -in /etc/letsencrypt/live/sbxr-subscription/cert.pem -outform DER | sha256sum | cut -d' ' -f1)
configuration=$(remote_outside_disclose)
printf %s "$configuration" | python3 "$operator_dir/subscription-observation.py" \
  3< <(printf %s "$link") 4< <(printf %s "$certificate") \
  | jq -cS --arg scenario "$scenario" --arg manifest "$(operator_manifest_digest)" \
      --arg request "$(sha256sum "$SBXR_QUALIFICATION_REQUEST" | cut -d' ' -f1)" \
      --arg not_before "$(jq -er .not_before "$SBXR_QUALIFICATION_REQUEST")" \
      --argjson deadline "$(jq -er .deadline_unix "$SBXR_QUALIFICATION_REQUEST")" \
      '. + {binding:{deadline_unix:$deadline,not_before:$not_before,qualification_manifest_sha256:$manifest,request_sha256:$request,scenario_id:$scenario}}'
