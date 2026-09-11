#!/usr/bin/env bash
# Private pipe only. Never display or save this script's stdout.
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
operator_expect_scenario enable-schema1
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
  3< <(printf %s "$link") \
  4< <(printf %s "$certificate") \
  | jq -cS --arg scenario enable-schema1 --arg manifest "$(operator_manifest_digest)" \
      --arg request "$(sha256sum "$SBXR_QUALIFICATION_REQUEST" | cut -d' ' -f1)" \
      --arg not_before "$(jq -er .not_before "$SBXR_QUALIFICATION_REQUEST")" \
      --argjson deadline "$(jq -er .deadline_unix "$SBXR_QUALIFICATION_REQUEST")" \
      '. + {binding:{deadline_unix:$deadline,not_before:$not_before,qualification_manifest_sha256:$manifest,request_sha256:$request,scenario_id:$scenario}}'
