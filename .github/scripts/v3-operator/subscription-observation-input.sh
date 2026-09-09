#!/usr/bin/env bash
# Private pipe only. Never display or save this script's stdout.
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
operator_expect_scenario enable-schema1
operator_exact_candidate
prove_running
details=$(printf '%s\n\n0\n' "$(menu_number 'View details')" | /usr/local/bin/sbxr)
link=$(printf '%s\n' "$details" | sed -n '/^https:\/\//p')
test "$(printf '%s\n' "$link" | wc -l | tr -d ' ')" -eq 1
certificate=$(openssl x509 -in /etc/letsencrypt/live/sbxr-subscription/cert.pem -outform DER | sha256sum | cut -d' ' -f1)
python3 "$operator_dir/subscription-observation.py" \
  3< <(printf %s "$link") \
  4< <(printf %s "$certificate") \
  < <(remote_outside_disclose)
