#!/usr/bin/env bash
# Harmless smoke of the *closed* public/private entry, never root product effects.
set -euo pipefail
test "$#" -eq 2
test "$(id -u)" -ne 0
executable=$1
capture=$2
mkdir -m 0700 "$capture"
if "$executable" >"$capture/non-root.out" 2>"$capture/non-root.err"; then exit 1; fi
test ! -s "$capture/non-root.out"
grep -Fx 'SBXR: This host is unsupported; Linux Ubuntu 24.04 amd64 and root are required. No simulation fallback is selected.' "$capture/non-root.err"
for role in --provision-mutation-lock --proxy-start-authorize --subscription-serving --certbot-recorder --certbot-deploy-hook --certbot-post-hook; do
  expected=1
  test "$role" != --certbot-recorder || expected=125
  status=0
  "$executable" "$role" >"$capture/private.out" 2>"$capture/private.err" || status=$?
  test "$status" -eq "$expected"
  test ! -s "$capture/private.out"
  test ! -s "$capture/private.err"
done
