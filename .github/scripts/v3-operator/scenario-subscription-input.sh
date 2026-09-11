#!/usr/bin/env bash
# Store the actual public disclosure privately; stdout contains no credential.
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
scenario=${1:?scenario required}
phase=${2:?before or final required}
case "$scenario" in
  managed-renewal|recorder-live|recorder-locks|snap-refresh|unsupported-route) ;;
  identity-unavailable) test "$phase" = final ;;
  *) exit 1 ;;
esac
case "$phase" in before|final) ;; *) exit 1 ;; esac
operator_expect_scenario "$scenario"
bash "$operator_dir/link-subscription-input.sh" "$scenario" |
  python3 "$operator_dir/scenario-subscription.py" "$scenario" "$phase"
