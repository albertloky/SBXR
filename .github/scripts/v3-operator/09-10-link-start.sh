#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
scenario=${1:?link scenario required}
case "$scenario" in link-precommit|link-postcommit) ;; *) exit 1 ;; esac
test "$SCENARIO_START" = "$STARTED_AT"
operator_expect_scenario "$scenario"
preflight initial
operator_exact_candidate
prove_running
remember_secrets
bash "$operator_dir/link-subscription-input.sh" "$scenario" \
  | python3 "$operator_dir/link-entry.py" prepare "$scenario"
python3 "$operator_dir/effective-route.py" --output "$SBXR_OPERATOR_STATE_DIR/link-$scenario-effective-route.json"
printf 'LINK_INITIAL_PREPARED scenario=%s\n' "$scenario"
