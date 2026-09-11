#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
scenario=${1:?scenario required}
case "$scenario" in
  managed-renewal|recorder-live|recorder-locks|snap-refresh) package_phase=initial ;;
  unsupported-route|identity-precommit|identity-postcommit|identity-unavailable|lifecycle-menu|remove-certbot|remove-writer|remove-admission-race|remove-directory-lock|secret-containment|karing-final) package_phase=after-snap-refresh ;;
  *) exit 1 ;;
esac
operator_expect_scenario "$scenario"
test "$STARTED_AT" = "$SCENARIO_START"
preflight "$package_phase"
operator_exact_candidate
prove_running
remember_secrets
python3 "$operator_dir/scenario-entry.py" begin "$scenario"
python3 "$operator_dir/effective-route.py" --output "$SBXR_OPERATOR_STATE_DIR/scenario-$scenario-effective-route.json"
printf 'SCENARIO_ENTRY_PREPARED scenario=%s\n' "$scenario"
