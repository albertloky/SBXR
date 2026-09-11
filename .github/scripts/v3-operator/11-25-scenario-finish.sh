#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
scenario=${1:?scenario required}
operator_expect_scenario "$scenario"
case "$scenario" in
  managed-renewal|recorder-live|recorder-locks) package_phase=initial ;;
  snap-refresh|unsupported-route|identity-precommit|identity-postcommit|identity-unavailable|lifecycle-menu|remove-certbot|remove-writer|remove-admission-race|remove-directory-lock|secret-containment) package_phase=after-snap-refresh ;;
  karing-final) package_phase=removed ;;
  *) exit 1 ;;
esac
if test "$package_phase" = removed; then
  prove_not_installed
else
  preflight "$package_phase"
  operator_exact_candidate
  prove_running
fi
python3 "$operator_dir/scenario-entry.py" finish "$scenario"
printf 'SCENARIO_ENTRY_COMPLETED scenario=%s\n' "$scenario"
