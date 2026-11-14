#!/usr/bin/env bash
# An explicit approved absolute deadline; never derive permission from attendance.
set -euo pipefail
cutoff=${1:-}
if ! [[ "$cutoff" =~ ^[1-9][0-9]{0,9}$ ]]; then
  printf '%s\n' 'An explicit security cutoff in UTC Unix seconds is required.' >&2
  exit 2
fi
now=$(date +%s)
if test "$cutoff" -le "$((now + 60))" || test "$cutoff" -gt "$((now + 21600))"; then
  printf '%s\n' 'Security cutoff must be more than 60 seconds and no more than six hours away.' >&2
  exit 2
fi
