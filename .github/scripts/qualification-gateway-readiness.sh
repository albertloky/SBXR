#!/usr/bin/env bash
set -euo pipefail

test "$#" -ge 5
readiness_url="$1"
gateway_log="$2"
gateway_pid_file="$3"
readiness_seconds="$4"
shift 4
[[ "$readiness_seconds" =~ ^[1-9][0-9]*$ ]]

nohup "$@" >"$gateway_log" 2>&1 &
gateway_pid="$!"
printf '%s\n' "$gateway_pid" >"$gateway_pid_file"
deadline=$((SECONDS + readiness_seconds))
while ((SECONDS < deadline)); do
  if ! kill -0 "$gateway_pid" 2>/dev/null; then
    break
  fi
  remaining=$((deadline - SECONDS))
  probe_seconds="$remaining"
  if ((probe_seconds > 2)); then
    probe_seconds=2
  fi
  if curl --connect-timeout "$probe_seconds" --max-time "$probe_seconds" -fsS "$readiness_url" >/dev/null && kill -0 "$gateway_pid" 2>/dev/null; then
    disown "$gateway_pid"
    exit 0
  fi
  sleep .1
done

if kill -0 "$gateway_pid" 2>/dev/null; then
  printf 'qualification gateway readiness timed out\n' >&2
  disown "$gateway_pid"
else
  wait "$gateway_pid" || true
  printf 'qualification gateway exited before readiness\n' >&2
fi
ss -ltnp 'sport = :443' >&2 || true
sed -n '1,120p' "$gateway_log" >&2 || true
exit 1
