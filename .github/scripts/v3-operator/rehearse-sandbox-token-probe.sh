#!/usr/bin/env bash
# Isolated Linux/systemd fixture. This never contacts the network or a CA.
set -euo pipefail
umask 077
test "$(id -u)" -eq 0
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(mktemp -d /run/sbxr-sandbox-probe.XXXXXX)
unit=sbxr-sandbox-probe-$RANDOM.service
unit_path=/run/systemd/system/$unit
cleanup() {
  systemctl stop "$unit" >/dev/null 2>&1 || true
  rm -f "$unit_path"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf "$root"
}
trap cleanup EXIT
printf 'fixture-secret\n' > "$root/token"
chmod 0600 "$root/token"
mkdir -m 0700 "$root/staging"
cat > "$root/sleep.py" <<'PY'
import time
time.sleep(120)
PY
chmod 0700 "$root/sleep.py"
cat > "$unit_path" <<UNIT
[Service]
Type=simple
ExecStart=/usr/bin/python3 $root/sleep.py
User=root
Group=root
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
InaccessiblePaths=$root/token $root/staging /proc
ProtectSystem=strict
PrivateTmp=yes
UNIT
systemctl daemon-reload
systemctl start "$unit"
systemctl is-active --quiet "$unit"
python3 "$operator_dir/sandbox-token-probe.py" --unit "$unit" --fragment "$unit_path" \
  --executable /usr/bin/python3 --argument="$root/sleep.py" \
  --token "$root/token" --staging "$root/staging" >/dev/null
printf 'SANDBOX_TOKEN_PROBE_REHEARSAL_OK\n'
