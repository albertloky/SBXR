#!/usr/bin/env bash
# Temporary draft delivery only; never drives or repairs product transactions.
set -euo pipefail
umask 077
root=/root/sbxr-qualification-v3
unit=sbxr-qualification-v3.service
unit_path=/etc/systemd/system/$unit
ca=/usr/local/share/ca-certificates/sbxr-qualification-v3.crt
hosts=/etc/hosts
hosts_line='127.0.0.2 api.github.com github.com # sbxr-qualification-v3'
redirect=(-p tcp -d 127.0.0.2 --dport 443 -m comment --comment sbxr-qualification-v3 -j REDIRECT --to-ports 9443)

has_redirect() {
  local status
  if iptables -w -t nat -C OUTPUT "${redirect[@]}" 2>/dev/null; then return 0; else status=$?; fi
  # Exit 1 means no matching rule; backend/lock/usage errors are not absence.
  if test "$status" -ne 1; then exit "$status"; fi
  return 1
}

route_down() {
  if has_redirect; then
    iptables -w -t nat -D OUTPUT "${redirect[@]}"
  fi
  # Remove only our exact hosts line; preserve concurrent unrelated changes.
  if test -f "$root/hosts.after" && cmp -s "$root/hosts.after" "$hosts"; then
    cat "$root/hosts.before" > "$hosts"
  else
    sed -i '\|^127\.0\.0\.2 api\.github\.com github\.com # sbxr-qualification-v3$|d' "$hosts"
  fi
  if test -e "$ca"; then
    cmp -s "$root/ca.crt" "$ca"
    rm "$ca"
  fi
  # Always refresh: a prior cleanup may have removed the source then failed.
  update-ca-certificates >/dev/null
}
check_start() {
    test -d "$root"
    test ! -e "$root/transport-owned"
    test ! -e "$unit_path"
    test ! -e "$ca"
    if grep -Fq 'sbxr-qualification-v3' "$hosts"; then exit 1; fi
    if has_redirect; then exit 1; fi
    listeners="$(ss -H -ltn 'sport = :9443')"
    test -z "$listeners"
}
# Permit shell checks to exercise routing error handling without root mutation.
if test "${BASH_SOURCE[0]}" != "$0"; then return; fi
test "$(id -u)" -eq 0
test "$#" -eq 1
case "$1" in
  up)
    check_start
    touch "$root/transport-owned"
    date -u -d "+6 hours" +%s > "$root/deadline"
    cat > "$root/unit" <<UNIT
[Unit]
Description=SBXR temporary signed candidate transport
After=network.target
[Service]
Type=simple
ExecStartPre=/usr/bin/bash $root/v3-qualification-transport.sh route-up
ExecStart=/usr/bin/bash $root/v3-qualification-transport.sh serve
ExecStopPost=/usr/bin/bash $root/v3-qualification-transport.sh route-down
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
UNIT
    install -m 0644 "$root/unit" "$unit_path"
    systemctl daemon-reload
    systemctl enable "$unit" >/dev/null
    systemctl start "$unit"
    for attempt in {1..30}; do
      if curl --connect-timeout 2 --max-time 2 -fsS https://api.github.com/repos/albertloky/SBXR/releases/latest >/dev/null; then exit 0; fi
      systemctl is-active --quiet "$unit"
      sleep 1
    done
    exit 1
    ;;
  serve)
    remaining=$(( $(cat "$root/deadline") - $(date +%s) ))
    test "$remaining" -gt 0
    exec timeout --signal=TERM "$remaining" "$root/sbxr-release" gateway -manifest "$root/qualification-manifest.json" -bundle "$root/qualification.bundle" -assets "$root/assets" -certificate "$root/gateway.crt" -key "$root/gateway.key" -listen 127.0.0.1:9443
    ;;
  route-up)
    test -f "$root/transport-owned"
    test "$(date +%s)" -lt "$(cat "$root/deadline")"
    if test -e "$ca"; then cmp -s "$root/ca.crt" "$ca"; else install -m 0644 "$root/ca.crt" "$ca"; fi
    update-ca-certificates >/dev/null
    if ! grep -Fxq "$hosts_line" "$hosts"; then
      cp "$hosts" "$root/hosts.before"
      {
        cat "$root/hosts.before"
        if test "$(tail -c 1 "$root/hosts.before" | wc -l)" -eq 0; then printf '\n'; fi
        printf '%s\n' "$hosts_line"
      } > "$root/hosts.after"
      cat "$root/hosts.after" > "$hosts"
    fi
    if ! has_redirect; then iptables -w -t nat -A OUTPUT "${redirect[@]}"; fi
    ;;
  route-down)
    test -f "$root/transport-owned"
    route_down
    ;;
  down)
    test -f "$root/transport-owned"
    if test -e "$unit_path"; then
      cmp -s "$root/unit" "$unit_path"
      systemctl disable "$unit" >/dev/null
      systemctl stop "$unit"
    fi
    route_down
    if test -e "$unit_path"; then rm "$unit_path"; fi
    systemctl daemon-reload
    if has_redirect; then exit 1; fi
    if grep -Fxq "$hosts_line" "$hosts"; then exit 1; fi
    test ! -e "$ca"
    # This directory contains only this workflow's handoff and transport keys.
    find "$root" -depth -delete
    ;;
  *) exit 2 ;;
esac
