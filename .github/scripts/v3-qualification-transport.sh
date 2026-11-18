#!/usr/bin/env bash
# Temporary draft delivery only; never drives or repairs product transactions.
set -euo pipefail
umask 077
root=/root/sbxr-qualification-v3
unit=sbxr-qualification-v3.service
unit_path=/etc/systemd/system/$unit
unit_link=/etc/systemd/system/multi-user.target.wants/$unit
ca=/usr/local/share/ca-certificates/sbxr-qualification-v3.crt
hosts=/etc/hosts
hosts_line='127.0.0.2 api.github.com github.com # sbxr-qualification-v3'
redirect=(-p tcp -d 127.0.0.2 --dport 443 -m comment --comment sbxr-qualification-v3 -j REDIRECT --to-ports 9443)

path_absent() {
  test ! -e "$1" && test ! -L "$1"
}

transport_owned() {
  test -d "$root"
  test ! -L "$root"
  test -f "$root/transport-owned"
  test ! -L "$root/transport-owned"
}

has_redirect() {
  local status
  if iptables -w 5 -t nat -C OUTPUT "${redirect[@]}" 2>/dev/null; then return 0; else status=$?; fi
  # Exit 1 means no matching rule; backend/lock/usage errors are not absence.
  if test "$status" -ne 1; then exit "$status"; fi
  return 1
}

# The signed attendance limit bounds a legacy default, not security approval.
# A newly approved run passes its own absolute security cutoff to `up`.
cutoff_deadline() {
  local now limit finish candidate explicit=${1:-}
  now=$(date +%s) || return 1
  limit=$((now + 21600))
  test -f "$root/qualification-manifest.json" || return 1
  test ! -L "$root/qualification-manifest.json" || return 1
  finish=$(jq -er 'if (.v3_attempt | has("attended_finish_by")) then
    "attended:" + (.v3_attempt.attended_finish_by | select(type == "string" and length > 0))
    else "legacy" end' "$root/qualification-manifest.json") || return 1
  if test "$finish" != legacy; then
    candidate=$(date -u -d "${finish#attended:}" +%s) || return 1
    candidate=$((candidate + 1800))
    if test "$candidate" -lt "$limit"; then limit=$candidate; fi
  fi
  if test -n "$explicit"; then
    [[ "$explicit" =~ ^[0-9]{1,10}$ ]] || return 1
    test "$explicit" -le "$limit" || return 1
    limit=$explicit
  fi
  # Leave time to stop the gateway and remove its staging directory.
  test "$limit" -gt "$((now + 60))" || return 1
  printf '%s\n' "$limit"
}

unit_route_owned() {
  local fragment dropins kill_mode
  fragment=$(systemctl show --property=FragmentPath --value "$unit") || return 1
  dropins=$(systemctl show --property=DropInPaths --value "$unit") || return 1
  kill_mode=$(systemctl show --property=KillMode --value "$unit") || return 1
  test "$fragment" = "$unit_path" || return 1
  test -z "$dropins" || return 1
  test "$kill_mode" = control-group
}

unit_stopped() {
  local main_pid control_pid state
  main_pid=$(systemctl show --property=MainPID --value "$unit") || return 1
  control_pid=$(systemctl show --property=ControlPID --value "$unit") || return 1
  state=$(systemctl show --property=ActiveState --value "$unit") || return 1
  test "$main_pid" = 0 || return 1
  test "$control_pid" = 0 || return 1
  case "$state" in inactive|failed) ;; *) return 1 ;; esac
}

owned_unit_link() {
  if ! path_absent "$unit_link"; then
    test -L "$unit_link"
    local target
    target=$(readlink "$unit_link")
    test "$target" = "$unit_path" || test "$target" = "../$unit"
  fi
}

# Called only after the coordinator's readers finish and the service is reaped.
# Unknown entries are retained, rather than recursively treating them as owned.
remove_staging() {
  python3 - "$root" <<'PYTHON'
import json, os, pathlib, re, stat, sys
root = pathlib.Path(sys.argv[1])
fixed = set("qualification-manifest.json qualification.bundle sbxr-release gateway.crt gateway.key ca.crt v3-qualification-transport.sh staging-owned transport-owned unit deadline runtime-deadline".split())
files, dirs = set(fixed), {"assets"}
def require(condition):
    if not condition:
        raise SystemExit("SBXR-TRANSPORT-STAGING-OWNERSHIP-REFUSED")
root_info = root.lstat()
require(stat.S_ISDIR(root_info.st_mode) and root_info.st_uid == os.geteuid() and not root_info.st_mode & 0o022)
manifest = root / "qualification-manifest.json"
# Refuse links before parsing any authority from this run's manifest.
st = manifest.lstat()
require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.geteuid())
releases = json.loads(manifest.read_text())["releases"]
require(isinstance(releases, list))
tags = set()
for release in releases:
    tag = release["tag"]
    require(isinstance(tag, str) and re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", tag) and tag not in tags)
    tags.add(tag)
    dirs.add("assets/" + tag)
    for name in ("install.sh", "release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"):
        files.add("assets/" + tag + "/" + name)
seen = []
def inspect(path, relative):
    st = path.lstat()
    require(st.st_uid == os.geteuid())
    if stat.S_ISDIR(st.st_mode):
        require((relative == "" or relative in dirs) and not st.st_mode & 0o022)
        for child in path.iterdir():
            inspect(child, str(child.relative_to(root)))
    else:
        require(relative in files and stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
    seen.append((path, st.st_dev, st.st_ino))
inspect(root, "")
# Validation finishes before the first unlink. No following of links or rm -rf.
for path, device, inode in seen:
    if path.parent == root and path.name in ("qualification-manifest.json", "transport-owned"):
        continue
    current = path.lstat()
    require((current.st_dev, current.st_ino) == (device, inode))
    if path == root:
        continue
    if stat.S_ISDIR(current.st_mode):
        path.rmdir()
    else:
        path.unlink()
manifest.unlink()
(root / "transport-owned").unlink()
root.rmdir()
PYTHON
}

finish_down() (
  transport_owned
  flock -w 15 -x 9
  transport_owned
  test "$root/transport-owned" -ef /proc/self/fd/9
  if has_redirect; then exit 1; fi
  if grep -Fxq "$hosts_line" "$hosts"; then exit 1; fi
  path_absent "$ca"
  owned_unit_link
  if ! path_absent "$unit_link"; then rm "$unit_link"; fi
  if ! path_absent "$unit_path"; then
    test ! -L "$unit_path"
    cmp -s "$root/unit" "$unit_path"
    rm "$unit_path"
  fi
  systemctl daemon-reload
  remove_staging
)

check_start() {
    test -d "$root"
    path_absent "$root/transport-owned"
    path_absent "$unit_path"
    path_absent "$unit_link"
    for name in deadline runtime-deadline unit hosts.before hosts.after; do path_absent "$root/$name"; done
    path_absent "$ca"
    if grep -Fq 'sbxr-qualification-v3' "$hosts"; then exit 1; fi
    if has_redirect; then exit 1; fi
    listeners="$(ss -H -ltn 'sport = :9443')"
    test -z "$listeners"
}
# Permit shell checks to exercise routing error handling without root mutation.
if test "${BASH_SOURCE[0]}" != "$0"; then return; fi
test "$(id -u)" -eq 0
test "$#" -ge 1
case "$1" in
  up)
    test "$#" -le 2
    cutoff=$(cutoff_deadline "${2:-}")
    check_start
    touch "$root/transport-owned"
    printf '%s\n' "$cutoff" > "$root/deadline"
    printf '%s\n' "$((cutoff - 60))" > "$root/runtime-deadline"
    cat > "$root/unit" <<UNIT
[Unit]
Description=SBXR temporary signed candidate transport
After=network.target
[Service]
Type=simple
KillMode=control-group
TimeoutStartSec=20
TimeoutStopSec=30
ExecStart=/usr/bin/bash $root/v3-qualification-transport.sh serve
StandardOutput=null
StandardError=journal
[Install]
WantedBy=multi-user.target
UNIT
    install -m 0644 "$root/unit" "$unit_path"
    systemctl daemon-reload
    unit_route_owned
    systemctl enable "$unit" >/dev/null
    systemctl start "$unit"
    for attempt in {1..30}; do
      if curl --disable --noproxy '*' --cacert "$root/ca.crt" --connect-timeout 2 --max-time 2 -fsS https://127.0.0.1:9443/repos/albertloky/SBXR/releases/latest >/dev/null; then exit 0; fi
      systemctl is-active --quiet "$unit"
      sleep 1
    done
    exit 1
    ;;
  serve)
    test "$#" -eq 1
    transport_owned
    runtime=$(cat "$root/runtime-deadline")
    [[ "$runtime" =~ ^[0-9]{1,10}$ ]]
    remaining=$((runtime - $(date +%s)))
    test "$remaining" -gt 0
    exec timeout --signal=TERM --kill-after=5 "$remaining" "$root/sbxr-release" gateway -manifest "$root/qualification-manifest.json" -bundle "$root/qualification.bundle" -assets "$root/assets" -certificate "$root/gateway.crt" -key "$root/gateway.key" -listen 127.0.0.1:9443
    ;;
  install)
    test "$#" -eq 2
    requested_tag=$2
    transport_owned
    runtime=$(cat "$root/runtime-deadline")
    [[ "$runtime" =~ ^[0-9]{1,10}$ ]]
    remaining=$((runtime - $(date +%s)))
    test "$remaining" -gt 5
    # Verify the whole bootstrap before giving it to bash. The signed gateway
    # verifies these same bytes when opening its assets.
    tag=$(jq -er --arg requested "$requested_tag" '.releases[] | select(.tag == $requested) | .tag | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))' "$root/qualification-manifest.json")
    installer="$root/assets/$tag/install.sh"
    expected=$(jq -er --arg tag "$tag" '.releases[] | select(.tag == $tag) | .assets[] | select(.name == "install.sh") | .sha256 | select(test("^[0-9a-f]{64}$"))' "$root/qualification-manifest.json")
    test -f "$installer"
    test ! -L "$installer"
    test "$(sha256sum "$installer" | cut -d' ' -f1)" = "$expected"
    fetch_seconds=$((runtime - $(date +%s) - 5))
    test "$fetch_seconds" -gt 0
    if test "$fetch_seconds" -gt 20; then fetch_seconds=20; fi
    curl --disable --noproxy '*' --cacert "$root/ca.crt" --fail --silent --show-error --connect-timeout 5 --max-time "$fetch_seconds" https://127.0.0.1:9443/albertloky/SBXR/releases/latest/download/install.sh | cmp - "$installer"
    remaining=$((runtime - $(date +%s) - 5))
    test "$remaining" -gt 0
    exec timeout --signal=TERM --kill-after=5 "$remaining" /usr/bin/bash "$installer" --qualification-gateway
    ;;
  down)
    test "$#" -eq 1
    transport_owned
    # Capture authority before stop without holding the staging lock.
    exec 9<"$root/transport-owned"
    owned_unit_link
    if ! path_absent "$unit_path"; then
      test ! -L "$unit_path"
      cmp -s "$root/unit" "$unit_path"
      unit_route_owned
      # Reap the service before locking and removing its staging files.
      systemctl stop "$unit"
    fi
    unit_stopped
    finish_down
    ;;
  *) exit 2 ;;
esac
