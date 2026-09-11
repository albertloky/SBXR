#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(uname -s)" = Linux
test "$(id -u)" -eq 0
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(mktemp -d /run/sbxr-protected-open-rehearsal.XXXXXX)
cleanup() {
  local status=$?
  rm -f -- "$root/private-link" "$root/private-file" "$root/private-fifo" "$root/paths.json" "$root/result.json"
  rmdir -- "$root"
  return "$status"
}
trap cleanup EXIT
chmod 0700 "$root"
install -m 0600 /dev/null "$root/private-file"
printf 'synthetic protected fixture\n' > "$root/private-file"
mkfifo -m 0600 "$root/private-fifo"
ln -s private-file "$root/private-link"
jq -cnS --arg file "$root/private-file" --arg fifo "$root/private-fifo" \
  --arg link "$root/private-link" \
  '{paths:[$file,$fifo,$link],schema:"sbxr-v4-protected-open-paths-v1"}' \
  > "$root/paths.json"
chmod 0600 "$root/paths.json"
python3 "$operator_dir/protected-open-probe.py" --paths-file "$root/paths.json" \
  --runtime-parent /run > "$root/result.json"
jq -e '.schema == "sbxr-v4-protected-open-probe-v1" and
  .protected_reads_refused == 3 and .capabilities_zero == true and
  .no_new_privileges == true and .no_supplementary_groups == true and
  .private_runtime_empty == true and .metadata_unchanged == true and
  .account_removed == true and .runtime_removed == true' "$root/result.json" >/dev/null
test "$(stat -c '%u:%g:%a:%h:%F' "$root/private-file")" = '0:0:600:1:regular file'
test "$(stat -c '%u:%g:%a:%h:%F' "$root/private-fifo")" = '0:0:600:1:fifo'
test "$(readlink "$root/private-link")" = private-file
! getent passwd | cut -d: -f1 | grep -E '^sbxr24-[0-9a-f]{12}$' >/dev/null
