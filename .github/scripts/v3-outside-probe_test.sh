#!/usr/bin/env bash
set -euo pipefail

test "$(uname -s)" = Linux || exit 0

root="$(cd "$(dirname "$0")/../.." && pwd)"
script="$root/.github/scripts/v3-packaged-live.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin" "$tmp/handoff"
export PROBE_PID_FILE="$tmp/client.pid"
cd "$tmp"
for path in /dev/shm/sbxr-v3-client.json /dev/shm/sbxr-v3-client.log /dev/shm/sing-box.deb /dev/shm/sagernet.asc /dev/shm/sbxr-v3-workflow.log; do
  if test -e "$path" || test -L "$path"; then exit 1; fi
done

printf '%s\n' '{"mode":"v3","source_state":"v3-subscription-clean","releases":[{"tag":"v3","sequence":1,"commit":"abc","release_identity":{"release_index_sha256":"index"}}]}' > "$tmp/manifest.json"

make_stub() { printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' "$2" > "$tmp/bin/$1"; chmod +x "$tmp/bin/$1"; }
make_stub ssh '
printf "%s\\n" "$*" >> "$PROBE_LOG"
if [[ "$*" == *remote-outside-disclose* ]]; then
  cat >/dev/null
  printf "%s\\n" "{\"inbounds\":[{\"type\":\"mixed\",\"tag\":\"mixed-in\",\"listen\":\"127.0.0.1\",\"listen_port\":2080}],\"outbounds\":[{\"uuid\":\"11111111-1111-4111-8111-111111111111\"}]}"
elif [[ "$*" == *api.ipify.org* ]]; then
  printf "198.51.100.8"
fi'
make_stub curl '
out=""
for arg in "$@"; do case "$arg" in -o) next=1 ;; *) if test "${next:-}" = 1; then out="$arg"; unset next; fi ;; esac; done
if test -n "$out"; then printf x > "$out"; exit 0; fi
if [[ " $* " == *" --proxy "* ]]; then printf "198.51.100.8"; else printf "203.0.113.5"; fi'
make_stub sha256sum '
if test "${PROBE_FAIL:-}" = key; then printf "wrong"; exit 0; fi
case "$1" in *sagernet.asc) printf "%s  %s\\n" 803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1 "$1" ;; *) printf "%s  %s\\n" fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf "$1" ;; esac'
make_stub stat '
if [[ "$*" == *"%s"* ]]; then printf 24597120; elif [[ "$*" == *"%a"* ]]; then printf 600; else /usr/bin/stat "$@"; fi'
make_stub findmnt 'printf tmpfs'
make_stub ss 'count=0; test -f "$PROBE_SS_COUNT" && count="$(<"$PROBE_SS_COUNT")"; count=$((count + 1)); printf "%s" "$count" > "$PROBE_SS_COUNT"; test "$count" -eq 1 && printf "LISTEN 0 0 127.0.0.1:2080 0.0.0.0:*\\n"'
make_stub pgrep 'exit 1'
make_stub probe-sing-box 'if test "${PROBE_FAIL:-}" = secret; then printf "11111111-1111-4111-8111-111111111111" >&2; fi; if test "$1" = run; then printf "%s" "$$" > "$PROBE_PID_FILE"; exec -a sing-box sleep 600; fi'
make_stub dpkg-deb 'dest="${@: -1}"; mkdir -p "$dest/usr/bin"; ln -s "$PROBE_SING_BOX" "$dest/usr/bin/sing-box"'

if PROBE_LOG="$tmp/probe.log" PATH="$tmp/bin:$PATH" RUNNER_TEMP="$tmp" bash "$script" outside-probe host key known "$tmp/manifest.json" arbitrary-command "$(( $(date +%s) + 60 ))" >/dev/null 2>&1; then
  printf '%s\n' 'outside probe accepted an unbound scenario' >&2
  exit 1
fi
if ! PROBE_LOG="$tmp/probe.log" PROBE_SS_COUNT="$tmp/ss-count" PROBE_SING_BOX="$tmp/bin/probe-sing-box" PATH="$tmp/bin:$PATH" RUNNER_TEMP="$tmp" bash "$script" outside-probe host key known "$tmp/manifest.json" baseline-clean "$(( $(date +%s) + 60 ))" > "$tmp/result.json"; then
  printf '%s\n' 'outside probe dispatch failed' >&2
  exit 1
fi
jq -e '.schema == "sbxr-v3-outside-probe-reply-v1" and .scenario_id == "baseline-clean" and .observation.egress_matched and .observation.outside_routes_differ' "$tmp/result.json" >/dev/null
grep -F 'remote-outside-disclose' "$tmp/probe.log" >/dev/null
test ! -e /dev/shm/sbxr-v3-client.json
test ! -e /dev/shm/sbxr-v3-client.log
test ! -e /dev/shm/sing-box.deb
test ! -e /dev/shm/sagernet.asc
test ! -e /dev/shm/sbxr-v3-workflow.log
test -s "$PROBE_PID_FILE"
if kill -0 "$(<"$PROBE_PID_FILE")" 2>/dev/null; then exit 1; fi

for failure in key secret; do
  if PROBE_FAIL="$failure" PROBE_LOG="$tmp/probe.log" PROBE_SS_COUNT="$tmp/ss-count" PROBE_SING_BOX="$tmp/bin/probe-sing-box" PATH="$tmp/bin:$PATH" RUNNER_TEMP="$tmp" bash "$script" outside-probe host key known "$tmp/manifest.json" baseline-clean "$(( $(date +%s) + 60 ))" > "$tmp/refused.json" 2> "$tmp/error.log"; then
    printf '%s\n' "outside probe accepted $failure failure" >&2
    exit 1
  fi
  test ! -s "$tmp/refused.json"
  ! grep -F '11111111-1111-4111-8111-111111111111' "$tmp/error.log"
  for path in /dev/shm/sbxr-v3-client.json /dev/shm/sbxr-v3-client.log /dev/shm/sing-box.deb /dev/shm/sagernet.asc /dev/shm/sbxr-v3-workflow.log "$tmp/sbxr-v3-client"; do test ! -e "$path"; done
done

printf sentinel > /dev/shm/sbxr-v3-client.json
if PROBE_LOG="$tmp/probe.log" PATH="$tmp/bin:$PATH" RUNNER_TEMP="$tmp" bash "$script" outside-probe host key known "$tmp/manifest.json" baseline-clean "$(( $(date +%s) + 60 ))" > "$tmp/refused.json"; then
  exit 1
fi
test "$(</dev/shm/sbxr-v3-client.json)" = sentinel
rm /dev/shm/sbxr-v3-client.json
