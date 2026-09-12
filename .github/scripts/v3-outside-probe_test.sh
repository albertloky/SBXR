#!/usr/bin/env bash
set -euo pipefail

test "$(uname -s)" = Linux || exit 0

root="$(cd "$(dirname "$0")/../.." && pwd)"
script="$root/.github/scripts/v3-packaged-live.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin" "$tmp/handoff"
export PROBE_PID_FILE="$tmp/client.pid"
remote_work="$tmp/remote-work"
remote_cwd="$tmp/foreign-cwd"
remote_request="$tmp/remote-request.json"
mkdir "$remote_work" "$remote_cwd"
# Keep the packaged script intact except for its fixed installed-binary path so
# this unprivileged fixture can drive the real remote dispatch and sibling load.
sed "s#/usr/local/bin/sbxr#$tmp/bin/remote-sbxr#g" "$script" > "$remote_work/v3-packaged-live.sh"
cp "$root/.github/scripts/v3-menu-session.py" "$remote_work/v3-menu-session.py"
chmod +x "$remote_work/v3-menu-session.py"
export PROBE_REMOTE_WORK="$remote_work"
export PROBE_REMOTE_CWD="$remote_cwd"
export PROBE_REMOTE_REQUEST="$remote_request"
export PROBE_REMOTE_SBXR="$tmp/bin/remote-sbxr"
export PROBE_STREAMED_SCRIPT="$tmp/streamed-script.sh"
export PROBE_CONFIRMATION_FILE="$tmp/disclosure-confirmed"
cd "$tmp"
for path in /dev/shm/sbxr-v3-client.json /dev/shm/sbxr-v3-client.log /dev/shm/sing-box.deb /dev/shm/sagernet.asc /dev/shm/sbxr-v3-workflow.log; do
  if test -e "$path" || test -L "$path"; then exit 1; fi
done

printf '%s\n' '{"mode":"v3","source_state":"v3-subscription-clean","releases":[{"tag":"v3","sequence":1,"commit":"abc","release_identity":{"release_index_sha256":"index"}}]}' > "$tmp/manifest.json"
printf '{"deadline_unix":%s}' "$(( $(date +%s) + 60 ))" > "$remote_request"

make_stub() { printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' "$2" > "$tmp/bin/$1"; chmod +x "$tmp/bin/$1"; }
make_stub ssh '
printf "%s\\n" "$*" >> "$PROBE_LOG"
if [[ "$*" == *remote-outside-disclose* ]]; then
  command=${*: -1}
  if [[ "$command" == "/usr/bin/bash -s remote-outside-disclose "* ]]; then
    sed "s#/usr/local/bin/sbxr#$PROBE_REMOTE_SBXR#g" > "$PROBE_STREAMED_SCRIPT"
    cd "$PROBE_REMOTE_CWD"
    SBXR_EXECUTABLE="$PROBE_REMOTE_SBXR" bash -c "$command" < "$PROBE_STREAMED_SCRIPT"
  else
    command=${command//\/root\/sbxr-qualification-evidence\/request.json/$PROBE_REMOTE_REQUEST}
    command=${command//\/run\/sbxr-qualification/$PROBE_REMOTE_WORK}
    cd "$PROBE_REMOTE_CWD"
    SBXR_EXECUTABLE="$PROBE_REMOTE_SBXR" bash -c "$command"
  fi
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
make_stub remote-sbxr '
cat <<"EOF"
SBXR V3
Proxy status: Running
Code: PROXY-INSTALLATION-SETUP-COMPLETE
1. Show client configuration
0. Exit
EOF
IFS= read -r choice
test "$choice" = 0 && exit 0
test "$choice" = 1
printf "%s\n" "Show client configuration? [y/N]"
IFS= read -r confirmation
test "$confirmation" = y
printf confirmed > "$PROBE_CONFIRMATION_FILE"
cat <<"EOF"
----- BEGIN SBXR CLIENT CONFIGURATION -----
{"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}],"outbounds":[{"uuid":"11111111-1111-4111-8111-111111111111"}]}
----- END SBXR CLIENT CONFIGURATION -----
Press Enter to preserve this configuration in terminal scrollback and return to the menu.
EOF
IFS= read -r continuation
test -z "$continuation"
cat <<"EOF"
Code: PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED
SBXR V3
Proxy status: Running
Code: PROXY-INSTALLATION-SETUP-COMPLETE
1. Show client configuration
0. Exit
EOF
IFS= read -r exit_choice
test "$exit_choice" = 0'
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
grep -F 'SBXR_QUALIFICATION_REQUEST=/root/sbxr-qualification-evidence/request.json /usr/bin/bash /run/sbxr-qualification/v3-packaged-live.sh remote-outside-disclose' "$tmp/probe.log" >/dev/null
! grep -F '/usr/bin/bash -s remote-outside-disclose' "$tmp/probe.log" >/dev/null
test -s "$PROBE_CONFIRMATION_FILE"

rm -f "$PROBE_CONFIRMATION_FILE"
printf '{"deadline_unix":%s}' "$(( $(date +%s) - 1 ))" > "$remote_request"
if PROBE_LOG="$tmp/probe.log" PATH="$tmp/bin:$PATH" "$tmp/bin/ssh" root@host "SBXR_QUALIFICATION_REQUEST=/root/sbxr-qualification-evidence/request.json /usr/bin/bash /run/sbxr-qualification/v3-packaged-live.sh remote-outside-disclose v3 1 abc index" >/dev/null 2> "$tmp/expired-error.log"; then
  printf '%s\n' 'outside disclosure accepted an expired request' >&2
  exit 1
fi
test ! -e "$PROBE_CONFIRMATION_FILE"
printf '{"deadline_unix":%s}' "$(( $(date +%s) + 60 ))" > "$remote_request"
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
