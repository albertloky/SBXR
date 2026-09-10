#!/usr/bin/env bash
set -euo pipefail
umask 077

operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
workspace=$(cd -- "$operator_dir/../../.." && pwd)
module=$workspace/.github/scripts/v3-packaged-live.sh
root=$(mktemp -d "${TMPDIR:-/tmp}/sbxr-v3-operator-rehearsal.XXXXXX")
trap 'rm -rf "$root"' EXIT
state=$root/state
evidence=$root/evidence
transport=$root/transport
executed_entries=$root/executed-entries
mkdir -m 0700 "$state" "$evidence" "$transport" "$executed_entries"
protected_input_refusals=0

printf 'fixture executable\n' > "$root/sbxr.fixture"
chmod 0700 "$root/sbxr.fixture"
executable_digest=$(sha256sum "$root/sbxr.fixture" | cut -d' ' -f1)
index=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
commit=2bcdd645124178609e2d73c1e08ef50e204b0c89
jq -cnS --arg commit "$commit" --arg index "$index" '
  {mode:"v3",releases:[{commit:$commit,release_identity:{commit:$commit,release_index_sha256:$index,repository:"albertloky/SBXR",tag:"v9.9.9"},sequence:999,tag:"v9.9.9"}],schema:"sbxr-qualification-manifest-v3",source_state:"v3-subscription-clean"}
' > "$root/manifest.json"
manifest_digest=$(sha256sum "$root/manifest.json" | cut -d' ' -f1)
jq -cnS --arg commit "$commit" --arg executable "$executable_digest" --arg index "$index" '
  {architecture:"amd64",commit:$commit,executable_sha256:$executable,release_index_sha256:$index,repository:"albertloky/SBXR",sequence:999,tag:"v9.9.9"}
' > "$root/installed.fixture.json"

cat > "$root/hook.sh" <<'HOOK'
rehearsal_stop() {
  if test "${REHEARSAL_STOP_AT:-}" = "$1"; then return 97; fi
}
preflight() {
  if test -n "${REHEARSAL_EXPECT_PACKAGE_SET:-}"; then test "${1:-initial}" = "$REHEARSAL_EXPECT_PACKAGE_SET"; fi
  rehearsal_stop preflight
}
prove_not_installed() { :; }
prove_not_set_up() { :; }
prove_running() { :; }
prove_status() { :; }
view_details() { :; }
protected_inventory() { printf 'fixture-inventory\n'; }
remember_secrets() { rehearsal_stop remember_secrets; }
scan_retained_capture() { local path; for path in "$@"; do test -f "$path"; done; }
scan_transport_captures() { rehearsal_stop scan_transport_captures; }
scan_journal() { rehearsal_stop scan_journal; }
action() { rehearsal_stop action; return 96; }
run_action() { rehearsal_stop run_action; return 96; }
interrupt_at() { rehearsal_stop interrupt_at; return 96; }
install() { rehearsal_stop install; return 96; }
remote_outside_disclose() { rehearsal_stop remote_outside_disclose; return 96; }
install_candidate() {
  test "$TAG:$SEQUENCE:$COMMIT:$INDEX" = "v9.9.9:999:2bcdd645124178609e2d73c1e08ef50e204b0c89:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  cp "$REHEARSAL_EXECUTABLE_SOURCE" "$SBXR_EXECUTABLE"
  cp "$REHEARSAL_INSTALLED_SOURCE" "$SBXR_INSTALLED_RECORD"
  chmod 0700 "$SBXR_EXECUTABLE"
  chmod 0600 "$SBXR_INSTALLED_RECORD"
  printf '%s\n' "$TAG:$SEQUENCE:$COMMIT:$INDEX" > "$REHEARSAL_INSTALL_MARKER"
}
stat() { printf 'root:root:600:1:regular file\n'; }
chown() { :; }
mv() {
  if test "${1:-}" = -T; then shift; fi
  command mv "$@"
}
HOOK
chmod 0600 "$root/hook.sh" "$root/manifest.json" "$root/installed.fixture.json"

write_request() {
  local scenario=$1
  jq -cnS --arg digest "$manifest_digest" --arg scenario "$scenario" \
    '{deadline_unix:4102444800,qualification_manifest_sha256:$digest,scenario_id:$scenario}' > "$root/request.json"
  chmod 0600 "$root/request.json"
}

record_entry() {
  : > "$executed_entries/$1"
}

operator_env=(
  PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
  SBXR_V3_PACKAGED_LIVE_MODULE="$module"
  SBXR_QUALIFICATION_MANIFEST="$root/manifest.json"
  SBXR_QUALIFICATION_REQUEST="$root/request.json"
  SBXR_INSTALLED_RECORD="$root/installed.json"
  SBXR_EXECUTABLE="$root/sbxr"
  SBXR_OPERATOR_STATE_DIR="$state"
  SBXR_OPERATOR_EVIDENCE_DIR="$evidence"
  SBXR_TRANSPORT_ROOT="$transport"
  SBXR_TRANSPORT_UNIT=sbxr-qualification-v3.service
  SBXR_OPERATOR_REHEARSAL=1
  SBXR_OPERATOR_REHEARSAL_HOOK="$root/hook.sh"
  REHEARSAL_EXECUTABLE_SOURCE="$root/sbxr.fixture"
  REHEARSAL_INSTALLED_SOURCE="$root/installed.fixture.json"
  STARTED_AT=2026-09-09T10:40:00Z
  SCENARIO_START=2026-09-09T10:40:00Z
)

run_until_boundary() {
  local script=$1 scenario=$2 boundary=$3 expect_install=${4:-false} status=0 marker
  marker=$root/${script%.sh}.install
  write_request "$scenario"
  env -i "${operator_env[@]}" REHEARSAL_STOP_AT="$boundary" REHEARSAL_INSTALL_MARKER="$marker" \
    /bin/bash --noprofile --norc "$operator_dir/$script" > "$root/$script.stdout" 2> "$root/$script.stderr" || status=$?
  test "$status" -eq 97
  test ! -s "$root/$script.stdout"
  test ! -s "$root/$script.stderr"
  if test "$expect_install" = true; then
    test "$(<"$marker")" = "v9.9.9:999:$commit:$index"
  else
    test ! -e "$marker"
  fi
  record_entry "$script"
}

expect_protected_input_refusal() {
  local name=$1 expected=$2 status=0
  shift 2
  env -i "${operator_env[@]}" "$@" REHEARSAL_INSTALL_MARKER="$root/unexpected-$name.install" \
    /bin/bash --noprofile --norc "$operator_dir/01-baseline-clean-start.sh" \
    > /dev/null 2> "$root/$name.stderr" || status=$?
  test "$status" -ne 0
  grep -F "$expected" "$root/$name.stderr" >/dev/null
  test ! -e "$root/unexpected-$name.install"
  protected_input_refusals=$((protected_input_refusals + 1))
  record_entry 01-baseline-clean-start.sh
}

for script in "$operator_dir"/*.sh; do bash -n "$script"; done
binding_scan_status=0
grep -En '__SIGNED_MANIFEST_SHA256__|release-prep-fresh-|342[0-9]{6,}|candidate\.yml' "$operator_dir"/0*.sh "$operator_dir/operator-support.sh" > "$root/stale-bindings" || binding_scan_status=$?
if test "$binding_scan_status" -ne 1; then
  printf 'stale binding found or binding scan failed\n' >&2
  exit 1
fi

if test "$(uname -s)" = Linux; then
  test -x /usr/bin/setsid
  test -x /usr/bin/script
  mkdir -m 0700 "$root/pty-bin" "$root/pty-work"
  cat > "$root/pty-bin/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
test "$*" = '-fsS https://github.com/albertloky/SBXR/releases/latest/download/install.sh'
/usr/bin/cat "$REHEARSAL_INSTALLER"
CURL
  cat > "$root/pty-installer.sh" <<'INSTALLER'
#!/usr/bin/env bash
set -euo pipefail
if (: </dev/tty >/dev/tty) 2>/dev/null; then
  printf 'interactive-autolaunch\n' > "$REHEARSAL_PTY_MARKER"
  exit 91
fi
printf 'FIXTURE_INSTALL_NONINTERACTIVE\n'
INSTALLER
  cat > "$root/pty-harness.sh" <<'HARNESS'
#!/usr/bin/env bash
set -euo pipefail
(: </dev/tty >/dev/tty)
source "$REHEARSAL_MODULE"
scan_vps_capture() { return 97; }
install_candidate
HARNESS
  chmod 0700 "$root/pty-bin/curl" "$root/pty-installer.sh" "$root/pty-harness.sh"
  pty_status=0
  REHEARSAL_INSTALLER="$root/pty-installer.sh" \
    REHEARSAL_MODULE="$module" \
    REHEARSAL_PTY_MARKER="$root/pty-autolaunch" \
    WORK="$root/pty-work" \
    PATH="$root/pty-bin:$PATH" \
    /usr/bin/script -qefc "/bin/bash --noprofile --norc '$root/pty-harness.sh'" /dev/null \
      > "$root/pty.stdout" 2> "$root/pty.stderr" || pty_status=$?
  test "$pty_status" -eq 97
  test ! -e "$root/pty-autolaunch"
  test "$(<"$root/pty-work/install-output")" = FIXTURE_INSTALL_NONINTERACTIVE
fi

status=0
env -i PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin \
  /bin/bash --noprofile --norc "$operator_dir/01-baseline-clean-start.sh" > /dev/null 2> "$root/missing.stderr" || status=$?
test "$status" -ne 0
grep -F 'SBXR_V3_PACKAGED_LIVE_MODULE is required' "$root/missing.stderr" >/dev/null
protected_input_refusals=$((protected_input_refusals + 1))
record_entry 01-baseline-clean-start.sh

write_request baseline-clean
ln -s "$root/manifest.json" "$root/manifest-link.json"
ln -s "$root/request.json" "$root/request-link.json"
ln -s "$root/hook.sh" "$root/hook-link.sh"
ln -s "$state" "$root/state-link"
ln -s "$evidence" "$root/evidence-link"
expect_protected_input_refusal manifest-symlink \
  'SBXR_QUALIFICATION_MANIFEST must name a non-symlink regular file' \
  SBXR_QUALIFICATION_MANIFEST="$root/manifest-link.json"
expect_protected_input_refusal request-symlink \
  'SBXR_QUALIFICATION_REQUEST must name a non-symlink regular file' \
  SBXR_QUALIFICATION_REQUEST="$root/request-link.json"
expect_protected_input_refusal hook-symlink \
  'SBXR_OPERATOR_REHEARSAL_HOOK must name a non-symlink regular file' \
  SBXR_OPERATOR_REHEARSAL_HOOK="$root/hook-link.sh"
expect_protected_input_refusal state-symlink \
  'SBXR_OPERATOR_STATE_DIR must name a non-symlink directory' \
  SBXR_OPERATOR_STATE_DIR="$root/state-link"
expect_protected_input_refusal evidence-symlink \
  'SBXR_OPERATOR_EVIDENCE_DIR must name a non-symlink directory' \
  SBXR_OPERATOR_EVIDENCE_DIR="$root/evidence-link"

run_until_boundary 01-baseline-clean-start.sh baseline-clean action true
run_until_boundary 02-baseline-refusal.sh baseline-refusal install true
run_until_boundary 03-baseline-precommit.sh baseline-precommit interrupt_at
run_until_boundary 04-baseline-postcommit-start.sh baseline-postcommit interrupt_at
run_until_boundary 05-baseline-drift.sh baseline-drift remember_secrets
run_until_boundary 06-baseline-removal.sh baseline-removal remember_secrets
run_until_boundary 07-identity-absent-start.sh identity-absent action true
run_until_boundary 08-enable-schema1-setup.sh enable-schema1 run_action true

# Scenario 19 occurs after the supported snap refresh and must bind the second
# package identity set before it reaches any public lifecycle action.
write_request lifecycle-menu
status=0
env -i "${operator_env[@]}" SBXR_INSTALLED_RECORD=/var/lib/sbxr/installed.json \
  SBXR_EXECUTABLE=/usr/local/bin/sbxr REHEARSAL_EXPECT_PACKAGE_SET=after-snap-refresh \
  REHEARSAL_STOP_AT=preflight REHEARSAL_INSTALL_MARKER="$root/unexpected-19.install" \
  /bin/bash --noprofile --norc "$operator_dir/19-lifecycle-menu.sh" > "$root/19.stdout" 2> "$root/19.stderr" || status=$?
test "$status" -eq 97
test ! -s "$root/19.stdout" && test ! -s "$root/19.stderr"
test ! -e "$root/unexpected-19.install"
record_entry 19-lifecycle-menu.sh

jq -cnS '{started_at:"2026-09-09T10:40:00Z"}' > "$state/01-state.json"
jq -cnS '{started_at:"2026-09-09T10:40:00Z"}' > "$state/04-state.json"
jq -cnS '{started_at:"2026-09-09T10:40:00Z"}' > "$state/07-state.json"
jq -cnS '{started_at:"2026-09-09T10:40:00Z"}' > "$state/08-private.json"
jq -cnS '{completed_at:"2026-09-09T10:40:03Z",observation:{egress_matched:true,outside_routes_differ:true,runner_cleanup_complete:true},scenario_id:"baseline-clean",schema:"sbxr-v3-outside-probe-reply-v1",started_at:"2026-09-09T10:40:02Z"}' > "$evidence/outside-reply-baseline-clean.json"
jq -cnS '{completed_at:"2026-09-09T10:40:03Z",observation:{egress_matched:true,outside_routes_differ:true,runner_cleanup_complete:true},scenario_id:"baseline-postcommit",schema:"sbxr-v3-outside-probe-reply-v1",started_at:"2026-09-09T10:40:02Z"}' > "$evidence/outside-reply-baseline-postcommit.json"
chmod 0600 "$state"/*.json "$evidence"/*.json

run_until_boundary 01-baseline-clean-finish.sh baseline-clean remember_secrets
run_until_boundary 04-baseline-postcommit-finish.sh baseline-postcommit remember_secrets
run_until_boundary 07-identity-absent-rotate.sh identity-absent preflight
run_until_boundary 07-identity-absent-finish.sh identity-absent preflight

write_request enable-schema1
status=0
env -i "${operator_env[@]}" REHEARSAL_STOP_AT=preflight \
  REHEARSAL_INSTALL_MARKER="$root/unexpected-08-finish.install" \
  /bin/bash --noprofile --norc "$operator_dir/08-enable-schema1-finish.sh" enable \
  > "$root/08-enable-schema1-finish.stdout" 2> "$root/08-enable-schema1-finish.stderr" || status=$?
test "$status" -eq 97
test ! -s "$root/08-enable-schema1-finish.stdout" && test ! -s "$root/08-enable-schema1-finish.stderr"
test ! -e "$root/unexpected-08-finish.install"
record_entry 08-enable-schema1-finish.sh

jq -cnS --arg secret "$state/24-known-secrets.json" \
  '{schema:"sbxr-v3-secret-containment-spec-v1",cleanup_paths:[$secret]}' > "$root/24-spec.json"
jq -cnS '{schema:"sbxr-v3-known-secrets-v1",secrets:[]}' > "$state/24-known-secrets.json"
chmod 0600 "$root/24-spec.json" "$state/24-known-secrets.json"
write_request secret-containment
status=0
env -i "${operator_env[@]}" REHEARSAL_EXPECT_PACKAGE_SET=after-snap-refresh REHEARSAL_STOP_AT=preflight \
  REHEARSAL_INSTALL_MARKER="$root/unexpected-24.install" \
  SBXR_SECRET_CONTAINMENT_KNOWN_SECRETS="$state/24-known-secrets.json" \
  SBXR_SECRET_CONTAINMENT_SPEC="$root/24-spec.json" \
  /bin/bash --noprofile --norc "$operator_dir/24-secret-containment.sh" \
  > "$root/24-secret-containment.stdout" 2> "$root/24-secret-containment.stderr" || status=$?
test "$status" -eq 97
test ! -s "$root/24-secret-containment.stdout" && test ! -s "$root/24-secret-containment.stderr"
test ! -e "$root/unexpected-24.install"
record_entry 24-secret-containment.sh

for pair in '01-outside-request.sh baseline-clean probe-1' '04-outside-request.sh baseline-postcommit probe-2'; do
  read -r script scenario request_id <<<"$pair"
  rm -f "$evidence/outside-request.json" "$evidence/outside-request.tmp" "$evidence/outside-reply-$scenario.json"
  write_request "$scenario"
  env -i "${operator_env[@]}" REHEARSAL_INSTALL_MARKER="$root/unused.install" \
    /bin/bash --noprofile --norc "$operator_dir/$script" > "$root/$script.stdout" 2> "$root/$script.stderr"
  test ! -s "$root/$script.stderr"
  jq -e --arg digest "$manifest_digest" --arg scenario "$scenario" --arg request "$request_id" '
    .schema == "sbxr-v3-outside-probe-request-v1" and
    .qualification_manifest_sha256 == $digest and .scenario_id == $scenario and
    .request_id == $request and .deadline_unix == 4102444800
  ' "$evidence/outside-request.json" >/dev/null
  record_entry "$script"
done

write_request baseline-clean
jq '.qualification_manifest_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
  "$root/request.json" > "$root/request.bad"
mv "$root/request.bad" "$root/request.json"
chmod 0600 "$root/request.json"
rm -f "$evidence/outside-request.json"
status=0
env -i "${operator_env[@]}" REHEARSAL_INSTALL_MARKER="$root/unused.install" \
  /bin/bash --noprofile --norc "$operator_dir/01-outside-request.sh" > /dev/null 2> "$root/digest.stderr" || status=$?
test "$status" -ne 0
test ! -e "$evidence/outside-request.json"
protected_input_refusals=$((protected_input_refusals + 1))
record_entry 01-outside-request.sh

python3 -m unittest discover -s "$operator_dir" -p 'test_*.py' >/dev/null
syntax_count=$(find "$operator_dir" -maxdepth 1 -type f -name '*.sh' | wc -l | tr -d ' ')
expected_entry_count=$(find "$operator_dir" -maxdepth 1 -type f -name '[0-9][0-9]-*.sh' | wc -l | tr -d ' ')
entry_count=$(find "$executed_entries" -maxdepth 1 -type f | wc -l | tr -d ' ')
test "$entry_count" -eq "$expected_entry_count"
for script in "$operator_dir"/[0-9][0-9]-*.sh; do
  test -f "$executed_entries/$(basename "$script")"
done
printf 'V3_OPERATOR_REHEARSAL_OK syntax=%s protected-input-refusals=%s bounded-entries=%s helper-tests=passed live-scenarios=not-run\n' \
  "$syntax_count" "$protected_input_refusals" "$entry_count"
