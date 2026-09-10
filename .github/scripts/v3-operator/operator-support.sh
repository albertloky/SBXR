#!/usr/bin/env bash
set -euo pipefail
umask 077

operator_require_absolute() {
  local name=$1 value=${!1:-}
  test -n "$value" || { printf '%s is required\n' "$name" >&2; return 1; }
  case "$value" in /*) ;; *) printf '%s must be an absolute path\n' "$name" >&2; return 1 ;; esac
}

operator_require_file() {
  operator_require_absolute "$1"
  local value=${!1}
  test -f "$value" && test ! -L "$value" || {
    printf '%s must name a non-symlink regular file\n' "$1" >&2
    return 1
  }
}

operator_require_directory() {
  operator_require_absolute "$1"
  local value=${!1}
  test -d "$value" && test ! -L "$value" || {
    printf '%s must name a non-symlink directory\n' "$1" >&2
    return 1
  }
}

operator_initialize() {
  operator_require_file SBXR_V3_PACKAGED_LIVE_MODULE
  operator_require_file SBXR_QUALIFICATION_MANIFEST
  operator_require_file SBXR_QUALIFICATION_REQUEST
  # These two paths are expected to be absent at clean-install entry points;
  # exact_candidate validates the files after install_candidate creates them.
  operator_require_absolute SBXR_INSTALLED_RECORD
  operator_require_absolute SBXR_EXECUTABLE
  operator_require_directory SBXR_OPERATOR_STATE_DIR
  operator_require_directory SBXR_OPERATOR_EVIDENCE_DIR
  operator_require_directory SBXR_TRANSPORT_ROOT
  : "${SBXR_TRANSPORT_UNIT:?SBXR_TRANSPORT_UNIT is required}"
  [[ "$SBXR_TRANSPORT_UNIT" =~ ^[A-Za-z0-9@_.-]+\.service$ ]]

  # Candidate authority remains in the tracked packaged-live module.
  # shellcheck source=../v3-packaged-live.sh
  source "$SBXR_V3_PACKAGED_LIVE_MODULE"
  declare -F run_action >/dev/null
  declare -F exact_candidate >/dev/null
  declare -F install_candidate >/dev/null

  if test -n "${SBXR_OPERATOR_REHEARSAL_HOOK:-}"; then
    test "${SBXR_OPERATOR_REHEARSAL:-}" = 1
    operator_require_file SBXR_OPERATOR_REHEARSAL_HOOK
    # Local rehearsal may replace host-mutating helpers, but still exercises
    # the tracked entry point and the real input/candidate binding above.
    source "$SBXR_OPERATOR_REHEARSAL_HOOK"
  fi
}

load_candidate_identity() {
  local manifest_digest candidate
  manifest_digest=$(sha256sum "$SBXR_QUALIFICATION_MANIFEST" | cut -d' ' -f1) || return 1
  jq -e --arg digest "$manifest_digest" '.qualification_manifest_sha256 == $digest' "$SBXR_QUALIFICATION_REQUEST" >/dev/null || return 1
  candidate=$(jq -ce '
    select(.mode == "v3" and .schema == "sbxr-qualification-manifest-v3" and
      .source_state == "v3-subscription-clean" and (.releases | length) == 1) |
    .releases[0] |
    select(.release_identity.repository == "albertloky/SBXR" and
      .tag == .release_identity.tag and .commit == .release_identity.commit and
      (.tag | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")) and
      (.commit | test("^[0-9a-f]{40}$")) and
      (.release_identity.release_index_sha256 | test("^[0-9a-f]{64}$")) and
      (.sequence | type == "number" and . > 0 and . == floor))' "$SBXR_QUALIFICATION_MANIFEST") || return 1
  TAG=$(jq -r .tag <<<"$candidate")
  SEQUENCE=$(jq -r .sequence <<<"$candidate")
  COMMIT=$(jq -r .commit <<<"$candidate")
  INDEX=$(jq -r .release_identity.release_index_sha256 <<<"$candidate")
  export TAG SEQUENCE COMMIT INDEX
}

operator_exact_candidate() {
  exact_candidate "$SBXR_QUALIFICATION_MANIFEST" "$SBXR_QUALIFICATION_REQUEST" "$SBXR_INSTALLED_RECORD" "$SBXR_EXECUTABLE"
}

# Extra read-only observations must not close the authority-bearing SSH shell.
# Keep strict mode in a fresh Bash process: wrapping a shell function or a
# subshell in `if`/`||` would suppress its errexit checks. The explicit status is
# an observation result, never a scenario pass. Required assertions stay outside.
# Bash -p suppresses BASH_ENV, imported functions and inherited shell options.
operator_observe() {
  OPERATOR_OBSERVATION_STATUS=0
  if test "$#" -ne 1; then
    OPERATOR_OBSERVATION_STATUS=64
  elif /bin/bash --noprofile --norc -p -euo pipefail -c "$1" </dev/null; then
    :
  else
    OPERATOR_OBSERVATION_STATUS=$?
  fi
  printf 'OPERATOR_OBSERVATION_EXIT=%s\n' "$OPERATOR_OBSERVATION_STATUS" >&2 || :
  return 0
}

operator_expect_scenario() {
  operator_manifest_digest >/dev/null || return 1
  test "$(jq -er .scenario_id "$SBXR_QUALIFICATION_REQUEST")" = "$1"
}

operator_manifest_digest() {
  local digest
  digest=$(sha256sum "$SBXR_QUALIFICATION_MANIFEST" | cut -d' ' -f1) || return 1
  jq -e --arg digest "$digest" '.qualification_manifest_sha256 == $digest' "$SBXR_QUALIFICATION_REQUEST" >/dev/null || return 1
  printf '%s\n' "$digest"
}

preflight() {
  local package_set=${1:-initial}
  local package_key certbot_revision snapd_revision package name version digest size current_path
  case "$package_set" in
    initial) package_key=packages ;;
    after-snap-refresh) package_key=after_snap_refresh ;;
    *) return 1 ;;
  esac
  test "$(sha256sum /etc/machine-id | cut -d' ' -f1)" = "$(jq -er .v3_attempt.vps_identity_sha256 "$SBXR_QUALIFICATION_MANIFEST")"
  test "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")" = ubuntu:24.04
  test "$(dpkg --print-architecture)" = amd64
  test "$(timedatectl show -p NTPSynchronized --value)" = yes
  ! systemctl is-active --quiet apt-daily.service
  ! systemctl is-active --quiet apt-daily-upgrade.service
  ! fuser /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock
  for package in certbot snap; do
    if test "$package" = certbot; then name=certbot; else name=snapd; fi
    version=$(jq -er --arg key "$package_key" --arg package "$package" '.v3_attempt[$key][$package].version' "$SBXR_QUALIFICATION_MANIFEST")
    digest=$(jq -er --arg key "$package_key" --arg package "$package" '.v3_attempt[$key][$package].sha256' "$SBXR_QUALIFICATION_MANIFEST")
    size=$(jq -er --arg key "$package_key" --arg package "$package" '.v3_attempt[$key][$package].size' "$SBXR_QUALIFICATION_MANIFEST")
    test "$(snap list "$name" | awk 'NR == 2 {print $2}')" = "$version"
    if test "$name" = certbot; then certbot_revision=$(readlink /snap/certbot/current); current_path=/var/lib/snapd/snaps/certbot_${certbot_revision}.snap
    else snapd_revision=$(readlink /snap/snapd/current); current_path=/var/lib/snapd/snaps/snapd_${snapd_revision}.snap
    fi
    test "$(stat -c %s "$current_path")" = "$size"
    test "$(sha256sum "$current_path" | cut -d' ' -f1)" = "$digest"
  done
}

action() {
  LAST_ACTION_OUTPUT=
  if run_action "$@"; then return; fi
  if test -n "${LAST_ACTION_OUTPUT:-}" && scan_vps_capture <(printf '%s' "$LAST_ACTION_OUTPUT"); then
    printf '%s\n' "$LAST_ACTION_OUTPUT" | sed -n '/^Failed safety check:/p; /^Correction:/p; /^Result:/p; /^Code:/p'
  fi
  return 1
}

remember_secrets() {
  KNOWN_PRIVATE_KEY="$(jq -er '.inbounds[0].tls.reality.private_key' /etc/sing-box/config.json)"
  KNOWN_CLIENT_UUID="$(jq -er '.inbounds[0].users[0].uuid' /etc/sing-box/config.json)"
  if test -e /var/lib/sbxr/subscription-token; then
    test ! -L /var/lib/sbxr/subscription-token
    test "$(stat -c '%u:%a:%h' /var/lib/sbxr/subscription-token)" = 0:600:1
    local credential
    credential=$(</var/lib/sbxr/subscription-token)
    test "${#credential}" -eq 43
    KNOWN_SUBSCRIPTION_CREDENTIALS="${KNOWN_SUBSCRIPTION_CREDENTIALS:-} $credential"
  fi
}

scan_retained_capture() {
  local capture credential
  for capture in "$@"; do
    test -f "$capture"
    scan_vps_capture "$capture"
    for credential in ${KNOWN_SUBSCRIPTION_CREDENTIALS:-}; do
      if grep -Fq -- "$credential" "$capture"; then return 1; fi
    done
    if grep -Eq 'https://[^[:space:]]*:8443/s/[A-Za-z0-9_-]{43}' "$capture"; then return 1; fi
  done
}

scan_journal() {
  local capture=$SBXR_OPERATOR_STATE_DIR/scenario-journal
  journalctl -u sing-box --since "$SCENARIO_START" --no-pager > "$capture"
  scan_retained_capture "$capture"
  rm "$capture"
}

scan_transport_captures() {
  local capture=$SBXR_OPERATOR_STATE_DIR/transport-journal
  test "$(systemctl show "$SBXR_TRANSPORT_UNIT" -p StandardOutput --value)" = null
  test "$(systemctl show "$SBXR_TRANSPORT_UNIT" -p StandardError --value)" = null
  test ! -e "$SBXR_TRANSPORT_ROOT/gateway.log"
  scan_retained_capture "$SBXR_QUALIFICATION_MANIFEST"
  journalctl -u "$SBXR_TRANSPORT_UNIT" --since "$SCENARIO_START" --no-pager > "$capture"
  scan_retained_capture "$capture"
  rm "$capture"
}

stamp() { printf '%s ' "$1"; date -u +%Y-%m-%dT%H:%M:%SZ; }

operator_initialize
