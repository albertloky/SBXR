package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/template"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func buildBootstrapFile(options bootstrapOptions) error {
	hash := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if options.output == "" || options.tag != "v"+options.version || !validTag(options.tag) || !validCommit(options.commit) || !hash.MatchString(options.amd64ExecutableSHA256) || !hash.MatchString(options.arm64ExecutableSHA256) || options.sequence == 0 || options.root != "" && (!strings.HasPrefix(options.root, "/") || strings.ContainsAny(options.root, "\n\r'")) {
		return errors.New("bootstrap build refused")
	}
	var body bytes.Buffer
	if template.Must(template.New("bootstrap").Parse(bootstrapBody)).Execute(&body, map[string]string{
		"Repository": softwarelifecycle.Repository,
		"Tag":        options.tag, "Commit": options.commit, "Version": options.version,
		"Sequence": fmt.Sprint(options.sequence), "Root": strings.TrimSuffix(options.root, "/"),
		"AMD64ExecutableSHA256": options.amd64ExecutableSHA256, "ARM64ExecutableSHA256": options.arm64ExecutableSHA256,
	}) != nil {
		return errors.New("bootstrap build refused")
	}
	body = *bytes.NewBuffer(append([]byte("#!/usr/bin/env bash\n"), body.Bytes()...))
	file, err := os.OpenFile(options.output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return errors.New("bootstrap output refused")
	}
	written, writeErr := file.Write(body.Bytes())
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != body.Len() {
		_ = os.Remove(options.output)
		return errors.New("bootstrap output unavailable")
	}
	return nil
}

const bootstrapBody = `set -u
set -f
umask 077
PATH='/usr/bin:/bin'
LC_ALL=C
export PATH LC_ALL
unset BASH_ENV ENV CDPATH GLOBIGNORE GREP_OPTIONS TAR_OPTIONS POSIXLY_CORRECT
IFS=$' \t\n'

REPOSITORY='{{.Repository}}'
TAG='{{.Tag}}'
COMMIT='{{.Commit}}'
VERSION='{{.Version}}'
SEQUENCE='{{.Sequence}}'
AMD64_EXECUTABLE_SHA256='{{.AMD64ExecutableSHA256}}'
ARM64_EXECUTABLE_SHA256='{{.ARM64ExecutableSHA256}}'
ROOT='{{.Root}}'
WORK=''
RECLAIMING=0
DEFERRED_SIGNAL=0
RESTORING_REMOVAL=0
REMOVAL_INDEX_SHA=''

cleanup() {
  if [ -n "$WORK" ]; then
    local path=$WORK
    WORK=''
    "$ROOT/usr/bin/rm" -rf -- "$path" >/dev/null 2>&1 || return 1
    [ ! -e "$path" ] && [ ! -L "$path" ]
  fi
}
finish() {
  local code=$1 status=${2:-1} check=${3:-}
  trap - EXIT
  cleanup || code='SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  [ -z "$check" ] || printf 'install/%s\n' "$check" >&2
  printf '%s\n' "$code"
  exit "$status"
}
host_refused() { finish 'SOFTWARE-LIFECYCLE-INSTALL-HOST-REFUSED' 1 "${1:-}"; }
release_refused() { finish 'SOFTWARE-LIFECYCLE-INSTALL-RELEASE-REFUSED' 1 "${1:-}"; }
release_unavailable() { finish 'SOFTWARE-LIFECYCLE-INSTALL-RELEASE-UNAVAILABLE' 1 "${1:-}"; }
prerequisite_failed() { finish 'SOFTWARE-LIFECYCLE-INSTALL-PREREQUISITE-FAILED'; }
path_refused() { finish 'SOFTWARE-LIFECYCLE-INSTALL-PATH-REFUSED'; }
reclamation_failed() { finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'; }
single_line() { [ "$("$ROOT/usr/bin/grep" -c '^' "$1" 2>/dev/null)" -eq 1 ] 2>/dev/null; }
verify_elf_architecture() {
  local executable=$1 class endian kind machine expected
  class=$("$ROOT/usr/bin/head" -c 6 "$executable" | "$ROOT/usr/bin/od" -An -tx1 -v | "$ROOT/usr/bin/tr" -d ' \n') || return 1
  kind=$("$ROOT/usr/bin/dd" if="$executable" bs=1 skip=16 count=2 2>/dev/null | "$ROOT/usr/bin/od" -An -tx1 -v | "$ROOT/usr/bin/tr" -d ' \n') || return 1
  machine=$("$ROOT/usr/bin/dd" if="$executable" bs=1 skip=18 count=2 2>/dev/null | "$ROOT/usr/bin/od" -An -tx1 -v | "$ROOT/usr/bin/tr" -d ' \n') || return 1
  case "$ARCH" in amd64) expected='3e00' ;; arm64) expected='b700' ;; *) return 1 ;; esac
  [ "$class" = '7f454c460201' ] && { [ "$kind" = '0200' ] || [ "$kind" = '0300' ]; } && [ "$machine" = "$expected" ]
}
verify_executable_identity() {
  local executable=$1 output=$2 size length identity_bytes document_sha stored_sha payload_sha
  size=$("$ROOT/usr/bin/wc" -c <"$executable") || return 1
  [ "$size" -gt 56 ] && [ "$size" -le 268435456 ] 2>/dev/null || return 1
  [ "$("$ROOT/usr/bin/tail" -c 16 "$executable")" = 'SBXR-IDENTITY-V1' ] || return 1
  length=$("$ROOT/usr/bin/tail" -c 24 "$executable" | "$ROOT/usr/bin/head" -c 8 | "$ROOT/usr/bin/od" -An -tu8 | "$ROOT/usr/bin/tr" -d ' \n') || return 1
  case "$length" in ''|*[!0-9]*) return 1 ;; esac
  [ "$length" -gt 0 ] && [ "$length" -le 4096 ] && [ "$size" -gt $((length + 56)) ] 2>/dev/null || return 1
  identity_bytes=$((length + 56))
  "$ROOT/usr/bin/tail" -c "$identity_bytes" "$executable" | "$ROOT/usr/bin/head" -c "$length" >"$output" || return 1
  document_sha=$("$ROOT/usr/bin/sha256sum" "$output" | "$ROOT/usr/bin/cut" -d' ' -f1) || return 1
  stored_sha=$("$ROOT/usr/bin/tail" -c 56 "$executable" | "$ROOT/usr/bin/head" -c 32 | "$ROOT/usr/bin/od" -An -tx1 -v | "$ROOT/usr/bin/tr" -d ' \n') || return 1
  [ "$document_sha" = "$stored_sha" ] || return 1
  payload_sha=$("$ROOT/usr/bin/head" -c $((size - identity_bytes)) "$executable" | "$ROOT/usr/bin/sha256sum" | "$ROOT/usr/bin/cut" -d' ' -f1) || return 1
  identity_pattern='^\{"schema":1,"repository":"{{.Repository}}","tag":"v[0-9]+\.[0-9]+\.[0-9]+","commit":"[0-9a-f]{40}","sequence":[1-9][0-9]*,"architecture":"(amd64|arm64)","payload_sha256":"'"$payload_sha"'"\}$'
  single_line "$output" && "$ROOT/usr/bin/grep" -Eqx "$identity_pattern" "$output"
}
# A committed removal authorizes restoration of one exact finisher. Its
# hash-derived destination-side staging may contain only that target's prefix.
# Unknown bytes, links, metadata, and other staging identities remain refused.
restoration_stage_safe() {
  local source=$1 stage=$2 mode=$3 size source_size facts
  if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then return 0; fi
  [ ! -L "$stage" ] || return 1
  facts=$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$stage" 2>/dev/null) || return 1
  case "$facts" in '0:600:1:regular file'|'0:600:1:regular empty file'|"0:$mode:1:regular file") ;; *) return 1 ;; esac
  size=$("$ROOT/usr/bin/wc" -c <"$stage" | "$ROOT/usr/bin/tr" -d ' \n') && source_size=$("$ROOT/usr/bin/wc" -c <"$source" | "$ROOT/usr/bin/tr" -d ' \n') || return 1
  [ "$size" -le "$source_size" ] 2>/dev/null || return 1
  if [ "$facts" = '0:755:1:regular file' ]; then [ "$size" -eq "$source_size" ] || return 1; fi
  if [ "$size" -eq 0 ]; then
    : >"$WORK/restoration-prefix" || return 1
  else
    "$ROOT/usr/bin/head" -c "$size" "$source" >"$WORK/restoration-prefix" || return 1
  fi
  "$ROOT/usr/bin/cmp" -s "$WORK/restoration-prefix" "$stage"
}
restore_file() {
  local source=$1 stage=$2 destination=$3 directory=$4 mode=$5 stage_identity directory_identity
  restoration_stage_safe "$source" "$stage" "$mode" || path_refused
  if [ -e "$destination" ]; then
    if [ -e "$stage" ]; then
      "$ROOT/usr/bin/rm" -f -- "$stage" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
      "$ROOT/usr/bin/sync" "$directory" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
    fi
    return
  fi
  if [ ! -e "$stage" ]; then
    (set -o noclobber; : >"$stage") 2>/dev/null || path_refused
  fi
  restoration_stage_safe "$source" "$stage" "$mode" || path_refused
  if ! "$ROOT/usr/bin/cmp" -s "$source" "$stage"; then
    "$ROOT/usr/bin/dd" if="$source" of="$stage" >/dev/null 2>&1 || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  fi
  "$ROOT/usr/bin/cmp" -s "$source" "$stage" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  "$ROOT/usr/bin/chmod" "$mode" "$stage" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  "$ROOT/usr/bin/sync" "$stage" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  stage_identity=$("$ROOT/usr/bin/stat" -c '%d:%i' "$stage") && directory_identity=$("$ROOT/usr/bin/stat" -c '%d:%i' "$directory") || path_refused
  [ "${stage_identity%%:*}" = "${directory_identity%%:*}" ] || path_refused
  # Both paths share a filesystem, so mv publishes with rename rather than
  # copying partial bytes into the final executable or Installed Record.
  "$ROOT/usr/bin/mv" -n "$stage" "$destination" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  [ ! -e "$stage" ] && [ ! -L "$stage" ] || path_refused
}
successful_finish() {
  local code=$1
  trap - EXIT
  cleanup || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  "$ROOT/usr/bin/flock" -u 9 || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  exec 9<&-
  printf '%s\n' "$code"
  if [ "$DEFERRED_SIGNAL" -ne 0 ]; then
    printf 'Installed %s\nRun: sudo sbxr\n' "$TAG"
    exit 130
  fi
  if (: </dev/tty >/dev/tty) 2>/dev/null; then
    LC_ALL='C.UTF-8' LANG='C.UTF-8' exec "$ROOT/usr/local/bin/sbxr" </dev/tty >/dev/tty 2>/dev/tty
  fi
  printf 'Installed %s\nRun: sudo sbxr\n' "$TAG"
  exit 0
}
interrupted() {
  if [ "$RECLAIMING" -eq 0 ]; then
    finish 'SOFTWARE-LIFECYCLE-INSTALL-INTERRUPTED' 130
  fi
  DEFERRED_SIGNAL=1
}
trap interrupted HUP INT TERM
trap cleanup EXIT

[ "$#" -eq 0 ] || host_refused 'host/arguments expected=none'
[ "$("$ROOT/usr/bin/id" -u 2>/dev/null)" = '0' ] || host_refused 'host/uid expected=root observed=mismatch'
[ "$("$ROOT/usr/bin/uname" -s 2>/dev/null)" = 'Linux' ] || host_refused 'host/kernel expected=Linux observed=mismatch'
case "$("$ROOT/usr/bin/uname" -m 2>/dev/null)" in
  x86_64) ARCH='amd64'; EXPECTED_EXECUTABLE_SHA256=$AMD64_EXECUTABLE_SHA256 ;;
  aarch64) ARCH='arm64'; EXPECTED_EXECUTABLE_SHA256=$ARM64_EXECUTABLE_SHA256 ;;
  *) host_refused 'host/architecture expected=amd64-or-arm64 observed=mismatch' ;;
esac
os_release="$ROOT/etc/os-release"
if [ -L "$os_release" ]; then
  [ "$("$ROOT/usr/bin/readlink" "$os_release" 2>/dev/null)" = '../usr/lib/os-release' ] || host_refused 'host/os-release-link'
  os_release="$ROOT/usr/lib/os-release"
fi
[ -f "$os_release" ] && [ ! -L "$os_release" ] || host_refused 'host/os-release-file'
[ "$("$ROOT/usr/bin/grep" -c '^ID=ubuntu$' "$os_release" 2>/dev/null)" = '1' ] || host_refused 'host/distribution expected=ubuntu observed=mismatch'
[ "$("$ROOT/usr/bin/grep" -Ec '^VERSION_ID="?24\.04"?$' "$os_release" 2>/dev/null)" = '1' ] || host_refused 'host/ubuntu-version expected=24.04 observed=mismatch'

"$ROOT/usr/bin/mkdir" -p "$ROOT/run/lock" >/dev/null 2>&1 || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
lock="$ROOT/run/lock/sbxr.lock"
if [ ! -e "$lock" ] && [ ! -L "$lock" ]; then
  (set -o noclobber; : >"$lock") 2>/dev/null || true
fi
[ ! -L "$lock" ] || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
lock_facts=$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$lock" 2>/dev/null) || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
case "$lock_facts" in '0:600:1:regular file'|'0:600:1:regular empty file') ;; *) finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED' ;; esac
lock_identity=$("$ROOT/usr/bin/stat" -c '%d:%i' "$lock" 2>/dev/null) || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
exec 9<"$lock" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
[ "$("$ROOT/usr/bin/stat" -Lc '%d:%i' "/proc/$$/fd/9" 2>/dev/null)" = "$lock_identity" ] || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
[ "$("$ROOT/usr/bin/stat" -c '%d:%i' "$lock" 2>/dev/null)" = "$lock_identity" ] || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
"$ROOT/usr/bin/flock" -n 9 || finish 'SOFTWARE-LIFECYCLE-INSTALL-CONCURRENT-MUTATION'

WORK=$("$ROOT/usr/bin/mktemp" -d "$ROOT/tmp/sbxr-install.XXXXXX" 2>/dev/null) || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
"$ROOT/usr/bin/chmod" 0700 "$WORK" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'

removal_record="$ROOT/var/lib/sbxr/proxy-ownership.json"
final_removal_record="$ROOT/var/lib/.sbxr-removal.json"
if { [ -e "$removal_record" ] || [ -L "$removal_record" ]; } && { [ -e "$final_removal_record" ] || [ -L "$final_removal_record" ]; }; then
  path_refused
fi
if [ ! -e "$removal_record" ] && [ ! -L "$removal_record" ] && { [ -e "$final_removal_record" ] || [ -L "$final_removal_record" ]; }; then
  removal_record="$final_removal_record"
fi
if [ -e "$removal_record" ] || [ -L "$removal_record" ]; then
  for parent in "$ROOT/var" "$ROOT/var/lib" "$ROOT/var/lib/sbxr" "$ROOT/usr" "$ROOT/usr/local" "$ROOT/usr/local/bin"; do
    if [ -e "$parent" ] || [ -L "$parent" ]; then
      [ ! -L "$parent" ] || path_refused
      case "$("$ROOT/usr/bin/stat" -c '%u:%a:%F' "$parent" 2>/dev/null)" in '0:755:directory'|'0:700:directory') ;; *) path_refused ;; esac
    fi
  done
  if [ -e "$ROOT/var/lib/sbxr" ]; then
    [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%F' "$ROOT/var/lib/sbxr" 2>/dev/null)" = '0:700:directory' ] || path_refused
  fi
  [ ! -L "$removal_record" ] && [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$removal_record" 2>/dev/null)" = '0:600:1:regular file' ] || path_refused
  [ "$("$ROOT/usr/bin/wc" -c <"$removal_record")" -le 65536 ] 2>/dev/null && single_line "$removal_record" || path_refused
  removal_subject=$("$ROOT/usr/bin/sed" -n '1p' "$removal_record")
  retirement=''
  retirement_suffix=''
  if printf '%s\n' "$removal_subject" | "$ROOT/usr/bin/grep" -Fq '"https_retirement":'; then
    retirement=$(printf '%s\n' "$removal_subject" | "$ROOT/usr/bin/sed" -n 's/.*,"https_retirement":\(.*\)}$/\1/p')
    [ -n "$retirement" ] || path_refused
    removal_subject=$(printf '%s\n' "$removal_subject" | "$ROOT/usr/bin/sed" 's/,"https_retirement":.*}$/}/')
  fi
` + bootstrapRecoveryPrelude + `
  # Committed records are canonical JSON. Match the complete supported contract,
  # never a prefix that could hide an unknown operation or conflicting identity.
  identity='\{"Repository":"{{.Repository}}","Tag":"v[1-9][0-9]*\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?","Commit":"[0-9a-f]{40}","IndexSHA256":"[0-9a-f]{64}"\}'
  schema=$("$ROOT/usr/bin/sed" -n 's/^{"schema":\([12]\),.*/\1/p' <<<"$removal_subject")
  case "$schema" in 1|2) ;; *) path_refused ;; esac
  prefix='\{"schema":'"$schema"',"phase":"Removal committed","unfinished_direction":"removal required","release_identity":'"$identity"
  config_sha=$("$ROOT/usr/bin/sed" -n 's/.*"configuration_sha256":"\([0-9a-f]*\)".*/\1/p' <<<"$removal_subject")
  resources='["/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-'"$schema"'","/var/lib/.sbxr-removal.json root:root 0600 one-link finalization authority"'
  if [ -z "$config_sha" ]; then
    fields=',"proxy_package_identity":"","public_ipv4":"","destination_address":"","destination_server_name":"","configuration_sha256":""'
    resources=$resources',"/usr/local/bin/sbxr exact committed Release Identity","/var/lib/sbxr/installed.json exact committed Release Identity"]'
    checkpoints='[0-3]'
    provenance_count=4
  else
    [ "${#config_sha}" -eq 64 ] || path_refused
    proxy_package=$("$ROOT/usr/bin/sed" -n 's/.*"proxy_package_identity":"\([^"]*\)".*/\1/p' <<<"$removal_subject")
    case "$proxy_package" in
      'https://deb.sagernet.org/ sing-box 1.14.3 amd64 32297878 ed7feaa6c2083d58a7195866bf25a2693abc2beaf5c0d192c9370ffa39e0fd6e')
        package_version=1.14.3; package_sha=ed7feaa6c2083d58a7195866bf25a2693abc2beaf5c0d192c9370ffa39e0fd6e ;;
      'https://deb.sagernet.org/ sing-box 1.13.19 amd64 24597120 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf')
        package_version=1.13.19; package_sha=fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf ;;
      *) path_refused ;;
    esac
    proxy_package_pattern=$(printf '%s' "$proxy_package" | "$ROOT/usr/bin/sed" 's/[][\\.^$*+?(){}|]/\\&/g')
    fields=',"proxy_package_identity":"'"$proxy_package_pattern"'","public_ipv4":"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+","destination_address":"google\.com:443","destination_server_name":"google\.com","configuration_sha256":"'"$config_sha"'"'
    resources=$resources',"/var/lib/sbxr/.proxy-ownership.json.next root:root 0600 one-link transaction material","/var/lib/sbxr/sing-box_'"$package_version"'_amd64.deb root-owned one-link verified package artifact","/etc/apt/keyrings/sagernet.asc sha256:803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1","/etc/apt/keyrings/sagernet.asc.sbxr-next root-owned transaction material","/etc/apt/sources.list.d/sagernet.sources https://deb.sagernet.org/ signed-by sagernet.asc","/etc/apt/sources.list.d/sagernet.sources.sbxr-next root-owned transaction material","sing-box package '"$package_version"' amd64 deb-sha256:'"$package_sha"'","sing-box package hold","/etc/sing-box/config.json sha256:'"$config_sha"'","/var/lib/sing-box package state","sing-box.service package provenance stopped-disabled-before-commit","sing-box package-created user and group","tcp/443 local listener"]'
    checkpoints='([0-9]|1[01])'
    provenance_count=15
    ip=$("$ROOT/usr/bin/sed" -n 's/.*"public_ipv4":"\([0-9.]*\)".*/\1/p' <<<"$removal_subject")
    IFS=. read -r ip1 ip2 ip3 ip4 <<<"$ip"
    for octet in "$ip1" "$ip2" "$ip3" "$ip4"; do
      case "$octet" in ''|*[!0-9]*|0[0-9]*) path_refused ;; esac
      [ "${#octet}" -le 3 ] && [ "$octet" -le 255 ] || path_refused
    done
    case "$ip1.$ip2.$ip3" in 0.*|10.*|127.*|169.254.*|192.0.0|192.0.2|192.88.99|192.168.*|198.51.100|203.0.113) path_refused ;; esac
    [ "$ip1" -lt 224 ] || path_refused
    if { [ "$ip1" -eq 100 ] && [ "$ip2" -ge 64 ] && [ "$ip2" -le 127 ]; } || { [ "$ip1" -eq 172 ] && [ "$ip2" -ge 16 ] && [ "$ip2" -le 31 ]; } || { [ "$ip1" -eq 198 ] && { [ "$ip2" -eq 18 ] || [ "$ip2" -eq 19 ]; }; }; then path_refused; fi
  fi
  lock_provisioning_suffix=''
  if "$ROOT/usr/bin/grep" -Fq '"lock_provisioning":' <<<"$removal_subject"; then
    [ -n "$config_sha" ] || path_refused
    lock_provisioning=$("$ROOT/usr/bin/sed" -n 's/.*,"lock_provisioning":\({"unit_sha256":"[0-9a-f]*"}\).*/\1/p' <<<"$removal_subject")
    printf '%s\n' "$lock_provisioning" | "$ROOT/usr/bin/grep" -Eqx '\{"unit_sha256":"440c4153f2db3ee3b8cd00f1297d9fcedda633c2761b00fa71429c222280dc40"\}' || path_refused
    resources=${resources%]}',"/etc/systemd/system/sbxr-mutation-lock.service root:root 0644 one-link sha256:440c4153f2db3ee3b8cd00f1297d9fcedda633c2761b00fa71429c222280dc40","/etc/systemd/system/sbxr-mutation-lock.service.sbxr-next root-owned synchronized no-replace publication","/etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service root-owned symlink ../sbxr-mutation-lock.service"]'
    provenance_count=$((provenance_count + 3))
    lock_provisioning_suffix=',"lock_provisioning":\{"unit_sha256":"440c4153f2db3ee3b8cd00f1297d9fcedda633c2761b00fa71429c222280dc40"\}'
  fi
  serving_suffix=''
  http_serving=0
  legacy_serving_pattern='\{"link_id":"[0-9a-f]{32}","credential_sha256":"[0-9a-f]{64}","certificate_generation":[1-9][0-9]{0,6},"certificate_sha256":\["[0-9a-f]{64}","[0-9a-f]{64}","[0-9a-f]{64}","[0-9a-f]{64}"\]\}'
  http_serving_pattern='\{"http":true,"link_id":"[0-9a-f]{32}","credential_sha256":"[0-9a-f]{64}","certificate_generation":0,"certificate_sha256":\["","","",""\]\}'
  serving_pattern=$legacy_serving_pattern
  if "$ROOT/usr/bin/grep" -Fq '"serving":' <<<"$removal_subject"; then
    [ "$schema" -eq 2 ] && [ -n "$config_sha" ] || path_refused
    # Serving and renewal are flat fixed-shape objects. Their following member
    # varies by transport/journal; the complete canonical record is checked below.
    serving=$("$ROOT/usr/bin/sed" -n 's/.*,"serving":\({[^}]*}\).*/\1/p' <<<"$removal_subject")
    if printf '%s\n' "$serving" | "$ROOT/usr/bin/grep" -Eqx "$http_serving_pattern"; then
      http_serving=1
      serving_pattern=$http_serving_pattern
    fi
    printf '%s\n' "$serving" | "$ROOT/usr/bin/grep" -Eqx "$serving_pattern" || path_refused
    if printf '%s\n' "$serving" | "$ROOT/usr/bin/grep" -Eq '"(0{32}|0{64})"'; then path_refused; fi
    generation=$(printf '%s' "$serving" | "$ROOT/usr/bin/sed" -n 's/.*"certificate_generation":\([0-9]*\),.*/\1/p')
    [ "$generation" -le 1000000 ] || path_refused
    resources=${resources%]}',"/etc/systemd/system/sbxr-subscription.service root:root 0644 one-link fixed-serving-v1","/etc/systemd/system/multi-user.target.wants/sbxr-subscription.service root-owned symlink ../sbxr-subscription.service","/var/lib/sbxr/subscription-token root:root 0600 one-link credential","/var/lib/sbxr/subscription-serving.json root:root 0600 immutable serving state","/var/lib/sbxr/subscription-staging root:root 0700 empty-directory"'
    provenance_count=$((provenance_count + 5))
    if [ "$http_serving" -eq 0 ]; then
      hashes=$(printf '%s' "$serving" | "$ROOT/usr/bin/sed" -n 's/.*"certificate_sha256":\["\([0-9a-f]*\)","\([0-9a-f]*\)","\([0-9a-f]*\)","\([0-9a-f]*\)"\]}/\1 \2 \3 \4/p')
      read -r cert_hash chain_hash fullchain_hash privkey_hash <<<"$hashes"
      resources=$resources',"/etc/letsencrypt/archive/sbxr-subscription root:root 0700 directory","/etc/letsencrypt/live/sbxr-subscription root:root 0700 directory"'
      for name in cert chain fullchain privkey; do
        mode=0644
        case "$name" in cert) hash=$cert_hash ;; chain) hash=$chain_hash ;; fullchain) hash=$fullchain_hash ;; privkey) hash=$privkey_hash; mode=0600 ;; esac
        resources=$resources',"/etc/letsencrypt/archive/sbxr-subscription/'"$name$generation"'.pem root:root '"$mode"' one-link '"$hash"'","/etc/letsencrypt/live/sbxr-subscription/'"$name"'.pem root:root symlink ../../archive/sbxr-subscription/'"$name$generation"'.pem"'
      done
      provenance_count=$((provenance_count + 10))
    fi
    resources=$resources']'
    serving_suffix=',"serving":'$(printf '%s' "$serving" | "$ROOT/usr/bin/sed" 's/[][\\.^$*+?(){}|]/\\&/g')
  fi
  renewal_suffix=''
  if "$ROOT/usr/bin/grep" -Fq '"renewal":' <<<"$removal_subject"; then
    [ -n "$serving_suffix" ] && [ "$http_serving" -eq 0 ] || path_refused
    renewal=$("$ROOT/usr/bin/sed" -n 's/.*,"renewal":\({[^}]*}\).*/\1/p' <<<"$removal_subject")
    printf '%s\n' "$renewal" | "$ROOT/usr/bin/grep" -Eqx '\{"recorder_id":"[0-9a-f]{32}","lineage":"sbxr-subscription","public_ipv4":"'"$ip"'","invocation":"snap-certbot-renew-v1"\}' || path_refused
    printf '%s\n' "$renewal" | "$ROOT/usr/bin/grep" -Eq '"recorder_id":"0{32}"' && path_refused
    resources=${resources%]}',"/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf root:root 0644 one-link recorder-v1","/etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription root:root 0700 one-link deploy-writer-v1","/etc/letsencrypt/renewal-hooks/post/sbxr-subscription root:root 0700 one-link post-writer-v1","/var/lib/sbxr/renewal-attempts.json root:root 0600 one-link bounded-evidence-v1","/var/lib/sbxr/renewal-admission.lock root:root 0600 one-link admission-v1","/var/lib/sbxr/renewal-writer.lock root:root 0600 one-link writer-v1"]'
    provenance_count=$((provenance_count + 6))
    renewal_suffix=',"renewal":'$(printf '%s' "$renewal" | "$ROOT/usr/bin/sed" 's/[][\\.^$*+?(){}|]/\\&/g')
  fi
  repair_suffix=''
  if "$ROOT/usr/bin/grep" -Fq '"subscription_repair":' <<<"$removal_subject"; then
    { [ -n "$renewal_suffix" ] || [ "$http_serving" -eq 1 ]; } || path_refused
    repair=$("$ROOT/usr/bin/sed" -n 's/.*,"subscription_repair":\(.*\),"subscription_resources":.*/\1/p' <<<"$removal_subject")
    repair_id=$(printf '%s' "$repair" | "$ROOT/usr/bin/sed" -n 's/^{"operation_id":"\([0-9a-f]*\)".*/\1/p')
    [ "${#repair_id}" -eq 32 ] && [ "$repair_id" != 00000000000000000000000000000000 ] || path_refused
    source=$(printf '%s' "$repair" | "$ROOT/usr/bin/sed" -n 's/.*,"source":\(.*\),"target":.*/\1/p')
    if [ -z "$source" ]; then source=$(printf '%s' "$repair" | "$ROOT/usr/bin/sed" -n 's/.*,"source":\(.*\)}$/\1/p'); fi
    target=$(printf '%s' "$repair" | "$ROOT/usr/bin/sed" -n 's/.*,"target":\(.*\)}$/\1/p')
    printf '%s\n' "$source" | "$ROOT/usr/bin/grep" -Eqx "$serving_pattern" || path_refused
    [ -z "$target" ] || printf '%s\n' "$target" | "$ROOT/usr/bin/grep" -Eqx "$serving_pattern" || path_refused
    correction=$(printf '%s' "$repair" | "$ROOT/usr/bin/sed" -n 's/.*,"correction":"\([^"]*\)".*/\1/p')
    [ "$http_serving" -eq 0 ] || [ "$correction" = 'restart owned serving runtime' ] || path_refused
    direction=$(printf '%s' "$repair" | "$ROOT/usr/bin/sed" -n 's/.*,"direction":"\([^"]*\)".*/\1/p')
    checkpoint=$(printf '%s' "$repair" | "$ROOT/usr/bin/sed" -n 's/.*,"checkpoint":"\([^"]*\)".*/\1/p')
    certificate_target_valid=0
    if [ -n "$target" ]; then
      source_link=$(printf '%s' "$source" | "$ROOT/usr/bin/sed" -n 's/.*"link_id":"\([0-9a-f]*\)".*/\1/p')
      source_credential=$(printf '%s' "$source" | "$ROOT/usr/bin/sed" -n 's/.*"credential_sha256":"\([0-9a-f]*\)".*/\1/p')
      source_generation=$(printf '%s' "$source" | "$ROOT/usr/bin/sed" -n 's/.*"certificate_generation":\([0-9]*\),.*/\1/p')
      target_link=$(printf '%s' "$target" | "$ROOT/usr/bin/sed" -n 's/.*"link_id":"\([0-9a-f]*\)".*/\1/p')
      target_credential=$(printf '%s' "$target" | "$ROOT/usr/bin/sed" -n 's/.*"credential_sha256":"\([0-9a-f]*\)".*/\1/p')
      target_generation=$(printf '%s' "$target" | "$ROOT/usr/bin/sed" -n 's/.*"certificate_generation":\([0-9]*\),.*/\1/p')
      if [ "$target_link" = "$source_link" ] && [ "$target_credential" = "$source_credential" ] && [ "$target_generation" -gt "$source_generation" ] && [ "$target_generation" -le 1000000 ]; then certificate_target_valid=1; fi
    fi
    case "$correction:$direction:$checkpoint" in
      'restart owned serving runtime:cleanup:prepared') effects='\["restart owned serving runtime"\]'; completed='null'; [ -z "$target" ] && [ "$source" = "$serving" ] || path_refused ;;
      'restart owned serving runtime:forward:committed') effects='\["restart owned serving runtime"\]'; completed='null'; { [ -z "$target" ] || [ "$target" = "$source" ]; } && [ "$source" = "$serving" ] || path_refused ;;
      'restart owned serving runtime:forward:accepted') effects='\["restart owned serving runtime"\]'; completed='\["restart owned serving runtime"\]'; [ "$target" = "$source" ] && [ "$target" = "$serving" ] || path_refused ;;
      'renew owned certificate:cleanup:prepared') effects='\["renew owned certificate","activate published certificate","resolve renewal evidence"\]'; completed='null'; [ -z "$target" ] && [ "$source" = "$serving" ] || path_refused ;;
      'renew owned certificate:forward:committed') effects='\["renew owned certificate","activate published certificate","resolve renewal evidence"\]'; completed='(null|\["certificate published"\])'; [ "$source" = "$serving" ] && { [ -z "$target" ] || [ "$certificate_target_valid" -eq 1 ]; } || path_refused ;;
      'renew owned certificate:forward:accepted') effects='\["renew owned certificate","activate published certificate","resolve renewal evidence"\]'; completed="$effects"; [ "$certificate_target_valid" -eq 1 ] && [ "$target" = "$serving" ] || path_refused ;;
      *) path_refused ;;
    esac
    printf '%s\n' "$repair" | "$ROOT/usr/bin/grep" -Eqx '^\{"operation_id":"[0-9a-f]{32}","kind":"repair subscription","direction":"'"$direction"'","correction":"'"$correction"'","effects":'"$effects"',"completed_effects":'"$completed"',"checkpoint":"'"$checkpoint"'","source":.*(,"target":.*)?\}$' || path_refused
    repair_suffix=',"subscription_repair":'$(printf '%s' "$repair" | "$ROOT/usr/bin/sed" 's/[][\\.^$*+?(){}|]/\\&/g')
  fi
  subscription_suffix=''
  if "$ROOT/usr/bin/grep" -Fq '"subscription_resources":' <<<"$removal_subject"; then
    { [ -n "$renewal_suffix" ] || [ "$http_serving" -eq 1 ]; } || path_refused
    subscription=$("$ROOT/usr/bin/sed" -n 's/.*,"subscription_resources":\(.*\)}$/\1/p' <<<"$removal_subject")
    if "$ROOT/usr/bin/grep" -Fq '"proxy_startup":' <<<"$removal_subject"; then
      subscription=$("$ROOT/usr/bin/sed" -n 's/.*,"subscription_resources":\(.*\),"proxy_startup":.*/\1/p' <<<"$removal_subject")
    elif [ -n "$lock_provisioning_suffix" ]; then
      subscription=$("$ROOT/usr/bin/sed" -n 's/.*,"subscription_resources":\(.*\),"lock_provisioning":.*/\1/p' <<<"$removal_subject")
    fi
    if [ "$http_serving" -eq 1 ]; then
      printf '%s\n' "$subscription" | "$ROOT/usr/bin/grep" -Eqx '\{"http":true,"public_ipv4":"'"$ip"'","firewall_sha256":"[0-9a-f]{64}","snapd_created":false,"certbot_created":false\}' || path_refused
    else
      printf '%s\n' "$subscription" | "$ROOT/usr/bin/grep" -Eqx '\{"public_ipv4":"'"$ip"'","firewall_sha256":"[0-9a-f]{64}","snapd_created":(true|false),"certbot_created":(true|false)(,"recorder_directory_created":true)?\}' || path_refused
    fi
    firewall_sha=$(printf '%s' "$subscription" | "$ROOT/usr/bin/sed" -n 's/.*"firewall_sha256":"\([0-9a-f]*\)".*/\1/p')
    [ "$firewall_sha" != 0000000000000000000000000000000000000000000000000000000000000000 ] || path_refused
    if [ "$http_serving" -eq 1 ]; then
      resources=${resources%]}',"/etc/systemd/system/sbxr-subscription-firewall.service root:root 0644 one-link sha256:'"$firewall_sha"'","iptables filter INPUT '"$ip"'/32 tcp/8443 comment=sbxr-subscription exact-owned"]'
      provenance_count=$((provenance_count + 2))
    else
      snapd=$(printf '%s' "$subscription" | "$ROOT/usr/bin/sed" -nE 's/.*"snapd_created":(true|false).*/\1/p'); [ "$snapd" = true ] && snapd=created || snapd=reused
      certbot=$(printf '%s' "$subscription" | "$ROOT/usr/bin/sed" -nE 's/.*"certbot_created":(true|false).*/\1/p'); [ "$certbot" = true ] && certbot=created || certbot=reused
      resources=${resources%]}',"/etc/systemd/system/sbxr-subscription-firewall.service root:root 0644 one-link sha256:'"$firewall_sha"'","iptables filter INPUT '"$ip"'/32 tcp/80 comment=sbxr-subscription exact-owned","iptables filter INPUT '"$ip"'/32 tcp/8443 comment=sbxr-subscription exact-owned","snapd dependency '"$snapd"'","official Certbot snap dependency '"$certbot"'"]'
      provenance_count=$((provenance_count + 5))
      if [[ "$subscription" = *',"recorder_directory_created":true}' ]]; then
        resources=${resources%]}',"/etc/systemd/system/snap.certbot.renew.service.d root:root 0755 SBXR-created empty-after-drop-in-removal"]'
        provenance_count=$((provenance_count + 1))
      fi
    fi
    subscription_suffix=',"subscription_resources":'$(printf '%s' "$subscription" | "$ROOT/usr/bin/sed" 's/[][\\.^$*+?(){}|]/\\&/g')
  fi
  [ "$http_serving" -eq 0 ] || [ -n "$subscription_suffix" ] || path_refused
  if [ -n "$retirement" ]; then
    [ "$schema" -eq 2 ] && [ "$http_serving" -eq 1 ] || path_refused
    retired_renewal_pattern='\{"recorder_id":"[0-9a-f]{32}","lineage":"sbxr-subscription","public_ipv4":"'"$ip"'","invocation":"snap-certbot-renew-v1"\}'
    retired_resources_pattern='\{"public_ipv4":"'"$ip"'","firewall_sha256":"[0-9a-f]{64}","snapd_created":(true|false),"certbot_created":(true|false)(,"recorder_directory_created":true)?\}'
    printf '%s\n' "$retirement" | "$ROOT/usr/bin/grep" -Eqx '^\{"serving":'"$legacy_serving_pattern"',"renewal":'"$retired_renewal_pattern"',"resources":'"$retired_resources_pattern"',"configuration_mode":(256|260|288|292|384|388|416|420),"configuration_sha256":"[0-9a-f]{64}","evidence_sha256":"[0-9a-f]{64}"\}$' || path_refused
    printf '%s\n' "$retirement" | "$ROOT/usr/bin/grep" -Eq '"(0{32}|0{64})"' && path_refused
    retired_generation=$(printf '%s' "$retirement" | "$ROOT/usr/bin/sed" -n 's/.*"certificate_generation":\([0-9]*\),.*/\1/p')
    [ "$retired_generation" -le 1000000 ] || path_refused
    retired_mode=$(printf '%s' "$retirement" | "$ROOT/usr/bin/sed" -n 's/.*"configuration_mode":\([0-9]*\),.*/\1/p')
    case "$retired_mode" in 256) retired_mode=0400 ;; 260) retired_mode=0404 ;; 288) retired_mode=0440 ;; 292) retired_mode=0444 ;; 384) retired_mode=0600 ;; 388) retired_mode=0604 ;; 416) retired_mode=0640 ;; 420) retired_mode=0644 ;; *) path_refused ;; esac
    retired_configuration_sha=$(printf '%s' "$retirement" | "$ROOT/usr/bin/sed" -n 's/.*"configuration_sha256":"\([0-9a-f]*\)".*/\1/p')
    retired_evidence_sha=$(printf '%s' "$retirement" | "$ROOT/usr/bin/sed" -n 's/.*"evidence_sha256":"\([0-9a-f]*\)".*/\1/p')
    resources=${resources%]}',"/var/lib/sbxr/subscription-https-retired root:root 0700 retained-https-v1","/var/lib/sbxr/subscription-https-retired/renewal.conf root:root '"$retired_mode"' one-link sha256:'"$retired_configuration_sha"'","/var/lib/sbxr/subscription-https-retired/recorder.conf root:root 0644 one-link recorder-v1","/var/lib/sbxr/subscription-https-retired/deploy-hook root:root 0700 one-link deploy-writer-v1","/var/lib/sbxr/subscription-https-retired/post-hook root:root 0700 one-link post-writer-v1","/var/lib/sbxr/renewal-attempts.json root:root 0600 one-link retired-evidence-sha256:'"$retired_evidence_sha"'","/var/lib/sbxr/renewal-admission.lock root:root 0600 one-link admission-v1","/var/lib/sbxr/renewal-writer.lock root:root 0600 one-link writer-v1","/etc/letsencrypt/archive/sbxr-subscription root:root 0700 directory","/etc/letsencrypt/live/sbxr-subscription root:root 0700 directory"'
    retired_hashes=$(printf '%s' "$retirement" | "$ROOT/usr/bin/sed" -n 's/.*"certificate_sha256":\["\([0-9a-f]*\)","\([0-9a-f]*\)","\([0-9a-f]*\)","\([0-9a-f]*\)"\].*/\1 \2 \3 \4/p')
    read -r retired_cert_hash retired_chain_hash retired_fullchain_hash retired_privkey_hash <<<"$retired_hashes"
    for name in cert chain fullchain privkey; do
      mode=0644
      case "$name" in cert) hash=$retired_cert_hash ;; chain) hash=$retired_chain_hash ;; fullchain) hash=$retired_fullchain_hash ;; privkey) hash=$retired_privkey_hash; mode=0600 ;; esac
      resources=$resources',"/etc/letsencrypt/archive/sbxr-subscription/'"$name$retired_generation"'.pem root:root '"$mode"' one-link '"$hash"'","/etc/letsencrypt/live/sbxr-subscription/'"$name"'.pem root:root symlink ../../archive/sbxr-subscription/'"$name$retired_generation"'.pem"'
    done
    retired_snapd=$(printf '%s' "$retirement" | "$ROOT/usr/bin/sed" -nE 's/.*"snapd_created":(true|false).*/\1/p'); [ "$retired_snapd" = true ] && retired_snapd=created || retired_snapd=reused
    retired_certbot=$(printf '%s' "$retirement" | "$ROOT/usr/bin/sed" -nE 's/.*"certbot_created":(true|false).*/\1/p'); [ "$retired_certbot" = true ] && retired_certbot=created || retired_certbot=reused
    resources=$resources',"snapd dependency '"$retired_snapd"'","official Certbot snap dependency '"$retired_certbot"'"]'
    provenance_count=$((provenance_count + 20))
    if printf '%s' "$retirement" | "$ROOT/usr/bin/grep" -Fq '"recorder_directory_created":true'; then
      resources=${resources%]}',"/etc/systemd/system/snap.certbot.renew.service.d root:root 0755 SBXR-created empty-after-drop-in-removal"]'
      provenance_count=$((provenance_count + 1))
    fi
    retirement_suffix=',"https_retirement":'$(printf '%s' "$retirement" | "$ROOT/usr/bin/sed" 's/[][\\.^$*+?(){}|]/\\&/g')
  fi
` + bootstrapRecoveryResources + `
  startup_suffix=''
  if "$ROOT/usr/bin/grep" -Fq '"proxy_startup":' <<<"$removal_subject"; then
    [ "$schema" -eq 2 ] && [ -n "$config_sha" ] || path_refused
    startup=$("$ROOT/usr/bin/sed" -n 's/.*,"proxy_startup":\(.*\)}$/\1/p' <<<"$removal_subject")
    if [ -n "$lock_provisioning_suffix" ]; then
      startup=$("$ROOT/usr/bin/sed" -n 's/.*,"proxy_startup":\(.*\),"lock_provisioning":.*/\1/p' <<<"$removal_subject")
    fi
    printf '%s\n' "$startup" | "$ROOT/usr/bin/grep" -Eqx '\{"drop_in_sha256":"[0-9a-f]{64}","directory_created":(true|false)\}' || path_refused
    startup_sha=$(printf '%s' "$startup" | "$ROOT/usr/bin/sed" -n 's/.*"drop_in_sha256":"\([0-9a-f]*\)".*/\1/p')
    [ "$startup_sha" != 0000000000000000000000000000000000000000000000000000000000000000 ] || path_refused
    resources=${resources%]}',"/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf root:root 0644 one-link sha256:'"$startup_sha"'"]'
    provenance_count=$((provenance_count + 1))
    if printf '%s' "$startup" | "$ROOT/usr/bin/grep" -Fq '"directory_created":true'; then
      resources=${resources%]}',"/etc/systemd/system/sing-box.service.d root:root 0755 SBXR-created empty-after-drop-in-removal"]'
      provenance_count=$((provenance_count + 1))
    fi
    startup_suffix=',"proxy_startup":'$(printf '%s' "$startup" | "$ROOT/usr/bin/sed" 's/[][\\.^$*+?(){}|]/\\&/g')
  fi
  if [ "${correction:-}" = 'renew owned certificate' ] && [ "${certificate_target_valid:-0}" -eq 1 ] && [ "$target" != "$serving" ]; then
    target_hashes=$(printf '%s' "$target" | "$ROOT/usr/bin/sed" -n 's/.*"certificate_sha256":\["\([0-9a-f]*\)","\([0-9a-f]*\)","\([0-9a-f]*\)","\([0-9a-f]*\)"\]}/\1 \2 \3 \4/p')
    read -r target_cert_hash target_chain_hash target_fullchain_hash target_privkey_hash <<<"$target_hashes"
    for name in cert chain fullchain privkey; do
      mode=0644
      case "$name" in cert) hash=$target_cert_hash ;; chain) hash=$target_chain_hash ;; fullchain) hash=$target_fullchain_hash ;; privkey) hash=$target_privkey_hash; mode=0600 ;; esac
      old_live='/etc/letsencrypt/live/sbxr-subscription/'"$name"'.pem root:root symlink ../../archive/sbxr-subscription/'"$name$source_generation"'.pem'
      new_live='/etc/letsencrypt/live/sbxr-subscription/'"$name"'.pem root:root symlink ../../archive/sbxr-subscription/'"$name$target_generation"'.pem'
      resources=${resources/"$old_live"/"$new_live"}
      resources=${resources%]}',"/etc/letsencrypt/archive/sbxr-subscription/'"$name$target_generation"'.pem root:root '"$mode"' one-link '"$hash"'"]'
    done
    provenance_count=$((provenance_count + 4))
  fi
` + bootstrapRecoveryClient + `
  # Escape literal contract text for ERE; no caller-controlled regular expression.
  resource_pattern=$(printf '%s' "$resources" | "$ROOT/usr/bin/sed" 's/[][\\.^$*+?(){}|]/\\&/g')
  suffix=',"permitted_resources":'"$resource_pattern"',"cleanup_checkpoint":0,"removal_checkpoint":'"$checkpoints"
  selector='release_identity'
  if [ "$schema" -eq 2 ]; then
    suffix=$suffix',"resource_creating_releases":\['"$identity"'(,'"$identity"'){'"$((provenance_count - 1))"'}\],"finishing_release_identity":'"$identity"
    selector='finishing_release_identity'
  fi
  "$ROOT/usr/bin/grep" -Eqx '^'"$prefix$fields$suffix$serving_suffix$renewal_suffix$activation_suffix$enablement_suffix$rotation_suffix$repair_suffix$compromised_suffix$subscription_suffix$startup_suffix$lock_provisioning_suffix$client_suffix$retirement_suffix"'\}$' "$removal_record" || path_refused
  if [ "$removal_record" = "$final_removal_record" ]; then
    final_checkpoint=3
    [ -z "$config_sha" ] || final_checkpoint=11
    "$ROOT/usr/bin/grep" -Fq '"removal_checkpoint":'"$final_checkpoint" "$removal_record" || path_refused
  fi
  TAG=$("$ROOT/usr/bin/sed" -n 's|.*"'"$selector"'":{"Repository":"{{.Repository}}","Tag":"\([^"]*\)".*|\1|p' "$removal_record")
  COMMIT=$("$ROOT/usr/bin/sed" -n 's|.*"'"$selector"'":{"Repository":"{{.Repository}}","Tag":"[^"]*","Commit":"\([0-9a-f]*\)".*|\1|p' "$removal_record")
  REMOVAL_INDEX_SHA=$("$ROOT/usr/bin/sed" -n 's|.*"'"$selector"'":{"Repository":"{{.Repository}}","Tag":"[^"]*","Commit":"[0-9a-f]*","IndexSHA256":"\([0-9a-f]*\)".*|\1|p' "$removal_record")
  RESTORING_REMOVAL=1
fi

# The moving GitHub HTTPS command trusts this script; its embedded identity pins every later download.
download() {
  local name=$1 destination=$2 limit=$3 url=${4:-} response status effective http diagnostic_http
  DOWNLOAD_FAILURE='download/redirect-target'
  if [ -z "$url" ]; then
    url="https://github.com/$REPOSITORY/releases/download/$TAG/$name"
  fi
  response=$("$ROOT/usr/bin/curl" --fail --silent --show-error --location --max-redirs 4 --max-filesize "$limit" --proto '=https' --proto-redir '=https' --output "$destination" --write-out $'%{url_effective}\n%{http_code}' "$url" 2>/dev/null)
  status=$?
  effective=$(printf '%s\n' "$response" | "$ROOT/usr/bin/sed" -n '1p')
  http=$(printf '%s\n' "$response" | "$ROOT/usr/bin/sed" -n '2p')
  if [ "$status" -ne 0 ]; then
    diagnostic_http=$http
    case "$diagnostic_http" in [0-9][0-9][0-9]) ;; *) diagnostic_http='unknown' ;; esac
    DOWNLOAD_FAILURE="download/curl asset=$name exit=$status http=$diagnostic_http"
    case "$status:$http" in 6:*|7:*|28:*|35:*|60:*|22:5??) return 3 ;; *) return 2 ;; esac
  fi
  case "$effective" in
    "$url") return 0 ;;
    https://release-assets.githubusercontent.com/*|https://*.githubusercontent.com/*) case "$url" in "https://github.com/$REPOSITORY/releases/download/"*/"$name") return 0 ;; *) return 2 ;; esac ;;
    *) return 2 ;;
  esac
}
download_or_finish() {
  download "$@"
  case "$?" in 0) return 0 ;; 3) release_unavailable "$DOWNLOAD_FAILURE" ;; *) release_refused "$DOWNLOAD_FAILURE" ;; esac
}

index="$WORK/release-index.json"
download_or_finish 'release-index.json' "$index" 1048576
[ -f "$index" ] && [ ! -L "$index" ] || release_refused 'index/file'
[ "$("$ROOT/usr/bin/wc" -c <"$index")" -le 1048576 ] 2>/dev/null || release_refused 'index/size expected<=1048576'
index_pattern='^\{"schema":1,"repository":"{{.Repository}}","tag":"'"$TAG"'","commit":"'"$COMMIT"'","sequence":[1-9][0-9]*,"assets":\[\{"name":"install\.sh","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\},\{"name":"sbxr-linux-amd64\.tar\.gz","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\},\{"name":"sbxr-linux-arm64\.tar\.gz","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\}\]\}$'
# Match the canonical ReleaseIdentity encoding and ReleaseSupport.valid contract:
# clean-install scopes have no sources; recurring support has 1..32 unique sources.
subscription_source_pattern='\{"Repository":"{{.Repository}}","Tag":"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)","Commit":"[0-9a-f]{40}","IndexSHA256":"[0-9a-f]{64}"\}'
subscription_support_pattern='\{"scope":("(first-subscription-clean-install|subscription-clean-install-repair|subscription-clean-install-only)","sources":\[\]|"recurring-subscription-upgrade","sources":\['"$subscription_source_pattern"'(,'"$subscription_source_pattern"'){0,31}\]),"contract":"sbxr-subscription-update-v1"\}'
subscription_index_pattern='^\{"schema":2,"repository":"{{.Repository}}","tag":"'"$TAG"'","commit":"'"$COMMIT"'","sequence":[1-9][0-9]*,"assets":\[\{"name":"install\.sh","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\},\{"name":"sbxr-linux-amd64\.tar\.gz","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\},\{"name":"sbxr-linux-arm64\.tar\.gz","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\}\],"support":'"$subscription_support_pattern"'\}$'
single_line "$index" && { "$ROOT/usr/bin/grep" -Eqx "$index_pattern" "$index" || "$ROOT/usr/bin/grep" -Eqx "$subscription_index_pattern" "$index"; } || release_refused 'index/canonical-contract'
if "$ROOT/usr/bin/grep" -Fq '"scope":"recurring-subscription-upgrade"' "$index"; then
  sources=$("$ROOT/usr/bin/grep" -Eo "$subscription_source_pattern" "$index") || release_refused
  seen_sources='|'
  while IFS= read -r source; do
    case "$seen_sources" in *"|$source|"*) release_refused ;; esac
    seen_sources="$seen_sources$source|"
  done <<<"$sources"
fi
index_sequence=$("$ROOT/usr/bin/sed" -n 's/.*"sequence":\([0-9]*\).*/\1/p' "$index")
if [ "$RESTORING_REMOVAL" -eq 1 ]; then SEQUENCE=$index_sequence; else [ "$index_sequence" = "$SEQUENCE" ] || release_refused 'index/sequence expected=embedded observed=mismatch'; fi
archive_name="sbxr-linux-$ARCH.tar.gz"
archive_sha=$("$ROOT/usr/bin/sed" -n 's/.*"name":"'"$archive_name"'"[^}]*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p' "$index")
archive_size=$("$ROOT/usr/bin/sed" -n 's/.*"name":"'"$archive_name"'"[^}]*"size":\([0-9][0-9]*\).*/\1/p' "$index")
[ "${#archive_sha}" -eq 64 ] && [ "$archive_size" -gt 0 ] 2>/dev/null || release_refused

archive="$WORK/$archive_name"
download_or_finish "$archive_name" "$archive" 268435456
[ -f "$archive" ] && [ ! -L "$archive" ] || release_refused 'archive/file'
[ "$("$ROOT/usr/bin/wc" -c <"$archive")" -eq "$archive_size" ] 2>/dev/null || release_refused 'archive/size expected=index observed=mismatch'
[ "$("$ROOT/usr/bin/sha256sum" "$archive" | "$ROOT/usr/bin/cut" -d' ' -f1)" = "$archive_sha" ] || release_refused 'archive/sha256 expected=index observed=mismatch'
index_sha=$("$ROOT/usr/bin/sha256sum" "$index" | "$ROOT/usr/bin/cut" -d' ' -f1) || release_refused
[ "$RESTORING_REMOVAL" -eq 0 ] || [ "$index_sha" = "$REMOVAL_INDEX_SHA" ] || release_refused

active="$ROOT/usr/local/bin/sbxr"
installed_directory="$ROOT/var/lib/sbxr"
installed_record="$installed_directory/installed.json"
[ ! -L "$active" ] || path_refused
if [ "$RESTORING_REMOVAL" -eq 0 ] && [ -f "$active" ] && [ ! -L "$active" ] && [ -d "$installed_directory" ] && [ ! -L "$installed_directory" ] && [ -f "$installed_record" ] && [ ! -L "$installed_record" ] \
  && [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$active" 2>/dev/null)" = '0:755:1:regular file' ] \
  && [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%F' "$installed_directory" 2>/dev/null)" = '0:700:directory' ] \
  && [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$installed_record" 2>/dev/null)" = '0:600:1:regular file' ] \
  && [ "$("$ROOT/usr/bin/wc" -c <"$installed_record")" -le 4096 ] 2>/dev/null; then
  record_pattern='^\{"schema":1,"repository":"{{.Repository}}","tag":"v[0-9]+\.[0-9]+\.[0-9]+","commit":"[0-9a-f]{40}","release_index_sha256":"[0-9a-f]{64}","sequence":[1-9][0-9]*,"architecture":"(amd64|arm64)","executable_sha256":"[0-9a-f]{64}"\}$'
  if single_line "$installed_record" && "$ROOT/usr/bin/grep" -Eqx "$record_pattern" "$installed_record" && verify_executable_identity "$active" "$WORK/active-identity.json" && verify_elf_architecture "$active"; then
    current_tag=$("$ROOT/usr/bin/sed" -n 's/.*"tag":"\([^"]*\)".*/\1/p' "$installed_record")
    current_commit=$("$ROOT/usr/bin/sed" -n 's/.*"commit":"\([0-9a-f]*\)".*/\1/p' "$installed_record")
    current_index=$("$ROOT/usr/bin/sed" -n 's/.*"release_index_sha256":"\([0-9a-f]*\)".*/\1/p' "$installed_record")
    current_sequence=$("$ROOT/usr/bin/sed" -n 's/.*"sequence":\([0-9]*\).*/\1/p' "$installed_record")
    current_arch=$("$ROOT/usr/bin/sed" -n 's/.*"architecture":"\([^"]*\)".*/\1/p' "$installed_record")
    current_sha=$("$ROOT/usr/bin/sed" -n 's/.*"executable_sha256":"\([0-9a-f]*\)".*/\1/p' "$installed_record")
    embedded_tag=$("$ROOT/usr/bin/sed" -n 's/.*"tag":"\([^"]*\)".*/\1/p' "$WORK/active-identity.json")
    embedded_commit=$("$ROOT/usr/bin/sed" -n 's/.*"commit":"\([0-9a-f]*\)".*/\1/p' "$WORK/active-identity.json")
    embedded_sequence=$("$ROOT/usr/bin/sed" -n 's/.*"sequence":\([0-9]*\).*/\1/p' "$WORK/active-identity.json")
    embedded_arch=$("$ROOT/usr/bin/sed" -n 's/.*"architecture":"\([^"]*\)".*/\1/p' "$WORK/active-identity.json")
    observed_sha=$("$ROOT/usr/bin/sha256sum" "$active" | "$ROOT/usr/bin/cut" -d' ' -f1)
    if [ "$current_tag:$current_commit:$current_sequence:$current_arch:$current_sha" = "$embedded_tag:$embedded_commit:$embedded_sequence:$embedded_arch:$observed_sha" ]; then
      if [ "$current_sequence" -gt "$SEQUENCE" ] 2>/dev/null; then
        finish 'SOFTWARE-LIFECYCLE-INSTALL-DOWNGRADE-REFUSED'
      fi
      if [ "$current_tag:$current_commit:$current_index:$current_sequence:$current_arch:$current_sha" = "$TAG:$COMMIT:$index_sha:$SEQUENCE:$ARCH:$EXPECTED_EXECUTABLE_SHA256" ]; then
        "$ROOT/usr/bin/sync" "$active" "$installed_record" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
        "$ROOT/usr/bin/sync" "$installed_directory" "$ROOT/usr/local/bin" "$ROOT/var/lib" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
        successful_finish 'SOFTWARE-LIFECYCLE-INSTALL-ALREADY-CURRENT'
      fi
    fi
  fi
fi
if [ ! -x "$ROOT/usr/bin/tar" ]; then
  "$ROOT/usr/bin/apt-get" install --yes --no-install-recommends tar >/dev/null 2>&1 || prerequisite_failed
  [ -x "$ROOT/usr/bin/tar" ] || prerequisite_failed
fi
[ "$("$ROOT/usr/bin/tar" -tzf "$archive" 2>/dev/null)" = 'sbxr' ] || release_refused 'archive/member expected=sbxr observed=mismatch'
candidate="$WORK/sbxr"
(ulimit -f 262144; "$ROOT/usr/bin/tar" -xOzf "$archive" sbxr >"$candidate") 2>/dev/null || release_refused 'archive/extraction'
[ -f "$candidate" ] && [ ! -L "$candidate" ] || release_refused
"$ROOT/usr/bin/chmod" 0600 "$candidate" || release_refused
executable_sha=$("$ROOT/usr/bin/sha256sum" "$candidate" | "$ROOT/usr/bin/cut" -d' ' -f1) || release_refused
verify_executable_identity "$candidate" "$WORK/candidate-identity.json" || release_refused 'executable/identity-trailer'
verify_elf_architecture "$candidate" || release_refused 'executable/architecture expected=host observed=mismatch'
candidate_identity_pattern='^\{"schema":1,"repository":"{{.Repository}}","tag":"'"$TAG"'","commit":"'"$COMMIT"'","sequence":'"$SEQUENCE"',"architecture":"'"$ARCH"'","payload_sha256":"[0-9a-f]{64}"\}$'
single_line "$WORK/candidate-identity.json" && "$ROOT/usr/bin/grep" -Eqx "$candidate_identity_pattern" "$WORK/candidate-identity.json" || release_refused 'executable/identity expected=release observed=mismatch'
[ "$RESTORING_REMOVAL" -eq 1 ] || [ "$executable_sha" = "$EXPECTED_EXECUTABLE_SHA256" ] || release_refused 'executable/sha256 expected=embedded observed=mismatch'

if [ "$RESTORING_REMOVAL" -eq 1 ]; then
  if [ "$http_serving" -eq 1 ] || [ "${pending_http:-0}" -eq 1 ]; then
    "$ROOT/usr/bin/grep" -aFq 'SBXR-SUBSCRIPTION-HTTP-V1' "$candidate" || release_refused
  fi
  if [ -n "$retirement" ]; then
    "$ROOT/usr/bin/grep" -aFq 'SBXR-SUBSCRIPTION-HTTPS-RETIREMENT-V1' "$candidate" || release_refused
  fi
  active="$ROOT/usr/local/bin/sbxr"
  installed_directory="$ROOT/var/lib/sbxr"
  installed_record="$installed_directory/installed.json"
  [ ! -L "$active" ] || path_refused
  if [ ! -e "$installed_directory" ] && [ ! -L "$installed_directory" ]; then
    "$ROOT/usr/bin/mkdir" "$installed_directory" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
    "$ROOT/usr/bin/chmod" 0700 "$installed_directory" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  fi
  [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%F' "$installed_directory" 2>/dev/null)" = '0:700:directory' ] || path_refused
  record_stage="$installed_record.sbxr-restore-$executable_sha"
  executable_stage="$active.sbxr-restore-$executable_sha"
  unexpected=$("$ROOT/usr/bin/find" "$installed_directory" -mindepth 1 -maxdepth 1 ! -name proxy-ownership.json ! -name installed.json ! -name "installed.json.sbxr-restore-$executable_sha" -print -quit 2>/dev/null) || path_refused
  [ -z "$unexpected" ] || path_refused
  restored_record=$(printf '{"schema":1,"repository":"%s","tag":"%s","commit":"%s","release_index_sha256":"%s","sequence":%s,"architecture":"%s","executable_sha256":"%s"}' "$REPOSITORY" "$TAG" "$COMMIT" "$index_sha" "$SEQUENCE" "$ARCH" "$executable_sha")
  if [ -e "$installed_record" ] || [ -L "$installed_record" ]; then
    [ ! -L "$installed_record" ] && [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$installed_record" 2>/dev/null)" = '0:600:1:regular file' ] && single_line "$installed_record" && "$ROOT/usr/bin/grep" -Fqx "$restored_record" "$installed_record" || path_refused
  fi
  # A prior restoration may have published the complete pair before a final
  # sync failed. Admit only that exact pair, never executable-only residue.
  if [ -e "$active" ]; then
    [ -e "$installed_record" ] && [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$active" 2>/dev/null)" = '0:755:1:regular file' ] || path_refused
    [ "$("$ROOT/usr/bin/sha256sum" "$active" | "$ROOT/usr/bin/cut" -d' ' -f1)" = "$executable_sha" ] || path_refused
  fi
  printf '%s\n' "$restored_record" >"$WORK/installed.json" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  "$ROOT/usr/bin/chmod" 0600 "$WORK/installed.json" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  restoration_stage_safe "$WORK/installed.json" "$record_stage" 0600 && restoration_stage_safe "$candidate" "$executable_stage" 0755 || path_refused
  restore_file "$WORK/installed.json" "$record_stage" "$installed_record" "$installed_directory" 0600
  [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$installed_record" 2>/dev/null)" = '0:600:1:regular file' ] && single_line "$installed_record" && "$ROOT/usr/bin/grep" -Fqx "$restored_record" "$installed_record" || path_refused
  # Publish the fully prepared executable last. Hard death before that point
  # leaves an exact record and absent executable, which the next run can resume.
  "$ROOT/usr/bin/sync" "$installed_record" "$installed_directory" "$ROOT/var/lib" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  restore_file "$candidate" "$executable_stage" "$active" "$ROOT/usr/local/bin" 0755
  [ ! -L "$active" ] && [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$active" 2>/dev/null)" = '0:755:1:regular file' ] || path_refused
  [ "$("$ROOT/usr/bin/sha256sum" "$active" | "$ROOT/usr/bin/cut" -d' ' -f1)" = "$executable_sha" ] || path_refused
  "$ROOT/usr/bin/sync" "$active" "$installed_record" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  "$ROOT/usr/bin/sync" "$installed_directory" "$ROOT/usr/local/bin" "$ROOT/var/lib" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  successful_finish 'SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED'
fi

# A clean installation never reclaims an existing product or protected state.
[ ! -e "$active" ] && [ ! -L "$active" ] && [ ! -e "$installed_directory" ] && [ ! -L "$installed_directory" ] || path_refused
for resource in /etc/sing-box /var/lib/sing-box /usr/bin/sing-box /etc/apt/sources.list.d/sagernet.sources /etc/apt/keyrings/sagernet.asc /etc/systemd/system/sbxr-mutation-lock.service /etc/systemd/system/sbxr-mutation-lock.service.sbxr-next /etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service /etc/systemd/system/sbxr-subscription.service /etc/systemd/system/sbxr-subscription-firewall.service /etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf /etc/letsencrypt/live/sbxr-subscription /etc/letsencrypt/archive/sbxr-subscription /etc/letsencrypt/renewal/sbxr-subscription.conf /etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription /etc/letsencrypt/renewal-hooks/post/sbxr-subscription /etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf; do
  [ ! -e "$ROOT$resource" ] && [ ! -L "$ROOT$resource" ] || path_refused
done
RECLAIMING=1
"$ROOT/usr/bin/mkdir" "$ROOT/var/lib/sbxr" || reclamation_failed
"$ROOT/usr/bin/chmod" 0700 "$ROOT/var/lib/sbxr" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
"$ROOT/usr/bin/mv" -n "$candidate" "$ROOT/usr/local/bin/sbxr" || reclamation_failed
[ ! -e "$candidate" ] || reclamation_failed
"$ROOT/usr/bin/chmod" 0600 "$ROOT/usr/local/bin/sbxr" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
"$ROOT/usr/bin/sync" "$ROOT/usr/local/bin/sbxr" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
record="$WORK/installed.json"
printf '{"schema":1,"repository":"%s","tag":"%s","commit":"%s","release_index_sha256":"%s","sequence":%s,"architecture":"%s","executable_sha256":"%s"}\n' "$REPOSITORY" "$TAG" "$COMMIT" "$index_sha" "$SEQUENCE" "$ARCH" "$executable_sha" >"$record" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
"$ROOT/usr/bin/chmod" 0600 "$record" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
"$ROOT/usr/bin/sync" "$record" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
"$ROOT/usr/bin/mv" -n "$record" "$ROOT/var/lib/sbxr/installed.json" || reclamation_failed
[ ! -e "$record" ] || reclamation_failed
"$ROOT/usr/bin/sync" "$ROOT/var/lib/sbxr" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
"$ROOT/usr/bin/chmod" 0755 "$ROOT/usr/local/bin/sbxr" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
verify_executable_identity "$ROOT/usr/local/bin/sbxr" "$WORK/final-identity.json" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
verify_elf_architecture "$ROOT/usr/local/bin/sbxr" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
final_record_pattern='^\{"schema":1,"repository":"{{.Repository}}","tag":"{{.Tag}}","commit":"{{.Commit}}","release_index_sha256":"'"$index_sha"'","sequence":{{.Sequence}},"architecture":"'"$ARCH"'","executable_sha256":"'"$executable_sha"'"\}$'
single_line "$WORK/final-identity.json" && "$ROOT/usr/bin/grep" -Eqx "$candidate_identity_pattern" "$WORK/final-identity.json" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
single_line "$ROOT/var/lib/sbxr/installed.json" && "$ROOT/usr/bin/grep" -Eqx "$final_record_pattern" "$ROOT/var/lib/sbxr/installed.json" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
[ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$ROOT/usr/local/bin/sbxr" 2>/dev/null)" = '0:755:1:regular file' ] || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
[ "$("$ROOT/usr/bin/stat" -c '%u:%a:%F' "$ROOT/var/lib/sbxr" 2>/dev/null)" = '0:700:directory' ] || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
[ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$ROOT/var/lib/sbxr/installed.json" 2>/dev/null)" = '0:600:1:regular file' ] || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
[ "$("$ROOT/usr/bin/sha256sum" "$ROOT/usr/local/bin/sbxr" | "$ROOT/usr/bin/cut" -d' ' -f1)" = "$executable_sha" ] || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
"$ROOT/usr/bin/sync" "$ROOT/usr/local/bin/sbxr" "$ROOT/var/lib/sbxr/installed.json" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
"$ROOT/usr/bin/sync" "$ROOT/var/lib/sbxr" "$ROOT/usr/local/bin" "$ROOT/var/lib" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'

successful_finish 'SOFTWARE-LIFECYCLE-INSTALL-INSTALLED'
`
