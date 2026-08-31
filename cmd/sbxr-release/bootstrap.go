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
  local code=$1 status=${2:-1}
  trap - EXIT
  cleanup || code='SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  printf '%s\n' "$code"
  exit "$status"
}
host_refused() { finish 'SOFTWARE-LIFECYCLE-INSTALL-HOST-REFUSED'; }
release_refused() { finish 'SOFTWARE-LIFECYCLE-INSTALL-RELEASE-REFUSED'; }
release_unavailable() { finish 'SOFTWARE-LIFECYCLE-INSTALL-RELEASE-UNAVAILABLE'; }
prerequisite_failed() { finish 'SOFTWARE-LIFECYCLE-INSTALL-PREREQUISITE-FAILED'; }
path_refused() { finish 'SOFTWARE-LIFECYCLE-INSTALL-PATH-REFUSED'; }
reclamation_failed() { finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'; }
single_line() { [ "$("$ROOT/usr/bin/grep" -c '^' "$1" 2>/dev/null)" -eq 1 ] 2>/dev/null; }
mounted_within() {
  local target=$1 mount mounts="$WORK/mounts"
  "$ROOT/usr/bin/findmnt" -rn -o TARGET >"$mounts" 2>/dev/null || return 0
  while IFS= read -r mount; do
    case "$mount" in "$target"|"$target"/*) return 0 ;; esac
  done <"$mounts"
  return 1
}
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

[ "$#" -eq 0 ] || host_refused
[ "$("$ROOT/usr/bin/id" -u 2>/dev/null)" = '0' ] || host_refused
[ "$("$ROOT/usr/bin/uname" -s 2>/dev/null)" = 'Linux' ] || host_refused
case "$("$ROOT/usr/bin/uname" -m 2>/dev/null)" in
  x86_64) ARCH='amd64'; EXPECTED_EXECUTABLE_SHA256=$AMD64_EXECUTABLE_SHA256 ;;
  aarch64) ARCH='arm64'; EXPECTED_EXECUTABLE_SHA256=$ARM64_EXECUTABLE_SHA256 ;;
  *) host_refused ;;
esac
os_release="$ROOT/etc/os-release"
if [ -L "$os_release" ]; then
  [ "$("$ROOT/usr/bin/readlink" "$os_release" 2>/dev/null)" = '../usr/lib/os-release' ] || host_refused
  os_release="$ROOT/usr/lib/os-release"
fi
[ -f "$os_release" ] && [ ! -L "$os_release" ] || host_refused
[ "$("$ROOT/usr/bin/grep" -c '^ID=ubuntu$' "$os_release" 2>/dev/null)" = '1' ] || host_refused
[ "$("$ROOT/usr/bin/grep" -Ec '^VERSION_ID="?24\.04"?$' "$os_release" 2>/dev/null)" = '1' ] || host_refused

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
  for parent in "$ROOT/var" "$ROOT/var/lib" "$ROOT/var/lib/sbxr"; do
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
  # Committed records are canonical JSON. Match the complete supported contract,
  # never a prefix that could hide an unknown operation or conflicting identity.
  identity='\{"Repository":"{{.Repository}}","Tag":"v[1-9][0-9]*\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?","Commit":"[0-9a-f]{40}","IndexSHA256":"[0-9a-f]{64}"\}'
  schema=$("$ROOT/usr/bin/sed" -n 's/^{"schema":\([12]\),.*/\1/p' "$removal_record")
  case "$schema" in 1|2) ;; *) path_refused ;; esac
  prefix='\{"schema":'"$schema"',"phase":"Removal committed","unfinished_direction":"removal required","release_identity":'"$identity"
  config_sha=$("$ROOT/usr/bin/sed" -n 's/.*"configuration_sha256":"\([0-9a-f]*\)".*/\1/p' "$removal_record")
  resources='["/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-'"$schema"'","/var/lib/.sbxr-removal.json root:root 0600 one-link finalization authority"'
  if [ -z "$config_sha" ]; then
    fields=',"proxy_package_identity":"","public_ipv4":"","destination_address":"","destination_server_name":"","configuration_sha256":""'
    resources=$resources',"/usr/local/bin/sbxr exact committed Release Identity","/var/lib/sbxr/installed.json exact committed Release Identity"]'
    checkpoints='[0-3]'
    provenance_count=4
  else
    [ "${#config_sha}" -eq 64 ] || path_refused
    fields=',"proxy_package_identity":"https://deb\.sagernet\.org/ sing-box 1\.13\.19 amd64 24597120 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf","public_ipv4":"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+","destination_address":"google\.com:443","destination_server_name":"google\.com","configuration_sha256":"'"$config_sha"'"'
    resources=$resources',"/var/lib/sbxr/.proxy-ownership.json.next root:root 0600 one-link transaction material","/var/lib/sbxr/sing-box_1.13.19_amd64.deb root-owned one-link verified package artifact","/etc/apt/keyrings/sagernet.asc sha256:803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1","/etc/apt/keyrings/sagernet.asc.sbxr-next root-owned transaction material","/etc/apt/sources.list.d/sagernet.sources https://deb.sagernet.org/ signed-by sagernet.asc","/etc/apt/sources.list.d/sagernet.sources.sbxr-next root-owned transaction material","sing-box package 1.13.19 amd64 deb-sha256:fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf","sing-box package hold","/etc/sing-box/config.json sha256:'"$config_sha"'","/var/lib/sing-box package state","sing-box.service package provenance stopped-disabled-before-commit","sing-box package-created user and group","tcp/443 local listener"]'
    checkpoints='([0-9]|1[01])'
    provenance_count=15
    ip=$("$ROOT/usr/bin/sed" -n 's/.*"public_ipv4":"\([0-9.]*\)".*/\1/p' "$removal_record")
    IFS=. read -r ip1 ip2 ip3 ip4 <<<"$ip"
    for octet in "$ip1" "$ip2" "$ip3" "$ip4"; do
      case "$octet" in ''|*[!0-9]*|0[0-9]*) path_refused ;; esac
      [ "${#octet}" -le 3 ] && [ "$octet" -le 255 ] || path_refused
    done
    case "$ip1.$ip2.$ip3" in 0.*|10.*|127.*|169.254.*|192.0.0|192.0.2|192.88.99|192.168.*|198.51.100|203.0.113) path_refused ;; esac
    [ "$ip1" -lt 224 ] || path_refused
    if { [ "$ip1" -eq 100 ] && [ "$ip2" -ge 64 ] && [ "$ip2" -le 127 ]; } || { [ "$ip1" -eq 172 ] && [ "$ip2" -ge 16 ] && [ "$ip2" -le 31 ]; } || { [ "$ip1" -eq 198 ] && { [ "$ip2" -eq 18 ] || [ "$ip2" -eq 19 ]; }; }; then path_refused; fi
  fi
  # Escape literal contract text for ERE; no caller-controlled regular expression.
  resource_pattern=$(printf '%s' "$resources" | "$ROOT/usr/bin/sed" 's/[][\\.^$*+?(){}|]/\\&/g')
  suffix=',"permitted_resources":'"$resource_pattern"',"cleanup_checkpoint":0,"removal_checkpoint":'"$checkpoints"
  selector='release_identity'
  if [ "$schema" -eq 2 ]; then
    suffix=$suffix',"resource_creating_releases":\['"$identity"'(,'"$identity"'){'"$((provenance_count - 1))"'}\],"finishing_release_identity":'"$identity"
    selector='finishing_release_identity'
  fi
  "$ROOT/usr/bin/grep" -Eqx '^'"$prefix$fields$suffix"'\}$' "$removal_record" || path_refused
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
  local name=$1 destination=$2 limit=$3 url=${4:-} response status effective http
  if [ -z "$url" ]; then
    url="https://github.com/$REPOSITORY/releases/download/$TAG/$name"
  fi
  response=$("$ROOT/usr/bin/curl" --fail --silent --show-error --location --max-redirs 4 --max-filesize "$limit" --proto '=https' --proto-redir '=https' --output "$destination" --write-out $'%{url_effective}\n%{http_code}' "$url" 2>/dev/null)
  status=$?
  effective=$(printf '%s\n' "$response" | "$ROOT/usr/bin/sed" -n '1p')
  http=$(printf '%s\n' "$response" | "$ROOT/usr/bin/sed" -n '2p')
  if [ "$status" -ne 0 ]; then
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
  case "$?" in 0) return 0 ;; 3) release_unavailable ;; *) release_refused ;; esac
}

index="$WORK/release-index.json"
download_or_finish 'release-index.json' "$index" 1048576
[ -f "$index" ] && [ ! -L "$index" ] || release_refused
[ "$("$ROOT/usr/bin/wc" -c <"$index")" -le 1048576 ] 2>/dev/null || release_refused
index_pattern='^\{"schema":1,"repository":"{{.Repository}}","tag":"'"$TAG"'","commit":"'"$COMMIT"'","sequence":[1-9][0-9]*,"assets":\[\{"name":"install\.sh","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\},\{"name":"sbxr-linux-amd64\.tar\.gz","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\},\{"name":"sbxr-linux-arm64\.tar\.gz","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\}\]\}$'
single_line "$index" && "$ROOT/usr/bin/grep" -Eqx "$index_pattern" "$index" || release_refused
index_sequence=$("$ROOT/usr/bin/sed" -n 's/.*"sequence":\([0-9]*\).*/\1/p' "$index")
if [ "$RESTORING_REMOVAL" -eq 1 ]; then SEQUENCE=$index_sequence; else [ "$index_sequence" = "$SEQUENCE" ] || release_refused; fi
archive_name="sbxr-linux-$ARCH.tar.gz"
archive_sha=$("$ROOT/usr/bin/sed" -n 's/.*"name":"'"$archive_name"'"[^}]*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p' "$index")
archive_size=$("$ROOT/usr/bin/sed" -n 's/.*"name":"'"$archive_name"'"[^}]*"size":\([0-9][0-9]*\).*/\1/p' "$index")
[ "${#archive_sha}" -eq 64 ] && [ "$archive_size" -gt 0 ] 2>/dev/null || release_refused

archive="$WORK/$archive_name"
download_or_finish "$archive_name" "$archive" 268435456
[ -f "$archive" ] && [ ! -L "$archive" ] || release_refused
[ "$("$ROOT/usr/bin/wc" -c <"$archive")" -eq "$archive_size" ] 2>/dev/null || release_refused
[ "$("$ROOT/usr/bin/sha256sum" "$archive" | "$ROOT/usr/bin/cut" -d' ' -f1)" = "$archive_sha" ] || release_refused
index_sha=$("$ROOT/usr/bin/sha256sum" "$index" | "$ROOT/usr/bin/cut" -d' ' -f1) || release_refused
[ "$RESTORING_REMOVAL" -eq 0 ] || [ "$index_sha" = "$REMOVAL_INDEX_SHA" ] || release_refused

active="$ROOT/usr/local/bin/sbxr"
installed_directory="$ROOT/var/lib/sbxr"
installed_record="$installed_directory/installed.json"
if [ -L "$active" ]; then
  legacy_target=$("$ROOT/usr/bin/readlink" "$active" 2>/dev/null) || path_refused
  legacy_path_pattern='^/opt/sbxr/releases/v1\.0\.([0-9]|1[0-5])-[0-9a-f]{40}-[0-9a-f]{64}/sbxr$'
  if printf '%s\n' "$legacy_target" | "$ROOT/usr/bin/grep" -Eqx "$legacy_path_pattern"; then
      legacy_release=${legacy_target#/opt/sbxr/releases/}
      legacy_release=${legacy_release%/sbxr}
      legacy_tag=${legacy_release%%-*}
      legacy_rest=${legacy_release#*-}
      legacy_commit=${legacy_rest%%-*}
      legacy_index_sha=${legacy_rest#*-}
      legacy="$ROOT$legacy_target"
      if [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$legacy" 2>/dev/null)" = '0:755:1:regular file' ]; then
        if [ ! -x "$ROOT/usr/bin/tar" ]; then
          "$ROOT/usr/bin/apt-get" install --yes --no-install-recommends tar >/dev/null 2>&1 || prerequisite_failed
          [ -x "$ROOT/usr/bin/tar" ] || prerequisite_failed
        fi
        legacy_index="$WORK/legacy-release-index.json"
        legacy_archive="$WORK/legacy-sbxr-linux-$ARCH.tar.gz"
        legacy_executable="$WORK/legacy-sbxr"
        if download 'release-index.json' "$legacy_index" 1048576 "https://github.com/$REPOSITORY/releases/download/$legacy_tag/release-index.json" \
          && [ "$("$ROOT/usr/bin/sha256sum" "$legacy_index" | "$ROOT/usr/bin/cut" -d' ' -f1)" = "$legacy_index_sha" ] \
          && single_line "$legacy_index" \
          && "$ROOT/usr/bin/grep" -Fqx '"repository":"{{.Repository}}"' <("$ROOT/usr/bin/sed" -n 's/.*\("repository":"[^"]*"\).*/\1/p' "$legacy_index") \
          && "$ROOT/usr/bin/grep" -Fqx '"tag":"'"$legacy_tag"'"' <("$ROOT/usr/bin/sed" -n 's/.*\("tag":"[^"]*"\).*/\1/p' "$legacy_index") \
          && "$ROOT/usr/bin/grep" -Fqx '"commit":"'"$legacy_commit"'"' <("$ROOT/usr/bin/sed" -n 's/.*\("commit":"[^"]*"\).*/\1/p' "$legacy_index"); then
          legacy_archive_sha=$("$ROOT/usr/bin/sed" -n 's/.*"name":"sbxr-linux-'"$ARCH"'\.tar\.gz"[^}]*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p' "$legacy_index")
          legacy_archive_size=$("$ROOT/usr/bin/sed" -n 's/.*"name":"sbxr-linux-'"$ARCH"'\.tar\.gz"[^}]*"size":\([0-9][0-9]*\).*/\1/p' "$legacy_index")
          if [ "${#legacy_archive_sha}" -eq 64 ] && [ "$legacy_archive_size" -gt 0 ] 2>/dev/null \
            && download "sbxr-linux-$ARCH.tar.gz" "$legacy_archive" 268435456 "https://github.com/$REPOSITORY/releases/download/$legacy_tag/sbxr-linux-$ARCH.tar.gz" \
            && [ "$("$ROOT/usr/bin/wc" -c <"$legacy_archive")" -eq "$legacy_archive_size" ] 2>/dev/null \
            && [ "$("$ROOT/usr/bin/sha256sum" "$legacy_archive" | "$ROOT/usr/bin/cut" -d' ' -f1)" = "$legacy_archive_sha" ] \
            && [ "$("$ROOT/usr/bin/tar" -tzf "$legacy_archive" 2>/dev/null)" = 'sbxr' ] \
            && "$ROOT/usr/bin/tar" -xOzf "$legacy_archive" sbxr >"$legacy_executable" 2>/dev/null \
            && "$ROOT/usr/bin/cmp" -s "$legacy" "$legacy_executable"; then
            finish 'SOFTWARE-LIFECYCLE-INSTALL-LEGACY-REFUSED'
          fi
        fi
      fi
  fi
fi
if [ -f "$active" ] && [ ! -L "$active" ] && [ -d "$installed_directory" ] && [ ! -L "$installed_directory" ] && [ -f "$installed_record" ] && [ ! -L "$installed_record" ] \
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
        successful_finish 'SOFTWARE-LIFECYCLE-INSTALL-ALREADY-CURRENT'
      fi
    fi
  fi
fi
if [ ! -x "$ROOT/usr/bin/tar" ]; then
  "$ROOT/usr/bin/apt-get" install --yes --no-install-recommends tar >/dev/null 2>&1 || prerequisite_failed
  [ -x "$ROOT/usr/bin/tar" ] || prerequisite_failed
fi
[ "$("$ROOT/usr/bin/tar" -tzf "$archive" 2>/dev/null)" = 'sbxr' ] || release_refused
candidate="$WORK/sbxr"
(ulimit -f 262144; "$ROOT/usr/bin/tar" -xOzf "$archive" sbxr >"$candidate") 2>/dev/null || release_refused
[ -f "$candidate" ] && [ ! -L "$candidate" ] || release_refused
"$ROOT/usr/bin/chmod" 0600 "$candidate" || release_refused
executable_sha=$("$ROOT/usr/bin/sha256sum" "$candidate" | "$ROOT/usr/bin/cut" -d' ' -f1) || release_refused
verify_executable_identity "$candidate" "$WORK/candidate-identity.json" || release_refused
verify_elf_architecture "$candidate" || release_refused
candidate_identity_pattern='^\{"schema":1,"repository":"{{.Repository}}","tag":"'"$TAG"'","commit":"'"$COMMIT"'","sequence":'"$SEQUENCE"',"architecture":"'"$ARCH"'","payload_sha256":"[0-9a-f]{64}"\}$'
single_line "$WORK/candidate-identity.json" && "$ROOT/usr/bin/grep" -Eqx "$candidate_identity_pattern" "$WORK/candidate-identity.json" || release_refused
[ "$RESTORING_REMOVAL" -eq 1 ] || [ "$executable_sha" = "$EXPECTED_EXECUTABLE_SHA256" ] || release_refused

if [ "$RESTORING_REMOVAL" -eq 1 ]; then
  active="$ROOT/usr/local/bin/sbxr"
  installed_directory="$ROOT/var/lib/sbxr"
  installed_record="$installed_directory/installed.json"
  [ ! -e "$active" ] && [ ! -L "$active" ] || path_refused
  if [ ! -e "$installed_directory" ] && [ ! -L "$installed_directory" ]; then
    "$ROOT/usr/bin/mkdir" "$installed_directory" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
    "$ROOT/usr/bin/chmod" 0700 "$installed_directory" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  fi
  [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%F' "$installed_directory" 2>/dev/null)" = '0:700:directory' ] || path_refused
  unexpected=$("$ROOT/usr/bin/find" "$installed_directory" -mindepth 1 -maxdepth 1 ! -name proxy-ownership.json ! -name installed.json -print -quit 2>/dev/null) || path_refused
  [ -z "$unexpected" ] || path_refused
  restored_record=$(printf '{"schema":1,"repository":"%s","tag":"%s","commit":"%s","release_index_sha256":"%s","sequence":%s,"architecture":"%s","executable_sha256":"%s"}' "$REPOSITORY" "$TAG" "$COMMIT" "$index_sha" "$SEQUENCE" "$ARCH" "$executable_sha")
  if [ -e "$installed_record" ] || [ -L "$installed_record" ]; then
    [ ! -L "$installed_record" ] && [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$installed_record" 2>/dev/null)" = '0:600:1:regular file' ] && single_line "$installed_record" && "$ROOT/usr/bin/grep" -Fqx "$restored_record" "$installed_record" || path_refused
  fi
  "$ROOT/usr/bin/mv" -n "$candidate" "$active" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  "$ROOT/usr/bin/chmod" 0755 "$active" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  "$ROOT/usr/bin/sync" "$active" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  if [ ! -e "$installed_record" ] && [ ! -L "$installed_record" ]; then
    printf '{"schema":1,"repository":"%s","tag":"%s","commit":"%s","release_index_sha256":"%s","sequence":%s,"architecture":"%s","executable_sha256":"%s"}\n' "$REPOSITORY" "$TAG" "$COMMIT" "$index_sha" "$SEQUENCE" "$ARCH" "$executable_sha" >"$WORK/installed.json" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
    "$ROOT/usr/bin/chmod" 0600 "$WORK/installed.json" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
    "$ROOT/usr/bin/sync" "$WORK/installed.json" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
    "$ROOT/usr/bin/mv" -n "$WORK/installed.json" "$installed_record" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  fi
  [ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$installed_record" 2>/dev/null)" = '0:600:1:regular file' ] && single_line "$installed_record" && "$ROOT/usr/bin/grep" -Fqx "$restored_record" "$installed_record" || path_refused
  "$ROOT/usr/bin/sync" "$installed_directory" "$ROOT/usr/local/bin" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'
  successful_finish 'SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED'
fi

active_identity=''
state_identity=''
if [ -e "$active" ] || [ -L "$active" ]; then
  before=$("$ROOT/usr/bin/stat" -c '%d:%i:%F' "$active" 2>/dev/null) || path_refused
  mounted_within "$active" && path_refused
  active_identity=$("$ROOT/usr/bin/stat" -c '%d:%i:%F' "$active" 2>/dev/null) || path_refused
  [ "$before" = "$active_identity" ] || path_refused
fi
if [ -e "$installed_directory" ] || [ -L "$installed_directory" ]; then
  before=$("$ROOT/usr/bin/stat" -c '%d:%i:%F' "$installed_directory" 2>/dev/null) || path_refused
  mounted_within "$installed_directory" && path_refused
  state_identity=$("$ROOT/usr/bin/stat" -c '%d:%i:%F' "$installed_directory" 2>/dev/null) || path_refused
  [ "$before" = "$state_identity" ] || path_refused
fi

RECLAIMING=1
if [ -n "$active_identity" ]; then
  mounted_within "$active" && reclamation_failed
  [ "$("$ROOT/usr/bin/stat" -c '%d:%i:%F' "$active" 2>/dev/null)" = "$active_identity" ] || reclamation_failed
  "$ROOT/usr/bin/rm" -rf --one-file-system -- "$active" || reclamation_failed
  [ ! -e "$active" ] && [ ! -L "$active" ] || reclamation_failed
fi
if [ -n "$state_identity" ]; then
  mounted_within "$installed_directory" && reclamation_failed
  [ "$("$ROOT/usr/bin/stat" -c '%d:%i:%F' "$installed_directory" 2>/dev/null)" = "$state_identity" ] || reclamation_failed
  "$ROOT/usr/bin/rm" -rf --one-file-system -- "$installed_directory" || reclamation_failed
  [ ! -e "$installed_directory" ] && [ ! -L "$installed_directory" ] || reclamation_failed
fi
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
"$ROOT/usr/bin/sync" "$ROOT/usr/local/bin" "$ROOT/var/lib" || finish 'SOFTWARE-LIFECYCLE-INSTALL-FAILED'

successful_finish 'SOFTWARE-LIFECYCLE-INSTALL-INSTALLED'
`
