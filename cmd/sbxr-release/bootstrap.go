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

var bootstrapValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

func buildBootstrapFile(options bootstrapOptions) error {
	if options.output == "" || !bootstrapValue.MatchString(options.version) || options.tag != "v"+options.version || !bootstrapValue.MatchString(options.tag) || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(options.commit) || options.sequence == 0 || options.root != "" && (!strings.HasPrefix(options.root, "/") || strings.ContainsAny(options.root, "\n\r'")) {
		return errors.New("bootstrap build refused")
	}
	var body bytes.Buffer
	if template.Must(template.New("bootstrap").Parse(bootstrapBody)).Execute(&body, map[string]string{
		"Repository": softwarelifecycle.Repository,
		"Tag":        options.tag, "Commit": options.commit, "Version": options.version,
		"Sequence": fmt.Sprint(options.sequence), "Root": strings.TrimSuffix(options.root, "/"),
	}) != nil {
		return errors.New("bootstrap build refused")
	}
	root := strings.TrimSuffix(options.root, "/")
	cleanBody := "'" + strings.ReplaceAll(body.String(), "'", `'"'"'`) + "'"
	body.Reset()
	fmt.Fprintf(&body, "#!/bin/sh\nexec %s/usr/bin/env -i TERM=\"${TERM-}\" PATH=/usr/bin:/bin LC_ALL=C %s/bin/sh -c %s sbxr-bootstrap \"$@\"\n", root, root, cleanBody)
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
umask 077
PATH='/usr/bin:/bin'
LC_ALL=C
export PATH LC_ALL

REPOSITORY='{{.Repository}}'
TAG='{{.Tag}}'
COMMIT='{{.Commit}}'
VERSION='{{.Version}}'
SEQUENCE='{{.Sequence}}'
ARCHITECTURES='amd64 arm64'
ASSET_NAMES='install.sh release-index.json sbxr-linux-amd64.tar.gz sbxr-linux-arm64.tar.gz sbxr-components-linux-amd64.tar.gz sbxr-components-linux-arm64.tar.gz'
ROOT='{{.Root}}'
WORK=''

cleanup() {
  if [ -n "$WORK" ]; then
	path=$WORK
	WORK=''
	"$ROOT/bin/rm" -rf -- "$path" >/dev/null 2>&1 || return 1
	[ ! -e "$path" ] && [ ! -L "$path" ] || return 1
  fi
}
refuse() {
	trap - EXIT
	if ! cleanup; then
		printf '%s\n' 'SBXR-BOOTSTRAP-CLEANUP-FAILED' >&2
		exit 1
	fi
  printf '%s\n' 'SBXR-BOOTSTRAP-REFUSED' >&2
  exit 1
}
interrupted() {
	trap - EXIT
	if ! cleanup; then
		printf '%s\n' 'SBXR-BOOTSTRAP-CLEANUP-FAILED' >&2
		exit 1
	fi
  printf '%s\n' 'SBXR-BOOTSTRAP-INTERRUPTED' >&2
  exit 130
}
trap interrupted HUP INT TERM
trap cleanup EXIT

if [ "$#" -eq 0 ]; then
  :
elif [ "$#" -eq 2 ] && [ "$1" = '--tag' ] && [ "$2" = "$TAG" ]; then
  :
else
  refuse
fi

[ -t 0 ] && [ -t 1 ] || refuse
case "${TERM-}" in ''|*[!A-Za-z0-9._+-]*) refuse ;; esac

for tool in curl grep id mktemp sed sha256sum stat tar uname getent cut env; do
  [ -x "$ROOT/usr/bin/$tool" ] || refuse
done
[ -x "$ROOT/bin/chmod" ] && [ -x "$ROOT/bin/rm" ] || refuse
[ "$("$ROOT/usr/bin/id" -u 2>/dev/null)" != '0' ] || refuse

os_release="$ROOT/etc/os-release"
[ -f "$os_release" ] && [ ! -L "$os_release" ] || refuse
"$ROOT/usr/bin/grep" -qx 'ID=ubuntu' "$os_release" >/dev/null 2>&1 || refuse
"$ROOT/usr/bin/grep" -Eq '^VERSION_ID="?24\.04"?$' "$os_release" >/dev/null 2>&1 || refuse

machine=$("$ROOT/usr/bin/uname" -m 2>/dev/null) || refuse
case "$machine" in
  x86_64) ARCH='amd64' ;;
  aarch64) ARCH='arm64' ;;
  *) refuse ;;
esac
case " $ARCHITECTURES " in *" $ARCH "*) : ;; *) refuse ;; esac

owner_uid=$("$ROOT/usr/bin/id" -u 2>/dev/null) || refuse
owner_name=$("$ROOT/usr/bin/id" -un 2>/dev/null) || refuse
owner_home=$("$ROOT/usr/bin/getent" passwd "$owner_uid" 2>/dev/null | "$ROOT/usr/bin/cut" -d: -f6) || refuse
case "$owner_name:$owner_home" in *[!A-Za-z0-9._+/:@-]*|*:|*:) refuse ;; esac
[ -d "$owner_home" ] || refuse

WORK=$("$ROOT/usr/bin/mktemp" -d "$ROOT/tmp/sbxr-bootstrap.XXXXXX" 2>/dev/null) || refuse
"$ROOT/bin/chmod" 0700 "$WORK" >/dev/null 2>&1 || refuse
[ "$("$ROOT/usr/bin/stat" -c '%u:%a:%F' "$WORK" 2>/dev/null)" = "$owner_uid:700:directory" ] || refuse

download() {
  asset=$1
  destination=$2
  effective=$3
  limit=$4
  url="https://github.com/$REPOSITORY/releases/download/$TAG/$asset"
  "$ROOT/usr/bin/curl" --fail --silent --show-error --location --max-redirs 4 --max-filesize "$limit" --proto '=https' --proto-redir '=https' --output "$destination" --write-out '%{url_effective}' "$url" >"$effective" 2>"$WORK/private.log" || return 1
  resolved=$("$ROOT/usr/bin/sed" -n '1p' "$effective" 2>/dev/null) || return 1
  case "$resolved" in
    "https://github.com/$REPOSITORY/releases/download/$TAG/$asset"|https://release-assets.githubusercontent.com/*|https://objects.githubusercontent.com/*) : ;;
    *) return 1 ;;
  esac
  [ -f "$destination" ] && [ ! -L "$destination" ] || return 1
}

printf '%s\n' 'SBXR bootstrap: verifying release'
index="$WORK/release-index.json"
download 'release-index.json' "$index" "$WORK/index.url" 1048576 || refuse
[ "$("$ROOT/usr/bin/stat" -c '%u:%a:%F' "$index" 2>/dev/null)" = "$owner_uid:600:regular file" ] || refuse
[ "$("$ROOT/usr/bin/stat" -c '%s' "$index" 2>/dev/null)" -le 1048576 ] || refuse

index_pattern='^\{"schema":1,"product":"sbxr","repository":"{{.Repository}}","version":"{{.Version}}","sequence":{{.Sequence}},"tag":"{{.Tag}}","commit":"{{.Commit}}","state_schema":[1-9][0-9]*,"minimum_updater_schema":[1-9][0-9]*,"assets":\[\{"role":"application-linux-amd64","name":"sbxr-linux-amd64.tar.gz","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\},\{"role":"application-linux-arm64","name":"sbxr-linux-arm64.tar.gz","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\},\{"role":"components-linux-amd64","name":"sbxr-components-linux-amd64.tar.gz","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\},\{"role":"components-linux-arm64","name":"sbxr-components-linux-arm64.tar.gz","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\},\{"role":"bootstrap","name":"install.sh","size":[1-9][0-9]*,"sha256":"[0-9a-f]{64}"\}\]\}$'
"$ROOT/usr/bin/grep" -Eq "$index_pattern" "$index" >/dev/null 2>&1 || refuse
state_schema=$("$ROOT/usr/bin/sed" -n 's|.*"state_schema":\([0-9][0-9]*\),"minimum_updater_schema".*|\1|p' "$index" 2>/dev/null) || refuse
case "$state_schema" in ''|*[!0-9]*) refuse ;; esac

archive_name="sbxr-linux-$ARCH.tar.gz"
archive_fact=$("$ROOT/usr/bin/sed" -n "s|.*\"role\":\"application-linux-$ARCH\",\"name\":\"$archive_name\",\"size\":\([0-9][0-9]*\),\"sha256\":\"\([0-9a-f][0-9a-f]*\)\".*|\1:\2|p" "$index" 2>/dev/null) || refuse
case "$archive_fact" in *:*) : ;; *) refuse ;; esac
archive_size=${archive_fact%%:*}
archive_sha=${archive_fact#*:}
[ "${#archive_sha}" -eq 64 ] || refuse

printf '%s\n' 'SBXR bootstrap: verifying executable'
archive="$WORK/$archive_name"
download "$archive_name" "$archive" "$WORK/archive.url" 268435456 || refuse
[ "$("$ROOT/usr/bin/stat" -c '%s' "$archive" 2>/dev/null)" = "$archive_size" ] || refuse
[ "$("$ROOT/usr/bin/sha256sum" "$archive" 2>/dev/null | "$ROOT/usr/bin/cut" -d' ' -f1)" = "$archive_sha" ] || refuse
[ "$("$ROOT/usr/bin/tar" -tzf "$archive" 2>"$WORK/private.log")" = 'sbxr' ] || refuse
"$ROOT/usr/bin/tar" -xzf "$archive" -C "$WORK" --no-same-owner --no-same-permissions 2>"$WORK/private.log" || refuse
executable="$WORK/sbxr"
"$ROOT/bin/chmod" 0700 "$executable" >/dev/null 2>&1 || refuse
[ "$("$ROOT/usr/bin/stat" -c '%u:%a:%h:%F' "$executable" 2>/dev/null)" = "$owner_uid:700:1:regular file" ] || refuse

"$executable" version --json >"$WORK/version.json" 2>"$WORK/private.log" || refuse
version_pattern='^\{"build":\{"repository":"{{.Repository}}","tag":"{{.Tag}}","commit":"{{.Commit}}","payload_sha256":"[0-9a-f]{64}"\},"architecture":"'$ARCH'","state_schema":'$state_schema'\}$'
"$ROOT/usr/bin/grep" -Eq "$version_pattern" "$WORK/version.json" >/dev/null 2>&1 || refuse

printf '%s\n' 'SBXR bootstrap: launching Owner Console'
"$ROOT/usr/bin/env" -i HOME="$owner_home" USER="$owner_name" LOGNAME="$owner_name" TERM="$TERM" LANG=C.UTF-8 PATH=/usr/bin:/bin "$executable"
launch_status=$?
cleanup
if [ "$?" -ne 0 ]; then
	trap - EXIT
	printf '%s\n' 'SBXR-BOOTSTRAP-CLEANUP-FAILED' >&2
	exit 1
fi
trap - EXIT
if [ "$launch_status" -ne 0 ]; then
  printf '%s\n' 'SBXR-BOOTSTRAP-LAUNCH-FAILED' >&2
fi
exit "$launch_status"
`
