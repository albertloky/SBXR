#!/usr/bin/env bash
# Temporary operator launcher; never installed as the SBXR executable.
set -euo pipefail
umask 077
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin

refuse() { printf 'MVP protected menu refused: %s\n' "$1" >&2; exit 1; }
test "$#" -eq 0 || refuse 'zero arguments required'
root=/root/sbxr-mvp-log-parent
wrapper=$root/with-protected-log-parent.sh

test "$(id -u)" -eq 0 || refuse 'root required'
test ! -L "$wrapper" || refuse 'wrapper symlink'
test "$(stat -c '%u:%g:%a:%h:%F' "$wrapper")" = '0:0:700:1:regular file' || refuse 'wrapper metadata'
test "$(sha256sum "$wrapper" | cut -d' ' -f1)" = 4358cb1ec189bd33518a081702355405e9110892cf2be7e8235671005e2959eb || refuse 'wrapper identity'

# The qualified wrapper pins /var/log's link count. Creating this immediate
# child during first issuance would change that count and prevent restoration.
# The operator must also freshly verify installed snapd and the declared
# official Certbot before every invocation; this launcher does not check those
# receipts. Package installation is outside the reviewed window's scope.
python3 - <<'PY' || refuse 'existing protected Certbot log directory required'
import os, stat
path = '/var/log/letsencrypt'
info = os.lstat(path)
if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or os.listxattr(path, follow_symlinks=False):
    raise SystemExit(1)
PY

# Put this launcher INSIDE v3-menu-session.py's --executable boundary. Wrapping
# the Python driver would not enclose the new session it creates for SBXR.
exec /usr/bin/bash "$wrapper" run "$root/window.state" -- /usr/local/bin/sbxr
