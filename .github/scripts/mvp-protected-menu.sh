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
test "$(sha256sum "$wrapper" | cut -d' ' -f1)" = 56fab3f89dbed0dbb668f296a33ac8b512e8676edb5962a796a45bbc649123de || refuse 'wrapper identity'

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

# Put this launcher INSIDE v3-menu-session.py's --executable boundary and pass
# --protected-wrapper so startup cancellation uses the private USR1 handshake.
# Wrapping
# the Python driver would not enclose the new session it creates for SBXR.
# Keep the wrapper/control files at 077. Only the product child gets the normal
# creation mask: the unchanged v3.1.81 updater requests 0755 for staged binaries
# and cannot tolerate the wrapper reducing those files to 0700. Explicit 0600
# product files stay private. exec keeps product death/cleanup in the same group.
exec /usr/bin/bash "$wrapper" run "$root/window.state" -- \
  /usr/bin/bash -c 'umask 022; exec /usr/local/bin/sbxr'
