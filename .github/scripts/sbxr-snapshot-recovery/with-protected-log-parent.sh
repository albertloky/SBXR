#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin

log_parent=/var/log
supervisor_sha256=9861f9a16af051c9dcb7d21324ddb97a60690f3cf3fca7987f6c642d972a56cc

refuse() {
  printf 'protected log-parent window refused: %s\n' "$1" >&2
  return 1
}

protected_state_path() {
  local state=$1 parent canonical
  case "$state" in
    /*) ;;
    *) return 1 ;;
  esac
  case "$state" in
    *$'\n'*|*/|*/.|*/..) return 1 ;;
  esac
  parent=$(dirname -- "$state")
  canonical=$(realpath -e -- "$parent") || return 1
  test "$canonical" = "$parent" || return 1
  test ! -L "$parent" || return 1
  python3 - "$parent" <<'PY' || return 1
import os, stat, sys
path = sys.argv[1]
while True:
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit(1)
    if path == "/":
        break
    path = os.path.dirname(path)
PY
  test "$(stat -c '%u:%g:%a:%F' -- "$parent")" = '0:0:700:directory'
}

no_xattrs() {
  python3 - "$1" <<'PY'
import os, sys
path = sys.argv[1]
if os.path.islink(path) or os.listxattr(path, follow_symlinks=False):
    raise SystemExit(1)
PY
}

channel_safe() {
  test ! -L "$1" || return 1
  test "$(stat -c '%u:%g:%a:%h:%F' -- "$1")" = '0:0:600:1:fifo' || return 1
  no_xattrs "$1"
}

channel_open() {
  python3 - "$1" <<'PY'
import errno, os, sys
try:
    wanted = os.stat(sys.argv[1], follow_symlinks=False)
    processes = os.listdir("/proc")
except OSError:
    raise SystemExit(0)
for process in processes:
    if not process.isdigit():
        continue
    try:
        descriptors = os.listdir(f"/proc/{process}/fd")
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ESRCH):
            continue
        raise SystemExit(0)
    for descriptor in descriptors:
        try:
            observed = os.stat(f"/proc/{process}/fd/{descriptor}")
        except OSError as error:
            if error.errno in (errno.EBADF, errno.ENOENT, errno.ESRCH):
                continue
            raise SystemExit(0)
        if (observed.st_dev, observed.st_ino) == (wanted.st_dev, wanted.st_ino):
            raise SystemExit(0)
raise SystemExit(1)
PY
}

log_identity() {
  test ! -L "$log_parent" || return 1
  test "$(stat -c '%U:%G:%F' -- "$log_parent")" = 'root:syslog:directory' || return 1
  no_xattrs "$log_parent" || return 1
  stat -c '%d:%i:%u:%g:%h:%a' -- "$log_parent"
}

group_has_live_processes() {
  local pgid=$1 processes
  processes=$(ps -eo pgid=,stat=) || return 0
  awk -v group="$pgid" '
    $1 == group && $2 !~ /^Z/ { found=1 }
    END { exit !found }
  ' <<< "$processes"
}

wait_group_quiescent() {
  local pgid=$1 attempt
  for ((attempt=0; attempt<50; attempt++)); do
    group_has_live_processes "$pgid" || return 0
    sleep 0.1
  done
  return 1
}

process_identity() {
  python3 - "$1" <<'PY'
import errno, sys
try:
    body = open(f"/proc/{int(sys.argv[1])}/stat", encoding="ascii").read()
    tail = body.rsplit(") ", 1)[1].split()
    print(":".join((tail[0], tail[1], tail[2], tail[3], tail[19])))
except OSError as error:
    if error.errno in (errno.ENOENT, errno.ESRCH):
        raise SystemExit(1)
    raise SystemExit(2)
except (ValueError, IndexError):
    raise SystemExit(2)
PY
}

read_state() {
  local state=$1 before after size
  protected_state_path "$state" || return 1
  test ! -L "$state" || return 1
  before=$(stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- "$state") || return 1
  test "$(stat -c '%u:%g:%a:%h:%F' -- "$state")" = '0:0:600:1:regular file' || return 1
  no_xattrs "$state" || return 1
  size=$(stat -c '%s' -- "$state") || return 1
  test "$size" -gt 0 && test "$size" -lt 512 || return 1
  mapfile -t saved < "$state" || return 1
  after=$(stat -c '%d:%i:%u:%g:%a:%h:%s:%F' -- "$state") || return 1
  test "$before" = "$after" || return 1
  test "${#saved[@]}" -eq 11 || return 1
  test "${saved[0]}" = 'sbxr-protected-log-parent-v1' || return 1
  test "${saved[1]}" = 'path=/var/log' || return 1
  [[ "${saved[2]}" =~ ^device=[0-9]+$ ]] || return 1
  [[ "${saved[3]}" =~ ^inode=[0-9]+$ ]] || return 1
  test "${saved[4]}" = 'uid=0' || return 1
  [[ "${saved[5]}" =~ ^gid=[0-9]+$ ]] || return 1
  [[ "${saved[6]}" =~ ^links=[0-9]+$ ]] || return 1
  [[ "${saved[7]}" =~ ^boot_id=[0-9a-f-]{36}$ ]] || return 1
  [[ "${saved[8]}" =~ ^controller_pid=[1-9][0-9]+$ ]] || return 1
  [[ "${saved[9]}" =~ ^controller_starttime=[1-9][0-9]*$ ]] || return 1
  test "${saved[10]}" = 'mode=775' || return 1
}

restore_window() {
  local state=$1 identity mode parent pid observed observed_status=0 current_boot control result
  read_state "$state" || { refuse 'unsafe state file'; return 1; }
  control=$state.control
  result=$state.result
  for channel in "$control" "$result"; do
    if test -e "$channel" || test -L "$channel"; then
      channel_safe "$channel" || { refuse 'unsafe control channels'; return 1; }
    fi
  done
  current_boot=$(cat /proc/sys/kernel/random/boot_id) || { refuse 'boot identity unavailable'; return 1; }
  test "$current_boot" = "${saved[7]#boot_id=}" || { refuse 'boot identity changed'; return 1; }
  pid=${saved[8]#controller_pid=}
  observed=$(process_identity "$pid") || observed_status=$?
  if test "$observed_status" -gt 1; then
    refuse 'controller identity inspection uncertain'
    return 1
  fi
  if test "$observed_status" -eq 0; then
    if test "${observed##*:}" != "${saved[9]#controller_starttime=}"; then
      refuse 'controller PID identity reused'
      return 1
    fi
    if test "${observed%%:*}" != Z; then
      refuse 'recorded controller remains live'
      return 1
    fi
  fi
  if group_has_live_processes "$pid"; then
    refuse 'recorded command group remains live'
    return 1
  fi
  for channel in "$control" "$result"; do
    if test -e "$channel" || test -L "$channel"; then
      channel_open "$channel" && { refuse 'control channel contention'; return 1; }
    fi
  done
  identity=$(log_identity) || { refuse 'changed log parent'; return 1; }
  test "${identity%:*}" = "${saved[2]#device=}:${saved[3]#inode=}:${saved[4]#uid=}:${saved[5]#gid=}:${saved[6]#links=}" || { refuse 'changed log-parent identity'; return 1; }
  mode=${identity##*:}
  case "$mode" in
    755) chmod 0775 -- "$log_parent" || { refuse 'log-parent chmod failed'; return 1; } ;;
    775) ;;
    *) refuse 'unexpected log-parent mode'; return 1 ;;
  esac
  identity=$(log_identity) || { refuse 'restored log parent unsafe'; return 1; }
  test "$identity" = "${saved[2]#device=}:${saved[3]#inode=}:${saved[4]#uid=}:${saved[5]#gid=}:${saved[6]#links=}:775" || { refuse 'log-parent restoration mismatch'; return 1; }
  parent=$(dirname -- "$state")
  for channel in "$control" "$result"; do
    if test -e "$channel" || test -L "$channel"; then
      channel_safe "$channel" || { refuse 'changed control channel'; return 1; }
      channel_open "$channel" && { refuse 'control channel contention'; return 1; }
      unlink -- "$channel" || { refuse 'control removal failed'; return 1; }
    fi
  done
  sync -f "$parent" || { refuse 'control removal durability failed'; return 1; }
  unlink -- "$state" || { refuse 'state removal failed'; return 1; }
  sync -f "$parent" || { refuse 'state removal durability failed'; return 1; }
}

usage() {
  printf '%s\n' \
    'usage: with-protected-log-parent.sh run /absolute/protected/state -- COMMAND [ARG...]' \
    '       with-protected-log-parent.sh restore /absolute/protected/state' >&2
  exit 2
}

test "$(id -u)" -eq 0 || refuse 'root required'
test "$#" -ge 2 || usage
mode=$1
state=$2

case "$mode" in
  restore)
    test "$#" -eq 2 || usage
    restore_window "$state"
    ;;
  run)
    test "$#" -ge 4 && test "$3" = -- || usage
    protected_state_path "$state" || refuse 'unsafe state path'
    test ! -e "$state" && test ! -L "$state" || refuse 'state already exists'
    control=$state.control
    result=$state.result
    test ! -e "$control" && test ! -L "$control" && test ! -e "$result" && test ! -L "$result" || refuse 'control channel already exists'
    identity=$(log_identity) || refuse 'unsafe log parent'
    test "${identity##*:}" = 775 || refuse 'original log-parent mode'
    IFS=: read -r device inode uid gid links original_mode <<< "$identity"
    script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    supervisor=$script_directory/protected_command_supervisor.py
    protected_state_path "$supervisor" || refuse 'unsafe supervisor path'
    test ! -L "$supervisor" || refuse 'unsafe supervisor file'
    test "$(stat -c '%u:%g:%a:%h:%F' -- "$supervisor")" = '0:0:600:1:regular file' || refuse 'unsafe supervisor file'
    no_xattrs "$supervisor" || refuse 'unsafe supervisor attributes'
    test "$(sha256sum "$supervisor" | cut -d' ' -f1)" = "$supervisor_sha256" || refuse 'supervisor identity'
    mkfifo -m 0600 "$control" "$result"
    channel_safe "$control" && channel_safe "$result" || refuse 'unsafe created control channels'
    sync -f "$(dirname -- "$state")"
    exec {control_anchor}<>"$control"
    exec {control_write}>"$control"
    exec {controller_control}<"$control"
    exec {result_anchor}<>"$result"
    exec {result_read}<"$result"
    exec {controller_result}>"$result"
    shift 3
    set +m
    /usr/bin/setsid --wait -- /usr/bin/python3 "$supervisor" "$$" "$controller_control" "$controller_result" "$@" <&0 &
    child_pid=$!
    owned_pgid=$child_pid
    exec {control_anchor}>&-
    exec {controller_control}>&-
    exec {result_anchor}>&-
    exec {controller_result}>&-
    IFS= read -r ready <&"$result_read" || refuse 'owned command launcher'
    test "$ready" = READY || refuse 'owned command launcher'
    facts=$(process_identity "$child_pid") || refuse 'owned command identity'
    IFS=: read -r observed_state observed_parent observed_group observed_session controller_starttime <<< "$facts"
    test "$observed_parent" = "$$" && test "$observed_session" = "$child_pid" && test "$observed_group" = "$child_pid" && test "$observed_state" != Z || refuse 'owned command identity'
    boot_id=$(cat /proc/sys/kernel/random/boot_id) || refuse 'boot identity unavailable'
    [[ "$boot_id" =~ ^[0-9a-f-]{36}$ ]] || refuse 'boot identity unavailable'
    ( set -o noclobber
      printf '%s\n' \
        'sbxr-protected-log-parent-v1' \
        'path=/var/log' \
        "device=$device" \
        "inode=$inode" \
        "uid=$uid" \
        "gid=$gid" \
        "links=$links" \
        "boot_id=$boot_id" \
        "controller_pid=$owned_pgid" \
        "controller_starttime=$controller_starttime" \
        'mode=775' > "$state"
    ) || refuse 'state creation'
    test "$(stat -c '%u:%g:%a:%h:%F' -- "$state")" = '0:0:600:1:regular file' || refuse 'created state unsafe'
    no_xattrs "$state" || refuse 'created state attributes'
    sync -f "$state"
    sync -f "$(dirname -- "$state")"
    read_state "$state" || refuse 'created state invalid'
    test "$(log_identity)" = "$identity" || refuse 'changed log parent before chmod'
    completion_received=false
    completion_status=
    read_completion() {
      local line
      IFS= read -r line <&"$result_read" || return 1
      [[ "$line" =~ ^DONE\ ([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]] || return 1
      completion_status=${line#DONE }
      completion_received=true
    }
    send_control() {
      printf '%s\n' "$1" >&"$control_write"
    }
    close_channels() {
      if test -n "${control_write:-}"; then
        exec {control_write}>&-
        control_write=
      fi
      if test -n "${result_read:-}"; then
        exec {result_read}>&-
        result_read=
      fi
    }
    cleanup() {
      local status=$?
      trap - EXIT HUP INT TERM
      close_channels 2>/dev/null || true
      if ! wait_group_quiescent "$owned_pgid"; then
        printf '%s\n' 'protected log-parent window refused: owned command group remains live' >&2
        exit 1
      fi
      if ! restore_window "$state"; then
        status=1
      fi
      exit "$status"
    }
    requested_exit=
    request_signal() {
      local status=$1 signal=$2
      trap '' HUP INT TERM
      requested_exit=$status
      send_control "$signal" || true
    }
    trap cleanup EXIT
    trap 'request_signal 129 HUP' HUP
    trap 'request_signal 130 INT' INT
    trap 'request_signal 143 TERM' TERM
    if test -z "$requested_exit"; then
      chmod 0755 -- "$log_parent"
      test "$(log_identity)" = "$device:$inode:$uid:$gid:$links:755" || refuse 'temporary log-parent mismatch'
    fi
    if test -z "$requested_exit"; then
      send_control START || refuse 'controller start'
    fi
    read_completion || refuse 'controller completion'
    send_control ACK || refuse 'controller acknowledgement'
    wait_status=0
    wait "$child_pid" || wait_status=$?
    test "$wait_status" -eq "$completion_status" || refuse 'controller exit status'
    child_pid=
    close_channels
    if test -n "$requested_exit"; then
      exit "$requested_exit"
    fi
    exit "$completion_status"
    ;;
  *) usage ;;
esac
