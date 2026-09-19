#!/usr/bin/env bash
# Destructive qualification for a disposable Ubuntu/systemd VM only.
set -euo pipefail
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin

root=/root/recovery/log-parent-qualification
wrapper=$root/with-protected-log-parent.sh
log=$root/qualification.log
baseline=$(stat -c '%d:%i:%u:%g:%h:%a:%F' /var/log)
test "${baseline##*:}" = directory
test "$(stat -c '%U:%G:%a' /var/log)" = root:syslog:775

pass() { printf 'PASS %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1" >&2; exit 1; }
mode() { stat -c '%a' /var/log; }
group_live() {
  local pgid=$1 processes
  processes=$(ps -eo pgid=,stat=) || return 0
  awk -v group="$pgid" '$1 == group && $2 !~ /^Z/ {found=1} END {exit !found}' <<< "$processes"
}
wait_absent() {
  local pgid=$1 attempt
  for ((attempt=0; attempt<100; attempt++)); do
    group_live "$pgid" || return 0
    sleep 0.1
  done
  return 1
}
wait_for() {
  local command=$1 attempt
  for ((attempt=0; attempt<200; attempt++)); do
    if eval "$command"; then return 0; fi
    sleep 0.05
  done
  return 1
}
numeric_file() {
  local value
  test -f "$1" || return 1
  value=$(cat -- "$1") || return 1
  [[ "$value" =~ ^[1-9][0-9]*$ ]]
}
make_channels() {
  mkfifo -m 0600 "$1.control" "$1.result"
}
remove_channels() {
  unlink "$1.control"
  unlink "$1.result"
}
make_restorable_state() {
  local state=$1 device inode uid gid links current_mode kind
  IFS=: read -r device inode uid gid links current_mode kind <<< "$(stat -c '%d:%i:%u:%g:%h:%a:%F' /var/log)"
  printf '%s\n' sbxr-protected-log-parent-v1 path=/var/log "device=$device" "inode=$inode" "uid=$uid" "gid=$gid" "links=$links" "boot_id=$(cat /proc/sys/kernel/random/boot_id)" controller_pid=999999 controller_starttime=1 mode=775 > "$state"
  chmod 0600 "$state"
}
cleanup() {
  local status=$?
  trap - EXIT
  printf 'FINAL=%s\n' "$(stat -c '%d:%i:%u:%g:%h:%a:%F' /var/log)"
  exit "$status"
}
trap cleanup EXIT

exec > >(tee "$log") 2>&1
printf 'START=%s\n' "$baseline"
printf 'WRAPPER_SHA256=%s\n' "$(sha256sum "$wrapper" | cut -d' ' -f1)"

state=$root/normal.state
"$wrapper" run "$state" -- bash -c 'test "$(stat -c %a /var/log)" = 755'
test "$(mode)" = 775 && test ! -e "$state" || fail normal
pass normal-success

state=$root/stdin.state
printf 'sentinel\n' | "$wrapper" run "$state" -- /bin/bash --noprofile --norc +m -e -c '
  read -r value
  test "$value" = sentinel
  sleep 0.1 & child=$!
  test "$(ps -o pgid= -p "$child" | tr -d " ")" = "$(ps -o pgid= -p $$ | tr -d " ")"
  wait "$child"
'
test "$(mode)" = 775 && test ! -e "$state" || fail stdin
pass piped-stdin-and-job-control-off

state=$root/nonzero.state
status=0
"$wrapper" run "$state" -- bash -c 'test "$(stat -c %a /var/log)" = 755; exit 37' || status=$?
test "$status" -eq 37 && test "$(mode)" = 775 && test ! -e "$state" || fail nonzero
pass nonzero-status-37-preserved

# The controller must retain its PID/PGID after command completion until ACK;
# signals use the bound channel, never a numeric PID that could be reused.
supervisor=$root/protected_command_supervisor.py
control=$root/ack.control
result=$root/ack.result
mkfifo -m 0600 "$control" "$result"
exec {control_anchor}<>"$control"
exec {control_write}>"$control"
exec {controller_control}<"$control"
exec {result_anchor}<>"$result"
exec {result_read}<"$result"
exec {controller_result}>"$result"
/usr/bin/setsid --wait -- /usr/bin/python3 "$supervisor" "$$" "$controller_control" "$controller_result" true &
controller_pid=$!
exec {control_anchor}>&-
exec {controller_control}>&-
exec {result_anchor}>&-
exec {controller_result}>&-
IFS= read -r controller_ready <&"$result_read"
test "$controller_ready" = READY || fail controller-ready
controller_start=$(python3 -c 'import sys; print(open(f"/proc/{sys.argv[1]}/stat").read().rsplit(") ",1)[1].split()[19])' "$controller_pid")
printf 'START\n' >&"$control_write"
IFS= read -r controller_result_line <&"$result_read"
test "$controller_result_line" = 'DONE 0' || fail controller-result
for _ in $(seq 1 100); do /bin/true; done
test "$(python3 -c 'import sys; print(open(f"/proc/{sys.argv[1]}/stat").read().rsplit(") ",1)[1].split()[19])' "$controller_pid")" = "$controller_start" || fail controller-ack-hold
/usr/bin/setsid sleep 30 & sentinel_pid=$!
printf 'TERM\n' >&"$control_write"
sleep 0.1
kill -0 "$sentinel_pid" || fail unrelated-sentinel
printf 'ACK\n' >&"$control_write"
wait "$controller_pid"
kill -TERM "$sentinel_pid"
wait "$sentinel_pid" 2>/dev/null || true
exec {control_write}>&-
exec {result_read}>&-
unlink "$control"
unlink "$result"
pass controller-ack-holds-identity-and-sentinel

# Cancellation must dominate a START queued in the same pre-admission batch.
control=$root/prestart.control
result=$root/prestart.result
marker=$root/prestart-admitted
mkfifo -m 0600 "$control" "$result"
exec {control_anchor}<>"$control"
exec {control_write}>"$control"
exec {controller_control}<"$control"
exec {result_anchor}<>"$result"
exec {result_read}<"$result"
exec {controller_result}>"$result"
/usr/bin/setsid --wait -- /usr/bin/python3 "$supervisor" "$$" "$controller_control" "$controller_result" /usr/bin/touch "$marker" &
controller_pid=$!
exec {control_anchor}>&-
exec {controller_control}>&-
exec {result_anchor}>&-
exec {controller_result}>&-
IFS= read -r controller_ready <&"$result_read"
test "$controller_ready" = READY || fail prestart-ready
printf 'TERM\nSTART\n' >&"$control_write"
IFS= read -r controller_result_line <&"$result_read"
test "$controller_result_line" = 'DONE 143' && test ! -e "$marker" || fail prestart-result
printf 'ACK\n' >&"$control_write"
status=0
wait "$controller_pid" || status=$?
test "$status" -eq 143 && test ! -e "$marker" || fail prestart-status
exec {control_write}>&-
exec {result_read}>&-
unlink "$control"
unlink "$result"
pass queued-prestart-term-dominates-start

# A split TERM then stale START must retain controller identity until ACK.
control=$root/prestart-os.control
result=$root/prestart-os.result
marker=$root/prestart-os-admitted
mkfifo -m 0600 "$control" "$result"
exec {control_anchor}<>"$control"
exec {control_write}>"$control"
exec {controller_control}<"$control"
exec {result_anchor}<>"$result"
exec {result_read}<"$result"
exec {controller_result}>"$result"
/usr/bin/setsid --wait -- /usr/bin/python3 "$supervisor" "$$" "$controller_control" "$controller_result" /usr/bin/touch "$marker" &
controller_pid=$!
exec {control_anchor}>&-
exec {controller_control}>&-
exec {result_anchor}>&-
exec {controller_result}>&-
IFS= read -r controller_ready <&"$result_read"
test "$controller_ready" = READY || fail prestart-os-ready
controller_start=$(python3 -c 'import sys; print(open(f"/proc/{sys.argv[1]}/stat").read().rsplit(") ",1)[1].split()[19])' "$controller_pid")
printf 'TERM\n' >&"$control_write"
IFS= read -r controller_result_line <&"$result_read"
test "$controller_result_line" = 'DONE 143' && test ! -e "$marker" || fail prestart-os-result
printf 'START\n' >&"$control_write"
sleep 0.1
test "$(python3 -c 'import sys; print(open(f"/proc/{sys.argv[1]}/stat").read().rsplit(") ",1)[1].split()[19])' "$controller_pid")" = "$controller_start" || fail prestart-os-ack-hold
test ! -e "$marker" || fail prestart-os-stale-start
printf 'ACK\n' >&"$control_write"
status=0
wait "$controller_pid" || status=$?
test "$status" -eq 143 && test ! -e "$marker" || fail prestart-os-status
exec {control_write}>&-
exec {result_read}>&-
unlink "$control"
unlink "$result"
pass split-prestart-term-ignores-start-until-ack

# A direct managed signal received while READY must also prevent admission.
control=$root/prestart-direct.control
result=$root/prestart-direct.result
marker=$root/prestart-direct-admitted
mkfifo -m 0600 "$control" "$result"
exec {control_anchor}<>"$control"
exec {control_write}>"$control"
exec {controller_control}<"$control"
exec {result_anchor}<>"$result"
exec {result_read}<"$result"
exec {controller_result}>"$result"
/usr/bin/setsid --wait -- /usr/bin/python3 "$supervisor" "$$" "$controller_control" "$controller_result" /usr/bin/touch "$marker" &
controller_pid=$!
exec {control_anchor}>&-
exec {controller_control}>&-
exec {result_anchor}>&-
exec {controller_result}>&-
IFS= read -r controller_ready <&"$result_read"
test "$controller_ready" = READY || fail prestart-direct-ready
kill -TERM "$controller_pid"
IFS= read -r controller_result_line <&"$result_read"
test "$controller_result_line" = 'DONE 143' && test ! -e "$marker" || fail prestart-direct-result
printf 'ACK\n' >&"$control_write"
status=0
wait "$controller_pid" || status=$?
test "$status" -eq 143 && test ! -e "$marker" || fail prestart-direct-status
exec {control_write}>&-
exec {result_read}>&-
unlink "$control"
unlink "$result"
pass direct-prestart-term-does-not-admit-command

cat > "$root/term-command.sh" <<'SH'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$$" > /root/recovery/log-parent-qualification/term-step.pid.tmp
mv -f -- /root/recovery/log-parent-qualification/term-step.pid.tmp /root/recovery/log-parent-qualification/term-step.pid
group=$(ps -o pgid= -p $$ | tr -d ' ')
printf '%s\n' "$group" > /root/recovery/log-parent-qualification/term.pgid.tmp
mv -f -- /root/recovery/log-parent-qualification/term.pgid.tmp /root/recovery/log-parent-qualification/term.pgid
trap 'sleep 2; exit 0' TERM
bash -c 'printf "%s\n" "$$" > /root/recovery/log-parent-qualification/term-child.pid.tmp; mv -f -- /root/recovery/log-parent-qualification/term-child.pid.tmp /root/recovery/log-parent-qualification/term-child.pid; trap "sleep 2; exit 0" TERM; while :; do sleep 1; done' &
wait
SH
chmod 0700 "$root/term-command.sh"
state=$root/term.state
"$wrapper" run "$state" -- "$root/term-command.sh" &
wrapper_pid=$!
wait_for "numeric_file '$root/term-child.pid' && numeric_file '$root/term.pgid' && test \"\$(mode)\" = 755"
term_pgid=$(cat "$root/term.pgid")
[[ "$term_pgid" =~ ^[1-9][0-9]*$ ]] || fail term-pgid
kill -TERM "$wrapper_pid"
status=0
wait "$wrapper_pid" || status=$?
test "$status" -eq 143 || fail term-status
wait_absent "$term_pgid" || fail term-descendants
test "$(mode)" = 775 && test ! -e "$state" || fail term-restore
pass term-delayed-descendants-drained

cat > "$root/timeout-command.sh" <<'SH'
#!/usr/bin/env bash
set -eu
ps -o pgid= -p $$ | tr -d ' ' > /root/recovery/log-parent-qualification/timeout.pgid
trap 'sleep 2; exit 0' TERM
while :; do sleep 1; done
SH
chmod 0700 "$root/timeout-command.sh"
state=$root/timeout.state
status=0
"$wrapper" run "$state" -- timeout --foreground --signal=TERM --kill-after=5s 1 "$root/timeout-command.sh" || status=$?
timeout_pgid=$(cat "$root/timeout.pgid")
test "$status" -eq 124 || fail timeout-status
wait_absent "$timeout_pgid" || fail timeout-descendants
test "$(mode)" = 775 && test ! -e "$state" || fail timeout-restore
pass timeout-expiry-delayed-term-restored

cat > "$root/leak-command.sh" <<'SH'
#!/usr/bin/env bash
set -eu
bash -c 'trap "" HUP INT TERM; while :; do sleep 1; done' &
printf '%s\n' "$!" > /root/recovery/log-parent-qualification/leak-child.pid
ps -o pgid= -p $$ | tr -d ' ' > /root/recovery/log-parent-qualification/leak.pgid
exit 0
SH
chmod 0700 "$root/leak-command.sh"
state=$root/leak.state
started=$(date +%s)
status=0
"$wrapper" run "$state" -- "$root/leak-command.sh" || status=$?
elapsed=$(($(date +%s)-started))
leak_pgid=$(cat "$root/leak.pgid")
test "$status" -ne 0 && test "$elapsed" -ge 9 || fail leak-status
wait_absent "$leak_pgid" || fail leak-descendant
test "$(mode)" = 775 && test ! -e "$state" || fail leak-restore
pass leaked-descendant-killed-and-failed

cat > "$root/kill-command.sh" <<'SH'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$$" > /root/recovery/log-parent-qualification/kill-child.pid.tmp
mv -f -- /root/recovery/log-parent-qualification/kill-child.pid.tmp /root/recovery/log-parent-qualification/kill-child.pid
group=$(ps -o pgid= -p $$ | tr -d ' ')
printf '%s\n' "$group" > /root/recovery/log-parent-qualification/kill.pgid.tmp
mv -f -- /root/recovery/log-parent-qualification/kill.pgid.tmp /root/recovery/log-parent-qualification/kill.pgid
sleep 30
SH
chmod 0700 "$root/kill-command.sh"
state=$root/kill.state
"$wrapper" run "$state" -- "$root/kill-command.sh" &
wrapper_pid=$!
wait_for "numeric_file '$root/kill-child.pid' && numeric_file '$root/kill.pgid' && test -s '$state' && test \"\$(mode)\" = 755"
kill_pgid=$(cat "$root/kill.pgid")
[[ "$kill_pgid" =~ ^[1-9][0-9]*$ ]] || fail kill-pgid
kill -KILL "$wrapper_pid"
test "$(mode)" = 755 && test -s "$state" || fail kill-residual
wait_for "group_live '$kill_pgid'" || fail kill-owned-child-expected-live
pass sigkill-retains-state-and-owned-child
# The protected PGID must make restore refuse while the command remains live.
status=0
"$wrapper" restore "$state" || status=$?
test "$status" -eq 1 && test "$(mode)" = 755 && test -s "$state" || fail kill-live-restore
pass sigkill-restore-refuses-live-recorded-group
status=0
wait "$wrapper_pid" || status=$?
test "$status" -eq 137 || fail kill-wrapper-status
# The delayed child exits naturally; only then may explicit restore proceed.
for attempt in $(seq 1 400); do
  group_live "$kill_pgid" || break
  sleep 0.1
done
group_live "$kill_pgid" && fail kill-quiescence
"$wrapper" restore "$state"
test "$(mode)" = 775 && test ! -e "$state" || fail kill-restore
pass sigkill-explicit-restore-after-quiescence

mkdir -m 0755 "$root/unsafe-parent"
status=0
"$wrapper" run "$root/unsafe-parent/state" -- true || status=$?
test "$status" -eq 1 && test "$(mode)" = 775 && test ! -e "$root/unsafe-parent/state" || fail unsafe-parent
pass unsafe-parent-refused

state=$root/existing.state
printf 'unrelated\n' > "$state"
chmod 0600 "$state"
status=0
"$wrapper" run "$state" -- true || status=$?
test "$status" -eq 1 && test "$(mode)" = 775 || fail existing-state
unlink "$state"
pass existing-state-not-adopted

state=$root/orphan-one.state
mkfifo -m 0600 "$state.control"
status=0
"$wrapper" restore "$state" || status=$?
test "$status" -eq 1 && test -p "$state.control" && test ! -e "$state" || fail orphan-one
status=0
"$wrapper" run "$state" -- true || status=$?
test "$status" -eq 1 && test -p "$state.control" || fail orphan-one-run
unlink "$state.control"
pass pre-authority-orphan-refuses-replan

state=$root/orphan-open.state
mkfifo -m 0600 "$state.control" "$state.result"
exec {orphan_open}<>"$state.control"
status=0
"$wrapper" restore "$state" || status=$?
test "$status" -eq 1 && test -p "$state.control" && test -p "$state.result" || fail orphan-open
exec {orphan_open}>&-
status=0
"$wrapper" restore "$state" || status=$?
test "$status" -eq 1 && test -p "$state.control" && test -p "$state.result" || fail orphan-closed
unlink "$state.control"
unlink "$state.result"
pass pre-authority-open-orphan-refuses-replan

state=$root/partial-one.state
make_restorable_state "$state"
make_channels "$state"
unlink "$state.control"
"$wrapper" restore "$state"
test ! -e "$state" && test ! -e "$state.control" && test ! -e "$state.result" || fail partial-one
pass interrupted-one-channel-removal-resumed

state=$root/partial-none.state
make_restorable_state "$state"
"$wrapper" restore "$state"
test ! -e "$state" && test ! -e "$state.control" && test ! -e "$state.result" || fail partial-none
pass interrupted-all-channel-removal-resumed

state=$root/authorized-open.state
make_restorable_state "$state"
make_channels "$state"
exec {authorized_open}<>"$state.control"
status=0
"$wrapper" restore "$state" || status=$?
test "$status" -eq 1 && test -f "$state" && test -p "$state.control" && test -p "$state.result" || fail authorized-open
exec {authorized_open}>&-
"$wrapper" restore "$state"
test ! -e "$state" && test ! -e "$state.control" && test ! -e "$state.result" || fail authorized-open-resume
pass authorized-channel-contention-refused-resumed

state=$root/oversize.state
python3 -c 'open("/root/recovery/log-parent-qualification/oversize.state","wb").write(b"x"*512)'
chmod 0600 "$state"
status=0
"$wrapper" restore "$state" || status=$?
test "$status" -eq 1 && test "$(mode)" = 775 || fail oversized-state
unlink "$state"
pass oversized-state-refused-before-read

touch "$root/link-target"
ln -s "$root/link-target" "$root/link.state"
status=0
"$wrapper" run "$root/link.state" -- true || status=$?
test "$status" -eq 1 && test "$(mode)" = 775 || fail symlink-state
unlink "$root/link.state"
unlink "$root/link-target"
pass symlink-state-refused

chmod 0750 /var/log
status=0
"$wrapper" run "$root/mode.state" -- true || status=$?
test "$status" -eq 1 && test "$(mode)" = 750 && test ! -e "$root/mode.state" || fail changed-mode
chmod 0775 /var/log
pass changed-original-mode-refused

IFS=: read -r device inode uid gid links current_mode kind <<< "$(stat -c '%d:%i:%u:%g:%h:%a:%F' /var/log)"
state=$root/identity.state
printf '%s\n' sbxr-protected-log-parent-v1 path=/var/log "device=$device" "inode=$((inode+1))" "uid=$uid" "gid=$gid" "links=$links" "boot_id=$(cat /proc/sys/kernel/random/boot_id)" controller_pid=999999 controller_starttime=1 mode=775 > "$state"
chmod 0600 "$state"
make_channels "$state"
status=0
"$wrapper" restore "$state" || status=$?
test "$status" -eq 1 && test "$(mode)" = 775 || fail changed-identity
unlink "$state"
remove_channels "$state"
pass changed-identity-refused

state=$root/boot.state
printf '%s\n' sbxr-protected-log-parent-v1 path=/var/log "device=$device" "inode=$inode" "uid=$uid" "gid=$gid" "links=$links" boot_id=00000000-0000-0000-0000-000000000000 controller_pid=999999 controller_starttime=1 mode=775 > "$state"
chmod 0600 "$state"
make_channels "$state"
status=0
"$wrapper" restore "$state" || status=$?
test "$status" -eq 1 && test "$(mode)" = 775 || fail changed-boot
unlink "$state"
remove_channels "$state"
pass changed-boot-refused

state=$root/reused-pid.state
printf '%s\n' sbxr-protected-log-parent-v1 path=/var/log "device=$device" "inode=$inode" "uid=$uid" "gid=$gid" "links=$links" "boot_id=$(cat /proc/sys/kernel/random/boot_id)" "controller_pid=$$" controller_starttime=1 mode=775 > "$state"
chmod 0600 "$state"
make_channels "$state"
status=0
"$wrapper" restore "$state" || status=$?
test "$status" -eq 1 && test "$(mode)" = 775 || fail reused-pid
unlink "$state"
remove_channels "$state"
pass controller-pid-reuse-refused

test "$(stat -c '%d:%i:%u:%g:%h:%a:%F' /var/log)" = "$baseline" || fail final-baseline
test "$(python3 -c 'import os; print(os.listxattr("/var/log",follow_symlinks=False))')" = '[]' || fail final-xattrs
systemctl is-active --quiet rsyslog.service || fail rsyslog
pass vm-baseline-restored
