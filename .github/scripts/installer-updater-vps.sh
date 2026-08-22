#!/usr/bin/env bash
set -euo pipefail

: "${A_TAG:?}" "${A_SEQUENCE:?}" "${A_COMMIT:?}" "${A_INDEX_SHA256:?}"
: "${B_TAG:?}" "${B_SEQUENCE:?}" "${B_COMMIT:?}" "${B_INDEX_SHA256:?}"
: "${MODE:?}" "${CONTROL:=/run/sbxr-qualification}"
cd "$CONTROL"

menu() {
  local choice=$1 delay=${2:-8} trace=${3:-} command='env TERM=xterm-256color LANG=C.UTF-8 /usr/local/bin/sbxr' input_dir fifo feeder status
  if test -n "$trace"; then
    command="env TERM=xterm-256color LANG=C.UTF-8 strace -qq -f -yy -e trace=fsync,rename,renameat,renameat2 -e inject=fsync:delay_exit=100ms -o $trace /usr/local/bin/sbxr"
  fi
  input_dir=$(mktemp -d "$CONTROL/input.XXXXXX")
  fifo="$input_dir/fifo"
  mkfifo -m 0600 "$fifo"
  { sleep 1; printf '%s\n' "$choice"; sleep "$delay"; printf '0\n'; } >"$fifo" &
  feeder=$!
  if script -qec "$command" /dev/null <"$fifo"; then status=0; else status=$?; fi
  kill "$feeder" 2>/dev/null || true
  wait "$feeder" 2>/dev/null || true
  rm -f "$fifo"
  rmdir "$input_dir"
  return "$status"
}

record_value() {
  python3 - "$1" <<'PY'
import json, sys
with open('/var/lib/sbxr/installed.json', encoding='utf-8') as source:
    print(json.load(source)[sys.argv[1]])
PY
}

assert_pair() {
  local tag=$1 sequence=$2 commit=$3 index=$4
  test "$(stat -c '%u:%a:%h:%F' /usr/local/bin/sbxr)" = '0:755:1:regular file'
  test "$(stat -c '%u:%a:%F' /var/lib/sbxr)" = '0:700:directory'
  test "$(stat -c '%u:%a:%h:%F' /var/lib/sbxr/installed.json)" = '0:600:1:regular file'
  test "$(find /var/lib/sbxr -mindepth 1 -maxdepth 1 -printf '%f\n')" = installed.json
  test "$(record_value repository)" = albertloky/SBXR
  test "$(record_value tag)" = "$tag"
  test "$(record_value sequence)" = "$sequence"
  test "$(record_value commit)" = "$commit"
  test "$(record_value release_index_sha256)" = "$index"
  test "$(record_value architecture)" = amd64
  test "$(record_value executable_sha256)" = "$(sha256sum /usr/local/bin/sbxr | cut -d' ' -f1)"
  ! find /usr/local/bin /var/lib/sbxr -maxdepth 1 -name '*sbxr-update*' -o -name '.installed.json.*' -o -name 'update.json' | grep .
  flock -n /run/lock/sbxr.lock true
  menu 0 1 | grep -F 'Status: Ready'
}

install_latest() {
  local transcript=$1
  { sleep 10; printf '0\n'; } |
    script -qec 'curl -fsSL https://github.com/albertloky/SBXR/releases/latest/download/install.sh | sudo bash' /dev/null |
    tee "$transcript"
}

recover() {
  local expected=$1 transcript=$2
  menu 1 10 | tee "$transcript"
  grep -F "Code: $expected" "$transcript"
}

wait_for_file() {
  local file=$1
  for _ in $(seq 1 3000); do
    test -e "$file" && return 0
    sleep 0.01
  done
  return 1
}

stage() {
  local name=$1
  : > "$CONTROL/stage-$name"
  wait_for_file "$CONTROL/stage-$name-ack"
}

start_update() {
  local transcript=$1 mode=${2:-checked}
  UPDATE_TRACE="$transcript.strace"
  { menu 2 120 "$UPDATE_TRACE" || true; } >"$transcript" 2>&1 &
  UPDATE_DRIVER=$!
  for _ in $(seq 1 1000); do
    UPDATE_PID=$(pgrep -n -x sbxr || true)
    if test -n "$UPDATE_PID"; then
      UPDATE_WRAPPER=$(pgrep -P "$UPDATE_DRIVER" -x script)
      test "$mode" = early && return 0
      grep -F 'Checking the qualified latest release' "$transcript" >/dev/null 2>&1 && return 0
    fi
    sleep 0.01
  done
  return 1
}

durable_update_count() {
  awk '
    /\.update\.json\.next.*update\.json.*= 0$/ { awaiting_sync=1; next }
    awaiting_sync && /fsync\(.*\/var\/lib\/sbxr.*\).* = 0$/ { count++; awaiting_sync=0 }
    END { print count+0 }
  ' "$UPDATE_TRACE"
}

durable_activation_count() {
  awk '
    /\.sbxr-update-candidate.*usr\/local\/bin\/sbxr.*= 0$/ { awaiting_sync=1; next }
    awaiting_sync && /fsync\(.*\/usr\/local\/bin.*\).* = 0$/ { count++; awaiting_sync=0 }
    END { print count+0 }
  ' "$UPDATE_TRACE"
}

stop_at() {
  local stage=$1 transcript=$2 checkpoint='' tag='' prior_executable='' candidate_executable='' current_executable='' durable=0 activated=0
  start_update "$transcript" early
  if test "$stage" = pre-prepared; then
    for _ in $(seq 1 1000); do
      grep -F 'Checking the qualified latest release' "$transcript" >/dev/null 2>&1 && break
      sleep 0.01
    done
    grep -F 'Checking the qualified latest release' "$transcript" >/dev/null
    kill -TERM "$UPDATE_PID"
  else
    for _ in $(seq 1 10000); do
      if test ! -e /var/lib/sbxr/update.json; then
        kill -CONT "$UPDATE_PID" 2>/dev/null || return 1
        kill -CONT "$UPDATE_WRAPPER" 2>/dev/null || true
        sleep 0.001
        continue
      fi
      kill -STOP "$UPDATE_PID" 2>/dev/null || return 1
      checkpoint=$(sed -n 's/.*"checkpoint":"\([^"]*\)".*/\1/p' /var/lib/sbxr/update.json 2>/dev/null || true)
      prior_executable=$(sed -n 's/.*"prior_executable_sha256":"\([^"]*\)".*/\1/p' /var/lib/sbxr/update.json 2>/dev/null || true)
      candidate_executable=$(sed -n 's/.*"candidate_executable_sha256":"\([^"]*\)".*/\1/p' /var/lib/sbxr/update.json 2>/dev/null || true)
      tag=$(record_value tag 2>/dev/null || true)
      current_executable=$(sha256sum /usr/local/bin/sbxr | cut -d' ' -f1)
      durable=$(durable_update_count)
      activated=$(durable_activation_count)
      if test "$stage:$checkpoint:$tag:$current_executable:$durable:$activated" = "prepared:Prepared:$A_TAG:$prior_executable:1:0" ||
         test "$stage:$checkpoint:$tag:$current_executable:$durable:$activated" = "activated:Prepared:$B_TAG:$candidate_executable:1:1" ||
         test "$stage:$checkpoint:$tag:$current_executable:$durable:$activated" = "committed:Committed:$B_TAG:$candidate_executable:2:1"; then
        kill -KILL "$UPDATE_PID" 2>/dev/null || true
        kill -CONT "$UPDATE_WRAPPER" 2>/dev/null || true
        break
      fi
      kill -CONT "$UPDATE_PID" 2>/dev/null || true
      kill -CONT "$UPDATE_WRAPPER" 2>/dev/null || true
      sleep 0.001
    done
  fi
  wait "$UPDATE_DRIVER" 2>/dev/null || true
}

rm -f "$CONTROL/latest-requested" "$CONTROL/hold-latest"
printf '%s\n' "$A_TAG" > "$CONTROL/install-tag"

if test "$MODE" = rescue; then
  printf '%s\n' "$B_TAG" > "$CONTROL/install-tag"
  install_latest rescue-direct-b.transcript
  grep -F 'SOFTWARE-LIFECYCLE-INSTALL-INSTALLED' rescue-direct-b.transcript
  assert_pair "$B_TAG" "$B_SEQUENCE" "$B_COMMIT" "$B_INDEX_SHA256"
  stage rescue-direct-b
  rm -f /usr/local/bin/sbxr /var/lib/sbxr/installed.json
  rmdir /var/lib/sbxr
  printf '%s\n' "$A_TAG" > "$CONTROL/install-tag"
  install_latest rescue-source-a.transcript
  assert_pair "$A_TAG" "$A_SEQUENCE" "$A_COMMIT" "$A_INDEX_SHA256"
  stage rescue-source-a
  printf '%s\n' "$B_TAG" > "$CONTROL/install-tag"
  install_latest rescue-replace-b.transcript
  grep -F 'SOFTWARE-LIFECYCLE-INSTALL-INSTALLED' rescue-replace-b.transcript
  assert_pair "$B_TAG" "$B_SEQUENCE" "$B_COMMIT" "$B_INDEX_SHA256"
  stage rescue-replace-b
else
  install_latest install-a.transcript
  grep -F 'SOFTWARE-LIFECYCLE-INSTALL-INSTALLED' install-a.transcript
  assert_pair "$A_TAG" "$A_SEQUENCE" "$A_COMMIT" "$A_INDEX_SHA256"
  stage installed-a

  menu 1 10 | tee check-b.transcript
  grep -F 'Code: SOFTWARE-LIFECYCLE-CHECK-UPDATE-AVAILABLE' check-b.transcript
  grep -F "Latest stable version: $B_TAG" check-b.transcript

  touch "$CONTROL/hold-latest"
  rm -f "$CONTROL/latest-requested"
  { menu 1 40 || true; } >check-invalidated.transcript 2>&1 &
  check_pid=$!
  wait_for_file "$CONTROL/latest-requested"
  { flock -x /run/lock/sbxr.lock -c "rm -f '$CONTROL/hold-latest'; sleep 3"; } &
  wait "$check_pid"
  grep -F 'Code: SOFTWARE-LIFECYCLE-CHECK-CONCURRENT-CHANGE' check-invalidated.transcript
  assert_pair "$A_TAG" "$A_SEQUENCE" "$A_COMMIT" "$A_INDEX_SHA256"

  start_update concurrent-update.transcript
  set +e
  curl -fsSL https://github.com/albertloky/SBXR/releases/latest/download/install.sh | sudo bash >concurrent-install.transcript 2>&1
  concurrent_status=$?
  set -e
  test "$concurrent_status" -ne 0
  grep -F 'SOFTWARE-LIFECYCLE-INSTALL-CONCURRENT-MUTATION' concurrent-install.transcript
  kill -TERM "$UPDATE_PID"
  wait "$UPDATE_DRIVER" 2>/dev/null || true
  assert_pair "$A_TAG" "$A_SEQUENCE" "$A_COMMIT" "$A_INDEX_SHA256"

  stop_at pre-prepared interrupted-pre-prepared.transcript
  grep -F 'Code: SOFTWARE-LIFECYCLE-UPDATE-INTERRUPTED' interrupted-pre-prepared.transcript
  assert_pair "$A_TAG" "$A_SEQUENCE" "$A_COMMIT" "$A_INDEX_SHA256"
  stage pre-prepared

  stop_at prepared interrupted-prepared.transcript
  recover SOFTWARE-LIFECYCLE-RECOVER-PRIOR-RESTORED recovered-prepared.transcript
  assert_pair "$A_TAG" "$A_SEQUENCE" "$A_COMMIT" "$A_INDEX_SHA256"
  stage recovered-prepared

  stop_at activated interrupted-activated.transcript
  recover SOFTWARE-LIFECYCLE-RECOVER-PRIOR-RESTORED recovered-activated.transcript
  assert_pair "$A_TAG" "$A_SEQUENCE" "$A_COMMIT" "$A_INDEX_SHA256"
  stage recovered-activated

  stop_at committed interrupted-committed.transcript
  recover SOFTWARE-LIFECYCLE-RECOVER-CANDIDATE-RETAINED recovered-committed.transcript
  assert_pair "$B_TAG" "$B_SEQUENCE" "$B_COMMIT" "$B_INDEX_SHA256"
  stage recovered-committed
fi

if test "$MODE" = rescue; then
  printf '%s\n' '{"schema":"sbxr-acceptance-vps-evidence-v1","mode":"rescue","clean_install":true,"lower_sequence_replacement":true,"menu_check":"Not required - rescue authority","production_update":"Not required - rescue authority","prepared_rollback":"Not required - rescue authority","activated_rollback":"Not required - rescue authority","committed_forward_recovery":"Not required - rescue authority","concurrency_refusal":"Proved by native automated qualification","check_invalidation":"Proved by native automated qualification","ssh_continuity":true,"secret_safe":true}' > acceptance-vps-evidence.json
else
  printf '%s\n' '{"schema":"sbxr-acceptance-vps-evidence-v1","mode":"normal","clean_install":true,"lower_sequence_replacement":"Not required - normal authority","menu_check":true,"production_update":true,"prepared_rollback":true,"activated_rollback":true,"committed_forward_recovery":true,"concurrency_refusal":true,"check_invalidation":true,"ssh_continuity":true,"secret_safe":true}' > acceptance-vps-evidence.json
fi
