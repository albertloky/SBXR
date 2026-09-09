#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
evidence=$SBXR_OPERATOR_EVIDENCE_DIR
test ! -e "$evidence/outside-request.json"
test ! -e "$evidence/outside-request.tmp"
test ! -e "$evidence/outside-reply-baseline-clean.json"
operator_expect_scenario baseline-clean
manifest_digest=$(operator_manifest_digest)
deadline=$(jq -er 'select((.deadline_unix|type)=="number") | .deadline_unix' "$SBXR_QUALIFICATION_REQUEST")
jq -cnS --argjson deadline "$deadline" --arg digest "$manifest_digest" '{deadline_unix:$deadline,qualification_manifest_sha256:$digest,request_id:"probe-1",scenario_id:"baseline-clean",schema:"sbxr-v3-outside-probe-request-v1"}' | tr -d '\n' > "$evidence/outside-request.tmp"
chown root:root "$evidence/outside-request.tmp"
chmod 0600 "$evidence/outside-request.tmp"
test "$(stat -c '%U:%G:%a:%h:%F' "$evidence/outside-request.tmp")" = 'root:root:600:1:regular file'
mv -T "$evidence/outside-request.tmp" "$evidence/outside-request.json"
printf 'OUTSIDE_REQUESTED deadline=%s\n' "$deadline"
