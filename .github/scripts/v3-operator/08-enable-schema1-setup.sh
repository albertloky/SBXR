#!/usr/bin/env bash
set -euo pipefail
umask 077
operator_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$operator_dir/operator-support.sh"
operator_expect_scenario enable-schema1
test "$SCENARIO_START" = "$STARTED_AT"
preflight
prove_not_installed
entry_started_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
load_candidate_identity
install_candidate
operator_exact_candidate
prove_not_set_up
install_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
run_action 'Start setup' y 'Code: PROXY-INSTALLATION-SETUP-COMPLETE'
prove_running
operator_exact_candidate
remember_secrets
jq -e '.schema==1 and .phase=="Running" and (.serving|not) and (.renewal|not) and (.certificate_activation|not) and (.subscription_enablement|not) and (.subscription_rotation|not) and (.subscription_repair|not) and (.subscription_resources|not)' /var/lib/sbxr/proxy-ownership.json >/dev/null
test ! -e /var/lib/sbxr/subscription-token
test ! -e /var/lib/sbxr/subscription-renewal.json
test ! -e /etc/systemd/system/sbxr-subscription.service
test ! -e /etc/systemd/system/sbxr-subscription.socket
test -z "$(ss -H -lnt 'sport = :8443')"
setup_at=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
proxy_pid=$(systemctl show sing-box.service -p MainPID --value)
test "$proxy_pid" -gt 1
proxy_start=$(awk '{print $22}' "/proc/$proxy_pid/stat")
config_sha=$(sha256sum /etc/sing-box/config.json | cut -d' ' -f1)
uuid_sha=$(printf %s "$KNOWN_CLIENT_UUID" | sha256sum | cut -d' ' -f1)
key_sha=$(printf %s "$KNOWN_PRIVATE_KEY" | sha256sum | cut -d' ' -f1)
creation=$(jq -cS '.resource_creating_releases' /var/lib/sbxr/proxy-ownership.json)
release=$(jq -cS '.release_identity' /var/lib/sbxr/proxy-ownership.json)
ownership_sha=$(sha256sum /var/lib/sbxr/proxy-ownership.json | cut -d' ' -f1)
test "$(systemctl is-active snap.certbot.renew.timer)" = active
test "$(systemctl is-enabled snap.certbot.renew.timer)" = enabled
systemctl show snap.certbot.renew.service -p ExecStart --value | grep -F '/usr/bin/snap run --timer=00:00~24:00/2 certbot.renew' >/dev/null
test ! -e /etc/systemd/system/snap.certbot.renew.service.d
jq -cnS --arg started "$STARTED_AT" --arg entry "$entry_started_at" --arg install "$install_at" --arg setup "$setup_at" --arg pid "$proxy_pid" --arg start "$proxy_start" --arg config "$config_sha" --arg uuid "$uuid_sha" --arg key "$key_sha" --arg ownership "$ownership_sha" --argjson creation "$creation" --argjson release "$release" '{config_sha256:$config,creation_provenance:$creation,entry_started_at:$entry,install_at:$install,key_sha256:$key,ownership_sha256:$ownership,proxy_pid:$pid,proxy_start_tick:$start,release_identity:$release,setup_at:$setup,started_at:$started,uuid_sha256:$uuid}' | tr -d '\n' > "${SBXR_OPERATOR_STATE_DIR}/08-private.json"
chmod 0600 "${SBXR_OPERATOR_STATE_DIR}/08-private.json"
python3 "$operator_dir/effective-route.py" --output "${SBXR_OPERATOR_STATE_DIR}/08-effective-route.json"
printf 'ENABLE_SCHEMA1_SETUP_READY started=%s install=%s setup=%s\n' "$STARTED_AT" "$install_at" "$setup_at"
