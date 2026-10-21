package main

// These bounded canonical forms extend the bootstrap's existing removal reader.
// They admit retained product journals, never choose or rewrite their direction.
const bootstrapRecoveryPrelude = `
  legacy_serving_pattern='\{"link_id":"[0-9a-f]{32}","credential_sha256":"[0-9a-f]{64}","certificate_generation":[1-9][0-9]{0,6},"certificate_sha256":\["[0-9a-f]{64}","[0-9a-f]{64}","[0-9a-f]{64}","[0-9a-f]{64}"\]\}'
  http_serving_pattern='\{"http":true,"link_id":"[0-9a-f]{32}","credential_sha256":"[0-9a-f]{64}","certificate_generation":0,"certificate_sha256":\["","","",""\]\}'
  recovery_serving_pattern="($legacy_serving_pattern|$http_serving_pattern)"
  recovery_renewal_pattern='\{"recorder_id":"[0-9a-f]{32}","lineage":"sbxr-subscription","public_ipv4":"[0-9.]+","invocation":"snap-certbot-renew-v1"\}'
  recovery_resources_pattern='\{("http":true,)?"public_ipv4":"[0-9.]+","firewall_sha256":"[0-9a-f]{64}","snapd_created":(true|false),"certbot_created":(true|false)(,"recorder_directory_created":true)?\}'
  recovery_enablement_pattern='\{"checkpoint":([0-9]|1[0-9]|2[0-3]),"link_id":"[0-9a-f]{32}","credential_sha256":"[0-9a-f]{64}","recorder_id":"[0-9a-f]{32}"(,"serving":'"$recovery_serving_pattern"')?(,"renewal":'"$recovery_renewal_pattern"')?(,"resources":'"$recovery_resources_pattern"')?\}'
  recovery_rotation_pattern='\{"operation_id":"[0-9a-f]{32}","kind":"rotate subscription link","direction":"(cleanup|forward)","effects":\["prepare target","stop source","publish target","activate target"\],"completed_effects":(null|\["target prepared"(,"source stopped")?\]),"source":'"$recovery_serving_pattern"',"target":'"$recovery_serving_pattern"',"checkpoint":"(target authorized|stop authorized|committed)"\}'
  recovery_activation_pattern='\{"source":'"$legacy_serving_pattern"',"target":'"$legacy_serving_pattern"',"checkpoint":"target (recorded|accepted)"\}'
  recovery_client_subscription_pattern='\{"source":'"$recovery_serving_pattern"',"target":'"$recovery_serving_pattern"',"source_artifact_sha256":"[0-9a-f]{64}","target_artifact_sha256":"[0-9a-f]{64}"\}'
  recovery_client_pattern='\{"operation_id":"[0-9a-f]{32}","direction":"(cleanup|forward)","effects":\[[^]]*\],"completed_effects":(null|\[[^]]*\]),"source_configuration_sha256":"[0-9a-f]{64}","target_configuration_sha256":"[0-9a-f]{64}","checkpoint":"[a-z ]+"(,"subscription":'"$recovery_client_subscription_pattern"')?\}'
  take_recovery_journal() {
    local name=$1 pattern=$2 match value
    printf -v "$name" '%s' ''
    pattern=',"'"$name"'":('"$pattern"')(,|})'
    if [[ "$removal_subject" =~ $pattern ]]; then
      value=${BASH_REMATCH[1]}
      match=',"'"$name"'":'"$value"
      removal_subject=${removal_subject/"$match"/}
      printf -v "$name" '%s' "$value"
    fi
  }
  take_recovery_journal certificate_activation "$recovery_activation_pattern"
  take_recovery_journal subscription_enablement "$recovery_enablement_pattern"
  take_recovery_journal subscription_rotation "$recovery_rotation_pattern"
  take_recovery_journal subscription_compromised true
  take_recovery_journal client_identity_rotation "$recovery_client_pattern"
  recovery_text() { printf '%s' "$2" | "$ROOT/usr/bin/sed" -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p'; }
  recovery_number() { printf '%s' "$2" | "$ROOT/usr/bin/sed" -n 's/.*"'"$1"'":\([0-9]*\).*/\1/p'; }
  recovery_source() { printf '%s' "$1" | "$ROOT/usr/bin/sed" -n 's/.*,"source":\({[^}]*}\),"target":.*/\1/p;s/^{"source":\({[^}]*}\),"target":.*/\1/p'; }
  recovery_target() { printf '%s' "$1" | "$ROOT/usr/bin/sed" -n 's/.*,"target":\({[^}]*}\).*/\1/p'; }
  recovery_serving_valid() {
    local value=$1 generation
    printf '%s\n' "$value" | "$ROOT/usr/bin/grep" -Eqx "$recovery_serving_pattern" || return 1
    printf '%s\n' "$value" | "$ROOT/usr/bin/grep" -Eq '"(0{32}|0{64})"' && return 1
    generation=$(recovery_number certificate_generation "$value")
    [ "$generation" -le 1000000 ]
  }
  recovery_same_link() {
    [ "$(recovery_text link_id "$1")" = "$(recovery_text link_id "$2")" ] &&
    [ "$(recovery_text credential_sha256 "$1")" = "$(recovery_text credential_sha256 "$2")" ] &&
    { { [[ "$1" = '{"http":true,'* ]] && [[ "$2" = '{"http":true,'* ]]; } || { [[ "$1" != '{"http":true,'* ]] && [[ "$2" != '{"http":true,'* ]]; }; }
  }
  append_recovery_resource() {
    resources=${resources%]}',"'"$1"'"]'
    provenance_count=$((provenance_count + 1))
  }
  append_recovery_serving() {
    local value=$1 generation hashes name mode hash
    append_recovery_resource '/etc/systemd/system/sbxr-subscription.service root:root 0644 one-link fixed-serving-v1'
    append_recovery_resource '/etc/systemd/system/multi-user.target.wants/sbxr-subscription.service root-owned symlink ../sbxr-subscription.service'
    append_recovery_resource '/var/lib/sbxr/subscription-token root:root 0600 one-link credential'
    append_recovery_resource '/var/lib/sbxr/subscription-serving.json root:root 0600 immutable serving state'
    append_recovery_resource '/var/lib/sbxr/subscription-staging root:root 0700 empty-directory'
    [[ "$value" != '{"http":true,'* ]] || return 0
    append_recovery_resource '/etc/letsencrypt/archive/sbxr-subscription root:root 0700 directory'
    append_recovery_resource '/etc/letsencrypt/live/sbxr-subscription root:root 0700 directory'
    append_recovery_certificates "$value"
  }
  append_recovery_certificates() {
    local value=$1 generation hashes name mode hash
    generation=$(recovery_number certificate_generation "$value")
    hashes=$(printf '%s' "$value" | "$ROOT/usr/bin/sed" -n 's/.*"certificate_sha256":\["\([0-9a-f]*\)","\([0-9a-f]*\)","\([0-9a-f]*\)","\([0-9a-f]*\)"\].*/\1 \2 \3 \4/p')
    read -r cert_hash chain_hash fullchain_hash privkey_hash <<<"$hashes"
    for name in cert chain fullchain privkey; do
      mode=0644
      case "$name" in cert) hash=$cert_hash ;; chain) hash=$chain_hash ;; fullchain) hash=$fullchain_hash ;; privkey) hash=$privkey_hash; mode=0600 ;; esac
      # Client Identity journals may retain a second certificate generation;
      # shared paths remain owned by the canonical Serving authority.
      if [[ "$resources" != *'"/etc/letsencrypt/archive/sbxr-subscription/'"$name$generation"'.pem '* ]]; then
        append_recovery_resource '/etc/letsencrypt/archive/sbxr-subscription/'"$name$generation"'.pem root:root '"$mode"' one-link '"$hash"
      fi
      if [[ "$resources" != *'"/etc/letsencrypt/live/sbxr-subscription/'"$name"'.pem '* ]]; then
        append_recovery_resource '/etc/letsencrypt/live/sbxr-subscription/'"$name"'.pem root:root symlink ../../archive/sbxr-subscription/'"$name$generation"'.pem'
      fi
    done
  }
`

const bootstrapRecoveryResources = `
  activation_suffix='' enablement_suffix='' rotation_suffix='' compromised_suffix='' client_suffix=''
  journal_count=0
  for journal in "$certificate_activation" "$subscription_enablement" "$subscription_rotation" "${repair:-}" "$client_identity_rotation"; do
    [ -z "$journal" ] || journal_count=$((journal_count + 1))
  done
  [ "$journal_count" -le 1 ] || path_refused
  if [ "$journal_count" -gt 0 ] || [ -n "$subscription_compromised" ]; then [ "$schema" -eq 2 ] && [ -n "$config_sha" ] || path_refused; fi
  for journal in "$certificate_activation" "$subscription_enablement" "$subscription_rotation" "$client_identity_rotation"; do
    printf '%s\n' "$journal" | "$ROOT/usr/bin/grep" -Eq '"(0{32}|0{64})"' && path_refused
  done
  if [ -n "$certificate_activation" ] || [ -n "$subscription_rotation" ]; then
    journal=$certificate_activation; [ -z "$subscription_rotation" ] || journal=$subscription_rotation
    source=$(recovery_source "$journal"); target=$(recovery_target "$journal")
    recovery_serving_valid "$source" && recovery_serving_valid "$target" && [ -n "$serving_suffix" ] || path_refused
    checkpoint=$(recovery_text checkpoint "$journal")
    if [ -n "$certificate_activation" ]; then
      recovery_same_link "$source" "$target" && [ "$(recovery_number certificate_generation "$target")" -gt "$(recovery_number certificate_generation "$source")" ] || path_refused
      case "$checkpoint" in 'target recorded') [ "$serving" = "$source" ] || path_refused ;; 'target accepted') [ "$serving" = "$target" ] || path_refused ;; *) path_refused ;; esac
      [ -n "$renewal_suffix" ] || path_refused
      activation_suffix=',"certificate_activation":'$(printf '%s' "$journal" | "$ROOT/usr/bin/sed" 's/[][\.^$*+?(){}|]/\\&/g')
    else
      [ "$(recovery_text link_id "$source")" != "$(recovery_text link_id "$target")" ] && [ "$(recovery_text credential_sha256 "$source")" != "$(recovery_text credential_sha256 "$target")" ] || path_refused
      [ "${source#*certificate_generation}" = "${target#*certificate_generation}" ] && { { [[ "$source" = '{"http":true,'* ]] && [[ "$target" = '{"http":true,'* ]]; } || { [[ "$source" != '{"http":true,'* ]] && [[ "$target" != '{"http":true,'* ]]; }; } || path_refused
      direction=$(recovery_text direction "$journal")
      case "$checkpoint:$direction" in
        'target authorized:cleanup') completed=null; [ "$serving" = "$source" ] || path_refused ;;
        'stop authorized:cleanup') completed='["target prepared"]'; [ "$serving" = "$source" ] || path_refused ;;
        'committed:forward') completed='["target prepared","source stopped"]'; [ "$serving" = "$target" ] || path_refused ;;
        *) path_refused ;;
      esac
      [[ "$journal" = *'"completed_effects":'"$completed"',"source":'* ]] || path_refused
      append_recovery_resource '/var/lib/sbxr/subscription-staging/credential root:root 0600 one-link replacement credential'
      append_recovery_resource '/var/lib/sbxr/subscription-staging/serving.json root:root 0600 immutable replacement serving state'
      rotation_suffix=',"subscription_rotation":'$(printf '%s' "$journal" | "$ROOT/usr/bin/sed" 's/[][\.^$*+?(){}|]/\\&/g')
    fi
  fi
  if [ -n "$subscription_compromised" ]; then
    [ -n "$serving_suffix" ] || path_refused
    compromised_suffix=',"subscription_compromised":true'
  fi
  if [ -n "$subscription_enablement" ]; then
    [ -z "$serving_suffix$renewal_suffix$subscription_suffix" ] || path_refused
    journal=$subscription_enablement
    checkpoint=$(recovery_number checkpoint "$journal")
    pending_serving=$(printf '%s' "$journal" | "$ROOT/usr/bin/sed" -n 's/.*,"serving":\({[^}]*}\).*/\1/p')
    pending_renewal=$(printf '%s' "$journal" | "$ROOT/usr/bin/sed" -n 's/.*,"renewal":\({[^}]*}\).*/\1/p')
    pending_resources=$(printf '%s' "$journal" | "$ROOT/usr/bin/sed" -n 's/.*,"resources":\({[^}]*}\).*/\1/p')
    pending_http=0; [[ "$pending_resources" != '{"http":true,'* ]] || pending_http=1
    link_id=$(printf '%s' "$journal" | "$ROOT/usr/bin/sed" -n 's/^{"checkpoint":[0-9]*,"link_id":"\([0-9a-f]*\)".*/\1/p')
    credential_sha=$(printf '%s' "$journal" | "$ROOT/usr/bin/sed" -n 's/^{"checkpoint":[0-9]*,"link_id":"[0-9a-f]*","credential_sha256":"\([0-9a-f]*\)".*/\1/p')
    recorder_id=$(recovery_text recorder_id "$journal")
    if [ -n "$pending_serving" ]; then
      recovery_serving_valid "$pending_serving" && [ "$(recovery_text link_id "$pending_serving")" = "$link_id" ] && [ "$(recovery_text credential_sha256 "$pending_serving")" = "$credential_sha" ] && [ -n "$pending_resources" ] || path_refused
      if [ "$pending_http" -eq 1 ]; then [[ "$pending_serving" = '{"http":true,'* ]] && [ -z "$pending_renewal" ] || path_refused
      else [ -n "$pending_renewal" ] && [[ "$pending_serving" != '{"http":true,'* ]] || path_refused; fi
      append_recovery_serving "$pending_serving"
    else
      [ -z "$pending_renewal" ] || path_refused
      [ "$pending_http" -eq 0 ] || [ "$checkpoint" -lt 8 ] || path_refused
      append_recovery_resource '/var/lib/sbxr/subscription-token root:root 0600 one-link provisional credential'
      append_recovery_resource '/var/lib/sbxr/subscription-staging root:root 0700 provisional material'
      append_recovery_resource '/etc/systemd/system/sbxr-subscription.service root:root 0644 one-link fixed-serving-v1'
      append_recovery_resource '/etc/systemd/system/multi-user.target.wants/sbxr-subscription.service root-owned provisional enablement symlink'
      if [ "$pending_http" -eq 0 ]; then
        for path in archive live renewal; do append_recovery_resource '/etc/letsencrypt/'"$path"'/sbxr-subscription'"$([ "$path" != renewal ] || printf '.conf')"' owned provisional lineage'; done
        append_recovery_resource '/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf root:root 0644 provisional recorder route'
        for path in deploy post; do append_recovery_resource '/etc/letsencrypt/renewal-hooks/'"$path"'/sbxr-subscription root:root 0700 provisional hook'; done
        append_recovery_resource '/var/lib/sbxr/renewal-attempts.json root:root 0600 provisional evidence'
      fi
    fi
    if [ -n "$pending_renewal" ]; then
      [ "$(recovery_text recorder_id "$pending_renewal")" = "$recorder_id" ] && [ "$(recovery_text public_ipv4 "$pending_renewal")" = "$ip" ] || path_refused
      append_recovery_resource '/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf root:root 0644 one-link recorder-v1'
      for path in deploy post; do append_recovery_resource '/etc/letsencrypt/renewal-hooks/'"$path"'/sbxr-subscription root:root 0700 one-link '"$path"'-writer-v1'; done
      append_recovery_resource '/var/lib/sbxr/renewal-attempts.json root:root 0600 one-link bounded-evidence-v1'
      append_recovery_resource '/var/lib/sbxr/renewal-admission.lock root:root 0600 one-link admission-v1'
      append_recovery_resource '/var/lib/sbxr/renewal-writer.lock root:root 0600 one-link writer-v1'
    fi
    if [ -n "$pending_resources" ]; then
      [ "$(recovery_text public_ipv4 "$pending_resources")" = "$ip" ] || path_refused
      append_recovery_resource '/etc/systemd/system/sbxr-subscription-firewall.service root:root 0644 one-link sha256:'"$(recovery_text firewall_sha256 "$pending_resources")"
      if [ "$pending_http" -eq 1 ]; then
        [[ "$pending_resources" = *'"snapd_created":false,"certbot_created":false}' ]] || path_refused
      else append_recovery_resource 'iptables filter INPUT '"$ip"'/32 tcp/80 comment=sbxr-subscription exact-owned'; fi
      append_recovery_resource 'iptables filter INPUT '"$ip"'/32 tcp/8443 comment=sbxr-subscription exact-owned'
      if [ "$pending_http" -eq 0 ]; then
        for path in snapd certbot; do state=reused; [[ "$pending_resources" != *'"'"$path"'_created":true'* ]] || state=created; [ "$path" != certbot ] || path='official Certbot snap'; append_recovery_resource "$path dependency $state"; done
        [[ "$pending_resources" != *'"recorder_directory_created":true'* ]] || append_recovery_resource '/etc/systemd/system/snap.certbot.renew.service.d root:root 0755 SBXR-created empty-after-drop-in-removal'
      fi
    fi
    if [ "$checkpoint" -ge 8 ] && [ "$checkpoint" -le 14 ]; then append_recovery_resource '/var/lib/sbxr/subscription-staging/credential root:root 0600 one-link provisional credential'; fi
    if [ "$checkpoint" -ge 8 ] && [ "$checkpoint" -le 15 ]; then append_recovery_resource '/var/lib/sbxr/subscription-staging/serving.json root:root 0600 immutable provisional serving state'; fi
    for path in /var/lib/sbxr/subscription-staging/credential /var/lib/sbxr/subscription-staging/serving.json /var/lib/sbxr/subscription-token /var/lib/sbxr/subscription-serving.json /etc/systemd/system/sbxr-subscription.service /etc/systemd/system/sbxr-subscription-firewall.service /etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf /etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription /etc/letsencrypt/renewal-hooks/post/sbxr-subscription /var/lib/sbxr/renewal-admission.lock /var/lib/sbxr/renewal-writer.lock /var/lib/sbxr/renewal-attempts.json; do
      if [ "$pending_http" -eq 1 ]; then case "$path" in *letsencrypt*|*certbot*|*renewal-*) continue ;; esac; fi
      append_recovery_resource "$path.sbxr-next root-owned synchronized no-replace publication"
    done
    enablement_suffix=',"subscription_enablement":'$(printf '%s' "$journal" | "$ROOT/usr/bin/sed" 's/[][\.^$*+?(){}|]/\\&/g')
  fi
`

const bootstrapRecoveryClient = `
  if [ -n "$client_identity_rotation" ]; then
    [ -n "$startup_suffix" ] || path_refused
    journal=$client_identity_rotation
    checkpoint=$(recovery_text checkpoint "$journal")
    direction=cleanup; target_canonical=0
    case "$checkpoint" in
      'rotation authorized') completed_count=0 ;; 'target prepared') completed_count=1 ;; 'startup integration published') completed_count=2 ;; 'systemd reloaded') completed_count=3 ;; 'startup route verified') completed_count=4 ;; 'cutover gated') completed_count=5 ;; 'source stopped') completed_count=6 ;; 'source quiescent') completed_count=7 ;; 'source revoked') completed_count=8; direction=forward ;; 'target published') completed_count=9; direction=forward; target_canonical=1 ;; 'target started') completed_count=10; direction=forward; target_canonical=1 ;; *) path_refused ;;
    esac
    source_sha=$(recovery_text source_configuration_sha256 "$journal"); target_sha=$(recovery_text target_configuration_sha256 "$journal")
    [ "$source_sha" != "$target_sha" ] && [ "$(recovery_text direction "$journal")" = "$direction" ] || path_refused
    if [ "$target_canonical" -eq 1 ]; then [ "$config_sha" = "$target_sha" ] || path_refused; else [ "$config_sha" = "$source_sha" ] || path_refused; fi
    effects=''; completed=''; effect_count=0
    for effect in 'prepare target' 'publish startup integration' 'reload systemd' 'verify startup route' 'establish cutover gate' 'stop source' 'prove source quiescence' 'revoke source' 'publish target' 'start target' 'verify target' 'clean staging'; do
      effects=$effects${effects:+,}'"'"$effect"'"'
      if [ "$effect_count" -lt "$completed_count" ]; then completed=$completed${completed:+,}'"'"$effect"'"'; fi
      effect_count=$((effect_count + 1))
    done
    effects='['"$effects"']'; [ -n "$completed" ] && completed='['"$completed"']' || completed=null
    [[ "$journal" = *'"effects":'"$effects"',"completed_effects":'"$completed"',"source_configuration_sha256":'* ]] || path_refused
    append_recovery_resource '/var/lib/sbxr/client-identity-target.json root:root 0600 one-link sha256:'"$target_sha"
    append_recovery_resource '/var/lib/sbxr/client-identity-target.json.sbxr-next root-owned Client Identity target publication'
    append_recovery_resource '/etc/sing-box/.config.json.sbxr-next root:sing-box 0640 one-link sha256:'"$target_sha"
    append_recovery_resource '/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf.sbxr-next root-owned Client Identity startup publication'
    sub=$(printf '%s' "$journal" | "$ROOT/usr/bin/sed" -n 's/.*,"subscription":\(.*\)}$/\1/p')
    if [ -n "$sub" ]; then
      source=$(recovery_source "$sub"); target=$(recovery_target "$sub")
      recovery_serving_valid "$source" && recovery_serving_valid "$target" && recovery_same_link "$source" "$target" && { [ "$source" = "$target" ] || [ "$(recovery_number certificate_generation "$target")" -gt "$(recovery_number certificate_generation "$source")" ]; } || path_refused
      [ "$serving" = "$source" ] || [ "$serving" = "$target" ] || path_refused
      source_artifact=$(recovery_text source_artifact_sha256 "$sub"); target_artifact=$(recovery_text target_artifact_sha256 "$sub")
      [ "$source_artifact" != "$target_artifact" ] || path_refused
      if [[ "$source" != '{"http":true,'* ]]; then append_recovery_certificates "$source"; append_recovery_certificates "$target"; fi
      append_recovery_resource '/var/lib/sbxr/subscription-staging/client-artifact root:root 0600 one-link sha256:'"$target_artifact"
      append_recovery_resource '/var/lib/sbxr/subscription-staging/serving.json root:root 0600 immutable Client Identity serving state'
      append_recovery_resource '/var/lib/sbxr/subscription-staging/client-artifact.sbxr-next root-owned Client Identity artifact publication'
      append_recovery_resource '/var/lib/sbxr/subscription-staging/serving.json.sbxr-next root-owned Client Identity state publication'
      append_recovery_resource '/etc/systemd/system/sbxr-subscription.service.sbxr-next root-owned Client Identity serving startup publication'
      append_recovery_resource '/etc/systemd/system/sbxr-subscription.service.sbxr-next.sbxr-next root-owned Client Identity serving startup publication'
    else [ -z "$serving_suffix" ] || path_refused; fi
    client_suffix=',"client_identity_rotation":'$(printf '%s' "$journal" | "$ROOT/usr/bin/sed" 's/[][\.^$*+?(){}|]/\\&/g')
  fi
`
