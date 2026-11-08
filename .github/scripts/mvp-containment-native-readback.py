"""Read actual native state and verify original use while retaining test data.

UI interaction is performed through CUA. This module never writes app settings,
removes profiles or substitutes fixture input for a native observation.
"""
import datetime
import hashlib
import json
from pathlib import Path
import time


def verify(n, inputs, ui, *, authority, source, deadline, clock=time.time):
    def require(v,why):
        if not v:raise ValueError(why)
    require(clock()<deadline,'native readback deadline')
    require(ui['binding']==authority and ui['origin']==source,'UI observation identity/origin')
    require(type(ui['observed_at']) in (int,float) and 0<=clock()-ui['observed_at']<=30,'UI observation stale')
    require(type(ui['connected']) is bool and type(ui['tun_enabled']) is bool,'actual UI flags required')
    raw,proof=n._native_bytes(n.NATIVE_SUBSCRIPTION_SOURCE)
    selected,selected_proof=n._native_bytes(n.NATIVE_SUBSCRIPTION_SOURCE.with_name('karing_subscribe_use.json'))
    settings_raw,settings_proof=n._native_bytes(n.NATIVE_SETTINGS_SOURCE)
    store=json.loads(raw,object_pairs_hook=n.unique)
    baseline=json.loads(n.source_file(inputs['original_store_baseline']),object_pairs_hook=n.unique)
    end=datetime.datetime.now(datetime.timezone.utc).isoformat()
    original_ids={p['groupid'] for p in baseline['items']}
    require(not any(p.get('remark')==inputs['profile_remark'] for p in baseline['items']),'candidate remark conflicts with original')
    require(len({p['groupid'] for p in store['items']})==len(store['items']),'duplicate native profile identity')
    originals=[p for p in store['items'] if p['groupid'] in original_ids]
    extras=[p for p in store['items'] if p['groupid'] not in original_ids]
    require(all(p.get('remark')==inputs['profile_remark'] for p in extras),'unknown additional native profile')
    audit=n.original_profiles_audit_v3(baseline['items'],originals,timezone=inputs['native_timezone'],tzif_record=inputs['native_tzif'],window_start=inputs['original_store_observed_at'],window_end=end)
    require(audit['passed'],'original profiles changed')
    require({k:v for k,v in store.items() if k!='items'}=={k:v for k,v in baseline.items() if k!='items'},'native store metadata changed')
    require(selected==n.source_file(inputs['selected_use_baseline']),'original selected use not restored')
    node=json.loads(selected,object_pairs_hook=n.unique)['select_default']
    profiles=[p for p in store['items'] if any(s.get('tag')==node for s in p.get('servers',[]))]
    require(len(profiles)==1 and profiles[0]['remark']!=inputs['profile_remark'],'candidate remains selected or ambiguous')
    require(n.settings_binding()==inputs['settings_binding'] and n.native_timezone_binding()==inputs['native_timezone'],'app/settings/timezone identity changed')
    current=n.settings_readback(inputs['settings_binding'])
    before=n.source_file(inputs['settings_baseline'])
    baseline_settings=json.loads(before,object_pairs_hook=n.unique)
    # Canonical helper owns the accepted projection and preservation comparison.
    n.compare_settings(baseline_settings,current,inputs['settings_binding'])
    connection=json.loads(n.source_file(inputs['selected_connection_baseline']))['connection']
    require(connection=={'configuration':profiles[0]['remark'],'node':node,'connected':ui['connected'],'tun_enabled':ui['tun_enabled']},'original connection/TUN not restored')
    require(n._native_bytes(n.NATIVE_SUBSCRIPTION_SOURCE)==(raw,proof)
            and n._native_bytes(n.NATIVE_SUBSCRIPTION_SOURCE.with_name('karing_subscribe_use.json'))==(selected,selected_proof)
            and n._native_bytes(n.NATIVE_SETTINGS_SOURCE)==(settings_raw,settings_proof),'native source changed during readback')
    candidate_hashes=sorted(hashlib.sha256(n._canonical(p)).hexdigest() for p in store['items'] if p.get('remark')==inputs['profile_remark'])
    require(candidate_hashes==inputs['retained_candidate_profiles'], 'candidate data was changed/deleted during restoration')
    require(clock()<deadline,'native verification exhausted deadline')
    return {'original_restored':True,'original_client_preserved':True,'candidate_selected':False,
            'test_data_deleted':False,'candidate_profiles_retained':sum(p.get('remark')==inputs['profile_remark'] for p in store['items']),
            'native_store_sha256':hashlib.sha256(raw).hexdigest(),'original_profile_audit':audit}
