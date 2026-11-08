"""Freeze concrete containment data from an authenticated ownership observation.

`review` is the existing review-cleanup producer's validated record. The caller
must check its original bytes/pins with that producer before invoking this code.
This function performs read-only operations only; source policy contains exact
package, HTTP unit and startup-drop-in byte identities from the candidate source.
"""
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import time

OWNED_ROOTS=('/etc/sing-box','/var/lib/sing-box','/var/lib/sbxr')


def freeze(Host,review,binding,policy,*,root=Path('/'),command=None,now=time.time,deadline):
    def require(v,why):
        if not v:raise ValueError(why)
    require(review['run_id']==binding['run_id'] and review['source']==binding['source']
            and review['manifest_sha256']==binding['manifest_sha256'] and review['request_sha256']==binding['request_sha256'],'review candidate differs')
    observed=datetime.datetime.fromisoformat(review['observed_at']).timestamp()
    require(0<=now()-observed<=120 and review['uncertain_action_reconciled'] is True
            and review['process_cleanup_verified'] is True,'review freshness/quiescence')
    require(review['exact_installed_identity_verified'] is True or review['installed_executable_present'] is False,'installed identity unverified')
    scope={'binding':binding,'machine_sha256':policy['machine_sha256'],'boot_sha256':policy['boot_sha256'],
           'authority_files':{p:None if v is None else v['sha256'] for p,v in review['authority_snapshot'].items()},
           'executable_sha256':review.get('executable_sha256'),'retained_files':{},'unrelated_files':policy['unrelated_files'],
           'expected_units':copy.deepcopy(policy['expected_units']),'effective_deadline':min(review['current_E'],policy['original_cutoff']),
           'final_cutoff':policy['final_cutoff'],'reviewed_at':observed,'prior_processes':policy['prior_processes'],
           'original_ca_bundle_sha256':policy['original_ca_bundle_sha256']}
    host=Host(scope,root=root,command=command,now=now)
    # Validate the signed/run/authority anchors before reading owned data.
    host.guard(deadline)
    records=[json.loads(host.read(p)) for p,v in scope['authority_files'].items() if v is not None and p!='/var/lib/sbxr/installed.json']
    dropin='/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf'
    if os.path.lexists(host.path(dropin)):
        expected=policy['startup_dropin_sha256']
        require(hashlib.sha256(host.read(dropin)).hexdigest()==expected,'unknown startup drop-in')
        require(any(r.get('proxy_startup',{}).get('drop_in_sha256')==expected for r in records),'startup drop-in has no owned record')
        scope['expected_units']['sing-box.service']['dropins']={dropin:expected}
    retained=set(scope['authority_files'])|{'/usr/local/bin/sbxr'}
    for prefix in OWNED_ROOTS:
        directory=host.path(prefix)
        if not os.path.lexists(directory):continue
        require(directory.is_dir() and not directory.is_symlink(),'owned root changed type')
        for folder,dirs,files in os.walk(directory,followlinks=False):
            for name in dirs:
                require(not (Path(folder)/name).is_symlink(),'owned tree contains directory link')
            for name in files:
                require(now()<deadline,'owned inventory deadline')
                path=Path(folder)/name;require(not path.is_symlink(),'owned tree contains file link')
                retained.add('/'+str(path.relative_to(root)))
                require(len(retained)<=512,'owned inventory exceeds fixed bound')
    scope['retained_files']=host.files(sorted(retained))
    owned,_,states=host.observe() # Validate concrete unit state before freezing pins.
    require(scope['executable_sha256'] is not None or not owned,'service without executable authority')
    host.candidate_processes(states)
    require(now()<deadline,'scope freeze deadline')
    return scope
