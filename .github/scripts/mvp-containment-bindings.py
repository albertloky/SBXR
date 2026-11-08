"""Pure offline caller/source binding; does not authenticate live observations.

The proposal is deliberately not a runnable scope. Actual run, failure, request,
clock, verified ownership and native UI observations must be supplied by their
existing producers after admission. Import and proposal creation have no effects.
"""
import ast
import hashlib
import json
from pathlib import Path
import re

PHASES=('clock','ownership','stop-services','verify-host','stop-outside','restore-client','verify-retained','record-failure','verify-transport')
MODULES=('bindings','entry','freeze','host','native-readback','process','transport-preservation')
LATE=('actual signed run and manifest verification','actual immutable original failure and request hashes',
      'fresh clock and validated review-cleanup receipt with process reconciliation',
      'read-only host scope freeze from that authenticated review and original host baseline',
      'exact outside process identities and retained local file inventory',
      'fresh CUA observation/restoration reply and frozen original native inputs',
      'actual live-job action-time disposal confirmation','remaining full per-scenario and final transport budgets')


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rust_string(file,name):
    text=Path(file).read_text()
    match=re.search(r'pub const '+name+r': &str =\s*("(?:[^"\\]|\\.)*");',text)
    if not match:raise ValueError('candidate unit source missing')
    return ast.literal_eval(match.group(1)).encode()


def proposal(repository,prepared):
    repo=Path(repository).resolve();prepared=Path(prepared).resolve();scripts=repo/'.github/scripts'
    cfg=json.loads((prepared/'preparation.json').read_text())
    entry=scripts/'mvp-containment-entry.py';runner=scripts/'mvp-operator-run.py'
    paths=[scripts/('mvp-containment-'+x+'.py') for x in MODULES]
    paths += [scripts/'mvp-retained-containment.py',scripts/'native-receipts.py',scripts/'mvp-host-baseline.py',runner]
    # Prepared imports may resolve other prepared helpers: freeze the complete
    # finite set without executing any of them or editing their original pins.
    paths += sorted(prepared.glob('*.py'))+sorted((prepared/'operator-source').glob('*'))
    paths=[p for p in paths if p.is_file()]
    paths += [repo/'src/runtime_handoff.rs',repo/'src/client_identity.rs',repo/'src/host/owner_runtime/testdata/sing-box.service']
    pins={str(p):digest(p) for p in paths}
    serving=rust_string(repo/'src/runtime_handoff.rs','SERVING_UNIT')
    startup=rust_string(repo/'src/client_identity.rs','STARTUP_DROP_IN')
    singbox=repo/'src/host/owner_runtime/testdata/sing-box.service'
    units={'sbxr-subscription.service':{'fragment_paths':['/etc/systemd/system/sbxr-subscription.service'],'fragment_sha256':hashlib.sha256(serving).hexdigest(),'dropins':{}},
           'sing-box.service':{'fragment_paths':['/lib/systemd/system/sing-box.service','/usr/lib/systemd/system/sing-box.service'],'fragment_sha256':digest(singbox),'dropins':{}}}
    caller={'path':str(entry),'sha256':digest(entry),'dependencies':pins}
    return {'schema':'sbxr-containment-offline-bindings-v1','ready_for_live':False,'origin':'native',
            'candidate':{k:cfg[k] for k in ('source','tag','sequence','host')},
            'original_window':{k:cfg[k] for k in ('approved_window_start','dispatch_guard_by','attended_finish_by','security_cutoff','test_finish_unix','cleanup_finish_unix')},
            'runner':str(runner),'runner_sha256':digest(runner),'callers':{x:caller for x in PHASES},
            'source_unit_pins':units,'startup_dropin_sha256':hashlib.sha256(startup).hexdigest(),
            'late_bound_prerequisites':list(LATE),
            'runtime_static':{'prepared':str(prepared),'host_module':str(scripts/'mvp-containment-host.py'),
                'native_inputs':str(prepared/'native-inputs.json'),'native_verifier':str(scripts/'mvp-containment-native-readback.py'),
                'transport_preservation_verifier':str(scripts/'mvp-containment-transport-preservation.py')},
            'runtime_actual_inputs_required':['scenario','ownership_review','ownership_budget','original_host_baseline','local_retained','transport_disposal_confirmation'],
            'late_bound_paths':{k:str(prepared.parent/'live'/v) for k,v in {
                'host_scope':'containment-host-scope.json','host_review_record':'containment-host-review.json',
                'clock_record':'containment-clock.json','original_failure':'original-failure.json',
                'native_retention_inputs':'containment-native-inputs.json','cua_request':'containment-cua-request.json',
                'cua_reply':'containment-cua-reply.json'}.items()}}
