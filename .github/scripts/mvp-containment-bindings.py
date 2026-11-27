"""Pure offline caller/source binding; does not authenticate live observations.

The proposal is deliberately not a runnable scope. Actual run, failure, request,
clock, verified ownership and native UI observations must be supplied by their
existing producers after admission. Import and proposal creation have no effects.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import runpy

PHASES=('clock','ownership','stop-services','verify-host','stop-outside','restore-client','verify-retained','record-failure','verify-transport')
MODULES=('bindings','entry','freeze','host','native-readback','process','transport-preservation')
PREPARED_INPUTS = ('preparation.json', 'native-inputs.json', 'operator-source/native-receipts.py',
                   'remote.py', 'review-cleanup.py', 'read-current-clock.py',
                   'outside-run.py', 'direct-control.py', 'finalize-failure.py')
LATE=('actual signed run and manifest verification','actual immutable original failure and request hashes',
      'fresh clock and validated review-cleanup receipt with process reconciliation',
      'read-only host scope freeze from that authenticated review and original host baseline',
      'exact outside process identities and retained local file inventory',
      'fresh CUA observation/restoration reply and frozen original native inputs',
      'actual live-job action-time disposal confirmation','remaining full per-scenario and final transport budgets')


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rust_string(file,name):
    return rust_value(Path(file).read_text(),name)


def rust_value(text,name):
    match=re.search(r'pub const '+name+r': &str =\s*("(?:[^"\\]|\\.)*");',text)
    if not match:raise ValueError('candidate unit source missing')
    return ast.literal_eval(match.group(1)).encode()


def prepared_inputs(prepared, scripts):
    if (prepared / 'operator-source').is_symlink():
        raise ValueError('linked prepared directory')
    missing = [name for name in PREPARED_INPUTS if not os.path.lexists(prepared / name)]
    if missing:
        raise ValueError('missing prepared inputs: ' + ', '.join(missing))
    # Use the supervisor's bounded regular-file reader before pinning any input.
    read = runpy.run_path(str(Path(__file__).with_name('mvp-containment-process.py')))['read']
    inputs = {prepared / name for name in PREPARED_INPUTS}
    inputs.update(prepared.glob('*.py'))
    inputs.update(p for p in (prepared / 'operator-source').iterdir()
                  if p.is_symlink() or not p.is_dir())
    metadata = {}
    pins = {}
    for path in sorted(inputs):
        if path.is_symlink():
            raise ValueError('linked prepared input: ' + path.name)
        raw = read(path)
        pins[str(path)] = hashlib.sha256(raw).hexdigest()
        if path in (prepared / 'preparation.json', prepared / 'native-inputs.json'):
            if path.stat().st_mode & 0o077:
                raise ValueError('expected private prepared input: ' + path.name)
            metadata[path.name] = json.loads(raw)
    cfg = metadata['preparation.json']
    native = metadata['native-inputs.json']
    if native['source_commit'] != cfg['source'] or native['candidate'] != {k: cfg[k] for k in ('tag', 'sequence')}:
        raise ValueError('native input candidate differs from preparation')
    helper = str(prepared / 'operator-source/native-receipts.py')
    canonical = (scripts / 'native-receipts.py').read_bytes()
    expected = {'source_file': helper, 'size': len(canonical), 'sha256': hashlib.sha256(canonical).hexdigest()}
    if native['canonical_helper'] != expected or pins[helper] != expected['sha256']:
        raise ValueError('prepared native-receipts.py differs from reviewed source')
    if 'cleanup_clock_sha256' in cfg:
        recorder_pin = digest(scripts / 'mvp-observe.py')
        if (cfg['cleanup_clock_sha256'] != recorder_pin
                or pins.get(str(prepared / 'operator-source/mvp-observe.py')) != recorder_pin
                or pins[str(prepared / 'read-current-clock.py')] != digest(scripts / 'read-current-clock.py')):
            raise ValueError('prepared cleanup clock differs from reviewed source')
    if 'provider_pins' in cfg:
        fixed = runpy.run_path(str(scripts / 'remote.py'))
        names = set(fixed['PROVIDERS']) | {'operator-source/'+name for name in fixed['ASSETS']}
        names |= {'read-current-clock.py','operator-source/native-receipts.py','operator-source/mvp-containment-process.py'}
        expected = {name: digest(scripts/Path(name).name) for name in names}
        if expected != cfg['provider_pins'] or any(pins.get(str(prepared/name)) != value for name,value in expected.items()):
            raise ValueError('prepared recovery providers differ from reviewed source')
    return cfg, pins


def proposal(repository,prepared):
    repo=Path(repository).resolve();scripts=repo/'.github/scripts'
    if Path(prepared).is_symlink():
        raise ValueError('linked prepared directory')
    prepared = Path(prepared).resolve(strict=True)
    cfg, prepared_pins = prepared_inputs(prepared, scripts)
    entry=scripts/'mvp-containment-entry.py';runner=scripts/'mvp-operator-run.py'
    paths=[scripts/('mvp-containment-'+x+'.py') for x in MODULES]
    paths += [scripts/'mvp-retained-containment.py',scripts/'native-receipts.py',scripts/'mvp-host-baseline.py',runner]
    paths += [repo/'src/runtime_handoff.rs',repo/'src/client_identity.rs',repo/'src/host/owner_runtime/testdata/sing-box.service']
    if 'provider_pins' in cfg:
        paths.extend([scripts/'mvp-recovery.py',scripts/'prepare-mvp-containment.py'])
    pins={str(p):digest(p) for p in paths}
    pins.update(prepared_pins)
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prepared', type=Path, help='directory containing the reviewed operator inputs')
    args = parser.parse_args()
    try:
        print(json.dumps(proposal(Path(__file__).resolve().parents[2], args.prepared), sort_keys=True))
    except (OSError, KeyError, TypeError, ValueError) as error:
        parser.exit(1, f'Containment preparation refused: {error}\n')
