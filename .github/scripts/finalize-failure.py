"""Assemble a retained failure using the protected collector's own fresh admission."""
import hashlib
import json
from pathlib import Path
import re
import sys

SCENARIOS = ('mvp-install', 'mvp-subscription', 'mvp-credentials', 'mvp-serving', 'mvp-removal')


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def notice(original, binding, scenario, window_digest):
    """The original file is the canonical failed observation, before hosted facts assembly."""
    failure = json.loads(original)
    run = binding['run_id']
    if (len(original) > 16384 or canonical(failure) != original or sha(original) != binding['failure_sha256']
            or type(run) is not int or run <= 0 or scenario not in SCENARIOS
            or failure['scenario_id'] != scenario or failure['attempt_id'] != f'run-{run}-attempt-1'
            or failure['operation_id'] != 'operation-'+str(SCENARIOS.index(scenario)+1)
            or failure['actual_result'] not in ('timeout','unexpected-failure','unexplained-drift','evidence-refused')
            or not all(re.fullmatch('[0-9a-f]{64}', value) for value in
                       (window_digest,binding['request_sha256'], binding['manifest_sha256']))):
        raise ValueError('immutable original failure or binding differs')
    return dict(schema='sbxr-retained-failure-notice-v1', run_id=run, run_attempt=1,
                manifest_sha256=binding['manifest_sha256'], request_sha256=binding['request_sha256'],
                window_sha256=window_digest, original_failure_sha256=sha(original), failure=failure)


def assemble(message, request_raw, manifest_raw, boundary, fresh):
    request, manifest = json.loads(request_raw), json.loads(manifest_raw)
    workflow = fresh['window_decision']['window']['workflow']
    window_digest = sha(canonical(fresh['window_decision']))
    failure = message['failure']
    original = canonical(failure)
    expected = notice(original, dict(failure_sha256=sha(original), run_id=int(workflow['run_id']),
                      manifest_sha256=sha(manifest_raw), request_sha256=sha(request_raw)),
                      request['scenario_id'], window_digest)
    if (canonical(message) != canonical(expected) or fresh['workflow'] != workflow or fresh['run_attempt'] != 1
            or request['qualification_manifest_sha256'] != sha(manifest_raw)
            or request['qualification_window_sha256'] != window_digest
            or manifest['releases'] != [failure['candidate']] or failure['vps_id'] != manifest['v3_attempt']['vps_id']):
        raise ValueError('failure notice differs from the protected request')
    return dict(schema='sbxr-release-qualification-facts-v1', stage='v3-scenario-failure',
                qualification_manifest=manifest, qualification_manifest_attested=True,
                qualification_boundary_facts=boundary, fresh_window=fresh, failure=failure,
                safety_cleanup={'status':'incomplete','host_state':'Unknown'})


if __name__ == '__main__':
    if len(sys.argv) != 6:
        sys.exit('Requires the notice, request, manifest, boundary facts and fresh admission.')
    notice_file, request, manifest, boundary, fresh = map(Path, sys.argv[1:])
    raw = notice_file.read_bytes()
    value = json.loads(raw)
    if len(raw) > 32768 or raw != canonical(value):
        sys.exit('Noncanonical retained failure notice.')
    sys.stdout.buffer.write(canonical(assemble(value, request.read_bytes(),
                            manifest.read_bytes(), json.loads(boundary.read_bytes()), json.loads(fresh.read_bytes()))))
