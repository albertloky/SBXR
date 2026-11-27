#!/usr/bin/env python3
"""Prepare the fixed operator recovery providers for a planned fresh HTTP window."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import runpy

HERE = Path(__file__).resolve().parent
SCENARIOS = 'mvp-install mvp-subscription mvp-credentials mvp-serving mvp-removal'.split()


def prepare(options):
    read = runpy.run_path(str(HERE / 'mvp-containment-process.py'))['read']
    observer = runpy.run_path(str(HERE / 'mvp-observe.py'))
    raw = read(options.manifest)
    if hashlib.sha256(raw).hexdigest() != options.manifest_sha256:
        raise ValueError('manifest differs from the independently reviewed digest')
    manifest = json.loads(raw, object_pairs_hook=observer['pairs'])
    window = json.loads(read(options.window), object_pairs_hook=observer['pairs'])
    if set(window) != {'origin_run_id', 'start_unix', 'test_until_unix', 'finish_unix'}:
        raise ValueError('fresh-window declaration fields differ')
    origin = window['origin_run_id']
    attempt = manifest['v3_attempt']
    release, = manifest['releases']
    source = manifest['workflow']['commit']
    if (manifest['repository'] != 'albertloky/SBXR' or manifest['schema'] != 'sbxr-qualification-manifest-v3'
            or manifest['mode'] != 'v3' or manifest['source_state'] != 'v3-subscription-clean'
            or not re.fullmatch(r'[1-9][0-9]*', origin) or manifest['workflow']['run_id'] != origin
            or attempt['attempt_id'] != f'run-{origin}-attempt-1' or type(attempt['run_attempt']) is not int
            or attempt['run_attempt'] != 1 or attempt['required_scenarios'] != SCENARIOS
            or attempt['evidence_policy'] != 'mvp-http-live-v1'
            or any(attempt.get(k) for k in ('diagnostic', 'proxy_profile', 'owner_exception',
                    'live89_correction_review', 'late_confirmation_review', 'attended_finish_by',
                    'karing_response_limit_seconds'))
            or not re.fullmatch(r'[0-9a-f]{64}', attempt['vps_identity_sha256'])
            or not re.fullmatch(r'[0-9a-f]{40}', source) or release['commit'] != source
            or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', release['tag'])
            or type(release['sequence']) is not int or release['sequence'] <= 0):
        raise ValueError('original ordinary five-journey candidate differs')
    start, test, end = (window[k] for k in ('start_unix', 'test_until_unix', 'finish_unix'))
    guard = options.dispatch_guard_by
    origin_start = observer['parse'](attempt['started_at']).timestamp()
    # matchesQualificationWindow and qualificationWindowCanStart at the earliest
    # possible admission. Actual job time, attestations and eligibility are live facts.
    if (any(type(v) is not int for v in (start, test, end)) or not 0 < start < test < end
            or start <= origin_start or end - start > 21600 or end - test < 1560
            or start + 1200 > test or start + 2760 > end or not 0 < guard <= test):
        raise ValueError('planned window or dispatch guard exceeds the fresh-window bounds')
    host = str(ipaddress.IPv4Address(options.host))
    recorder = read(HERE / 'mvp-observe.py')
    config = dict(source=source, tag=release['tag'], sequence=release['sequence'], host=host,
                  origin_run_id=origin, manifest_sha256=options.manifest_sha256, machine_sha256=attempt['vps_identity_sha256'],
                  approved_window_start=start, dispatch_guard_by=guard, attended_finish_by=test,
                  security_cutoff=end, test_finish_unix=test, cleanup_finish_unix=end,
                  cleanup_clock_sha256=hashlib.sha256(recorder).hexdigest())
    # Create a new directory only. Write preparation.json last. An interrupted
    # partial directory cannot be frozen or silently reused on a retry.
    dest = options.prepared
    if dest.parent.resolve(strict=True) != dest.absolute().parent or dest.name in ('', '.', '..'):
        raise ValueError('prepared directory must have a canonical parent')
    files = {'read-current-clock.py': read(HERE / 'read-current-clock.py'),
             'operator-source/mvp-observe.py': recorder,
             'operator-source/native-receipts.py': read(HERE / 'native-receipts.py'),
             'operator-source/mvp-containment-process.py': read(HERE / 'mvp-containment-process.py')}
    transport = runpy.run_path(str(HERE/'remote.py'))
    for name in transport['PROVIDERS']:
        files[name] = read(HERE/name)
    for name in transport['ASSETS']:
        files['operator-source/'+name] = read(HERE/name)
    config['provider_pins'] = {name: hashlib.sha256(data).hexdigest() for name,data in files.items()}
    files['preparation.json'] = (json.dumps(config, sort_keys=True) + '\n').encode()
    dest.mkdir(mode=0o700)
    (dest / 'operator-source').mkdir(mode=0o700)
    for name, body in files.items():
        fd = os.open(dest / name, os.O_WRONLY | os.O_EXCL | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
    return {'ready_for_live': False, 'prepared_files': list(files)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prepared', type=Path, help='new preparation directory')
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True, help='independently authenticated original digest')
    parser.add_argument('--window', type=Path, required=True, help='proposed fresh_window declaration JSON')
    parser.add_argument('--host', required=True, help='reviewed destination IPv4')
    parser.add_argument('--dispatch-guard-by', type=int, required=True, help='planned latest dispatch, Unix seconds')
    try:
        print(json.dumps(prepare(parser.parse_args()), sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f'Preparation refused: {error}\n')
