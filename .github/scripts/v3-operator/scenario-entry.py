#!/usr/bin/env python3
"""Record the actual phases of a current-request 11–25 operator procedure."""
import argparse
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scenario_entry_assembler', HERE / 'assemble-evidence.py')
api = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = api
spec.loader.exec_module(api)
PHASES = ('begin', 'action-start', 'action-complete', 'finish')
FIELDS = ('entry_started_at', 'action_started_at', 'action_completed_at', 'completed_at')


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def read_authority(scenario):
    manifest_path = Path(os.environ['SBXR_QUALIFICATION_MANIFEST'])
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    manifest, body, manifest_raw = api.load(manifest_path, 'manifest')
    request, _, request_raw = api.load(request_path, 'request', True)
    _, attempt, manifest_sha = api.validate_manifest(manifest, body, scenario)
    _, request_sha = api.validate_request(request, request_raw, manifest_sha, scenario, attempt)
    if not api.before(request['not_before'], timestamp()) or time.time() >= request['deadline_unix']:
        raise api.Refusal('original scenario deadline or not-before differs')
    return manifest, manifest_raw, request, request_raw, manifest_sha, request_sha


def advance(previous, phase, scenario, manifest_sha, request_sha, request, started, at):
    if started != request['not_before']:
        raise api.Refusal('scenario start must equal the original collector start')
    index = PHASES.index(phase)
    base = {'schema': 'sbxr-v4-scenario-entry-v1', 'scenario_id': scenario,
            'qualification_manifest_sha256': manifest_sha, 'request_sha256': request_sha, 'started_at': started}
    if index:
        api.exact(previous, tuple(base) + FIELDS[:index], 'previous scenario phase')
        if any(previous[key] != value for key, value in base.items()):
            raise api.Refusal('scenario phase belongs to another request or start')
        value = dict(previous)
    else:
        value = base
    prior = request['not_before']
    for field in ('started_at',) + FIELDS[:index]:
        if not api.before(prior, value[field]):
            raise api.Refusal('original phase order differs')
        prior = value[field]
    if not api.before(prior, at) or api.instant(at, 'phase time') > api.timing.Instant(request['deadline_unix'], 0):
        raise api.Refusal('phase lies outside original scenario window')
    value[FIELDS[index]] = at
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=PHASES)
    parser.add_argument('scenario', choices=api.later.SCENARIOS)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise api.Refusal('Linux root required')
    root = Path(os.environ['SBXR_OPERATOR_STATE_DIR'])
    info = root.lstat()
    if root != Path('/run/sbxr-qualification') or root.is_symlink() or info.st_mode & 0o777 != 0o700 or info.st_uid != 0:
        raise api.Refusal('private operator state directory required')
    _, _, request, request_raw, manifest_sha, request_sha = read_authority(args.scenario)
    started = os.environ['STARTED_AT']
    if started != os.environ['SCENARIO_START']:
        raise api.Refusal('original scenario clock differs')
    prefix = 'scenario-' + args.scenario + '-'
    index = PHASES.index(args.phase)
    previous = None if index == 0 else api.load(root / (prefix + PHASES[index - 1] + '.json'), 'prior phase', True)[0]
    value = advance(previous, args.phase, args.scenario, manifest_sha, request_sha, request, started, timestamp())
    if api.private_bytes(Path(os.environ['SBXR_QUALIFICATION_REQUEST']), 'current request') != request_raw:
        raise api.Refusal('collector request changed')
    api.identity.atomic_write_new(root / (prefix + args.phase + '.json'), api.canonical(value))
    print(api.json.dumps({'scenario_id': args.scenario, 'phase': args.phase, 'recorded': True}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('{"scenario_entry_refused":true}', file=sys.stderr)
        sys.exit(1)
