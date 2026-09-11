#!/usr/bin/env python3
"""Store the public subscription disclosure and request its outside witness."""
import argparse
import importlib.util
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scenario_subscription_entry', HERE / 'scenario-entry.py')
entry = importlib.util.module_from_spec(spec); sys.modules[spec.name] = entry; spec.loader.exec_module(entry)
api = entry.api
SCENARIOS = api.later.SCENARIOS[:5] + ('identity-unavailable',)


def request_document(scenario, manifest_sha, request_sha, request, attempt):
    return {'schema': 'sbxr-v4-managed-outside-request-v1', 'scenario_id': scenario,
            'qualification_manifest_sha256': manifest_sha, 'request_sha256': request_sha,
            'outside_runner_id': attempt['outside_runner_id'], 'deadline_unix': request['deadline_unix'],
            'operator_directory': '/run/sbxr-qualification', 'state_directory': '/run/sbxr-qualification'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario', choices=SCENARIOS)
    parser.add_argument('phase', choices=('before', 'final'))
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise api.Refusal('Linux root required')
    if args.scenario == 'identity-unavailable' and args.phase != 'final':
        raise api.Refusal('identity repair uses only the final restored link')
    manifest, _, request, request_raw, manifest_sha, request_sha = entry.read_authority(args.scenario)
    raw = sys.stdin.buffer.read(api.JSON_LIMIT + 1)
    bound = {'scenario_id': args.scenario, 'qualification_manifest_sha256': manifest_sha,
             'request_sha256': request_sha, 'deadline_unix': request['deadline_unix'], 'not_before': request['not_before']}
    outside = api.import_sibling('scenario_subscription_outside', 'link-outside.py')
    value = outside.observation(raw, bound)
    root = Path('/run/sbxr-qualification')
    info = root.lstat()
    if root.is_symlink() or info.st_uid != 0 or info.st_mode & 0o777 != 0o700:
        raise api.Refusal('private operator directory required')
    number = 18 if args.scenario == 'identity-unavailable' else 11 + SCENARIOS.index(args.scenario)
    destination = root / f'{number}-subscription-{args.phase}.json'
    if (api.private_bytes(Path(os.environ['SBXR_QUALIFICATION_REQUEST']), 'current request') != request_raw or
            api.instant(entry.timestamp(), 'disclosure time') > api.timing.Instant(request['deadline_unix'], 0)):
        raise api.Refusal('collector request changed or expired')
    api.identity.atomic_write_new(destination, api.canonical(value))
    if args.phase == 'before':
        trigger = Path('/root/sbxr-qualification-evidence/managed-outside-request.json')
        api.identity.atomic_write_new(trigger, api.canonical(request_document(args.scenario, manifest_sha, request_sha,
                                                                             request, manifest['v3_attempt'])))
    print(api.json.dumps({'scenario_id': args.scenario, 'phase': args.phase, 'private_disclosure_stored': True}, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except Exception:
        print('{"scenario_subscription_refused":true}', file=sys.stderr); sys.exit(1)
