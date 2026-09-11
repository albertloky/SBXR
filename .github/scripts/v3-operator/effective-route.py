#!/usr/bin/env python3
"""Inspect the supported Certbot timer-to-service route without starting it.

Run before a scenario stops its timer or injects a route fault. With no renewal
authority, require the official snap route and absence of owned interception.
With renewal authority, require the exact recorder drop-in and both hooks.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('transition', HERE / 'transition-operator.py')
transition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transition)
SERVICE = 'snap.certbot.renew.service'
TIMER = 'snap.certbot.renew.timer'
DROP_IN = '/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf'
OWNED = {
    DROP_IN: (0o644, b'[Service]\nExecStart=\nExecStart=/usr/local/bin/sbxr --certbot-recorder\n'),
    '/etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription': (0o700, b'#!/bin/sh\nexec /usr/local/bin/sbxr --certbot-deploy-hook\n'),
    '/etc/letsencrypt/renewal-hooks/post/sbxr-subscription': (0o700, b'#!/bin/sh\nexec /usr/local/bin/sbxr --certbot-post-hook\n'),
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def show(unit, name):
    result = subprocess.run(['systemctl', 'show', '--property=' + name, '--value', unit],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
    require(result.returncode == 0 and len(result.stdout) <= 65536, 'route property unavailable')
    return result.stdout.strip()


def calendar(value):
    matches = re.findall(r'OnCalendar=\*-\*-\* ([0-9]{2}):([0-9]{2}):([0-9]{2})', value)
    require(len(matches) == value.count('OnCalendar=') == 2, 'official twice-daily calendar absent')
    times = [tuple(map(int, row)) for row in matches]
    require(all(h < 24 and m < 60 and s < 60 for h, m, s in times) and
            sum(h < 12 for h, _, _ in times) == 1, 'official calendar slots mismatch')


def inspect(managed, property_reader=show, file_reader=transition.protected_bytes):
    expected = {'LoadState': 'loaded', 'FragmentPath': '/etc/systemd/system/' + TIMER,
                'DropInPaths': '', 'Unit': SERVICE, 'UnitFileState': 'enabled', 'ActiveState': 'active'}
    for key, value in expected.items():
        require(property_reader(TIMER, key) == value, 'timer route mismatch')
    calendar(property_reader(TIMER, 'TimersCalendar'))
    require(property_reader(SERVICE, 'LoadState') == 'loaded' and
            property_reader(SERVICE, 'FragmentPath') == '/etc/systemd/system/' + SERVICE and
            property_reader(SERVICE, 'NeedDaemonReload') == 'no', 'generated service not effectively loaded')
    route = property_reader(SERVICE, 'ExecStart')
    if managed:
        transition.startup.exact_condition(route, expected_arguments='/usr/local/bin/sbxr --certbot-recorder')
        require(property_reader(SERVICE, 'DropInPaths') == DROP_IN, 'recorder drop-in route mismatch')
    else:
        accepted = False
        for arguments in ('/usr/bin/snap run --timer=00:00~24:00/2 certbot.renew',
                          '/usr/bin/snap run --timer="00:00~24:00/2" certbot.renew'):
            try:
                transition.startup.exact_condition(route, expected_path='/usr/bin/snap', expected_arguments=arguments)
                accepted = True
            except ValueError:
                pass
        require(accepted and property_reader(SERVICE, 'DropInPaths') == '', 'official snap route mismatch')
    artifacts = {}
    for name, (mode, expected_body) in OWNED.items():
        if managed:
            body = file_reader(Path(name), mode)
            require(body == expected_body, 'owned route artifact mismatch')
            artifacts[name] = transition.digest(body)
        else:
            require(not os.path.lexists(name), 'unexpected owned route artifact')
    return {'route': 'owned-recorder' if managed else 'official-snap',
            'timer_calendar_verified': True, 'effective_exec_verified': True,
            'owned_artifacts_sha256': artifacts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root observation required')
    require(not os.environ.get('SBXR_OPERATOR_REHEARSAL') and not os.environ.get('SBXR_OPERATOR_REHEARSAL_HOOK'),
            'qualification observation cannot use rehearsal overrides')
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    manifest_path = Path(os.environ['SBXR_QUALIFICATION_MANIFEST'])
    request_raw = transition.protected_bytes(request_path, 0o600)
    manifest_raw = transition.protected_bytes(manifest_path, 0o600)
    request = json.loads(request_raw, object_pairs_hook=transition.unique)
    manifest = json.loads(manifest_raw, object_pairs_hook=transition.unique)
    scenario = request['scenario_id']
    scenarios = manifest['v3_attempt']['required_scenarios']
    require(manifest['v3_attempt']['evidence_policy'] == 'repair-issuance-bounded-v4' and
            request['qualification_manifest_sha256'] == transition.digest(manifest_raw) and
            scenario in scenarios and not scenario.startswith('baseline-') and
            type(request['deadline_unix']) is int and request['deadline_unix'] > time.time() + 30,
            'current V4 request binding refused')
    phase = 'after-snap-refresh' if scenarios.index(scenario) > scenarios.index('snap-refresh') else 'initial'
    subprocess.run(['bash', '-c', 'source "$1"; operator_expect_scenario "$2"; preflight "$3"; operator_exact_candidate',
                    'route-preflight', str(HERE / 'operator-support.sh'), scenario, phase], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    raw, record = transition.protected_record()
    started = transition.startup.timestamp()
    result = inspect(record.get('renewal') is not None)
    require(transition.protected_record()[0] == raw and transition.protected_bytes(request_path, 0o600) == request_raw and
            transition.protected_bytes(manifest_path, 0o600) == manifest_raw and time.time() <= request['deadline_unix'],
            'route observation authority changed')
    result.update({'schema': 'sbxr-v4-effective-route-v1', 'scenario_id': scenario,
                   'qualification_manifest_sha256': transition.digest(manifest_raw),
                   'request_sha256': transition.digest(request_raw), 'record_sha256': transition.digest(raw),
                   'started_at': started, 'completed_at': transition.startup.timestamp(),
                   'check': 'supported-effective-route-inspected'})
    require(args.output.is_absolute() and args.output.parent.is_dir() and not args.output.parent.is_symlink() and
            args.output.parent.stat().st_mode & 0o777 == 0o700, 'private observation directory required')
    transition.write_state(args.output, result)
    print('{"effective_route_verified":true}')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'state': 'refused', 'error_type': type(error).__name__}), file=sys.stderr)
        sys.exit(1)
