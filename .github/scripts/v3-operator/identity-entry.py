#!/usr/bin/env python3
"""Publish the protected server/outside handoff for identity scenarios 16--18."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import gzip
import glob
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('identity_entry_api', HERE / 'assemble-evidence.py')
api = importlib.util.module_from_spec(spec); sys.modules[spec.name] = api; spec.loader.exec_module(api)
SCENARIOS = ('identity-precommit', 'identity-postcommit', 'identity-unavailable')
ROOT = Path('/run/sbxr-qualification')


def now(): return api.datetime.now(api.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')

def issuance_count():
    total = 0
    for name in glob.glob('/var/log/letsencrypt/letsencrypt.log*'):
        opener = gzip.open if name.endswith('.gz') else open
        try:
            with opener(name, 'rt', errors='replace') as stream:
                total += sum('Certificate is saved at:' in line for line in stream)
        except OSError:
            raise api.Refusal('identity entry: certificate history unreadable')
    return total


def publish(path, value):
    api.identity.atomic_write_new(path, api.canonical(value))


def client(raw):
    value = json.loads(raw, object_pairs_hook=api.unique)
    api.exact(value, ('inbounds', 'outbounds', 'log'), 'confirmed client configuration')
    if (value['inbounds'] != [{'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 2080}] or
            not isinstance(value['outbounds'], list) or len(value['outbounds']) != 1 or
            not re.fullmatch(r'[0-9a-fA-F-]{36}', value['outbounds'][0].get('uuid', ''))):
        raise api.Refusal('confirmed official client configuration required')
    return value


def prepare(scenario, disclosure):
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    manifest_path = Path(os.environ['SBXR_QUALIFICATION_MANIFEST'])
    manifest, manifest_body, manifest_raw = api.load(manifest_path, 'manifest')
    request, _, request_raw = api.load(request_path, 'request', True)
    _, attempt, manifest_sha = api.validate_manifest(manifest, manifest_body, scenario)
    _, request_sha = api.validate_request(request, request_raw, manifest_sha, scenario, attempt)
    common, _, _ = api.load(ROOT / ('scenario-' + scenario + '-begin.json'), 'common scenario begin', True)
    api.exact(common, ('schema', 'scenario_id', 'qualification_manifest_sha256', 'request_sha256',
                       'started_at', 'entry_started_at'), 'common scenario begin')
    started, at = common['started_at'], common['entry_started_at']
    if (common['schema'] != 'sbxr-v4-scenario-entry-v1' or common['scenario_id'] != scenario or
            common['qualification_manifest_sha256'] != manifest_sha or common['request_sha256'] != request_sha or
            started != os.environ.get('SCENARIO_START') or started != request['not_before'] or
            not api.before(started, at) or not api.before(at, now())):
        raise api.Refusal('identity entry: original scenario start differs')
    value = client(disclosure)
    source = ROOT / (scenario + '-source-client.json')
    publish(source, value)
    ownership_raw = api.private_bytes(Path('/var/lib/sbxr/proxy-ownership.json'), 'Ownership Record')
    record = json.loads(ownership_raw, object_pairs_hook=api.unique)
    source_sha = record.get('configuration_sha256')
    if not isinstance(source_sha, str) or api.SHA256.fullmatch(source_sha) is None:
        raise api.Refusal('identity entry: current source authority absent')
    noncredential = copy.deepcopy(value)
    del noncredential['outbounds'][0]['uuid']
    serving = record.get('serving')
    if not isinstance(serving, dict):
        raise api.Refusal('identity entry: current Subscription Link authority absent')
    token = api.private_bytes(Path('/var/lib/sbxr/subscription-token'), 'Subscription credential').rstrip(b'\n')
    if api.digest(token) != serving['credential_sha256']:
        raise api.Refusal('identity entry: Subscription credential differs')
    link_sha = api.digest(('https://' + record['public_ipv4'] + ':8443/s/').encode() + token)
    baseline = {'schema': 'sbxr-v4-identity-private-baseline-v1', 'scenario_id': scenario,
                'qualification_manifest_sha256': manifest_sha, 'request_sha256': request_sha,
                'source_configuration_sha256': source_sha,
                'noncredential_sha256': api.digest(api.canonical(noncredential)),
                'serving_sha256': api.digest(api.canonical(serving)), 'observed_at': at}
    if scenario == 'identity-unavailable':
        baseline['issuance_lines'] = issuance_count()
        host = record.get('public_ipv4')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(5)
        try:
            try: sock.connect((host, 8443))
            except OSError: baseline['local_public_https_failed_at'] = now()
            else: raise api.Refusal('identity entry: local public HTTPS unexpectedly reachable')
        finally: sock.close()
    publish(ROOT / (scenario + '-private-baseline.json'), baseline)
    entry = {'schema': 'sbxr-v4-identity-transition-entry-v1', 'scenario_id': scenario,
             'qualification_manifest_sha256': manifest_sha, 'request_sha256': request_sha,
             'started_at': started, 'entry_started_at': at,
             'source_configuration_sha256': source_sha,
             'noncredential_sha256': baseline['noncredential_sha256'],
             'link_sha256': link_sha}
    publish(ROOT / (scenario + '-entry.json'), entry)
    trigger = {'schema': 'sbxr-v4-identity-transition-outside-request-v1', 'scenario_id': scenario,
               'qualification_manifest_sha256': manifest_sha, 'request_sha256': request_sha,
               'deadline_unix': request['deadline_unix'], 'request_id': 'identity-' + scenario,
               'operator_directory': os.fspath(HERE), 'state_directory': os.fspath(ROOT),
               'source_configuration_sha256': source_sha}
    evidence_dir = Path(os.environ['SBXR_OPERATOR_EVIDENCE_DIR'])
    publish(evidence_dir / 'identity-transition-outside-request.json', trigger)
    return trigger


def selected(scenario, disclosure):
    if scenario == 'identity-precommit':
        raise api.Refusal('precommit recovery must not disclose a replacement')
    source_raw = api.private_bytes(ROOT / (scenario + '-source-client.json'), 'source client')
    source, target = json.loads(source_raw), client(disclosure)
    old_uuid, new_uuid = source['outbounds'][0].pop('uuid'), target['outbounds'][0].pop('uuid')
    if old_uuid == new_uuid or source != target:
        raise api.Refusal('selected client changed fields other than Client Identity')
    publish(ROOT / (scenario + '-selected-client.json'), client(disclosure))


def public_disclosure(scenario):
    """Obtain the configuration from the installed public confirmation path."""
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    request, _, request_raw = api.load(request_path, 'request', True)
    if request['scenario_id'] != scenario or time.time() >= request['deadline_unix']:
        raise api.Refusal('public disclosure: original request expired or changed')
    environment = {key: value for key, value in os.environ.items()
                   if key not in ('BASH_ENV', 'ENV', 'SHELLOPTS', 'BASHOPTS') and not key.startswith('BASH_FUNC_')}
    result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c',
        'source "$1"; operator_expect_scenario "$2"; operator_exact_candidate; remote_outside_disclose',
        'identity-public-disclosure', str(HERE / 'operator-support.sh'), scenario],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=min(30, request['deadline_unix'] - time.time()), env=environment, check=True)
    if (result.stderr or not 0 < len(result.stdout) <= api.JSON_LIMIT or
            api.private_bytes(request_path, 'current request') != request_raw or time.time() > request['deadline_unix']):
        raise api.Refusal('public disclosure: current confirmed result refused')
    client(result.stdout)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('operation', choices=('prepare', 'selected'))
    parser.add_argument('scenario', choices=SCENARIOS); args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise api.Refusal('Linux root required')
    raw = public_disclosure(args.scenario)
    result = prepare(args.scenario, raw) if args.operation == 'prepare' else selected(args.scenario, raw)
    print(json.dumps({'identity_entry_prepared': True, 'scenario_id': args.scenario,
                      'operation': args.operation}, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except Exception:
        print('{"identity_entry_refused":true}', file=sys.stderr); raise SystemExit(1)
