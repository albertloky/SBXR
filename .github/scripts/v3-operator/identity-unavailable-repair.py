#!/usr/bin/env python3
"""Observe scenario 18 recovery from product, firewall and outside receipts."""
import glob
import gzip
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = Path('/run/sbxr-qualification')


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


api = load('identity_repair_entry', 'scenario-entry.py').api
firewall = load('identity_repair_firewall', 'firewall-control.py')


def read(path):
    return json.loads(api.private_bytes(path, 'identity repair input'), object_pairs_hook=api.unique)


def certbot_children():
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():
            continue
        try:
            arguments = (process / 'cmdline').read_bytes().split(b'\0')
            executable = os.readlink(process / 'exe')
            if any(b'certbot' in argument.lower() for argument in arguments if argument) or executable.endswith('/certbot'):
                return True
        except FileNotFoundError:
            continue
    return False


def issuance_count():
    total = 0
    for name in glob.glob('/var/log/letsencrypt/letsencrypt.log*'):
        opener = gzip.open if name.endswith('.gz') else open
        with opener(name, 'rt', errors='replace') as stream:
            total += sum('Certificate is saved at:' in line for line in stream)
    return total


def main():
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    request = read(request_path)
    if os.geteuid() != 0 or request['scenario_id'] != 'identity-unavailable':
        raise api.Refusal('current root identity repair required')
    added = read(ROOT / '18-firewall-added.json')
    restored = read(ROOT / '18-firewall-restored.json')
    if (restored.get('restored') is not True or restored.get('qualification_rule_count') != 0 or
            restored.get('original_filter_sha256') != added.get('before_sha256') or
            restored.get('after_sha256') != added.get('before_sha256') or
            firewall.qualification_rules(firewall.rules()) or certbot_children()):
        raise api.Refusal('firewall restoration or Certbot quiescence differs')
    baseline = read(ROOT / 'identity-unavailable-private-baseline.json')
    entry = read(ROOT / 'identity-unavailable-entry.json')
    ownership = read(Path('/var/lib/sbxr/proxy-ownership.json'))
    serving = ownership['serving']
    if api.digest(api.canonical(serving)) != baseline['serving_sha256'] or issuance_count() != baseline['issuance_lines']:
        raise api.Refusal('certificate authority or issuance history changed')
    actual_certificates = []
    for name, mode in (('cert', 0o644), ('chain', 0o644), ('fullchain', 0o644), ('privkey', 0o600)):
        path = Path(f"/etc/letsencrypt/archive/sbxr-subscription/{name}{serving['certificate_generation']}.pem")
        actual_certificates.append(api.digest(api.private_bytes(path, 'certificate file', mode)))
    if actual_certificates != serving['certificate_sha256']:
        raise api.Refusal('certificate bytes differ from unchanged authority')
    plan = api.private_bytes(ROOT / 'identity-unavailable-repair-plan.txt', 'reviewed repair plan').decode()
    result = api.private_bytes(ROOT / 'identity-unavailable-repair-result.txt', 'public repair result').decode()
    if 'restart only owned Subscription Serving' not in plan or 'PROXY-INSTALLATION-SUBSCRIPTION-REPAIRED' not in result:
        raise api.Refusal('reviewed runtime repair or public result differs')
    outside = read(ROOT / 'identity-unavailable-repair-outside.json')
    manifest = read(Path(os.environ['SBXR_QUALIFICATION_MANIFEST']))
    if (outside.get('schema') != 'sbxr-v4-identity-repair-outside-v1' or
            outside.get('scenario_id') != request['scenario_id'] or
            outside.get('request_sha256') != api.digest(api.private_bytes(request_path, 'current request')) or
            outside.get('qualification_manifest_sha256') != request['qualification_manifest_sha256'] or
            outside.get('outside_runner_id') != manifest['v3_attempt']['outside_runner_id'] or
            outside.get('link_sha256') != entry['link_sha256'] or
            outside.get('same_link_restored') is not True or outside.get('trusted_tls') is not True):
        raise api.Refusal('outside restored-link receipt differs')
    subprocess.run(['systemctl', 'is-active', '--quiet', 'sing-box.service'], check=True)
    print(json.dumps({'event': 'same_link_restored_at', 'result': 'observed', 'facts': {
        'runtime_only_plan': True, 'no_certbot_child': True, 'no_issuance': True,
        'certificate_lineage_unchanged': True, 'same_link_restored': True,
        'proxy_healthy': True, 'firewall_exactly_restored': True}}, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('{"identity_unavailable_repair_failed":true}', file=sys.stderr)
        sys.exit(1)
