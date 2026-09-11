#!/usr/bin/env python3
"""Check scenario 18's restored exact link on the declared outside runner."""
import importlib.util
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('identity_repair_renewal_probe', HERE / 'renewal-outside.py')
renewal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renewal)
link = renewal.link


def produce(raw, bound, expected_link_sha256, probe=None):
    """The collector backend supplies the original request and entry authority."""
    link.require(bound['scenario_id'] == 'identity-unavailable' and time.time() < bound['deadline_unix'])
    value = link.observation(raw, bound)
    link.require(link.hashes(value)['link'] == expected_link_sha256)
    started = link.now()
    (probe or renewal.OutsideHTTPSProbe()).complete(value, 200, min(12, bound['deadline_unix'] - time.time()))
    completed = link.now()
    link.require(link.timestamp(completed) <= bound['deadline_unix'])
    return {'schema': 'sbxr-v4-identity-repair-outside-v1', 'scenario_id': 'identity-unavailable',
            'qualification_manifest_sha256': bound['qualification_manifest_sha256'],
            'request_sha256': bound['request_sha256'], 'outside_runner_id': bound['outside_runner_id'],
            'started_at': started, 'completed_at': completed, 'link_sha256': expected_link_sha256,
            'same_link_restored': True, 'trusted_tls': True}
