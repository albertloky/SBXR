"""Read an immutable host-baseline binding produced by the bounded SSH caller.

No network access or native observation is performed here. The caller supplies
its existing private-file reader and actual source/host identity. Old evidence
is not moved or rewritten to match a consumer's expected directory.
"""
import hashlib
import json
from pathlib import Path


def baseline_input(root, binding, configuration, private_bytes, required_paths=()):
    root=Path(root)
    if binding['source']!=configuration['source'] or binding['host']!=configuration['host']:
        raise ValueError('baseline source/host differs')
    record=binding['baseline'];path=Path(record['source_file'])
    if path!=root/'live/host-baseline.operator.stdout':
        raise ValueError('baseline path differs')
    raw=private_bytes(path)
    if len(raw)!=record['size'] or hashlib.sha256(raw).hexdigest()!=record['sha256']:
        raise ValueError('baseline bytes differ')
    baseline=json.loads(raw)
    if not all(path in baseline['files'] for path in required_paths):
        raise ValueError('required preserved baseline paths missing')
    if any(path in baseline['files'] for path in ('/root/mvp-observation-draft.json','/root/sbxr-qualification-evidence')):
        raise ValueError('baseline precedes previous evidence preservation')
    for key in ('packages','holds','accounts','groups','firewall','ip6firewall'):
        if baseline['checks'][key]['exit']!=0:
            raise ValueError('baseline inspection failed: '+key)
    return baseline,record
