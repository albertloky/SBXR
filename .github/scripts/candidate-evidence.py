#!/usr/bin/env python3
"""Stage only bounded, secret-screened qualification JSON for CI retention."""
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_FILE = 16 << 20
MAX_TOTAL = 64 << 20
SECRET = re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|Authorization: Bearer |[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|(?:vless|vmess)://|https?://[^ /\"\s]+:8443/|/s/[A-Za-z0-9_-]{20,}", re.I)
STAGES = {'v3-scenario-failure', 'v3-scenario-result', 'candidate-failure-finalization', 'candidate-failure-verification'}

def unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate evidence member')
        result[key] = value
    return result

def stage(root, destination):
    root, destination = Path(root), Path(destination)
    paths = [root / 'handoff/failure-evidence' / name for name in ('failure.json', 'failure-decision.json')]
    paths += [root / 'handoff/v3-scenarios' / (str(index) + suffix)
              for index in range(1, 65) for suffix in ('-facts.json', '-decision.json')]
    paths += [root / directory / ('candidate-failure-' + kind + '.json')
              for directory in ('', 'boundary', 'boundary/unsigned')
              for kind in ('facts', 'decision', 'verification-facts', 'verification-decision')]
    retained, total, rejected = [], 0, 0
    for path in paths:
        try:
            for parent in (path, *path.parents):
                if parent == root:
                    break
                if parent.is_symlink():
                    raise ValueError('linked evidence refused')
            if not path.exists():
                continue
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE:
                    raise ValueError('unsafe evidence file')
                raw = stream.read(MAX_FILE + 1)
                after = os.fstat(stream.fileno())
            if len(raw) > MAX_FILE or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('unstable evidence file')
            value = json.loads(raw, object_pairs_hook=unique)
            if not isinstance(value, dict):
                raise ValueError('unexpected evidence document type')
            schema, evidence_stage = value.get('schema'), value.get('stage')
            if (not isinstance(schema, str) or not isinstance(evidence_stage, str)
                    or schema not in {'sbxr-release-qualification-facts-v1', 'sbxr-release-qualification-decision-v1'}
                    or evidence_stage not in STAGES):
                raise ValueError('unexpected evidence schema or stage')
            # Scan decoded strings too: JSON escaping must not hide credential URLs.
            if SECRET.search(raw.decode('utf-8')) or SECRET.search(json.dumps(value, ensure_ascii=False)):
                raise ValueError('secret-shaped evidence refused')
            if total + len(raw) > MAX_TOTAL:
                raise ValueError('evidence total bound')
        except (OSError, ValueError, RecursionError):
            # Failed producers can leave empty/partial output. Never publish it,
            # but preserve independent safe records without exposing their data.
            rejected += 1
            continue
        total += len(raw)
        retained.append((path.relative_to(root), raw))
    if rejected:
        print(f'Candidate evidence: omitted {rejected} unsafe or incomplete records.', file=sys.stderr)
    destination.mkdir(mode=0o700)
    for relative, raw in retained:
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(0o600)
    return len(retained)

if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('destination required')
        stage(Path.cwd(), sys.argv[1])
    except (OSError, ValueError):
        print('Candidate evidence retention refused.', file=sys.stderr)
        raise SystemExit(1)
