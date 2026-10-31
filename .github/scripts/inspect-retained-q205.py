#!/usr/bin/env python3
"""One fixed retained-draft inventory. GitHub GETs only; never executes assets."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPOSITORY = 'albertloky/SBXR'
EXPECTED = json.loads((HERE / 'retained-q205.json').read_text())
spec = importlib.util.spec_from_file_location('github_observation', HERE / 'observe-github-resource.py')
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def inspect(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    result = {'status': 'failed', 'stage': 'metadata', 'source': os.environ.get('GITHUB_SHA'),
              'run_id': os.environ.get('GITHUB_RUN_ID'), 'reads': [], 'assets': []}
    try:
        release = observer.observe(f'repos/{REPOSITORY}/releases/{EXPECTED["release_id"]}')
        if release['state'] != 'present':
            raise ValueError('draft unavailable')
        value = release['value']
        actual = {k: value.get(k) for k in ('id', 'tag_name', 'target_commitish', 'draft', 'prerelease', 'body')}
        wanted = dict(id=EXPECTED['release_id'], tag_name=EXPECTED['tag'], target_commitish=EXPECTED['source'],
                      draft=True, prerelease=False, body='Qualification pending.')
        if actual != wanted or value.get('immutable', False) is not False:
            raise ValueError('draft identity changed')
        assets = [{k: a.get(k) for k in ('id', 'name', 'size', 'digest')} for a in value['assets']]
        if sorted(assets, key=lambda a: a['name']) != sorted(EXPECTED['assets'], key=lambda a: a['name']):
            raise ValueError('asset identity changed')
        result['metadata'] = actual
        result['reads'].append('draft metadata matched')
        result['stage'] = 'refs'
        for tag in (EXPECTED['tag'], 'release-burned/' + EXPECTED['tag']):
            observation = observer.observe(f'repos/{REPOSITORY}/git/ref/tags/{tag}')
            if observation != {'state': 'absent', 'value': None}:
                raise ValueError('existing or unavailable ref')
        result['reads'].append('release and burn refs explicitly absent')
        result['stage'] = 'assets'
        for asset in EXPECTED['assets']:
            path = directory / asset['name']
            with path.open('xb') as output:
                command = ['gh', 'api', f'repos/{REPOSITORY}/releases/assets/{asset["id"]}',
                           '--method', 'GET', '-H', 'Accept: application/octet-stream']
                completed = subprocess.run(command, stdout=output, stderr=subprocess.PIPE, timeout=60,
                                           env={**os.environ, 'GH_DEBUG': ''})
            if completed.returncode != 0:
                raise ValueError('asset GET failed; no retry')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if path.stat().st_size != asset['size'] or 'sha256:' + digest != asset['digest']:
                raise ValueError('asset bytes changed')
            result['assets'].append(asset)
        index = json.loads((directory / 'release-index.json').read_text())
        if (index['repository'], index['tag'], index['sequence'], index['commit']) != (
                REPOSITORY, EXPECTED['tag'], EXPECTED['sequence'], EXPECTED['source']):
            raise ValueError('index identity changed')
        result['status'] = 'verified'
        result['stage'] = 'complete'
        return result
    finally:
        (directory / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    try:
        if len(sys.argv) != 1:
            raise ValueError('no parameters accepted')
        inspect('q205-inventory')
        print('Fixed q205 inventory verified; no release mutations requested.')
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('Fixed q205 inventory failed; stopped without retry.', file=sys.stderr)
        sys.exit(1)
