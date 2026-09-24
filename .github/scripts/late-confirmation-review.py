#!/usr/bin/env python3
"""Reproduce the target-bound r24 applicability review from committed Git inputs.

No network, runtime observation, or human signature is produced here. The
release-policy reader changes are intentional; proxy/menu runtime and build
inputs must still match the previously tested source exactly.
"""
import hashlib
import json
import re
import subprocess
import sys

BASE = '1878d6fb57dd3f28a4c90ce9b3b5dc009b756f52'
TREE = 'c70633b317322ff495abc4b700137022fa99a2f44c8b166896db4c0ab4a05d04'
SUPPLEMENT = 'f20a3644592f5af4e1b2927358774c8f9d8e7c4a127ceed7f7a17724157eca71'
POLICY_READERS = {
    'internal/softwarelifecycle/late_confirmation.go',
    'internal/softwarelifecycle/adapter/github/github.go',
    'internal/softwarelifecycle/adapter/github/release_support.go',
}

def git(*args):
    return subprocess.check_output(['git', *args])

def review(commit):
    if not re.fullmatch('[0-9a-f]{40}', commit) or commit == BASE:
        raise ValueError('exact fresh source commit required')
    git('merge-base', '--is-ancestor', BASE, commit)
    paths = ['cmd/sbxr', 'internal/proxyinstallation', 'go.mod', 'go.sum']
    if hashlib.sha256(git('ls-tree', '-r', commit, '--', *paths)).hexdigest() != TREE:
        raise ValueError('proxy/runtime/build inputs changed: prior live evidence not automatically applicable')
    # All installed production code outside the proxy tree is preserved except
    # the explicitly reviewed release-record recognition files.
    changed = git('diff', '--name-only', BASE, commit, '--', 'internal', 'cmd/sbxr').decode().splitlines()
    if any(p not in POLICY_READERS and not p.endswith('_test.go') for p in changed):
        raise ValueError('unreviewed production source change')
    fixture = git('show', f'{commit}:cmd/sbxr-release/testdata/r24-late-confirmation.json')
    if hashlib.sha256(fixture).hexdigest() != SUPPLEMENT:
        raise ValueError('approved evidence changed')
    diff = git('diff', '--binary', '--no-ext-diff', BASE, commit)
    return dict(base_commit=BASE, policy_diff_sha256=hashlib.sha256(diff).hexdigest(),
                reviewer='Codex source comparison; Owner-approved exception',
                runtime_tree_sha256=TREE, supplement_sha256=SUPPLEMENT,
                target_commit=commit, target_sequence=159, target_tag='v3.1.81')

if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('usage: late-confirmation-review.py FULL_COMMIT')
        print(json.dumps(review(sys.argv[1]), sort_keys=True, separators=(',', ':')), end='')
    except (ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f'Late-confirmation applicability refused: {error}')
