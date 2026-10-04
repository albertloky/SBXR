#!/usr/bin/env python3
"""Reproduce the one-target live89 evidence correction from exact Git inputs.

No live observations, signatures, or historical edits are made. Fresh release
identity bytes may differ; every product input and unstamped executable payload
must match the archived tested build.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile

BASE = '1723e06aca91465dc687b0ac72f06a2e48f8974d'
TREE = 'd1b3eddefcee885e636c6467b9c8ddbe9958592c0187a0b2fdd218013a28dc84'
EVIDENCE = '73e8c3930c796c899e039c5d31bf9783073b0b375496b9b2406cda6d7b4d3154'
PRODUCT_PATHS = ['cmd/sbxr', 'internal', 'go.mod', 'go.sum', 'cmd/sbxr-release/bootstrap.go']
PAYLOADS = {
    'amd64': '2a39346a228641fd7776f453a9b8f85a897a1ce4b58bc4e678456e7429cf9e55',
    'arm64': '8d43e1e7fbde0db0b1c099f80b3a9e397e2d7a05aec35eb9318538172c35c2c1',
}
MAGIC = b'SBXR-IDENTITY-V1'
LIMIT = 256 << 20


def git(*args):
    return subprocess.check_output(['git', *args])


def fresh_commit(commit):
    if not re.fullmatch('[0-9a-f]{40}', commit) or commit == BASE:
        raise ValueError('exact fresh source commit required')


def review(commit):
    fresh_commit(commit)
    git('merge-base', '--is-ancestor', BASE, commit)
    if hashlib.sha256(git('ls-tree', '-r', commit, '--', *PRODUCT_PATHS)).hexdigest() != TREE:
        raise ValueError('product/runtime/build inputs changed: archived evidence does not apply')
    fixture = git('show', f'{commit}:cmd/sbxr-release/testdata/live89-correction.json')
    if hashlib.sha256(fixture).hexdigest() != EVIDENCE:
        raise ValueError('accepted archived evidence changed')
    diff = git('diff', '--binary', '--no-ext-diff', BASE, commit)
    return dict(base_commit=BASE, policy_diff_sha256=hashlib.sha256(diff).hexdigest(),
                reviewer='Codex source comparison; Owner-approved live89 recording correction',
                runtime_tree_sha256=TREE, evidence_sha256=EVIDENCE,
                target_commit=commit, target_sequence=168, target_tag='v3.1.90')


def payload(path, commit):
    fresh_commit(commit)
    path = Path(path)
    architecture = next((arch for arch in PAYLOADS if path.name == f'sbxr-linux-{arch}.tar.gz'), None)
    if architecture is None or path.stat().st_size > LIMIT:
        raise ValueError('exact bounded application archive required')
    with tarfile.open(path, 'r:gz') as archive:
        member = archive.next()
        if member is None or not member.isreg() or member.name != 'sbxr' or member.mode != 0o755 or not 0 < member.size <= LIMIT:
            raise ValueError('one executable archive required')
        executable = archive.extractfile(member).read(LIMIT + 1)
        if len(executable) != member.size or archive.next() is not None:
            raise ValueError('one bounded executable archive required')
    tail = len(MAGIC) + 8 + 32
    if len(executable) <= tail or not executable.endswith(MAGIC):
        raise ValueError('release identity trailer missing')
    length_offset = len(executable) - len(MAGIC) - 8
    length = struct.unpack('<Q', executable[length_offset:length_offset + 8])[0]
    if not 0 < length <= 4096 or length + tail >= len(executable):
        raise ValueError('release identity trailer length refused')
    document_offset = len(executable) - tail - length
    document = executable[document_offset:document_offset + length]
    if hashlib.sha256(document).digest() != executable[document_offset + length:length_offset]:
        raise ValueError('release identity digest refused')
    actual = hashlib.sha256(executable[:document_offset]).hexdigest()
    if actual != PAYLOADS[architecture]:
        raise ValueError('tested executable payload changed')
    # This is the exact Go embeddedIdentity field order and encoding. It also
    # rejects unknown/duplicate fields and an identity for another release.
    identity = dict(schema=1, repository='albertloky/SBXR', tag='v3.1.90',
                    commit=commit, sequence=168, architecture=architecture,
                    payload_sha256=actual)
    if document != json.dumps(identity, separators=(',', ':')).encode():
        raise ValueError('exact fresh release identity refused')
    return identity


if __name__ == '__main__':
    try:
        if len(sys.argv) == 2:
            result = review(sys.argv[1])
        elif len(sys.argv) == 3 and sys.argv[1] == 'payload':
            result = payload(sys.argv[2], git('rev-parse', 'HEAD').decode().strip())
        else:
            raise ValueError('usage: live89-correction-review.py FULL_COMMIT | payload ARCHIVE')
        print(json.dumps(result, sort_keys=True, separators=(',', ':')), end='')
    except (ValueError, OSError, tarfile.TarError, subprocess.CalledProcessError) as error:
        sys.exit(f'Live89 correction applicability refused: {error}')
