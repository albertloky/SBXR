#!/usr/bin/env python3
"""Derive the window observer's proxy-binary pin from a reviewed local DEB.

Other expectation fields are preserved; this neither refreshes host facts nor
authenticates the supplied package receipt or authorizes an operator action.
"""
import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate expectation member: ' + key)
        result[key] = value
    return result


def prepare(expected, deb):
    receipt = expected['proxy_package']
    if (receipt['name'], receipt['version'], receipt['architecture']) != ('sing-box', '1.13.19', 'amd64'):
        raise ValueError('Unsupported proxy package')
    raw = Path(deb).read_bytes()
    if len(raw) != receipt['size'] or hashlib.sha256(raw).hexdigest() != receipt['sha256']:
        raise ValueError('Proxy DEB size or SHA-256 differs from reviewed receipt')
    if not raw.startswith(b'!<arch>\n'):
        raise ValueError('Invalid DEB archive')
    members = {}
    offset = 8
    while offset < len(raw):
        header = raw[offset:offset + 60]
        if len(header) != 60 or header[58:] != b'`\n':
            raise ValueError('Invalid DEB member header')
        name = header[:16].decode('ascii').strip().rstrip('/')
        size = int(header[48:58])
        offset += 60
        if size < 0 or offset + size > len(raw) or name in members:
            raise ValueError('Invalid or duplicate DEB member')
        members[name] = raw[offset:offset + size]
        offset += size + size % 2
    if offset != len(raw) or members.get('debian-binary') != b'2.0\n' or 'data.tar.gz' not in members:
        raise ValueError('Expected Debian 2.0 gzip payload')
    binary = None
    with tarfile.open(fileobj=io.BytesIO(members['data.tar.gz']), mode='r:gz') as archive:
        for member in archive:
            if member.name != './usr/bin/sing-box':
                continue
            if binary is not None or not member.isfile() or not 0 < member.size <= 256 << 20:
                raise ValueError('Invalid or duplicate proxy executable')
            stream = archive.extractfile(member)
            with stream:
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1 << 20), b''):
                    digest.update(chunk)
            binary = digest.hexdigest()
    if binary is None:
        raise ValueError('Proxy executable missing')
    result = copy.deepcopy(expected)
    # This field names /usr/bin/sing-box, never the candidate SBXR executable.
    result['installed_binary_sha256'] = binary
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--proxy-deb', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        expected = json.loads(args.input.read_bytes(), object_pairs_hook=unique)
        result = prepare(expected, args.proxy_deb)
        with args.output.open('x') as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write('\n')
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        parser.error(str(error))
    print(json.dumps({'proxy_binary_path': '/usr/bin/sing-box',
                      'proxy_binary_sha256': result['installed_binary_sha256'],
                      'proxy_deb_sha256': result['proxy_package']['sha256'],
                      'fresh_host_observations_produced': False}))


if __name__ == '__main__':
    main()
