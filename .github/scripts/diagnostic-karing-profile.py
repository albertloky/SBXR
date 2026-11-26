"""Read-only file-import observations. Keep the pre-Save and receiver digests independently.

The UI flags are fresh operator observations. Include every inventoried additional
native side file in each call. Only the operator performs and records a UI action.
"""
import argparse
from contextlib import contextmanager
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from uuid import UUID

spec = importlib.util.spec_from_file_location('native', Path(__file__).with_name('native-receipts.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
MAX_SOURCE = 64 * 1024 * 1024
MAX_CACHE_DB = 128 * 1024 * 1024
CACHE_CHUNK = 1024 * 1024
SHA256 = re.compile('[a-f0-9]{64}')
HANDOFF = re.compile(r'karing-(run-[1-9][0-9]*-attempt-[1-9][0-9]*)')


def require(value):
    if not value:
        raise ValueError('Readback refused')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def private_dir(path):
    mode = path.lstat()
    return stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.getuid() and stat.S_IMODE(mode.st_mode) == 0o700


@contextmanager
def native_entry(root, path):
    # Resolve each directory relative to its open parent, including for absent files.
    parts = path.relative_to(root).parts
    require(parts and '..' not in parts)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(path.anchor, flags)
    try:
        try:
            for part in path.parts[1:-1]:
                child = os.open(part, flags, dir_fd=parent)
                os.close(parent)
                parent = child
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        yield parent, info
    finally:
        os.close(parent)


@contextmanager
def checked_file(path, limit, *, parent=None):
    if parent is None:
        require(path.is_absolute() and path.resolve(strict=True) == path)
    name = path if parent is None else path.name
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        modes = (0o600, 0o644) if parent is not None and any(private_dir(p) for p in path.parents) else (0o600,)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) in modes and 0 < info.st_size <= limit)
        yield stream, info
        require(identity(info) == identity(os.fstat(fd)))
    require(identity(info) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))


def read(path, limit, *, parent=None):
    with checked_file(path, limit, parent=parent) as (stream, info):
        raw = stream.read(info.st_size + 1)
        require(len(raw) == info.st_size)
    return raw, info


def cache_digest(path, parent, needles):
    hasher = hashlib.sha256()
    overlap = max(map(len, needles)) - 1
    tail = b''
    with checked_file(path, MAX_CACHE_DB, parent=parent) as (stream, info):
        remaining = info.st_size
        while remaining:
            chunk = stream.read(min(remaining, CACHE_CHUNK))
            require(chunk)
            remaining -= len(chunk)
            hasher.update(chunk)
            window = tail + chunk
            require(all(needle not in window for needle in needles))
            tail = window[-overlap:] if overlap else b''
        require(not stream.read(1))
    return hasher.hexdigest(), info


def wire(args, attempt, label):
    directory = args.handoff_dir
    require(private_dir(directory) and private_dir(directory.parent))
    receipt_raw, _ = read(directory / 'receipt.json', 4096)
    require(SHA256.fullmatch(args.receipt_sha256) and digest(receipt_raw) == args.receipt_sha256)
    receipt = native._decode_settings(receipt_raw)
    raw, info = read(directory / 'node.txt', 4096)
    require(receipt['request_sha256'] == args.request_sha256 and receipt['attempt_id'] == attempt
            and receipt['label'] == label and SHA256.fullmatch(receipt['manifest_sha256'])
            and type(receipt['device']) is int and receipt['device'] == info.st_dev
            and type(receipt['inode']) is int and receipt['inode'] == info.st_ino
            and receipt['sha256'] == digest(raw)
            and raw.count(b'\n') == 1 and raw.endswith(b'#' + label.encode('ascii') + b'\n'))
    require(type(receipt['client_until_unix']) is int)
    return raw, receipt['client_until_unix']


def original_snapshot(profiles, bundle, baseline):
    if bundle is None:
        # A digest alone cannot establish the ordered before/after updateTime interval.
        # Canonical v3 permits two positive ASCII latency strings for a non-custom node.
        for group in profiles:
            if group['groupid'] != 'custom':
                for node in group['servers']:
                    latency = node.get('latency')
                    if isinstance(latency, str) and re.fullmatch('0*[1-9][0-9]*', latency):
                        node['latency'] = '1'
        return profiles, None

    # Existing preflight bundle, independently retained prior to any client action.
    require(private_dir(bundle.parent))
    raw, _ = read(bundle, MAX_SOURCE)
    inputs = native._decode_settings(raw)
    record = inputs['original_store_baseline']
    require(Path(record['source_file']).parent == bundle.parent)
    original_raw, _ = read(Path(record['source_file']), MAX_SOURCE)
    require(digest(original_raw) == record['sha256'] and len(original_raw) == record['size'])
    before = native._decode_settings(original_raw)['items']
    if baseline:
        require(native._canonical(before) == native._canonical(profiles))
    zone = inputs['native_tzif']
    require(Path(zone['source_file']).parent == bundle.parent and native.native_timezone_binding() == inputs['native_timezone'])
    zone_raw, _ = read(Path(zone['source_file']), 2 * 1024 * 1024)
    require(digest(zone_raw) == zone['sha256'] and len(zone_raw) == zone['size'])
    audit = native.original_profiles_audit_v3(
        before, profiles, timezone=inputs['native_timezone'], tzif_record=zone,
        window_start=inputs['original_store_observed_at'], window_end=dt.datetime.now(dt.timezone.utc).isoformat())
    require(audit['passed'])
    return before, digest(raw)


def split_originals(store, label, source, baseline):
    originals = []
    candidate = None
    ids = set()
    require(isinstance(store['items'], list))
    for group in store['items']:
        gid = group['groupid']
        require(isinstance(gid, str) and gid and gid not in ids and isinstance(group['servers'], list))
        ids.add(gid)
        if group.get('remark') == label or group.get('urlOrPath') == source:
            require(not baseline and candidate is None and group.get('remark') == label
                    and group.get('urlOrPath') == source and str(UUID(gid)) == gid and UUID(gid).version == 4)
            candidate = group
        else:
            originals.append(group)
    require('custom' in ids)
    return originals, candidate


def decide(args, native_dir):
    require(native_dir.is_absolute() and native_dir.resolve(strict=True) == native_dir)
    directory = args.handoff_dir
    match = HANDOFF.fullmatch(directory.name)
    require(match and directory.is_absolute() and directory.resolve() == directory
            and private_dir(directory.parent) and SHA256.fullmatch(args.request_sha256))
    label = 'SBXR-' + args.request_sha256[:16]
    source = str(directory / 'node.txt')
    require(bool(args.expected_state) == (args.phase == 'before-remove'))
    baseline = args.phase == 'baseline'
    if baseline:
        require(not args.baseline_sha256 and not args.receipt_sha256 and not args.group_id)
    else:
        require(args.baseline_sha256 and SHA256.fullmatch(args.baseline_sha256) and args.receipt_sha256)
        require(bool(args.group_id) == (args.phase in ('before-test', 'before-remove', 'after-remove')))
        if args.group_id:
            require(str(UUID(args.group_id)) == args.group_id and UUID(args.group_id).version == 4)
        expected_wire, client_until = wire(args, match.group(1), label)

    store_path = native_dir / native.NATIVE_SUBSCRIPTION_SOURCE.name
    use_path = native_dir / 'karing_subscribe_use.json'
    settings_path = native_dir / native.NATIVE_SETTINGS_SOURCE.name
    optional_files = sorted({native_dir / 'karing_routing_group.json', *args.side_file})
    paths = [store_path, use_path, settings_path, *optional_files]
    require(len(paths) <= 35 and len(set(paths)) == len(paths))
    reads = {}
    side_hashes = {}
    for path in paths:
        is_cache_db = path == native_dir / 'cache.db'
        with native_entry(native_dir, path) as (parent, entry):
            if entry is None:
                require(path in optional_files)
                reads[path] = None
                side_hashes[str(path)] = None
                continue
            reads[path] = identity(entry)
            if is_cache_db:
                side_hashes[str(path)], info = cache_digest(path, parent, needles)
            else:
                raw, info = read(path, MAX_SOURCE, parent=parent)
            require(identity(info) == reads[path])
        if is_cache_db:
            continue
        if path == store_path:
            store = native._decode_settings(raw)
            originals, candidate = split_originals(store, label, source, baseline)
            # Group removal also touches use, favorites, recent entries and
            # diversion references. Check for a pre-existing orphan reference.
            markers = [source, label]
            gid = candidate['groupid'] if candidate else args.group_id
            if gid:
                markers.append(gid)
            needles = [native._canonical(marker)[1:-1] for marker in markers]
            preserved = native._canonical(dict(store, items=originals))
            require(all(needle not in preserved for needle in needles))
        else:
            if path.suffix == '.json':
                value = native._decode_settings(raw)
                if path == use_path:
                    selected = value['select_default']
                    require(isinstance(selected, str) and selected and selected != label)
                elif path == settings_path:
                    native._permitted_values(value)  # Validate types before masking these three leaves.
                    for parent, key in native._PERMITTED_PATHS:
                        value[parent][key] = None
                raw = native._canonical(value)
            require(all(needle not in raw for needle in needles))
            side_hashes[str(path)] = digest(raw)

    originals, bundle_hash = original_snapshot(originals, args.native_inputs, baseline)
    snapshot = dict(store=dict(store, items=originals), side_files=side_hashes, connected=args.connected,
                    tun=args.tun, native_dir=str(native_dir), source=source, request=args.request_sha256,
                    native_inputs_sha256=bundle_hash)
    frozen = digest(native._canonical(snapshot))

    # Karing can rewrite several files on Save/Remove. Reject a mixed observation.
    for path, previous in reads.items():
        with native_entry(native_dir, path) as (_, entry):
            require((identity(entry) if entry is not None else None) == previous)
    if baseline:
        return {'baseline_sha256': frozen}
    require(frozen == args.baseline_sha256)
    if args.phase == 'before-save':
        require(candidate is None and time.time() + 30 < client_until)
        return {'state': 'save-once'}
    if candidate is None:
        require(args.phase != 'before-test')
        return {'state': 'absent'}
    gid = candidate['groupid']
    require(not args.group_id or args.group_id == gid)
    require(all(candidate.get(key) is False for key in ('keepDiversionRules', 'testLatencyAutoRemove',
                'testLatencyAfterProfileUpdate', 'enableDiversionRules', 'reloadAfterProfileUpdate', 'preferOutboundDns')))
    require(candidate.get('urltests') == [] and candidate.get('outboundDns') == [])
    state = 'empty'
    if candidate['servers']:
        native.subscription_nodes(candidate, expected_wire)
        node, = candidate['servers']
        require(node['groupid'] == gid and node['tag'] == label)
        state = 'complete'
    if args.phase == 'after-remove':
        return {'state': 'residue', 'group_id': gid}
    if args.phase == 'before-test':
        require(state == 'complete' and candidate.get('enable') is True and time.time() + 30 < client_until)
        state = 'test-once'
    if args.phase == 'before-remove':
        require(state == args.expected_state)
        state = 'remove-once'
    return {'state': state, 'group_id': gid}


def main(argv=None, *, native_dir=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('baseline', 'before-save', 'inspect', 'before-test', 'before-remove', 'after-remove'))
    parser.add_argument('--handoff-dir', type=Path, required=True)
    parser.add_argument('--request-sha256', required=True)
    parser.add_argument('--baseline-sha256')
    parser.add_argument('--receipt-sha256')
    parser.add_argument('--group-id')
    parser.add_argument('--expected-state', choices=('complete', 'empty'), help='Prior inspect outcome for before-remove')
    parser.add_argument('--connected', required=True, choices=('yes', 'no'))
    parser.add_argument('--tun', required=True, choices=('yes', 'no'))
    parser.add_argument('--native-inputs', type=Path, help='Existing frozen profile/TZif input bundle')
    parser.add_argument('--side-file', type=Path, action='append', default=[])
    args = parser.parse_args(argv)
    try:
        result = decide(args, native_dir or native.NATIVE_SUBSCRIPTION_SOURCE.parent)
    except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        print('Karing readback refused. Stop client actions and record unresolved state.', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 1 if result.get('state') == 'residue' else 0


if __name__ == '__main__':
    sys.exit(main())
