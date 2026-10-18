"""Validate explicit root observations; importing this module performs no actions.

sbxr-native-receipt-v1: run, candidate, candidate_bindings_sha256,
qualification_manifest_sha256, scenario_id, request_sha256, request_source_file,
kind, observed_at (UTC seconds), facts, evidence (nonempty source-file records).
Each source-file record contains source_file (absolute path), sha256 and size.
Karing timing receipts additionally name phase. No receipt is generated here.

Fresh operator preparation copies this canonical module alongside its native
capture/recording helpers before freezing inputs. Historical copies stay frozen.
"""
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import urllib.parse

NATIVE_SUBSCRIPTION_SOURCE = Path('/Users/Albert/Library/Group Containers/group.com.nebula.karing/karing_subscribe.json')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def timestamp(value):
    require(isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value),
            'An actual UTC timestamp in YYYY-MM-DDTHH:MM:SSZ form is required')
    return dt.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc)


def private_bytes(path):
    path = Path(path)
    require(path.is_absolute(), 'Evidence paths must be absolute')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                'Evidence must be an owned, private, one-link regular file: ' + str(path))
        raw = stream.read(64 * 1024 * 1024 + 1)
    require(len(raw) <= 64 * 1024 * 1024, 'Evidence exceeds byte bound')
    return raw


def unique(items):
    value = {}
    for key, item in items:
        require(key not in value, 'Duplicate receipt member: ' + key)
        value[key] = item
    return value


def source_file(record):
    require(isinstance(record, dict) and set(record) == {'source_file', 'sha256', 'size'},
            'An explicit source_file/sha256/size record is required')
    require(isinstance(record['source_file'], str) and type(record['size']) is int and
            record['size'] > 0 and isinstance(record['sha256'], str) and
            re.fullmatch('[0-9a-f]{64}', record['sha256']), 'Invalid source-file identity')
    raw = private_bytes(record['source_file'])
    require(len(raw) == record['size'] and hashlib.sha256(raw).hexdigest() == record['sha256'],
            'Root evidence bytes differ: ' + record['source_file'])
    return raw


def load(live, path, kind, scenario):
    bound = live.bindings.require_final()
    live.bindings.require_normal_actions()
    identity = bound['identity']
    require(type(identity.get('workflow_run_id')) is int and identity['workflow_run_id'] > 0 and
            type(identity.get('workflow_run_attempt')) is int and identity['workflow_run_attempt'] > 0,
            'An actual final workflow identity is required; pending identity refuses')
    raw = private_bytes(path)
    receipt = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(receipt, dict) and receipt.get('schema') == 'sbxr-native-receipt-v1',
            'An explicit fresh root receipt is required')
    require(receipt.get('run') == str(live.r) and receipt.get('candidate') == identity and
            receipt.get('candidate_bindings_sha256') ==
            live.bindings.file_sha256(live.r / 'candidate-bindings.json') and
            receipt.get('qualification_manifest_sha256') == bound['manifest_sha256'],
            'Root receipt is for another candidate, binding, manifest or run')
    require(receipt.get('kind') == kind and receipt.get('scenario_id') == scenario,
            'Root receipt is for another observation')
    request_raw = source_file(receipt.get('request_source_file'))
    require(hashlib.sha256(request_raw).hexdigest() == receipt.get('request_sha256'),
            'Root receipt request digest differs')
    request = json.loads(request_raw, object_pairs_hook=unique)
    require(request.get('scenario_id') == scenario and
            request.get('qualification_manifest_sha256') == bound['manifest_sha256'] and
            request.get('karing_response_limit_seconds') == 3600 and
            request.get('attended_finish_by') == live.CUTOFF == identity['cutoff'],
            'Root receipt request has different signed scenario/timing bindings')
    observed = timestamp(receipt.get('observed_at'))
    now = dt.datetime.now(dt.timezone.utc)
    require(timestamp(request['not_before']) <= observed <= now < timestamp(live.CUTOFF) and
            (now - observed).total_seconds() <= 300,
            'Root observation is future, stale, before the request or beyond attendance')
    require(isinstance(receipt.get('facts'), dict), 'Explicit observed facts are required')
    evidence = receipt.get('evidence')
    require(isinstance(evidence, list) and evidence, 'Actual captured root evidence is required')
    for record in evidence:
        source_file(record)
    return receipt


def current_request(live, receipt, scenario, label):
    live.request(scenario, label)
    require(hashlib.sha256((live.r / (label + '.private')).read_bytes()).hexdigest() ==
            receipt['request_sha256'], 'Root receipt is not for the current collector request')


def positive_latency(facts):
    value = facts.get('latency_ms')
    require(type(value) in (int, float) and math.isfinite(value) and value > 0,
            'An actually measured positive native latency is required')


def preserved(facts):
    settings = facts.get('settings')
    require(isinstance(settings, dict) and
            settings.get('baseline', {}).get('source_file') !=
            settings.get('current', {}).get('source_file') and
            source_file(settings.get('baseline')) == source_file(settings.get('current')),
            'Actual complete settings readback differs from its baseline')
    connection = facts.get('selected_connection')
    require(isinstance(connection, dict), 'Actual selected-connection facts are required')
    before, after = connection.get('baseline'), connection.get('current')
    require(isinstance(before, dict) and before == after and
            set(before) == {'configuration', 'node', 'connected', 'tun_enabled'} and
            all(isinstance(before[key], str) and before[key] for key in ('configuration', 'node')) and
            before['connected'] is True and type(before['tun_enabled']) is bool,
            'Original selected connection, connection state or TUN setting differs')


def readbacks(live, facts, url_name, content_name):
    actual = {}
    for field, expected in (('saved_url', url_name), ('saved_subscription_content', content_name)):
        record = facts.get(field)
        raw = source_file(record)
        path = Path(record['source_file'])
        require(path.parent == live.r and '.private' in path.name,
                'Secret readbacks must be direct private run files covered by cleanup')
        require(path != live.r / expected, 'Expected transport bytes cannot stand in for a native readback')
        expected_raw = private_bytes(live.r / expected)
        if field == 'saved_url':
            # Files may have one terminal newline; compare the entire actual URL.
            raw, expected_raw = raw.removesuffix(b'\n'), expected_raw.removesuffix(b'\n')
            require(re.fullmatch(rb'http://107\.175\.53\.219:8443/[^\s]+', raw),
                    'Saved URL readback is not the complete emitted subscription URL')
            require(raw == expected_raw, 'Actual saved URL readback differs')
        actual[field] = raw
        if field == 'saved_subscription_content':
            wire_raw = expected_raw
    profile = json.loads(actual['saved_subscription_content'], object_pairs_hook=unique)
    require(isinstance(profile, dict) and all(isinstance(profile.get(key), str) and profile[key]
            for key in ('groupid', 'remark', 'urlOrPath')), 'Actual native profile identity is missing')
    require(profile['urlOrPath'].encode() == actual['saved_url'], 'Actual native profile saved URL differs')
    proof = facts.get('native_subscription_source')
    require(isinstance(proof, dict) and set(proof) == {'source_app_path', 'sha256', 'size', 'mtime_ns'} and
            proof['source_app_path'] == str(NATIVE_SUBSCRIPTION_SOURCE), 'Actual native app source provenance is missing')
    with os.fdopen(os.open(NATIVE_SUBSCRIPTION_SOURCE, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1 and
                stat.S_IMODE(before.st_mode) in (0o600, 0o644), 'Native app store file is not protected')
        source = stream.read(64 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
    stable = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                           info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    require(len(source) <= 64 * 1024 * 1024 and
            stable(before) == stable(after) == stable(NATIVE_SUBSCRIPTION_SOURCE.lstat()),
            'Native app source changed during readback')
    require(type(proof['size']) is int and type(proof['mtime_ns']) is int and
            proof['size'] == len(source) and proof['mtime_ns'] == before.st_mtime_ns and
            proof['sha256'] == hashlib.sha256(source).hexdigest(), 'Native app source hash/size/mtime differs')
    store = json.loads(source, object_pairs_hook=unique)
    require(isinstance(store, dict) and isinstance(store.get('items'), list), 'Native app store items are missing')
    matching = [item for item in store['items'] if isinstance(item, dict) and
                (item.get('groupid'), item.get('remark')) == (profile['groupid'], profile['remark'])]
    require(len(matching) == 1 and matching[0] == profile, 'Readback is not the unique actual native profile entry')
    nodes = profile.get('servers')
    require(isinstance(nodes, list) and len(nodes) == 1 and isinstance(nodes[0], dict),
            'Exactly one actual native REALITY node is required')
    node = nodes[0]
    require(set(node) == {'groupid', 'attach', 'latency', 'outlet_ip', 'outlet_region', 'server', 'server_port',
                         'tag', 'type', 'uuid', 'flow', 'packet_encoding', 'tls'}, 'Native node fields differ')
    try:
        lines = wire_raw.decode().splitlines()
        require(len(lines) == 1, 'Exactly one expected wire node is required')
        uri = urllib.parse.urlsplit(lines[0])
        query = urllib.parse.parse_qs(uri.query, keep_blank_values=True, strict_parsing=True)
        port = uri.port
    except (UnicodeError, ValueError):
        raise ValueError('Expected wire node parsing failed') from None
    require(uri.scheme == 'vless' and uri.username and uri.hostname and uri.password is None and uri.path == '' and
            set(query) == {'encryption', 'flow', 'security', 'sni', 'fp', 'pbk', 'sid', 'type'} and
            all(len(value) == 1 for value in query.values()) and query['encryption'] == ['none'] and
            query['security'] == ['reality'] and query['type'] == ['tcp'], 'Expected one-node VLESS/REALITY wire schema differs')
    tls = node.get('tls')
    require(isinstance(tls, dict) and set(tls) == {'enabled', 'server_name', 'utls', 'reality'} and
            isinstance(tls['utls'], dict) and set(tls['utls']) == {'enabled', 'fingerprint'} and
            isinstance(tls['reality'], dict) and set(tls['reality']) == {'enabled', 'public_key', 'short_id'},
            'Native TLS/REALITY fields differ')
    # The URI omits packet encoding: sing-box defaults to XUDP; explicit "" disables it.
    # https://github.com/SagerNet/sing-box/blob/v1.14.3/protocol/vless/outbound.go#L77-L85
    comparisons = {'protocol': (node['type'], 'vless'), 'uuid': (node['uuid'], uri.username),
                   'address': (node['server'], uri.hostname), 'port': (node['server_port'], port),
                   'flow': (node['flow'], query['flow'][0]), 'tls.enabled': (tls['enabled'], True),
                   'tls.server_name': (tls['server_name'], query['sni'][0]),
                   'utls.enabled': (tls['utls']['enabled'], True),
                   'utls.fingerprint': (tls['utls']['fingerprint'], query['fp'][0]),
                   'reality.enabled': (tls['reality']['enabled'], True),
                   'reality.public_key': (tls['reality']['public_key'], query['pbk'][0]),
                   'reality.short_id': (tls['reality']['short_id'], query['sid'][0]),
                   'packet_encoding': (node['packet_encoding'], 'xudp'), 'attach': (node['attach'], '')}
    for field, (observed, wanted) in comparisons.items():
        require(type(observed) is type(wanted) and observed == wanted, 'Native REALITY node differs: ' + field)


def true_facts(facts, names):
    for name in names:
        require(facts.get(name) is True, 'Actual root observation is missing: ' + name)
