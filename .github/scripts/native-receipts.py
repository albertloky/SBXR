"""Validate explicit root observations; importing this module performs no actions.

sbxr-native-receipt-v1: run, candidate, candidate_bindings_sha256,
qualification_manifest_sha256, scenario_id, request_sha256, request_source_file,
kind, observed_at (UTC seconds), facts, evidence (nonempty source-file records).
Each source-file record contains source_file (absolute path), sha256 and size.
Karing timing receipts additionally name phase. No receipt is generated here.

Fresh operator preparation copies this canonical module alongside its native
capture/recording helpers before freezing inputs. Historical copies stay frozen.
Settings v2 is an explicit future API with a trusted pre-dispatch binding;
the existing preserved(facts) API keeps its byte-strict v1 interpretation.
"""
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import plistlib
import re
import stat
import urllib.parse

NATIVE_SUBSCRIPTION_SOURCE = Path('/Users/Albert/Library/Group Containers/group.com.nebula.karing/karing_subscribe.json')
NATIVE_SETTINGS_SOURCE = NATIVE_SUBSCRIPTION_SOURCE.with_name('karing_setting.json')
NATIVE_APP_INFO = Path('/Applications/karing.app/Contents/Info.plist')
NATIVE_APP_EXECUTABLE = Path('/Applications/karing.app/Contents/MacOS/karing')
SETTINGS_POLICY = 'sbxr-karing-settings-preservation-v2'
_PERMITTED_PATHS = (('window', 'x'), ('window', 'y'), ('dns', 'client_subnet_latest_update'))


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
    preserved_connection(facts)


def preserved_connection(facts):
    connection = facts.get('selected_connection')
    require(isinstance(connection, dict), 'Actual selected-connection facts are required')
    before, after = connection.get('baseline'), connection.get('current')
    require(isinstance(before, dict) and before == after and
            set(before) == {'configuration', 'node', 'connected', 'tun_enabled'} and
            all(isinstance(before[key], str) and before[key] for key in ('configuration', 'node')) and
            before['connected'] is True and type(before['tun_enabled']) is bool,
            'Original selected connection, connection state or TUN setting differs')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def _decode_settings(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: require(False, 'Nonfinite JSON number'))


def _native_bytes(path, app=False):
    """A stable actual file read; never follow a replacement final symlink."""
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_uid in ((0, os.getuid()) if app else (os.getuid(),)) and
                stat.S_IMODE(before.st_mode) in ((0o644, 0o755) if app else (0o600, 0o644)),
                'Native source must be an owned protected one-link file')
        limit = (512 if app else 64) * 1024 * 1024
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    identity = lambda info: tuple(getattr(info, key) for key in keys)
    require(0 < len(raw) <= limit and identity(before) == identity(after) == identity(path.lstat()),
            'Native source changed during readback')
    return raw, dict(source_app_path=str(path), sha256=hashlib.sha256(raw).hexdigest(),
                     **{key.removeprefix('st_'): getattr(before, key) for key in keys})


def settings_binding():
    """Freeze this returned contract in reviewed candidate inputs before dispatch."""
    info_raw, _ = _native_bytes(NATIVE_APP_INFO, app=True)
    executable, _ = _native_bytes(NATIVE_APP_EXECUTABLE, app=True)
    info = plistlib.loads(info_raw)
    require(isinstance(info, dict) and info.get('CFBundleIdentifier') == 'com.nebula.karing' and
            info.get('CFBundleExecutable') == 'karing' and
            info.get('CFBundleShortVersionString') == '1.2.25' and
            info.get('CFBundleVersion') == '2802', 'Unsupported Karing identity for settings v2')
    return {'schema': 'sbxr-karing-settings-binding-v2', 'policy': SETTINGS_POLICY,
            'app': {'version': '1.2.25', 'build': '2802',
                    'executable_sha256': hashlib.sha256(executable).hexdigest(),
                    'info_plist_sha256': hashlib.sha256(info_raw).hexdigest()},
            'helper_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def _normalized(value):
    if isinstance(value, str):
        raw = value.encode()
        return {'type': 'string', 'utf8_length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    if isinstance(value, dict):
        return {'type': 'object', 'fields': {key: _normalized(item) for key, item in sorted(value.items())}}
    if isinstance(value, list):
        return {'type': 'array', 'items': [_normalized(item) for item in value]}
    if value is None:
        return {'type': 'null'}
    if type(value) is bool:
        return {'type': 'boolean', 'value': value}
    require(type(value) in (int, float) and math.isfinite(value), 'Invalid settings number/type')
    return {'type': 'number', 'value': value}


def _validate_normalized(value):
    require(isinstance(value, dict), 'Malformed normalized settings')
    kind = value.get('type')
    if kind == 'object':
        require(set(value) == {'type', 'fields'} and isinstance(value['fields'], dict) and
                all(isinstance(key, str) for key in value['fields']), 'Malformed settings object')
        for item in value['fields'].values():
            _validate_normalized(item)
    elif kind == 'array':
        require(set(value) == {'type', 'items'} and isinstance(value['items'], list), 'Malformed settings array')
        for item in value['items']:
            _validate_normalized(item)
    elif kind == 'string':
        require(set(value) == {'type', 'utf8_length', 'sha256'} and
                type(value['utf8_length']) is int and value['utf8_length'] >= 0 and
                isinstance(value['sha256'], str) and re.fullmatch('[0-9a-f]{64}', value['sha256']),
                'Malformed settings string')
    elif kind == 'null':
        require(set(value) == {'type'}, 'Malformed settings null')
    else:
        require(set(value) == {'type', 'value'} and
                ((kind == 'boolean' and type(value['value']) is bool) or
                 (kind == 'number' and type(value['value']) in (int, float) and
                  math.isfinite(value['value']))), 'Malformed settings primitive')


def _permitted_values(settings):
    try:
        values = {'/' + '/'.join(path): settings[path[0]][path[1]] for path in _PERMITTED_PATHS}
    except (KeyError, TypeError):
        raise ValueError('Required settings paths are missing') from None
    require(all(type(values['/window/' + key]) is int for key in ('x', 'y')),
            'Window position must retain its integer type')
    value = values['/dns/client_subnet_latest_update']
    require(isinstance(value, str), 'DNS refresh timestamp must be a string')
    # Karing initializes this field to "" and writes DateTime.now().toString().
    if value:
        require(re.fullmatch(r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.(?:\d{3}|\d{6})Z?', value),
                'Malformed DNS refresh timestamp')
        dt.datetime.strptime(value.removesuffix('Z'), '%Y-%m-%d %H:%M:%S.%f')
    return values


def settings_readback(binding):
    """Capture full v2 audit data from the actual app; no evidence is written."""
    require(_canonical(binding) == _canonical(settings_binding()), 'Settings binding differs from actual app/helper')
    raw, proof = _native_bytes(NATIVE_SETTINGS_SOURCE)
    settings = _decode_settings(raw)
    require(isinstance(settings, dict), 'Native settings must be an object')
    result = {'schema': 'sbxr-complete-native-settings-readback-v2', 'binding': binding,
              'native_source': proof, 'source_canonical_sha256': hashlib.sha256(_canonical(settings)).hexdigest(),
              'complete_settings': _normalized(settings), 'permitted_values': _permitted_values(settings)}
    _settings_projection(result, binding)
    return result


def _settings_projection(snapshot, binding):
    require(isinstance(snapshot, dict) and set(snapshot) ==
            {'schema', 'binding', 'native_source', 'source_canonical_sha256', 'complete_settings', 'permitted_values'} and
            snapshot['schema'] == 'sbxr-complete-native-settings-readback-v2' and
            _canonical(snapshot['binding']) == _canonical(binding), 'Settings schema/binding differs')
    proof = snapshot['native_source']
    require(isinstance(proof, dict) and set(proof) ==
            {'source_app_path', 'sha256', 'dev', 'ino', 'mode', 'uid', 'nlink', 'size', 'mtime_ns', 'ctime_ns'} and
            proof['source_app_path'] == str(NATIVE_SETTINGS_SOURCE) and
            all(type(proof[key]) is int for key in ('dev', 'ino', 'mode', 'uid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')) and
            proof['ino'] > 0 and proof['size'] > 0 and proof['nlink'] == 1 and proof['uid'] == os.getuid() and
            stat.S_ISREG(proof['mode']) and stat.S_IMODE(proof['mode']) in (0o600, 0o644) and
            all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
                for value in (proof['sha256'], snapshot['source_canonical_sha256'])), 'Invalid native settings source proof')
    complete = snapshot['complete_settings']
    _validate_normalized(complete)
    require(complete.get('type') == 'object', 'Complete settings must retain the root object')
    permitted = snapshot['permitted_values']
    require(isinstance(permitted, dict) and set(permitted) == {'/' + '/'.join(path) for path in _PERMITTED_PATHS},
            'Only the fixed three permitted settings values are accepted')
    values = _permitted_values({'window': {'x': permitted['/window/x'], 'y': permitted['/window/y']},
                               'dns': {'client_subnet_latest_update': permitted['/dns/client_subnet_latest_update']}})
    projection = _decode_settings(_canonical(complete))
    try:
        for parent, key in _PERMITTED_PATHS:
            leaf = projection['fields'][parent]['fields'][key]
            require(_canonical(leaf) == _canonical(_normalized(values['/' + parent + '/' + key])),
                    'Permitted value differs from complete audit')
            projection['fields'][parent]['fields'][key] = {'policy': SETTINGS_POLICY}
    except (KeyError, TypeError):
        raise ValueError('Required complete settings paths are missing') from None
    return projection


def compare_settings(baseline, current, binding):
    """Use only a trusted pre-dispatch binding, never one selected by a receipt."""
    require(_canonical(binding) == _canonical(settings_binding()), 'Settings binding differs from actual app/helper')
    require(_canonical(_settings_projection(baseline, binding)) ==
            _canonical(_settings_projection(current, binding)), 'Preserved settings differ outside the three permitted paths')
    changes = []
    for parts in _PERMITTED_PATHS:
        path = '/' + '/'.join(parts)
        before, after = baseline['permitted_values'][path], current['permitted_values'][path]
        if _canonical(before) != _canonical(after):
            changes.append({'path': path, 'baseline': _normalized(before), 'current': _normalized(after)})
    return {'policy': SETTINGS_POLICY, 'changes': changes}


def capture_settings(baseline_record, current_path, binding):
    """Fresh producer seam shared by baseline checks and M2/M3/M5 capture."""
    baseline = _decode_settings(source_file(baseline_record))
    current_path = Path(current_path)
    require(current_path.is_absolute() and current_path.parent == Path(baseline_record['source_file']).parent and
            str(current_path) != baseline_record['source_file'], 'Settings captures must be distinct direct run files')
    current = settings_readback(binding)
    comparison = compare_settings(baseline, current, binding)
    raw = _canonical(current) + b'\n'
    require(_canonical(settings_readback(binding)) == _canonical(current), 'Native settings changed before capture publication')
    with os.fdopen(os.open(current_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {'baseline': baseline_record,
            'current': {'source_file': str(current_path), 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)},
            'comparison': comparison}


def preserved_v2(facts, binding, baseline_record):
    """Explicit future policy; preserved(facts) and frozen v1 stay byte-strict."""
    settings = facts.get('settings')
    require(isinstance(settings, dict) and set(settings) == {'baseline', 'current', 'comparison'}, 'Explicit v2 settings facts required')
    require(_canonical(settings['baseline']) == _canonical(baseline_record),
            'Settings baseline differs from the trusted frozen original')
    baseline, current = (_decode_settings(source_file(settings[key])) for key in ('baseline', 'current'))
    require(settings['baseline']['source_file'] != settings['current']['source_file'], 'Distinct settings readbacks required')
    comparison = compare_settings(baseline, current, binding)
    require(_canonical(settings['comparison']) == _canonical(comparison), 'Settings comparison audit differs')
    require(_canonical(current) == _canonical(settings_readback(binding)), 'Native settings changed after capture')
    preserved_connection(facts)
    connection = facts['selected_connection']
    require(_canonical(connection['baseline']) == _canonical(connection['current']),
            'Original connection must preserve exact value types')


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
