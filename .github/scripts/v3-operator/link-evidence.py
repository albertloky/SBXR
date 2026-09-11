#!/usr/bin/env python3
"""Source adapters for the two link-rotation scenarios; no live operations."""
import re
import os
import stat
import urllib.parse


def is_digest(api, value):
    return isinstance(value, str) and api.SHA256.fullmatch(value) is not None


def controller_source(api, receipt, raw, scenario, manifest_sha, request_sha, state):
    keys = ('schema', 'scenario', 'phase', 'qualification_manifest_sha256', 'request_sha256',
            'started_at', 'action_started_at', 'target_prepared_at', 'quiesced_at', 'interrupted_at',
            'recovery_started_at', 'recovered_at', 'initial_record_sha256',
            'interrupted_record_sha256', 'final_record_sha256', 'target_record_sha256', 'field', 'checkpoint', 'direction',
            'result_code', 'boundary_path', 'boundary_process', 'source', 'target', 'source_target_comparison',
            'outside_handoff', 'runtime')
    api.exact(receipt, keys, 'link controller')
    precommit = scenario == 'link-precommit'
    expected = {
        'schema': 'sbxr-v4-link-transition-controller-v1', 'scenario': scenario, 'phase': 'recovered',
        'qualification_manifest_sha256': manifest_sha, 'request_sha256': request_sha,
        'field': 'subscription_rotation.checkpoint', 'checkpoint': 'stop authorized' if precommit else 'committed',
        'boundary_path': '/var/lib/sbxr/.proxy-ownership.json.next' if precommit else '/var/lib/sbxr/subscription-token',
        'direction': 'cleanup' if precommit else 'forward',
        'result_code': 'PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-CLEANED-UP' if precommit else 'PROXY-INSTALLATION-SUBSCRIPTION-LINK-ROTATED',
    }
    if any(receipt[key] != value for key, value in expected.items()):
        raise api.Refusal('link controller: scenario, boundary, or recovery result differs')
    timestamps = [state['entry_started_at']] + [receipt[key] for key in (
        'started_at', 'action_started_at', 'target_prepared_at', 'quiesced_at', 'interrupted_at',
        'recovery_started_at', 'recovered_at')] + [state['completed_at']]
    if any(not api.before(left, right) for left, right in zip(timestamps, timestamps[1:])):
        raise api.Refusal('link controller: actual event order differs')
    for key in ('initial_record_sha256', 'interrupted_record_sha256', 'final_record_sha256', 'target_record_sha256'):
        if not is_digest(api, receipt[key]):
            raise api.Refusal('link controller: record digest required')
    process = api.exact(receipt['boundary_process'], ('pid', 'start_tick', 'executable_device', 'executable_inode', 'cgroup'), 'link action process')
    if (any(type(process[k]) is not int or process[k] < 1 for k in ('pid', 'start_tick', 'executable_device', 'executable_inode')) or
            process['pid'] < 2 or not isinstance(process['cgroup'], str) or
            re.fullmatch(r'/system.slice/sbxr-v4-' + re.escape(scenario) + r'-[1-9][0-9]*\.service', process['cgroup']) is None):
        raise api.Refusal('link controller: actual action process required')
    runtime_api = api.import_sibling('sbxr_link_runtime_evidence', 'link-runtime.py')
    try:
        selector = 'source' if precommit else 'target'
        comparison = runtime_api.comparison(receipt['source'], receipt['target'], 'source', selector, selector)
    except (ValueError, TypeError) as error:
        raise api.Refusal('link controller: invalid source/target authority') from error
    if receipt['source_target_comparison'] != comparison or any(comparison[key] is not True for key in (
            'link_id_changed', 'credential_sha256_changed', 'certificate_generation_unchanged',
            'certificate_sha256_unchanged', 'configuration_sha256_unchanged')):
        raise api.Refusal('link controller: replacement changed more than link identity')
    runtime = api.exact(receipt['runtime'], ('initial', 'target_prepared', 'quiescent', 'recovered') + (() if precommit else ('committed',)), 'link runtime')
    initial = api.exact(runtime['initial'], ('source_process', 'proxy_process', 'configuration_sha256', 'staging_empty'), 'initial link runtime')
    if initial['staging_empty'] is not True or not is_digest(api, initial['configuration_sha256']):
        raise api.Refusal('link runtime: proxy configuration digest required')
    source_process = api.exact(initial['source_process'], ('pid', 'start_tick', 'executable_device', 'executable_inode', 'cgroup', 'serving_state_sha256'), 'source serving process')
    proxy_process = api.exact(initial['proxy_process'], ('pid', 'start_tick', 'executable_device', 'executable_inode'), 'source proxy process')
    for process in (source_process, proxy_process):
        if any(type(process[k]) is not int or process[k] < 1 for k in ('pid', 'start_tick', 'executable_device', 'executable_inode')) or process['pid'] < 2:
            raise api.Refusal('link runtime: invalid process identity')
    source_state_sha = api.digest(runtime_api.serving_state_bytes(receipt['source']))
    if source_process['cgroup'] != '/system.slice/sbxr-subscription.service' or source_process['serving_state_sha256'] != source_state_sha:
        raise api.Refusal('link runtime: source serving state differs')
    staged = api.exact(runtime['target_prepared'], ('source_process', 'target_state_sha256', 'target_credential_sha256', 'source_still_running', 'target_staged_only'), 'prepared link target')
    if staged != {'source_process': source_process, 'target_state_sha256': api.digest(runtime_api.serving_state_bytes(receipt['target'])),
                  'target_credential_sha256': receipt['target']['credential_sha256'], 'source_still_running': True, 'target_staged_only': True}:
        raise api.Refusal('link runtime: exactly one staged target required')
    for name in ('quiescent',) + (() if precommit else ('committed',)):
        row = api.exact(runtime[name], ('active_state', 'main_pid', 'source_process_absent', 'owned_processes_and_descendants_absent',
                                       'cgroup_state', 'listener_8443_absent', 'accepted_sockets_8443_absent', 'proxy_process', 'configuration_sha256',
                                       'unowned_kernel_time_wait_sockets') + (('observed_at', 'target_state_sha256', 'target_credential_sha256',
                                           'target_staged_only', 'serving_material', 'source_state_sha256', 'source_credential_sha256') if name == 'committed' else ()), 'link quiescence')
        if (row['active_state'] != 'inactive' or type(row['main_pid']) is not int or row['main_pid'] != 0 or row['cgroup_state'] not in ('absent', 'empty') or
                any(row[k] is not True for k in ('source_process_absent', 'owned_processes_and_descendants_absent', 'listener_8443_absent', 'accepted_sockets_8443_absent')) or
                row['proxy_process'] != proxy_process or row['configuration_sha256'] != initial['configuration_sha256'] or
                type(row['unowned_kernel_time_wait_sockets']) is not int or row['unowned_kernel_time_wait_sockets'] < 0):
            raise api.Refusal('link runtime: old serving requests or processes not proved absent')
        if name == 'committed' and not (api.before(receipt['quiesced_at'], row['observed_at']) and api.before(row['observed_at'], receipt['interrupted_at'])):
            raise api.Refusal('link runtime: commitment observation order differs')
        if name == 'committed' and (row['target_staged_only'] is not True or row['serving_material'] != 'source' or
                row['target_state_sha256'] != staged['target_state_sha256'] or
                row['target_credential_sha256'] != receipt['target']['credential_sha256'] or
                row['source_state_sha256'] != source_state_sha or row['source_credential_sha256'] != receipt['source']['credential_sha256']):
            raise api.Refusal('link runtime: target already published at committed hold')
    final = api.exact(runtime['recovered'], ('subscription_process', 'proxy_process', 'configuration_sha256', 'selected_authority_sha256', 'staging_empty'), 'recovered link runtime')
    selected = receipt[selector]
    selected_process = api.exact(final['subscription_process'], tuple(source_process), 'recovered serving process')
    if (final['staging_empty'] is not True or final['proxy_process'] != proxy_process or final['configuration_sha256'] != initial['configuration_sha256'] or
            final['selected_authority_sha256'] != api.digest(api.canonical(selected)) or
            selected_process['serving_state_sha256'] != api.digest(runtime_api.serving_state_bytes(selected)) or
            selected_process['cgroup'] != source_process['cgroup'] or
            any(type(selected_process[k]) is not int or selected_process[k] < 1 for k in ('pid', 'start_tick', 'executable_device', 'executable_inode'))):
        raise api.Refusal('link runtime: recovered generation or proxy continuity differs')
    events = {key: receipt[key] for key in ('action_started_at', 'target_prepared_at', 'quiesced_at', 'interrupted_at', 'recovery_started_at', 'recovered_at')}
    return api.timing.EventSource('controller', scenario, manifest_sha, request_sha, raw, api.digest(raw), events)


def entry_source(api, state, raw, scenario, manifest_sha, request_sha, request):
    api.exact(state, ('schema', 'scenario_id', 'qualification_manifest_sha256', 'request_sha256', 'started_at', 'entry_started_at',
                      'completed_at', 'initial_disclosure_sha256', 'final_disclosure_sha256', 'controller_receipt_sha256', 'outside_receipt_sha256'), 'link entry state')
    if (state['schema'] != 'sbxr-v4-link-entry-v1' or state['scenario_id'] != scenario or state['qualification_manifest_sha256'] != manifest_sha or
            state['request_sha256'] != request_sha or any(not is_digest(api, state[key]) for key in (
                'initial_disclosure_sha256', 'final_disclosure_sha256', 'controller_receipt_sha256', 'outside_receipt_sha256'))):
        raise api.Refusal('link entry: source binding differs')
    if any(not api.before(left, right) for left, right in zip(
            (request['not_before'], state['started_at'], state['entry_started_at']),
            (state['started_at'], state['entry_started_at'], state['completed_at']))):
        raise api.Refusal('link entry: original clock order differs')


def sources(api, options, state, state_raw, manifest_raw, request_raw, scenario, manifest_sha, request_sha, request):
    entry_source(api, state, state_raw, scenario, manifest_sha, request_sha, request)
    controller, _, controller_raw = api.load(options.controller_receipt, 'link controller', True)
    controller_event_source = controller_source(api, controller, controller_raw, scenario, manifest_sha, request_sha, state)
    directory = options.outside_directory
    info = directory.lstat()
    if not directory.is_absolute() or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise api.Refusal('outside evidence: mode-0700 directory required')
    documents, raw = {}, {}
    for name in ('initial', 'final', 'ready', 'challenge', 'ack', 'closed', 'finalize', 'result'):
        documents[name], _, raw[name] = api.load(directory / f'link-{scenario}-{name}.json', 'link outside ' + name, True)
    expected_hashes = {'initial_disclosure_sha256': api.digest(raw['initial']), 'final_disclosure_sha256': api.digest(raw['final']),
                       'controller_receipt_sha256': api.digest(controller_raw), 'outside_receipt_sha256': api.digest(raw['result'])}
    if any(state[key] != value for key, value in expected_hashes.items()):
        raise api.Refusal('link entry: retained receipt bytes differ')
    outside = api.import_sibling('sbxr_link_outside_evidence', 'link-outside.py')
    try:
        result = outside.check_chain(manifest_raw, request_raw, raw['result'],
                                     {name: raw[name] for name in ('ready', 'challenge', 'ack', 'closed', 'finalize')},
                                     raw['initial'], raw['final'])
    except (outside.Refused, ValueError, TypeError, KeyError) as error:
        raise api.Refusal('link outside: complete current-request producer chain refused') from error
    challenge, ack, closed, finalize, ready = [documents[name] for name in ('challenge', 'ack', 'closed', 'finalize', 'ready')]
    if (challenge['transition_record_sha256'] != controller['target_record_sha256'] or
            finalize['recovered_transition_sha256'] != api.digest(controller_raw) or finalize['recovered_at'] != controller['recovered_at']):
        raise api.Refusal('link outside: actual held or recovered controller differs')
    expected_handoff = {'ready_sha256': api.digest(raw['ready']), 'ready_at': ready['ready_at'],
                        'challenge_sha256': api.digest(raw['challenge']), 'challenged_at': challenge['challenged_at'],
                        'ack_sha256': api.digest(raw['ack']), 'pending_ready_at': ack['pending_ready_at'],
                        'connection_id': ack['connection_id'], 'closed_sha256': api.digest(raw['closed']),
                        'closed_at': closed['closed_at'], 'closure_kind': closed['closure_kind'],
                        'pending_elapsed_milliseconds': closed['pending_elapsed_milliseconds'],
                        'old_link_sha256': ready['old_link_sha256'], 'configuration_sha256': ready['configuration_sha256'],
                        'certificate_der_sha256': ready['certificate_der_sha256']}
    if controller['outside_handoff'] != expected_handoff:
        raise api.Refusal('link controller: outside handoff bytes or events differ')
    for left, right in ((state['entry_started_at'], result['old_initial_at']),
                        (result['old_initial_at'], controller['action_started_at']),
                        (controller['target_prepared_at'], challenge['challenged_at']),
                        (ack['pending_ready_at'], controller['quiesced_at']),
                        (closed['closed_at'], controller['interrupted_at']),
                        (controller['recovered_at'], finalize['finalized_at']),
                        (finalize['finalized_at'], result['old_final_at']),
                        (result['cleanup_at'], state['completed_at'])):
        if not api.before(left, right):
            raise api.Refusal('link evidence: outside event occurred in the wrong transition phase')
    for name, authority in (('initial', controller['source']), ('final', controller['source'] if scenario == 'link-precommit' else controller['target'])):
        value = documents[name]
        token = urllib.parse.urlsplit(value['link']).path.removeprefix('/s/').encode('ascii')
        if api.digest(token) != authority['credential_sha256']:
            raise api.Refusal('link evidence: disclosed link differs from selected authority')
    trace_raw = api.private_bytes(options.connection_observation, 'link proxy connection')
    summary, _, _ = api.load(options.connection_summary, 'link proxy connection summary', True)
    try:
        expected = api.connection.validate(os.fspath(options.connection_observation), state['started_at'], controller['action_started_at'],
                                           controller['recovered_at'], request['deadline_unix'], request_sha)
    except Exception as error:
        raise api.Refusal('link proxy connection: must span interruption and recovery') from error
    if summary != expected or api.private_bytes(options.connection_observation, 'link proxy connection') != trace_raw:
        raise api.Refusal('link proxy connection: exact trace summary or bytes differ')
    trace = [api.json.loads(line, object_pairs_hook=api.unique) for line in trace_raw.splitlines()]
    return {'controller': controller_event_source,
            'outside': api.timing.EventSource('outside', scenario, manifest_sha, request_sha, raw['result'], api.digest(raw['result']),
                {key: result[key] for key in ('old_initial_at', 'closed_at', 'old_final_at', 'new_final_at') if result[key] is not None}),
            'connection': api.timing.EventSource('connection', scenario, manifest_sha, request_sha, trace_raw, api.digest(trace_raw),
                                                 {'last_at': trace[-1]['time']})}
