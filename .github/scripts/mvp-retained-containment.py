#!/usr/bin/env python3
"""Stop-only containment sequence; native activation needs actual producer evidence.

The backend is a reviewed operator adapter, not evidence supplied by a user or
by the tested product. It must independently observe the exact bound machine,
run, candidate, unit fragments/drop-ins, cgroups, listeners and preserved files.
Each call must enforce the supplied absolute deadline independently (including
remote execution), with the row's final ten seconds reserved for local stopping.
A callback overrun is detected and reported UNKNOWN; this module cannot terminate
a blocked in-process adapter or prove a remote systemd job stopped on SSH timeout.

This module executes no shell, SSH, deletion, credential rotation, gate, terminal
submission or transport teardown. The only supplied host-effect argv are fixed
systemctl disable --now operations for the two reviewed test-owned services.
Concrete adapters are provided in mvp-containment-{process,entry,host}.py; the
offline source map is not a runnable live scope. Fixture success is not admission.
"""
import copy
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

UNITS = ('sbxr-subscription.service', 'sing-box.service')
HTTP_PHASES = ('clock', 'ownership', 'stop-services', 'verify-host', 'stop-outside',
               'restore-client', 'verify-retained', 'record-failure')
ROWS = dict(zip(HTTP_PHASES, (90, 90, 400, 90, 60, 300, 90, 30)))
GUARD = 50
EFFECTS = {'stop-services', 'stop-outside', 'restore-client'}


class Refusal(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def clocks_now():
    return time.time(), time.monotonic()


def read_clocks(clocks, previous=None):
    wall, mono = clocks()
    require(number(wall) and number(mono), 'clock unavailable')
    if previous is not None:
        require(wall >= previous[0] and mono >= previous[1], 'clock rollback')
    return wall, mono


def retain(directory, name, value):
    """Exclusive, private evidence; no overwrite or deletion on failure."""
    directory = Path(directory)
    require(re.fullmatch('[a-z-]+[.]json', name) is not None, 'evidence name')
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        st = os.fstat(parent)
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()
                and stat.S_IMODE(st.st_mode) == 0o700, 'unsafe evidence directory')
        try:
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
        except FileExistsError as error:
            raise Refusal('existing intent/outcome: inspect without replay') from error
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)



def validate_scope(scope, now):
    require(isinstance(scope, dict), 'scope missing')
    binding = scope['binding']
    require(set(binding) == {'run_id', 'source', 'manifest_sha256', 'request_sha256',
                            'failure_sha256', 'host', 'tag', 'sequence'}, 'binding fields')
    require(type(binding['run_id']) is int and binding['run_id'] > 0, 'run identity')
    require(type(binding['sequence']) is int and binding['sequence'] > 0, 'sequence')
    require(re.fullmatch(r'v\d+\.\d+\.\d+', binding['tag']) is not None, 'tag')
    require(isinstance(binding['host'], str) and binding['host'], 'host identity')
    require(isinstance(binding['source'], str) and re.fullmatch('[0-9a-f]{40}', binding['source']) is not None, 'Git source identity')
    require(all(digest(binding[k]) for k in ('manifest_sha256', 'request_sha256',
                                           'failure_sha256')), 'identity digest')
    for key in ('original_cutoff', 'signed_finish', 'runtime_finish', 'final_cutoff'):
        require(number(scope[key]) and scope[key] > now, 'invalid or expired ' + key)
    require(scope['final_cutoff'] >= scope['original_cutoff'], 'final cutoff ordering')
    require(type(scope['http_state_possible']) is bool, 'uncertain native state needs HTTP reserve')
    reply = scope['confirmation']
    require(reply['status'] in ('missing', 'declined'), 'not a no-reply/declined route')
    require(number(reply['notified_at']) and reply['notified_at'] <= now, 'notification clock')
    require(type(reply['response_cap']) is int and reply['response_cap'] == 60,
            'unreviewed response allocation')
    if reply['status'] == 'missing':
        require(now >= reply['notified_at'] + reply['response_cap'], 'reply allocation still pending')
    units = scope['expected_units']
    require(set(units) == set(UNITS), 'complete service inventory required')
    for unit in units.values():
        require(set(unit) == {'fragment_sha256', 'dropins'} and digest(unit['fragment_sha256']),
                'reviewed unit pin missing')
        require(isinstance(unit['dropins'], dict) and all(digest(v) for v in unit['dropins'].values()),
                'reviewed drop-in pins missing')
    files = scope['retained_files']
    require(isinstance(files, dict) and files and all(digest(v) for v in files.values()),
            'finite retained-file inventory required')
    require(binding['failure_sha256'] in files.values(), 'original failure must be preserved')
    clients = scope['outside_client_ids']
    require(isinstance(clients, list) and len(set(clients)) == len(clients)
            and all(isinstance(x, str) and x for x in clients), 'outside client inventory')
    require(isinstance(scope['candidate_profile'], str) and scope['candidate_profile'], 'profile identity')
    return min(scope[k] for k in ('original_cutoff', 'signed_finish', 'runtime_finish'))


def common(receipt, scope, start, end):
    require(isinstance(receipt, dict) and receipt.get('binding') == scope['binding'],
            'observation candidate identity changed')
    require(receipt.get('outcome') == 'complete', 'operation incomplete or uncertain')
    at = receipt.get('observed_at')
    require(number(at) and start <= at <= end, 'observation not from this operation')
    cutoff = receipt.get('current_cutoff')
    require(number(cutoff) and cutoff <= scope['original_cutoff'], 'cutoff extension refused')
    return cutoff


def validate_ownership(receipt, scope):
    require(receipt.get('prior_uncertain') is False and receipt.get('foreign_processes') == [],
            'uncertain action or foreign process')
    owned, absent = receipt.get('owned_units'), receipt.get('absent_units')
    require(isinstance(owned, dict) and isinstance(absent, list), 'unit observations missing')
    require(len(absent) == len(set(absent)) and not set(owned).intersection(absent)
            and set(owned).union(absent) == set(UNITS), 'partial or foreign unit inventory')
    for name, unit in owned.items():
        pins = scope['expected_units'][name]
        require(unit.get('fragment_sha256') == pins['fragment_sha256']
                and unit.get('dropins') == pins['dropins'], 'foreign unit fragment/drop-in')
        require(unit.get('exec_stop') == [] and unit.get('exec_stop_post') == []
                and unit.get('kill_mode') == 'control-group', 'unreviewed stop hooks or kill mode')
        duration = unit.get('timeout_stop_seconds')
        require(number(duration) and 0 < duration <= 90, 'unbounded service stop')
    require(receipt.get('retained_files') == scope['retained_files'], 'retained data changed before stop')
    return tuple(name for name in UNITS if name in owned), tuple(absent)


def validate_phase(action, receipt, scope, owned, absent):
    if action == 'clock':
        require(receipt.get('clock_consistent') is True, 'request/runtime clock unproved')
    elif action == 'ownership':
        return validate_ownership(receipt, scope)
    elif action == 'stop-services':
        require(receipt.get('stopped_units') == list(owned), 'stop result missing or differs')
    elif action == 'verify-host':
        require(set(receipt.get('inactive_disabled_units', [])) == set(owned)
                and set(receipt.get('absent_units', [])) == set(absent), 'service stop not proved')
        require(receipt.get('candidate_pids') == [] and receipt.get('open_test_ports') == [],
                'candidate process/listener remains')
        require(receipt.get('ssh_preserved') is True and receipt.get('unrelated_state_preserved') is True,
                'SSH/unrelated state preservation unproved')
        require(receipt.get('retained_files') == scope['retained_files'], 'stop changed retained data')
    elif action == 'stop-outside':
        require(receipt.get('stopped_client_ids') == scope['outside_client_ids']
                and receipt.get('public_ports_closed') == [443, 8443], 'outside containment unproved')
    elif action == 'restore-client':
        require(receipt.get('original_restored') is True and receipt.get('candidate_selected') is False
                and receipt.get('test_data_deleted') is False, 'native restoration/retention unproved')
    elif action == 'verify-retained':
        require(receipt.get('retained_files') == scope['retained_files'], 'retained bytes missing/changed')
        require(receipt.get('original_client_preserved') is True
                and receipt.get('candidate_selected') is False
                and receipt.get('test_data_deleted') is False, 'original client/retention unproved')
    elif action == 'record-failure':
        require(receipt.get('failure_sha256') == scope['binding']['failure_sha256']
                and receipt.get('failure_recorded') is True
                and receipt.get('qualification_passed') is False, 'failure relabelled or unrecorded')
    return owned, absent


def contain(scope, backend, directory, *, clocks=clocks_now):
    """Run one reviewed adapter sequence. Native adapters are not supplied here."""
    scope = copy.deepcopy(scope)
    previous = read_clocks(clocks)
    cutoff = validate_scope(scope, previous[0])
    phases = HTTP_PHASES if scope['http_state_possible'] else tuple(x for x in HTTP_PHASES if x != 'restore-client')
    require(previous[0] + sum(ROWS[x] for x in phases) + GUARD < cutoff,
            'complete containment budget does not fit')
    result = {'binding': scope['binding'], 'status': 'pending', 'product_contained': False,
              'cleanup_complete': False, 'qualification_passed': False,
              'transport_status': 'pending', 'retention_requested': True,
              'retained_data_verified': False, 'completed_phases': []}
    retain(directory, 'containment-intent.json', {'scope': scope, 'started_at': previous[0]})
    owned, absent = (), ()
    for i, action in enumerate(phases):
        called = False
        try:
            start = read_clocks(clocks, previous)
            remaining = sum(ROWS[x] for x in phases[i + 1:]) + GUARD
            cap = ROWS[action]
            require(start[0] + cap + remaining < cutoff, 'remaining full budget does not fit')
            deadline = min(start[0] + cap - 10, cutoff - remaining - 10)
            commands = tuple(('/usr/bin/systemctl', 'disable', '--now', name) for name in owned) if action == 'stop-services' else ()
            retain(directory, action + '-intent.json', {'binding': scope['binding'], 'deadline': deadline,
                                                        'row_seconds': cap, 'downstream_seconds': remaining,
                                                        'commands': commands})
            called = True
            receipt = backend.run(action, deadline, commands)
            retain(directory, action + '-observation.json', receipt)
            end = read_clocks(clocks, start)
            require(end[0] - start[0] < cap and end[1] - start[1] < cap,
                    'adapter overran bounded row; outcome uncertain')
            next_cutoff = common(receipt, scope, start[0], end[0])
            cutoff = min(cutoff, next_cutoff)
            require(end[0] + remaining < cutoff, 'tightened cutoff cannot cover downstream work')
            owned, absent = validate_phase(action, receipt, scope, owned, absent)
            retain(directory, action + '-outcome.json', receipt)
            result['completed_phases'].append(action)
            previous = end
        except Exception as error:
            result.update(status='uncertain' if called and action in EFFECTS else 'refused',
                          blocked_action=action, reason=str(error), fixed_cutoff=cutoff)
            retain(directory, 'containment-outcome.json', result)
            return result
    require(previous[0] + GUARD < cutoff, 'final guard exhausted')
    result.update(status='contained-with-retained-data', product_contained=True,
                  retained_data_verified=True, fixed_cutoff=cutoff)
    retain(directory, 'containment-outcome.json', result)
    return result


def verify_transport(scope, product_result, backend, directory, *, clocks=clocks_now):
    """Observe separately approved automatic rollback; never invoke teardown."""
    require(product_result.get('binding') == scope['binding']
            and product_result.get('product_contained') is True, 'product containment unproved')
    result = copy.deepcopy(product_result)
    start = read_clocks(clocks)
    cutoff = scope['final_cutoff']
    require(number(cutoff) and start[0] + 1350 + 450 < cutoff, 'full transport reserve does not fit')
    retain(directory, 'transport-intent.json', {'binding': scope['binding'], 'deadline': start[0] + 1340,
                                               'cutoff': cutoff, 'read_only': True, 'reserve': 450})
    try:
        receipt = backend.run('verify-transport', start[0] + 1340, ())
        retain(directory, 'transport-raw-observation.json', receipt)
        end = read_clocks(clocks, start)
        require(end[0] - start[0] < 1350 and end[1] - start[1] < 1350, 'transport observation timed out')
        common(receipt, scope, start[0], end[0])
        for name in ('gateway_stopped', 'test_ca_absent', 'test_hosts_entry_absent',
                     'test_redirect_absent', 'ssh_preserved', 'unrelated_state_preserved'):
            require(receipt.get(name) is True, 'transport restoration unproved: ' + name)
        retain(directory, 'transport-observation.json', receipt)
        result['transport_status'] = 'restored'
    except Exception as error:
        result.update(transport_status='unproved', transport_reason=str(error))
    retain(directory, 'transport-outcome.json', result)
    return result


if __name__ == '__main__':
    print('Containment refused: CLI has no actual producer-bound scope; use the reviewed caller.', file=sys.stderr)
    raise SystemExit(2)
