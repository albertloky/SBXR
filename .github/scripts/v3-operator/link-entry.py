#!/usr/bin/env python3
"""Publish protected link-scenario inputs without resetting the collector clock."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('link_entry_assembler', HERE / 'assemble-evidence.py')
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)


def now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def publish(path, value):
    evidence.identity.atomic_write_new(path, evidence.canonical(value))


def disclosure_binding(request, request_sha):
    binding = dict(request)
    binding.pop('scenario_limit_seconds')
    binding['request_sha256'] = request_sha
    return binding


def prepare_documents(scenario, manifest_sha, request_sha, request, raw, started, at):
    if (started is None or started != os.environ.get('SCENARIO_START') or
            not evidence.before(request['not_before'], started) or not evidence.before(started, at)):
        raise evidence.Refusal('original scenario start differs')
    state = {'schema': 'sbxr-v4-link-entry-v1', 'scenario_id': scenario,
             'qualification_manifest_sha256': manifest_sha, 'request_sha256': request_sha,
             'started_at': started, 'entry_started_at': at,
             'initial_disclosure_sha256': evidence.digest(raw)}
    trigger = {'schema': 'sbxr-v4-link-outside-request-v1', 'scenario_id': scenario,
               'deadline_unix': request['deadline_unix'], 'qualification_manifest_sha256': manifest_sha,
               'operator_directory': '/run/sbxr-qualification',
               'state_directory': '/run/sbxr-qualification'}
    return state, trigger


def finalize_document(scenario, manifest_sha, request_sha, request, raw, controller,
                      controller_raw, challenge_raw, closed_raw, at):
    return {'schema': 'sbxr-v4-link-outside-finalize-v1', 'scenario_id': scenario,
            'qualification_manifest_sha256': manifest_sha, 'request_sha256': request_sha,
            'deadline_unix': request['deadline_unix'], 'challenge_sha256': evidence.digest(challenge_raw),
            'closed_sha256': evidence.digest(closed_raw), 'final_disclosure_sha256': evidence.digest(raw),
            'recovered_transition_sha256': evidence.digest(controller_raw),
            'recovered_at': controller['recovered_at'], 'finalized_at': at}


def validate_entry_state(state, scenario, manifest_sha, request_sha, request):
    evidence.exact(state, ('schema', 'scenario_id', 'qualification_manifest_sha256',
                           'request_sha256', 'started_at', 'entry_started_at',
                           'initial_disclosure_sha256'), 'link entry')
    if (state['schema'] != 'sbxr-v4-link-entry-v1' or
            state['scenario_id'] != scenario or
            state['qualification_manifest_sha256'] != manifest_sha or
            state['request_sha256'] != request_sha or
            not isinstance(state['initial_disclosure_sha256'], str) or
            evidence.SHA256.fullmatch(state['initial_disclosure_sha256']) is None or
            not evidence.before(request['not_before'], state['started_at']) or
            not evidence.before(state['started_at'], state['entry_started_at'])):
        raise evidence.Refusal('link entry: original request or clock differs')
    return state


def wait_result(path, request_path, request_raw, deadline, pause=0.2):
    while not path.exists():
        if time.time() >= deadline:
            raise evidence.Refusal('outside result missed original deadline')
        if evidence.private_bytes(request_path, 'current request') != request_raw:
            raise evidence.Refusal('collector request changed while waiting')
        time.sleep(pause)
    if (time.time() > deadline or
            evidence.private_bytes(request_path, 'current request') != request_raw):
        raise evidence.Refusal('outside result exceeded or changed original request')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'finalize'))
    parser.add_argument('scenario', choices=('link-precommit', 'link-postcommit'))
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise evidence.Refusal('Linux root required')
    root = Path(os.environ['SBXR_OPERATOR_STATE_DIR'])
    directory = root.lstat()
    if root != Path('/run/sbxr-qualification') or root.is_symlink() or directory.st_mode & 0o777 != 0o700 or directory.st_uid != 0:
        raise evidence.Refusal('operator state directory refused')
    request_path = Path(os.environ['SBXR_QUALIFICATION_REQUEST'])
    manifest, manifest_body, _ = evidence.load(Path(os.environ['SBXR_QUALIFICATION_MANIFEST']), 'manifest')
    request, _, request_raw = evidence.load(request_path, 'request', True)
    _, attempt, manifest_sha = evidence.validate_manifest(manifest, manifest_body, args.scenario)
    _, request_sha = evidence.validate_request(request, request_raw, manifest_sha, args.scenario, attempt)
    raw = sys.stdin.buffer.read(evidence.JSON_LIMIT + 1)
    if len(raw) > evidence.JSON_LIMIT:
        raise evidence.Refusal('disclosure exceeds bound')
    value = json.loads(raw, object_pairs_hook=evidence.unique)
    binding = disclosure_binding(request, request_sha)
    evidence.exact(value, ('link', 'certificate_der_sha256', 'configuration', 'binding'), 'link disclosure')
    if value['binding'] != binding:
        raise evidence.Refusal('disclosure: exact current request binding differs')
    # Retain canonical bytes so the outside runner and assembler see the same input.
    raw = evidence.canonical(value)
    prefix = 'link-' + args.scenario + '-'
    at = now()
    if time.time() > request['deadline_unix']:
        raise evidence.Refusal('original scenario deadline expired')
    if args.operation == 'prepare':
        state, trigger = prepare_documents(args.scenario, manifest_sha, request_sha, request, raw,
                                           os.environ.get('STARTED_AT'), at)
        publish(root / (prefix + 'initial.json'), value)
        publish(root / (prefix + 'entry.json'), state)
        publish(Path(os.environ['SBXR_OPERATOR_EVIDENCE_DIR']) / 'link-outside-request.json', trigger)
    else:
        state, _, _ = evidence.load(root / (prefix + 'entry.json'), 'link entry')
        validate_entry_state(state, args.scenario, manifest_sha, request_sha, request)
        controller, _, controller_raw = evidence.load(root / ('transition-' + args.scenario + '.json'), 'link controller', True)
        if (controller.get('phase') != 'recovered' or controller.get('scenario') != args.scenario or
                controller.get('request_sha256') != request_sha or controller.get('qualification_manifest_sha256') != manifest_sha):
            raise evidence.Refusal('recovered transition required')
        challenge, _, challenge_raw = evidence.load(root / (prefix + 'challenge.json'), 'link challenge', True)
        closed, _, closed_raw = evidence.load(root / (prefix + 'closed.json'), 'link closure', True)
        publish(root / (prefix + 'final.json'), value)
        finalize = finalize_document(args.scenario, manifest_sha, request_sha, request, raw,
                                     controller, controller_raw, challenge_raw, closed_raw, now())
        publish(root / (prefix + 'finalize.json'), finalize)
        result_path = root / (prefix + 'result.json')
        wait_result(result_path, request_path, request_raw, request['deadline_unix'])
        _, _, outside_raw = evidence.load(result_path, 'outside result', True)
        completed = dict(state, completed_at=now(), final_disclosure_sha256=evidence.digest(raw),
                         controller_receipt_sha256=evidence.digest(controller_raw), outside_receipt_sha256=evidence.digest(outside_raw))
        publish(root / (prefix + 'entry-final.json'), completed)
    print(json.dumps({'link_entry_prepared': True, 'scenario_id': args.scenario, 'operation': args.operation}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('{"link_entry_refused":true}', file=sys.stderr)
        sys.exit(1)
