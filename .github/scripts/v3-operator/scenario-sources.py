#!/usr/bin/env python3
"""Read current-request observations for the remaining V4 scenario families."""
from dataclasses import dataclass
from pathlib import Path
import os
import stat


SCENARIOS = (
    'managed-renewal', 'recorder-live', 'recorder-locks', 'snap-refresh',
    'unsupported-route', 'identity-precommit', 'identity-postcommit',
    'identity-unavailable', 'lifecycle-menu', 'remove-certbot', 'remove-writer',
    'remove-admission-race', 'remove-directory-lock', 'secret-containment', 'karing-final',
)


@dataclass
class Context:
    api: object
    scenario: str
    manifest: dict
    manifest_raw: bytes
    manifest_sha: str
    request: dict
    request_raw: bytes
    request_sha: str
    state: dict
    directory: Path

    def __post_init__(self):
        info = self.directory.lstat()
        self.require(self.directory.is_absolute() and not stat.S_ISLNK(info.st_mode) and
                     stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(),
                     'sources: absolute private directory required')

    def require(self, condition, reason):
        if not condition:
            raise self.api.Refusal(reason)

    def read(self, name):
        self.require(isinstance(name, str) and Path(name).name == name and name not in ('', '.', '..'),
                     'sources: direct retained filename required')
        return self.api.load(self.directory / name, 'source ' + name, True)

    def capture(self, name, helper):
        value, _, raw = self.read(name)
        self.api.exact(value, ('schema', 'scenario_id', 'qualification_manifest_sha256', 'request_sha256',
                              'helper', 'started_at', 'completed_at', 'exit_code', 'events'), 'captured source')
        self.require(value['schema'] == 'sbxr-v4-captured-source-v1' and value['scenario_id'] == self.scenario and
                     value['qualification_manifest_sha256'] == self.manifest_sha and value['request_sha256'] == self.request_sha and
                     value['helper'] == helper and type(value['exit_code']) is int and value['exit_code'] == 0,
                     'captured source: failed helper or different request')
        self.require(self.api.before(self.state['entry_started_at'], value['started_at']) and
                     self.api.before(value['started_at'], value['completed_at']) and
                     self.api.before(value['completed_at'], self.state['completed_at']) and
                     self.api.instant(value['completed_at'], 'capture completion') <= self.api.timing.Instant(self.request['deadline_unix'], 0),
                     'captured source: outside original scenario window')
        self.require(isinstance(value['events'], list) and 0 < len(value['events']) <= 10000,
                     'captured source: actual helper output required')
        previous = value['started_at']
        for event in value['events']:
            self.api.exact(event, ('observed_at', 'record'), 'captured event')
            self.require(isinstance(event['record'], dict) and self.api.before(previous, event['observed_at']) and
                         self.api.before(event['observed_at'], value['completed_at']), 'captured source: event order differs')
            previous = event['observed_at']
        return value, raw

    def source(self, name, raw, events):
        return self.api.timing.EventSource(name, self.scenario, self.manifest_sha, self.request_sha,
                                           raw, self.api.digest(raw), events)


def state_source(api, state, raw, scenario, manifest_sha, request_sha, request):
    api.exact(state, ('schema', 'scenario_id', 'qualification_manifest_sha256', 'request_sha256',
                      'started_at', 'entry_started_at', 'action_started_at', 'action_completed_at', 'completed_at'),
              'scenario entry')
    if (state['schema'] != 'sbxr-v4-scenario-entry-v1' or state['scenario_id'] != scenario or
            state['qualification_manifest_sha256'] != manifest_sha or state['request_sha256'] != request_sha or
            state['started_at'] != request['not_before']):
        raise api.Refusal('scenario entry: original request differs')
    keys = ('started_at', 'entry_started_at', 'action_started_at', 'action_completed_at', 'completed_at')
    times = [request['not_before']] + [state[key] for key in keys]
    if any(not api.before(left, right) for left, right in zip(times, times[1:])):
        raise api.Refusal('scenario entry: actual phase order differs')
    if api.instant(state['completed_at'], 'scenario completion') > api.timing.Instant(request['deadline_unix'], 0):
        raise api.Refusal('scenario entry: original deadline exceeded')
    return api.timing.EventSource('state', scenario, manifest_sha, request_sha, raw, api.digest(raw),
                                  {key: state[key] for key in keys})


def family(scenario):
    if scenario in SCENARIOS[:5]:
        return 'managed-evidence.py'
    if scenario in SCENARIOS[5:8]:
        return 'identity-evidence.py'
    if scenario in SCENARIOS[8:]:
        return 'final-evidence.py'
    raise ValueError('unsupported later scenario')


def adapter(api, scenario):
    filename = family(scenario)
    return api.import_sibling('sbxr_' + filename.replace('-', '_').removesuffix('.py'), filename)
