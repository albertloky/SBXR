#!/usr/bin/env python3
"""Bind typed evidence observations to authenticated source events.

Scenario adapters authenticate retained artifacts and construct EventSource values.
This module performs no I/O and preserves the existing wire observation shape.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
from typing import Mapping, Sequence


UTC_TIME = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$"
)
UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PROOF_SOURCE = "$proof"


class EvidenceTimingRefusal(ValueError):
    pass


@dataclass(frozen=True, order=True)
class Instant:
    epoch_second: int
    nanosecond: int


@dataclass(frozen=True)
class Anchor:
    source: str
    event: str


@dataclass(frozen=True)
class ObservationRule:
    check: str
    required_sources: tuple[str, ...]
    not_before: tuple[Anchor, ...]
    not_after: tuple[Anchor, ...]


@dataclass(frozen=True)
class EventSource:
    source_id: str
    scenario_id: str
    qualification_manifest_sha256: str
    request_sha256: str
    artifact: bytes
    artifact_sha256: str
    events: Mapping[str, str]


def parse_instant(value: object, label: str) -> Instant:
    if not isinstance(value, str):
        raise EvidenceTimingRefusal(f"{label}: canonical UTC timestamp required")
    match = UTC_TIME.fullmatch(value)
    if match is None:
        raise EvidenceTimingRefusal(f"{label}: canonical UTC timestamp required")
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    fraction = match.group(7) or ""
    try:
        parsed = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError as error:
        raise EvidenceTimingRefusal(f"{label}: invalid UTC timestamp") from error
    return Instant(calendar.timegm(parsed.utctimetuple()), int(fraction.ljust(9, "0") or "0"))


def ceil_wire_timestamp(value: object, label: str = "source event") -> str:
    """Return the first whole-second wire instant not before a full-resolution event."""
    instant = parse_instant(value, label)
    second = instant.epoch_second + (1 if instant.nanosecond else 0)
    return datetime.fromtimestamp(second, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validated_source(
    source_id: str,
    sources: Mapping[str, EventSource],
    scenario_id: str,
    qualification_manifest_sha256: str,
    request_sha256: str,
) -> EventSource:
    source = sources.get(source_id)
    if source is None:
        raise EvidenceTimingRefusal(f"source {source_id!r}: required artifact is missing")
    if source.source_id != source_id:
        raise EvidenceTimingRefusal(f"source {source_id!r}: identity differs from map key")
    if source.scenario_id != scenario_id or source.qualification_manifest_sha256 != qualification_manifest_sha256 or source.request_sha256 != request_sha256:
        raise EvidenceTimingRefusal(f"source {source_id!r}: scenario, manifest, or request binding differs")
    if not isinstance(source.artifact, bytes) or not source.artifact or not SHA256.fullmatch(source.artifact_sha256) or hashlib.sha256(source.artifact).hexdigest() != source.artifact_sha256:
        raise EvidenceTimingRefusal(f"source {source_id!r}: exact artifact bytes or SHA-256 refused")
    return source


def _source_event(
    source_id: str,
    event: str,
    sources: Mapping[str, EventSource],
    proof_completed: str,
    scenario_id: str,
    qualification_manifest_sha256: str,
    request_sha256: str,
) -> Instant:
    if source_id == PROOF_SOURCE:
        if event != "completed_at":
            raise EvidenceTimingRefusal(f"proof: unknown event {event!r}")
        return parse_instant(proof_completed, "proof.completed_at")
    source = _validated_source(
        source_id, sources, scenario_id, qualification_manifest_sha256, request_sha256
    )
    if event not in source.events:
        raise EvidenceTimingRefusal(f"source {source_id!r}: required event {event!r} is missing")
    return parse_instant(source.events[event], f"source {source_id}.{event}")


def validate_observations(
    *,
    scenario_id: str,
    qualification_manifest_sha256: str,
    request_sha256: str,
    observations: object,
    proof_completed_at: object,
    rules: Sequence[ObservationRule],
    sources: Mapping[str, EventSource],
) -> tuple[dict, ...]:
    """Validate and return unchanged existing-wire observation records."""
    if not isinstance(scenario_id, str) or not scenario_id:
        raise EvidenceTimingRefusal("scenario_id: nonempty string required")
    if not isinstance(qualification_manifest_sha256, str) or not SHA256.fullmatch(qualification_manifest_sha256):
        raise EvidenceTimingRefusal("qualification_manifest_sha256: lowercase SHA-256 required")
    if not isinstance(request_sha256, str) or not SHA256.fullmatch(request_sha256):
        raise EvidenceTimingRefusal("request_sha256: lowercase SHA-256 required")
    if not isinstance(proof_completed_at, str) or UTC_SECONDS.fullmatch(proof_completed_at) is None:
        raise EvidenceTimingRefusal("proof.completed_at: canonical UTC whole seconds required")
    proof_completed = parse_instant(proof_completed_at, "proof.completed_at")
    if not isinstance(observations, list) or len(observations) != len(rules):
        raise EvidenceTimingRefusal("proof: one explicit observation is required for every timing rule")
    checks = [rule.check for rule in rules]
    if any(not isinstance(check, str) or not check for check in checks) or len(set(checks)) != len(checks):
        raise EvidenceTimingRefusal("rules: unique nonempty checks required")

    accepted = []
    for position, (record, rule) in enumerate(zip(observations, rules), 1):
        if not isinstance(record, dict) or set(record) != {"check", "observed_at", "result"}:
            raise EvidenceTimingRefusal(f"observation {position}: exact wire shape required")
        if record["check"] != rule.check or record["result"] != "observed":
            raise EvidenceTimingRefusal(f"observation {position}: expected explicit {rule.check!r} observation")
        if not isinstance(record["observed_at"], str) or UTC_SECONDS.fullmatch(record["observed_at"]) is None:
            raise EvidenceTimingRefusal(f"observation {rule.check!r}: canonical UTC whole seconds required")
        if not rule.required_sources or not rule.not_before or not rule.not_after:
            raise EvidenceTimingRefusal(f"rule {rule.check!r}: explicit sources and time anchors required")
        if len(set(rule.required_sources)) != len(rule.required_sources) or PROOF_SOURCE in rule.required_sources:
            raise EvidenceTimingRefusal(f"rule {rule.check!r}: invalid required source list")
        anchor_sources = {anchor.source for anchor in (*rule.not_before, *rule.not_after) if anchor.source != PROOF_SOURCE}
        if not anchor_sources.issubset(set(rule.required_sources)):
            raise EvidenceTimingRefusal(f"rule {rule.check!r}: anchor source is not explicitly required")
        for source_id in rule.required_sources:
            # Requiring a source is independent of whether its event supplies the limiting bound.
            _validated_source(
                source_id, sources, scenario_id, qualification_manifest_sha256, request_sha256
            )
        earliest = max(
            _source_event(anchor.source, anchor.event, sources, proof_completed_at, scenario_id, qualification_manifest_sha256, request_sha256)
            for anchor in rule.not_before
        )
        latest = min(
            _source_event(anchor.source, anchor.event, sources, proof_completed_at, scenario_id, qualification_manifest_sha256, request_sha256)
            for anchor in rule.not_after
        )
        observed = parse_instant(record["observed_at"], f"observation {rule.check}.observed_at")
        if earliest > latest:
            raise EvidenceTimingRefusal(f"rule {rule.check!r}: source event interval is impossible")
        if observed < earliest or observed > latest or observed > proof_completed:
            raise EvidenceTimingRefusal(f"observation {rule.check!r}: outside authenticated source event bounds")
        accepted.append(record)
    return tuple(accepted)


def _rule(check: str, sources: tuple[str, ...], *before: Anchor, after: tuple[Anchor, ...] = (Anchor(PROOF_SOURCE, "completed_at"),)) -> ObservationRule:
    return ObservationRule(check, sources, before, after)


S07 = "state"
O07 = "outside"
E07 = "entry"
T07 = "controller"
SCENARIO_07_RULES = (
    _rule("fresh-disposable-vps-preflight", (E07,), Anchor(E07, "preflight_completed_at")),
    _rule("unchanged-candidate-bytes", (E07,), Anchor(E07, "final_candidate_checked_at")),
    _rule("initial-state-proved", (S07, E07), Anchor(S07, "setup_at"), Anchor(E07, "running_proved_at")),
    _rule("boundary-observed", (S07, O07), Anchor(S07, "rotation_completed_at"), Anchor(O07, "old_terminated_at")),
    _rule("final-state-proved", (S07, E07), Anchor(S07, "absence_at"), Anchor(E07, "final_state_proved_at")),
    _rule("original-ssh-continuity", (E07,), Anchor(E07, "ssh_continuity_at")),
    _rule("capture-coverage-complete", (E07,), Anchor(E07, "capture_coverage_at")),
    _rule("exact-secrets-absent", (E07,), Anchor(E07, "exact_secrets_absent_at")),
    _rule("prohibited-patterns-absent", (E07,), Anchor(E07, "prohibited_patterns_absent_at")),
    _rule("supported-effective-route-inspected", ("route",), Anchor("route", "completed_at")),
    _rule("old-established-outside-session", (O07,), Anchor(O07, "old_established_at")),
    _rule("outside-target-healthy", (O07,), Anchor(O07, "target_healthy_at")),
    _rule("startup-publication", (T07,), Anchor(T07, "startup_published_at")),
    _rule("reload", (T07,), Anchor(T07, "reload_verified_at")),
    _rule("effective-route", (T07,), Anchor(T07, "effective_route_verified_at")),
    _rule("source-only-before-gate", (T07,), Anchor(T07, "source_only_before_gate_at")),
    _rule("ordinary-start-denied-after-gate", (T07,), Anchor(T07, "ordinary_start_denied_at")),
    _rule("unchanged-link-and-noncredential-fields", (E07,), Anchor(E07, "noncredential_fields_compared_at")),
    _rule("owned-process-groups-and-descendants-terminated", (O07, E07), Anchor(O07, "old_terminated_at"), Anchor(E07, "source_group_empty_at")),
    _rule("old-new-connections-refused", (O07,), Anchor(O07, "old_terminated_at"), Anchor(O07, "old_refused_at")),
    _rule("replacement-traffic-proved", (O07,), Anchor(O07, "replacement_at")),
    _rule("subscription-remains-absent", (E07,), Anchor(E07, "subscription_absent_at")),
    _rule("absent-subscription-fallback", (O07, E07), Anchor(O07, "replacement_at"), Anchor(E07, "fallback_confirmed_at")),
    _rule("candidate-supported-setup-origin", (S07, E07), Anchor(S07, "setup_at"), Anchor(E07, "candidate_setup_origin_at"), after=(Anchor(S07, "rotation_started_at"),)),
    _rule("schema1-rotation-origin", (S07, E07), Anchor(S07, "setup_at"), Anchor(E07, "schema1_origin_at"), after=(Anchor(S07, "rotation_started_at"),)),
    _rule("reviewed-complete-removal", (S07, E07), Anchor(S07, "absence_at"), Anchor(E07, "removal_completed_at")),
    _rule("complete-owned-absence", (S07, E07), Anchor(S07, "absence_at"), Anchor(E07, "owned_absence_at")),
    _rule("no-certificate-request", (E07,), Anchor(E07, "issuance_unchanged_at")),
)


S08 = "state"
N08 = "connection"
U08 = "subscription"
E08 = "entry"
SCENARIO_08_RULES = (
    _rule("fresh-disposable-vps-preflight", (E08,), Anchor(E08, "preflight_completed_at")),
    _rule("unchanged-candidate-bytes", (E08,), Anchor(E08, "final_candidate_checked_at")),
    _rule("initial-state-proved", (S08, E08), Anchor(S08, "setup_at"), Anchor(E08, "running_proved_at")),
    _rule("boundary-observed", (S08,), Anchor(S08, "action_completed_at")),
    _rule("final-state-proved", (E08,), Anchor(E08, "final_state_proved_at")),
    _rule("original-ssh-continuity", (E08,), Anchor(E08, "ssh_continuity_at")),
    _rule("capture-coverage-complete", (E08,), Anchor(E08, "capture_coverage_at")),
    _rule("exact-secrets-absent", (E08,), Anchor(E08, "exact_secrets_absent_at")),
    _rule("prohibited-patterns-absent", (E08,), Anchor(E08, "prohibited_patterns_absent_at")),
    _rule("supported-effective-route-inspected", ("route",), Anchor("route", "completed_at")),
    _rule("proxy-and-traffic-unchanged", (N08, E08), Anchor(N08, "last_at"), Anchor(E08, "proxy_unchanged_at")),
    _rule("client-identity-unchanged", (E08,), Anchor(E08, "client_identity_unchanged_at")),
    _rule("schema1-conversion", (S08, E08), Anchor(S08, "action_completed_at"), Anchor(E08, "schema_conversion_verified_at")),
    _rule("creation-provenance-preserved", (E08,), Anchor(E08, "creation_provenance_verified_at")),
    _rule("enabled-generation-agreement", (N08, U08, E08), Anchor(N08, "last_at"), Anchor(U08, "observed_at"), Anchor(E08, "generation_agreement_at")),
    _rule("authoritative-link-disclosed", (S08, U08, E08), Anchor(S08, "action_completed_at"), Anchor(U08, "observed_at"), Anchor(E08, "link_binding_verified_at")),
    _rule("candidate-supported-setup-origin", (S08, E08), Anchor(S08, "setup_at"), Anchor(E08, "candidate_setup_origin_at"), after=(Anchor(S08, "action_started_at"),)),
    _rule("no-protected-state-edit", (E08,), Anchor(E08, "protected_state_audit_at")),
    _rule("no-unsupported-migration", (E08,), Anchor(E08, "supported_action_audit_at")),
)


LINK_COMMON_RULES = (
    _rule("fresh-disposable-vps-preflight", ("entry", "controller"), Anchor("entry", "preflight_completed_at"),
          after=(Anchor("controller", "action_started_at"),)),
    _rule("unchanged-candidate-bytes", ("entry", "controller"), Anchor("controller", "recovered_at"), Anchor("entry", "final_candidate_checked_at")),
    _rule("initial-state-proved", ("entry", "outside", "controller"), Anchor("entry", "running_proved_at"), Anchor("outside", "old_initial_at"),
          after=(Anchor("controller", "action_started_at"),)),
    _rule("boundary-observed", ("controller",), Anchor("controller", "interrupted_at"),
          after=(Anchor("controller", "recovery_started_at"),)),
    _rule("final-state-proved", ("controller", "outside", "entry"), Anchor("controller", "recovered_at"), Anchor("outside", "old_final_at"), Anchor("entry", "final_state_proved_at")),
    _rule("original-ssh-continuity", ("entry",), Anchor("entry", "ssh_continuity_at")),
    _rule("capture-coverage-complete", ("entry",), Anchor("entry", "capture_coverage_at")),
    _rule("exact-secrets-absent", ("entry",), Anchor("entry", "exact_secrets_absent_at")),
    _rule("prohibited-patterns-absent", ("entry",), Anchor("entry", "prohibited_patterns_absent_at")),
    _rule("supported-effective-route-inspected", ("route", "controller"), Anchor("route", "completed_at"),
          after=(Anchor("controller", "action_started_at"),)),
    _rule("proxy-and-traffic-unchanged", ("connection", "entry", "controller"), Anchor("connection", "last_at"), Anchor("controller", "recovered_at"), Anchor("entry", "proxy_unchanged_at")),
    _rule("client-identity-unchanged", ("entry", "outside"), Anchor("outside", "old_final_at"), Anchor("entry", "client_identity_unchanged_at")),
    _rule("one-prepared-target", ("controller",), Anchor("controller", "target_prepared_at"),
          after=(Anchor("controller", "recovery_started_at"),)),
)

LINK_PRECOMMIT_RULES = LINK_COMMON_RULES + (
    _rule("old-serving-quiesced", ("controller", "outside"), Anchor("controller", "quiesced_at"), Anchor("outside", "closed_at"),
          after=(Anchor("controller", "recovery_started_at"),)),
    _rule("old-generation-restored", ("controller", "outside"), Anchor("controller", "recovered_at"), Anchor("outside", "old_final_at")),
    _rule("unused-target-removed", ("controller", "entry"), Anchor("controller", "recovered_at"), Anchor("entry", "staging_absent_at")),
    _rule("old-link-usable", ("outside",), Anchor("outside", "old_final_at")),
    _rule("no-replacement-disclosure", ("entry", "controller"), Anchor("controller", "recovered_at"), Anchor("entry", "disclosure_audited_at")),
)

LINK_POSTCOMMIT_RULES = LINK_COMMON_RULES + (
    _rule("no-old-process-or-request-overlap", ("controller", "outside"), Anchor("controller", "quiesced_at"), Anchor("outside", "closed_at"),
          after=(Anchor("controller", "recovery_started_at"),)),
    _rule("target-only-finishing", ("controller",), Anchor("controller", "recovered_at")),
    _rule("old-link-404", ("outside",), Anchor("outside", "old_final_at")),
    _rule("new-link-usable", ("outside",), Anchor("outside", "new_final_at")),
)


def later_common_rules() -> tuple[ObservationRule, ...]:
    """Current-request operator observations shared by scenarios 11–25."""
    return (
        _rule('fresh-disposable-vps-preflight', ('entry', 'state'), Anchor('entry', 'preflight_completed_at'),
              after=(Anchor('state', 'action_started_at'),)),
        _rule('unchanged-candidate-bytes', ('entry',), Anchor('entry', 'final_candidate_checked_at')),
        _rule('initial-state-proved', ('entry', 'state'), Anchor('entry', 'running_proved_at'),
              after=(Anchor('state', 'action_started_at'),)),
        _rule('boundary-observed', ('entry', 'state'), Anchor('entry', 'boundary_observed_at'), Anchor('state', 'action_started_at'),
              after=(Anchor('state', 'action_completed_at'),)),
        _rule('final-state-proved', ('entry', 'state'), Anchor('entry', 'final_state_proved_at'), Anchor('state', 'action_completed_at')),
        _rule('original-ssh-continuity', ('entry', 'state'), Anchor('entry', 'ssh_continuity_at'), Anchor('state', 'completed_at')),
        _rule('capture-coverage-complete', ('entry', 'state'), Anchor('entry', 'capture_coverage_at'), Anchor('state', 'completed_at')),
        _rule('exact-secrets-absent', ('entry', 'state'), Anchor('entry', 'exact_secrets_absent_at'), Anchor('state', 'completed_at')),
        _rule('prohibited-patterns-absent', ('entry', 'state'), Anchor('entry', 'prohibited_patterns_absent_at'), Anchor('state', 'completed_at')),
        _rule('supported-effective-route-inspected', ('route', 'state'), Anchor('route', 'completed_at'),
              after=(Anchor('state', 'action_started_at'),)),
    )


def scenario_rules(scenario_id: str) -> tuple[ObservationRule, ...]:
    if scenario_id == "identity-absent":
        return SCENARIO_07_RULES
    if scenario_id == "enable-schema1":
        return SCENARIO_08_RULES
    if scenario_id == "link-precommit":
        return LINK_PRECOMMIT_RULES
    if scenario_id == "link-postcommit":
        return LINK_POSTCOMMIT_RULES
    raise EvidenceTimingRefusal(f"scenario {scenario_id!r}: no tracked timing rules")
