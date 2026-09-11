import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).with_name("evidence-timing.py")
SPEC = importlib.util.spec_from_file_location("evidence_timing", MODULE_PATH)
timing = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = timing
SPEC.loader.exec_module(timing)


REQUEST = hashlib.sha256(b"current request").hexdigest()
MANIFEST = hashlib.sha256(b"signed manifest").hexdigest()


def sources_for(scenario, rules, at="2030-01-01T00:00:05Z"):
    events = {}
    for rule in rules:
        for anchor in (*rule.not_before, *rule.not_after):
            if anchor.source != timing.PROOF_SOURCE:
                events.setdefault(anchor.source, {})[anchor.event] = at
        for source in rule.required_sources:
            events.setdefault(source, {})
    # The origin checks have a real pre-action upper bound after their lower event.
    if "state" in events:
        if "rotation_started_at" in events["state"]:
            events["state"]["rotation_started_at"] = "2030-01-01T00:00:08Z"
        if "action_started_at" in events["state"]:
            events["state"]["action_started_at"] = "2030-01-01T00:00:08Z"
    return {
        source: timing.EventSource(
            source, scenario, MANIFEST, REQUEST, source.encode(), hashlib.sha256(source.encode()).hexdigest(), values
        )
        for source, values in events.items()
    }


def records(rules, at):
    return [{"check": rule.check, "observed_at": at, "result": "observed"} for rule in rules]


class EvidenceTimingTests(unittest.TestCase):
    def validate(self, scenario, rules, source_values, observed="2030-01-01T00:00:06Z"):
        return timing.validate_observations(
            scenario_id=scenario,
            qualification_manifest_sha256=MANIFEST,
            request_sha256=REQUEST,
            observations=records(rules, observed),
            proof_completed_at="2030-01-01T00:00:20Z",
            rules=rules,
            sources=source_values,
        )

    def test_scenario_07_rejects_all_checks_at_scenario_start(self):
        rules = timing.scenario_rules("identity-absent")
        with self.assertRaisesRegex(timing.EvidenceTimingRefusal, "source event bounds"):
            self.validate("identity-absent", rules, sources_for("identity-absent", rules), "2030-01-01T00:00:00Z")

    def test_rule_order_matches_the_existing_07_and_08_wire_contract(self):
        common = """fresh-disposable-vps-preflight unchanged-candidate-bytes initial-state-proved
            boundary-observed final-state-proved original-ssh-continuity capture-coverage-complete
            exact-secrets-absent prohibited-patterns-absent supported-effective-route-inspected""".split()
        identity = """old-established-outside-session outside-target-healthy startup-publication reload
            effective-route source-only-before-gate ordinary-start-denied-after-gate
            unchanged-link-and-noncredential-fields owned-process-groups-and-descendants-terminated
            old-new-connections-refused replacement-traffic-proved subscription-remains-absent
            absent-subscription-fallback candidate-supported-setup-origin schema1-rotation-origin
            reviewed-complete-removal complete-owned-absence no-certificate-request""".split()
        enable = """proxy-and-traffic-unchanged client-identity-unchanged schema1-conversion
            creation-provenance-preserved enabled-generation-agreement authoritative-link-disclosed
            candidate-supported-setup-origin no-protected-state-edit no-unsupported-migration""".split()
        self.assertEqual([rule.check for rule in timing.SCENARIO_07_RULES], common + identity)
        self.assertEqual([rule.check for rule in timing.SCENARIO_08_RULES], common + enable)

    def test_scenario_08_rejects_all_checks_at_scenario_start(self):
        rules = timing.scenario_rules("enable-schema1")
        with self.assertRaisesRegex(timing.EvidenceTimingRefusal, "source event bounds"):
            self.validate("enable-schema1", rules, sources_for("enable-schema1", rules), "2030-01-01T00:00:00Z")

    def test_both_complete_rule_sets_accept_explicit_post_source_observations(self):
        for scenario in ("identity-absent", "enable-schema1"):
            with self.subTest(scenario=scenario):
                rules = timing.scenario_rules(scenario)
                accepted = self.validate(scenario, rules, sources_for(scenario, rules))
                self.assertEqual([record["check"] for record in accepted], [rule.check for rule in rules])

    def test_fractional_source_is_compared_at_full_resolution(self):
        rule = timing.ObservationRule(
            "later-fact",
            ("receipt",),
            (timing.Anchor("receipt", "fact_at"),),
            (timing.Anchor(timing.PROOF_SOURCE, "completed_at"),),
        )
        source = timing.EventSource(
            "receipt", "identity-absent", MANIFEST, REQUEST, b"receipt", hashlib.sha256(b"receipt").hexdigest(),
            {"fact_at": "2030-01-01T00:00:05.000000001Z"},
        )
        with self.assertRaisesRegex(timing.EvidenceTimingRefusal, "source event bounds"):
            self.validate("identity-absent", (rule,), {"receipt": source}, "2030-01-01T00:00:05Z")
        self.assertEqual(timing.ceil_wire_timestamp("2030-01-01T00:00:05.000000001Z"), "2030-01-01T00:00:06Z")
        self.validate("identity-absent", (rule,), {"receipt": source}, "2030-01-01T00:00:06Z")

    def test_missing_required_source_and_event_fail_closed(self):
        rule = timing.ObservationRule(
            "linked", ("receipt",), (timing.Anchor("receipt", "fact_at"),),
            (timing.Anchor(timing.PROOF_SOURCE, "completed_at"),),
        )
        with self.assertRaisesRegex(timing.EvidenceTimingRefusal, "required artifact is missing"):
            self.validate("identity-absent", (rule,), {})
        source = timing.EventSource("receipt", "identity-absent", MANIFEST, REQUEST, b"x", hashlib.sha256(b"x").hexdigest(), {})
        with self.assertRaisesRegex(timing.EvidenceTimingRefusal, "required event"):
            self.validate("identity-absent", (rule,), {"receipt": source})

    def test_wrong_request_binding_is_refused(self):
        rule = timing.ObservationRule(
            "linked", ("receipt",), (timing.Anchor("receipt", "fact_at"),),
            (timing.Anchor(timing.PROOF_SOURCE, "completed_at"),),
        )
        source = timing.EventSource(
            "receipt", "identity-absent", MANIFEST, "0" * 64, b"x", hashlib.sha256(b"x").hexdigest(),
            {"fact_at": "2030-01-01T00:00:05Z"},
        )
        with self.assertRaisesRegex(timing.EvidenceTimingRefusal, "binding"):
            self.validate("identity-absent", (rule,), {"receipt": source})

    def test_artifact_digest_must_bind_the_exact_supplied_bytes(self):
        rule = timing.ObservationRule(
            "linked", ("receipt",), (timing.Anchor("receipt", "fact_at"),),
            (timing.Anchor(timing.PROOF_SOURCE, "completed_at"),),
        )
        source = timing.EventSource(
            "receipt", "identity-absent", MANIFEST, REQUEST, b"changed",
            hashlib.sha256(b"expected").hexdigest(), {"fact_at": "2030-01-01T00:00:05Z"},
        )
        with self.assertRaisesRegex(timing.EvidenceTimingRefusal, "SHA-256"):
            self.validate("identity-absent", (rule,), {"receipt": source})

    def test_rule_without_explicit_anchors_is_refused(self):
        rule = timing.ObservationRule("unanchored", ("receipt",), (), ())
        source = timing.EventSource(
            "receipt", "identity-absent", MANIFEST, REQUEST, b"x", hashlib.sha256(b"x").hexdigest(),
            {"fact_at": "2030-01-01T00:00:05Z"},
        )
        with self.assertRaisesRegex(timing.EvidenceTimingRefusal, "explicit sources and time anchors"):
            self.validate("identity-absent", (rule,), {"receipt": source})

    def test_pre_gate_wire_observation_cannot_precede_its_source_receipt(self):
        rule = next(rule for rule in timing.SCENARIO_07_RULES if rule.check == "source-only-before-gate")
        source_values = sources_for("identity-absent", (rule,))
        with self.assertRaisesRegex(timing.EvidenceTimingRefusal, "source event bounds"):
            self.validate("identity-absent", (rule,), source_values, "2030-01-01T00:00:04Z")


if __name__ == "__main__":
    unittest.main()
