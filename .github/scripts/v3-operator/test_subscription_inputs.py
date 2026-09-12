"""Run both protected input scripts with fixture menu and certificate producers."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
CONFIGURATION = {"outbounds": [{"type": "fixture", "credential": "test-only"}]}
LINK = "https://203.0.113.7:8443/s/" + "A" * 43

MODULE = r'''
run_action() { :; }
exact_candidate() { :; }
install_candidate() { :; }
prove_running() { :; }
menu_session_details() {
  if test "$SBXR_INPUT_FIXTURE_MODE" != missing-link; then printf '%s\n' "$SBXR_INPUT_FIXTURE_LINK"; fi
}
openssl() { printf 'fixture-certificate'; }
remote_outside_disclose() {
  printf '%s\n' '{"outbounds":[{"type":"fixture","credential":"test-only"}]}'
  # A producer may write complete-looking bytes and still fail its final checks.
  test "$SBXR_INPUT_FIXTURE_MODE" != failed-disclosure
}
'''


class SubscriptionInputTest(unittest.TestCase):
    def invoke(self, name, scenario, mode):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "packaged-live.sh"
            module.write_text(MODULE)
            manifest = root / "manifest.json"
            manifest.write_text("{}")
            manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
            request = root / "request.json"
            request.write_text(json.dumps({"scenario_id": scenario,
                "qualification_manifest_sha256": manifest_sha,
                "not_before": "2030-01-01T00:00:00Z", "deadline_unix": 4102444800}))
            env = dict(os.environ,
                SBXR_V3_PACKAGED_LIVE_MODULE=str(module),
                SBXR_QUALIFICATION_MANIFEST=str(manifest),
                SBXR_QUALIFICATION_REQUEST=str(request),
                SBXR_INSTALLED_RECORD=str(root / "installed.json"),
                SBXR_EXECUTABLE=str(root / "unused-executable"),
                SBXR_OPERATOR_STATE_DIR=str(root),
                SBXR_OPERATOR_EVIDENCE_DIR=str(root),
                SBXR_TRANSPORT_ROOT=str(root),
                SBXR_TRANSPORT_UNIT="fixture.service",
                SBXR_INPUT_FIXTURE_LINK=LINK,
                SBXR_INPUT_FIXTURE_MODE=mode)
            args = ["/bin/bash", str(ROOT / name)]
            if name.startswith("link-"):
                args.append(scenario)
            return subprocess.run(args, env=env, text=True, capture_output=True, timeout=10)

    def cases(self):
        yield "subscription-observation-input.sh", "enable-schema1"
        for scenario in ("link-precommit", "link-postcommit", "managed-renewal",
                         "recorder-live", "recorder-locks", "snap-refresh",
                         "unsupported-route", "identity-unavailable"):
            yield "link-subscription-input.sh", scenario

    def test_success_emits_the_current_confirmed_configuration_and_binding(self):
        for name, scenario in self.cases():
            with self.subTest(scenario=scenario):
                result = self.invoke(name, scenario, "normal")
                self.assertEqual(result.returncode, 0, result.stderr)
                document = json.loads(result.stdout)
                self.assertEqual(document["configuration"], CONFIGURATION)
                self.assertEqual(document["link"], LINK)
                self.assertEqual(document["binding"]["scenario_id"], scenario)
                self.assertEqual(document["certificate_der_sha256"],
                                 hashlib.sha256(b"fixture-certificate").hexdigest())

    def test_failed_disclosure_emits_no_observation_even_after_valid_looking_bytes(self):
        for name, scenario in self.cases():
            with self.subTest(scenario=scenario):
                result = self.invoke(name, scenario, "failed-disclosure")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("test-only", result.stderr)

    def test_missing_details_link_emits_no_observation(self):
        for name, scenario in self.cases():
            with self.subTest(scenario=scenario):
                result = self.invoke(name, scenario, "missing-link")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
