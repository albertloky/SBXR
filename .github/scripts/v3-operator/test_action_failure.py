"""Regression coverage for scanned action output when the real menu driver fails."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


HERE = Path(__file__).resolve().parent
SUPPORT = HERE / "operator-support.sh"

SAFE_LINES = (
    "Failed safety check: fixture mismatch\n"
    "Correction: inspect the interrupted operation\n"
    "Result: fixture refused the finishing action\n"
    "Code: PROXY-INSTALLATION-ACTION-REFUSED\n"
)

FIXTURE = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

mode = os.environ["ACTION_FIXTURE_MODE"]
events = Path(os.environ["ACTION_FIXTURE_EVENTS"])

def record(value):
    with events.open("a") as stream:
        stream.write(json.dumps(value, separators=(",", ":")) + "\n")

if mode in ("label-missing", "label-missing-secret"):
    record({"event": "started", "pid": os.getpid()})
    print("SBXR V3")
    print("Proxy status: Running")
    print("Subscription status: Available")
    print("Software Lifecycle: Ready")
    print("Code: SOFTWARE-LIFECYCLE-STATUS-READY")
    print("1. View details")
    print("2. Show client configuration")
    print("3. Rotate Client Identity")
    if mode == "label-missing-secret":
        print("Diagnostic: " + os.environ["KNOWN_CLIENT_UUID"])
    print("4. Check")
    print("5. Update")
    print("6. Recover")
    print("0. Exit", flush=True)
    choice = sys.stdin.readline().strip()
    record({"event": "choice", "value": choice})
    raise SystemExit(93)

print("SBXR V3")
print("Proxy status: Setup incomplete")
print("Code: PROXY-INSTALLATION-STATUS-SETUP-INCOMPLETE")
print("1. Finish cleanup")
print("0. Exit", flush=True)
choice = sys.stdin.readline().strip()
record({"choice": choice})
if choice != "1":
    raise SystemExit(90)
print("Finish proxy cleanup? [y/N]", flush=True)
confirmation = sys.stdin.readline().strip()
record({"confirmation": confirmation})
if confirmation != "y":
    raise SystemExit(91)

if mode == "success":
    print("Code: PROXY-INSTALLATION-SETUP-CLEANED-UP")
    print("SBXR V3")
    print("Proxy status: Not set up")
    print("Software Lifecycle: Ready")
    print("Code: PROXY-INSTALLATION-STATUS-NOT-SET-UP")
    print("1. Start setup")
    print("0. Exit", flush=True)
    exit_choice = sys.stdin.readline().strip()
    record({"exit": exit_choice})
    raise SystemExit(0 if exit_choice == "0" else 92)

print("Failed safety check: fixture mismatch")
print("Correction: inspect the interrupted operation")
print("Result: fixture refused the finishing action")
if mode == "secret":
    print("Captured value: " + os.environ["KNOWN_CLIENT_UUID"])
print("Code: PROXY-INSTALLATION-ACTION-REFUSED", flush=True)
raise SystemExit(0)
'''


class ActionFailureTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.executable = self.root / "sbxr"
        self.executable.write_text(FIXTURE)
        self.executable.chmod(0o700)
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text("{}")
        self.request = self.root / "request.json"
        self.request.write_text(json.dumps({"deadline_unix": 4102444800}))
        for name in ("state", "evidence", "transport"):
            (self.root / name).mkdir(mode=0o700)

    def invoke(self, interface, mode, stale="", label="Finish cleanup"):
        events = self.root / f"{interface}-{mode}.events"
        retained = self.root / f"{interface}-{mode}.retained"
        script = textwrap.dedent(
            f"""\
            source {str(SUPPORT)!r}
            LAST_ACTION_OUTPUT={stale!r}
            status=0
            if {interface} {label!r} y 'Code: PROXY-INSTALLATION-SETUP-CLEANED-UP'; then
              status=0
            else
              status=$?
            fi
            printf '%s' "${{LAST_ACTION_OUTPUT:-}}" > {str(retained)!r}
            exit "$status"
            """
        )
        environment = os.environ.copy()
        environment.update({
            "ACTION_FIXTURE_EVENTS": str(events),
            "ACTION_FIXTURE_MODE": mode,
            "KNOWN_CLIENT_UUID": "11111111-2222-4333-8444-555555555555",
            "SBXR_EXECUTABLE": str(self.executable),
            "SBXR_INSTALLED_RECORD": str(self.root / "installed.json"),
            "SBXR_OPERATOR_EVIDENCE_DIR": str(self.root / "evidence"),
            "SBXR_OPERATOR_STATE_DIR": str(self.root / "state"),
            "SBXR_QUALIFICATION_MANIFEST": str(self.manifest),
            "SBXR_QUALIFICATION_REQUEST": str(self.request),
            "SBXR_TRANSPORT_ROOT": str(self.root / "transport"),
            "SBXR_TRANSPORT_UNIT": "fixture.service",
            "SBXR_V3_PACKAGED_LIVE_MODULE": str(HERE.parent / "v3-packaged-live.sh"),
        })
        result = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-c", script],
            env=environment, text=True, capture_output=True, timeout=10,
        )
        observed = [json.loads(line) for line in events.read_text().splitlines()]
        return result, retained.read_text(), observed

    def assert_fixture_process_cleaned_up(self, events):
        pid = events[0]["pid"]
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_driver_failure_is_scanned_retained_and_reported_by_both_interfaces(self):
        for interface in ("run_action", "action"):
            with self.subTest(interface=interface):
                result, retained, events = self.invoke(interface, "failure", "stale output")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, SAFE_LINES)
                self.assertEqual(result.stdout.count("Failed safety check:"), 1)
                self.assertIn(SAFE_LINES.rstrip("\n"), retained)
                self.assertNotIn("stale output", retained)
                self.assertEqual(events, [{"choice": "1"}, {"confirmation": "y"}])

    def test_secret_bearing_failure_clears_stale_output_without_exposure(self):
        for interface in ("run_action", "action"):
            with self.subTest(interface=interface):
                result, retained, events = self.invoke(interface, "secret", "stale output")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(retained, "")
                self.assertNotIn("11111111-2222-4333-8444-555555555555",
                                 result.stdout + result.stderr)
                self.assertEqual(events, [{"choice": "1"}, {"confirmation": "y"}])

    def test_success_is_quiet_and_retains_the_real_driver_capture(self):
        for interface in ("run_action", "action"):
            with self.subTest(interface=interface):
                result, retained, events = self.invoke(interface, "success", "stale output")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn("Code: PROXY-INSTALLATION-SETUP-CLEANED-UP", retained)
                self.assertNotIn("stale output", retained)
                self.assertEqual(events, [{"choice": "1"}, {"confirmation": "y"},
                                          {"exit": "0"}])

    def test_missing_label_reports_the_scanned_initial_menu_without_selecting(self):
        expected = (
            "SBXR V3\n"
            "Proxy status: Running\n"
            "Subscription status: Available\n"
            "Software Lifecycle: Ready\n"
            "Code: SOFTWARE-LIFECYCLE-STATUS-READY\n"
            "1. View details\n"
            "2. Show client configuration\n"
            "3. Rotate Client Identity\n"
            "4. Check\n"
            "5. Update\n"
            "6. Recover\n"
            "0. Exit\n"
        )
        for interface in ("run_action", "action"):
            with self.subTest(interface=interface):
                result, retained, events = self.invoke(
                    interface, "label-missing", "stale output", "Rotate subscription link")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, expected)
                self.assertIn(
                    "SBXR_MENU_SESSION_REFUSED phase=label-missing "
                    "code=SOFTWARE-LIFECYCLE-STATUS-READY",
                    result.stderr,
                )
                self.assertEqual(retained, expected.rstrip("\n"))
                self.assertNotIn("stale output", retained)
                self.assertEqual([event["event"] for event in events], ["started"])
                self.assert_fixture_process_cleaned_up(events)

    def test_secret_in_missing_label_initial_menu_is_not_reported_or_retained(self):
        for interface in ("run_action", "action"):
            with self.subTest(interface=interface):
                result, retained, events = self.invoke(
                    interface, "label-missing-secret", "stale output", "Rotate subscription link")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(retained, "")
                self.assertNotIn("11111111-2222-4333-8444-555555555555",
                                 result.stdout + result.stderr)
                self.assertEqual([event["event"] for event in events], ["started"])
                self.assert_fixture_process_cleaned_up(events)


if __name__ == "__main__":
    unittest.main()
