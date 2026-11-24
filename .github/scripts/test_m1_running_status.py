"""Offline regressions for the manual M1 running-state readback."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

SCRIPTS = Path(__file__).resolve().parent
MODULE = SCRIPTS / "v3-packaged-live.sh"
# Reduced native menu. The setup result belongs to the preceding action.
FRAME = """SBXR V3
Proxy status: Running
Subscription status: Not enabled
Software Lifecycle: Ready
Result: SBXR is ready.
Code: SOFTWARE-LIFECYCLE-STATUS-READY
Proxy traffic: cannot be verified
1. Complete removal
0. Exit
Choose: """


class RunningStatus(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.product = self.root / "sbxr"
        self.product.write_text(
            "#!/bin/bash\n"
            'read -r choice && [[ $choice == 0 ]] || exit 9\n'
            'sleep "$DELAY"\nprintf "%s" "$FRAME"\nexit "$MENU_RC"\n'
        )
        self.product.chmod(0o700)

    def observe(self, frame=FRAME, menu_rc=0):
        # Exercise the same conditional calling context as remote_outside_disclose.
        script = 'source "$1"; function /usr/local/bin/sbxr { "$FIXTURE"; }; prove_running || exit $?'
        return subprocess.run(
            ["bash", "-c", script, "fixture", str(MODULE)],
            env=dict(os.environ, FRAME=frame, MENU_RC=str(menu_rc), DELAY="0", FIXTURE=str(self.product)),
            capture_output=True, timeout=5,
        )

    def test_current_running_frame(self):
        result = self.observe()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_failing_menu_cannot_pass_via_its_stdout(self):
        self.assertNotEqual(self.observe(menu_rc=7).returncode, 0)

    def test_retained_go_menu_with_its_status_result(self):
        legacy = FRAME.replace("SBXR V3\n", "SBXR V3\nVersion: v3.0.0\n")
        proxy_result = "Code: PROXY-INSTALLATION-SETUP-COMPLETE\n"
        legacy = legacy.replace("Software Lifecycle: Ready\n", proxy_result + "Software Lifecycle: Ready\n")
        self.assertEqual(self.observe(legacy).returncode, 0)

    def test_incomplete_conflicting_and_non_native_frames(self):
        for frame in (
            FRAME.replace("Proxy status: Running", "Proxy status: Not set up"),
            FRAME.replace("Proxy status: Running", "Proxy status: Running (fixture)"),
            FRAME.replace("Proxy status: Running", "Proxy status: Problem detected\nProxy status: Running"),
            FRAME.replace("0. Exit", ""),
            FRAME.replace("Software Lifecycle: Ready", "Software Lifecycle: Recovery required"),
            FRAME.replace("SOFTWARE-LIFECYCLE-STATUS-READY", "SOFTWARE-LIFECYCLE-CHECK-REFUSED"),
            FRAME.replace("Code: SOFTWARE-LIFECYCLE-STATUS-READY", "Code: PROXY-INSTALLATION-SETUP-COMPLETE"),
            FRAME + "\n" + FRAME,
        ):
            with self.subTest(frame=frame):
                self.assertNotEqual(self.observe(frame).returncode, 0)

    def bounded(self, delay, *, remaining=1500, guard=":"):
        # The inert transport receives the real remote command and module. Only
        # the installed executable is redirected, inside this fixture process.
        transport = self.root / "transport"
        transport.write_text(
            "#!/bin/bash\nset -eu\n"
            'touch "$ENTERED"\n'
            'sed "s|/usr/local/bin/sbxr|$FIXTURE|g" | bash -c "$1"\n'
        )
        transport.chmod(0o700)
        env = dict(os.environ, FRAME=FRAME, MENU_RC="0", DELAY=str(delay),
                   FIXTURE=str(self.product), ENTERED=str(self.root / "entered"))
        script = 'source "$1"; observe_m1_running "$2" "$3" "$4" "$5" < "$1"'
        return subprocess.run(
            ["bash", "-c", script, "fixture", str(MODULE), str(self.root),
             str(int(time.time()) + remaining), guard, str(transport)],
            env=env, capture_output=True, timeout=95,
        )

    def test_slow_healthy_status_within_existing_read_only_batch(self):
        result = self.bounded(35)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "entered").exists())

    def test_real_observer_timeout(self):
        result = self.bounded(75)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertEqual((self.root / "m1-prove-running.operator.stdout").read_bytes(), b"")

    def test_refuses_before_transport_when_full_reserve_cannot_fit(self):
        result = self.bounded(0, remaining=980)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "entered").exists())

    def test_guard_failure_propagates_before_readback(self):
        result = self.bounded(0, guard="exit 42")
        self.assertEqual(result.returncode, 42)

    def test_remote_remaining_time_rechecked_after_identity_checks(self):
        # Simulate a later host clock at the remote boundary only.
        result = self.bounded(0, guard='date() { echo 4000000000; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / "entered").exists())

    def test_unavailable_remote_clock_refuses_readback(self):
        self.assertNotEqual(self.bounded(0, guard="date() { return 1; }").returncode, 0)


if __name__ == "__main__":
    unittest.main()
