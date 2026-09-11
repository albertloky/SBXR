#!/usr/bin/env python3
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "admission_race_operator", HERE / "admission-race-operator.py")
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)


def line_reader(lines):
    values = iter(lines)
    return lambda _stream, _deadline: next(values)


class Input:
    def __init__(self):
        self.value = b""
        self.closed = False

    def write(self, value):
        self.value += value

    def flush(self):
        pass

    def close(self):
        self.closed = True


class Process:
    def __init__(self):
        self.stdin = Input()
        self.stdout = object()
        self.stderr = io.BytesIO()
        self.returncode = None
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self):
        self.killed = True
        self.returncode = -9


class AdmissionRaceOperatorTests(unittest.TestCase):
    def test_menu_is_held_at_exact_plan_before_confirmation(self):
        process = Process()
        prepared = operator.prepare_removal(process, time.monotonic() + 1, line_reader([
            "SBXR V3", "4. Complete removal", "0. Exit",
            "Complete removal deletes SBXR, proxy credentials, and every proved V3-owned resource from this VPS.",
            "Exact confirmation required: REMOVE SBXR", operator.CONFIRMATION_PROMPT,
        ]))
        self.assertEqual(process.stdin.value, b"4\n")
        self.assertEqual(prepared["action_number"], 4)

        refused = operator.complete_refusal(process, time.monotonic() + 1, line_reader([
            "Failed safety check: Prepared Action facts",
            "Correction: Review Complete removal again.",
            "Result: No changes were made.",
            "Code: PROXY-INSTALLATION-ACTION-REFUSED",
            "SBXR V3", "0. Exit",
        ]))
        self.assertEqual(process.stdin.value, b"4\nREMOVE SBXR\n0\n")
        self.assertTrue(refused["removal_commitment_absent"])

    def test_pipe_reader_does_not_block_past_deadline_on_partial_line(self):
        read_fd, write_fd = os.pipe()
        try:
            with os.fdopen(read_fd, "rb", buffering=0) as stream:
                os.write(write_fd, b"partial")
                with self.assertRaisesRegex(TimeoutError, "output deadline"):
                    operator.LineStream(stream).line(time.monotonic() + 0.01)
        finally:
            os.close(write_fd)

    def test_menu_refuses_missing_plan_or_removal_commitment(self):
        with self.assertRaisesRegex(ValueError, "plan is incomplete"):
            operator.prepare_removal(Process(), time.monotonic() + 1, line_reader([
                "1. Complete removal", "0. Exit", operator.CONFIRMATION_PROMPT,
            ]))
        with self.assertRaisesRegex(ValueError, "did not refuse before commitment"):
            operator.complete_refusal(Process(), time.monotonic() + 1, line_reader([
                "Progress: Removal committed",
                "Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED", "0. Exit",
            ]))

    def held(self):
        return {
            "state": "boundary-held", "mode": "admission", "recorder_pid": 21,
            "process_tick": 33, "attempt_id": "a" * 32, "receipt_sha256": "b" * 64,
            "writer": {"lock_state": "unlocked", "holders": []},
            "whole_host": {"lock_state": "unlocked", "holders": []},
            "admission": {"lock_state": "locked", "holders": [{"mode": "READ", "pid": 21}]},
            "actual_boundary": {"state": "boundary-held", "boundary": "after-close",
                                "path": "/run/lock/sbxr.lock", "pid": 21},
        }

    def test_held_event_requires_actual_recorder_lock_identity(self):
        operator.validate_held(self.held())
        for mutation in ("wrong-pid", "wrong-lock", "wrong-path"):
            value = self.held()
            if mutation == "wrong-pid":
                value["actual_boundary"]["pid"] = 22
            elif mutation == "wrong-lock":
                value["admission"] = {"lock_state": "unlocked", "holders": []}
            else:
                value["actual_boundary"]["path"] = "/tmp/lock"
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "boundary refused"):
                operator.validate_held(value)

    def exercise(self, drift=False, bad_held=False, stop_failure=False,
                 wrong_request=False, menu_drift=False):
        order = []
        menu, boundary = Process(), Process()
        held = self.held()
        if bad_held:
            held["admission"] = {"lock_state": "unlocked", "holders": []}
        events = iter([held, {"state": "completed", "no_ca_egress": True,
                             "receipt_sha256": "c" * 64}])
        snapshots = iter(["d" * 64, ("e" if drift else "d") * 64])
        timer = ["active", "enabled"]

        def stop_timer(_initial):
            order.append("timer-stop")
            timer[0] = "inactive"
            if stop_failure:
                raise ValueError("timer stop postcondition")

        def restore_timer(_state):
            order.append("timer-restore")
            timer[0] = "active"

        def prepare(*_args):
            order.append("menu-prepared")
            return {"action_number": 4, "prepared_at": "2026-01-01T00:00:00Z"}

        def refuse(*_args):
            order.append("removal-refused")
            return {"code": "PROXY-INSTALLATION-ACTION-REFUSED",
                    "failed_check": "Prepared Action facts",
                    "removal_commitment_absent": True,
                    "refused_at": "2026-01-01T00:00:01Z"}

        def snapshot():
            order.append("snapshot")
            return next(snapshots)

        def write(path, _value):
            order.append("write-" + path.name)

        def input_write(process, value):
            process.stdin.write(value)
            order.append("boundary-release" if process is boundary else "menu-input")

        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            deadline = int(time.time() + 100)
            menu_identities = [{"pid": 10, "start_tick": 20, "unit": "menu"},
                               {"pid": 11 if menu_drift else 10, "start_tick": 20, "unit": "menu"}]
            patches = [
                mock.patch.dict(os.environ, {
                    "STARTED_AT": "2026-01-01T00:00:00Z",
                    "SCENARIO_START": "2026-01-01T00:00:00Z",
                    "SBXR_OPERATOR_EVIDENCE_DIR": directory,
                    "SBXR_QUALIFICATION_REQUEST": "/request",
                    "SBXR_QUALIFICATION_MANIFEST": "/manifest",
                }, clear=True),
                mock.patch.object(operator.sys, "platform", "linux"),
                mock.patch.object(operator.os, "geteuid", return_value=0),
                mock.patch.object(operator, "evidence_directory", return_value=Path(directory)),
                mock.patch.object(operator, "stop_timer", side_effect=stop_timer),
                mock.patch.object(operator, "restore_timer", side_effect=restore_timer),
                mock.patch.object(operator, "timer_state", return_value=("active", "enabled")),
                mock.patch.object(operator, "pre_stop_preflight",
                    side_effect=ValueError("current request") if wrong_request else None,
                    return_value=(b"authority", b"authority", deadline)),
                mock.patch.object(operator.managed, "preflight", return_value=(
                    {}, "route", b"dropin", Path("/interpreter"), deadline)),
                mock.patch.object(operator.managed, "protected_bytes", return_value=b"authority"),
                mock.patch.object(operator, "launch_menu", return_value=menu),
                mock.patch.object(operator, "wait_menu_identity", return_value=menu_identities[0]),
                mock.patch.object(operator, "menu_identity", return_value=menu_identities[1]),
                mock.patch.object(operator, "launch_boundary", return_value=boundary),
                mock.patch.object(operator.subprocess, "run", return_value=mock.Mock(returncode=0)),
                mock.patch.object(operator, "prepare_removal", side_effect=prepare),
                mock.patch.object(operator, "complete_refusal", side_effect=refuse),
                mock.patch.object(operator, "event", side_effect=lambda *_args: next(events)),
                mock.patch.object(operator, "owned_snapshot", side_effect=snapshot),
                mock.patch.object(operator, "write_exclusive", side_effect=write),
                mock.patch.object(operator, "write_input", side_effect=input_write),
                mock.patch.object(operator, "final_health", side_effect=lambda: order.append("health")),
            ]
            for patch in patches:
                stack.enter_context(patch)
            error = None
            try:
                result = operator.run("/interpreter", "f" * 64, 90)
            except Exception as caught:
                result, error = None, caught
        return order, result, error, boundary

    def test_full_sequence_holds_review_then_races_refusal_then_releases(self):
        order, result, error, _ = self.exercise()
        self.assertIsNone(error)
        self.assertTrue(result["removal_refused_before_commitment"])
        self.assertLess(order.index("menu-prepared"), order.index("write-22-admission-held.json"))
        self.assertLess(order.index("write-22-admission-held.json"), order.index("removal-refused"))
        self.assertLess(order.index("removal-refused"), order.index("boundary-release"))
        self.assertLess(order.index("boundary-release"), order.index("health"))
        self.assertEqual(order[-1], "timer-restore")

    def test_inventory_drift_refuses_but_releases_boundary_and_restores_timer(self):
        order, result, error, boundary = self.exercise(drift=True)
        self.assertIsNone(result)
        self.assertRegex(str(error), "owned resources changed")
        self.assertIn("boundary-release", order)
        self.assertIn("timer-restore", order)
        self.assertEqual(boundary.returncode, 0)

    def test_unproved_boundary_never_submits_removal_confirmation(self):
        order, result, error, boundary = self.exercise(bad_held=True)
        self.assertIsNone(result)
        self.assertRegex(str(error), "boundary refused")
        self.assertNotIn("removal-refused", order)
        self.assertTrue(boundary.stdin.closed)
        self.assertIn("timer-restore", order)

    def test_wrong_request_never_stops_timer_or_launches_menu(self):
        order, result, error, _ = self.exercise(wrong_request=True)
        self.assertIsNone(result)
        self.assertRegex(str(error), "current request")
        self.assertNotIn("timer-stop", order)
        self.assertNotIn("menu-prepared", order)

    def test_failed_stop_after_attempt_restores_original_timer(self):
        order, result, error, _ = self.exercise(stop_failure=True)
        self.assertIsNone(result)
        self.assertRegex(str(error), "timer stop postcondition")
        self.assertEqual(order, ["timer-stop", "timer-restore"])

    def test_changed_menu_process_never_submits_confirmation(self):
        order, result, error, boundary = self.exercise(menu_drift=True)
        self.assertIsNone(result)
        self.assertRegex(str(error), "menu process changed")
        self.assertNotIn("removal-refused", order)
        self.assertTrue(boundary.stdin.closed)
        self.assertIn("timer-restore", order)

    def test_menu_identity_waits_for_transient_service_main_pid(self):
        menu = mock.Mock()
        menu.poll.return_value = None
        identity = {"pid": 41, "start_tick": 29}
        with mock.patch.object(operator.managed, "show", side_effect=["0", "inactive", "0", "activating", "41", "active"]) as show, \
             mock.patch.object(operator, "menu_identity", return_value=identity) as bind, \
             mock.patch.object(operator.time, "sleep"):
            self.assertEqual(operator.wait_menu_identity(menu, "menu.service", time.monotonic() + 1), identity)
        self.assertEqual(show.call_count, 6)
        bind.assert_called_once_with("menu.service")

    def test_menu_start_failure_or_deadline_never_binds_process(self):
        menu = mock.Mock()
        menu.poll.return_value = 1
        with mock.patch.object(operator, "menu_identity") as bind:
            with self.assertRaisesRegex(ValueError, "exited before service readiness"):
                operator.wait_menu_identity(menu, "menu.service", time.monotonic() + 1)
            menu.poll.return_value = None
            with self.assertRaisesRegex(TimeoutError, "service readiness deadline"):
                operator.wait_menu_identity(menu, "menu.service", time.monotonic() - 1)
            bind.assert_not_called()


if __name__ == "__main__":
    unittest.main()
