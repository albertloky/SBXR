"""Pure attachment state/launch-contract tests; never execute the wrapper."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("runner", Path(__file__).with_name("dns-child-observer-run.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class AttachmentBarrierTests(unittest.TestCase):
    def test_early_marker_cannot_release_and_actual_notification_is_required(self):
        b = runner.AttachmentBarrier(100)
        self.assertEqual(b.stdout("STARTING 100 10", 11), "STARTING 100 10\n")
        self.assertFalse(b.ready)
        self.assertEqual(b.stdout(runner.NOTIFY, 12), "ATTACHED 100 12\n")
        self.assertTrue(b.ready)
        self.assertEqual(b.stdout("BEGIN 7 100 13", 14), "BEGIN 7 100 13\n")

    def test_direct_notification_can_precede_async_starting_but_both_are_required(self):
        b = runner.AttachmentBarrier(100)
        b.stdout(runner.NOTIFY, 12)
        self.assertFalse(b.ready)
        b.stdout("STARTING 100 10", 13)
        self.assertTrue(b.ready)
        b.stdout("DONE 15", 16)
        self.assertFalse(b.ready)
        with self.assertRaises(ValueError): b.stdout(runner.NOTIFY, 17)

    def test_missing_probe_error_early_query_wrong_identity_and_duplicates_latch_refusal(self):
        sequences = [
            [("STARTING 100 10", 11), ("BEGIN 7 100 12", 13)],
            [(runner.NOTIFY, 12), ("STARTING 101 10", 13)],
            [(runner.NOTIFY, 12), ("STARTING 100 10", 13), (runner.NOTIFY, 14)],
            [(runner.NOTIFY, 12), ("STARTING 100 10", 13), ("STARTING 100 10", 14)],
            [(runner.NOTIFY, 12), ("STARTING 100 10", 13), ("BEGIN 7 100 11", 14)],
            [("Attaching 9 probes...", 11)],
        ]
        for rows in sequences:
            b = runner.AttachmentBarrier(100)
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                for line, now in rows: b.stdout(line, now)
            self.assertFalse(b.ready)
        b = runner.AttachmentBarrier(100)
        with self.assertRaises(ValueError): b.stderr(b"missing probe")
        with self.assertRaises(ValueError): b.stdout(runner.NOTIFY, 12)
        self.assertFalse(b.ready)

    def test_exact_launch_configuration_ignores_inherited_overrides(self):
        with patch.dict(runner.os.environ, {"BPFTRACE_MISSING_PROBES": "warn", "BPFTRACE_MAX_MAP_KEYS": "999999"}):
            argv, env = runner.launch_spec("/usr/bin/bpftrace", "/tmp/observer.bt")
        self.assertEqual(argv, ["/usr/bin/bpftrace", "-q", "-B", "none", "/tmp/observer.bt"])
        self.assertEqual(env["BPFTRACE_MISSING_PROBES"], "error")
        self.assertEqual(env["BPFTRACE_MAX_MAP_KEYS"], "64")
        self.assertEqual(env["BPFTRACE_PERF_RB_PAGES"], "8")
        self.assertEqual(env[runner.NOTIFY], "1")
        self.assertEqual(set(env), {"PATH", "LANG", "LC_ALL", runner.NOTIFY,
                                   "BPFTRACE_MISSING_PROBES", "BPFTRACE_MAX_MAP_KEYS",
                                   "BPFTRACE_PERF_RB_PAGES", "BPFTRACE_COLOR"})
        for path in ("bpftrace", "/tmp/a;echo", "/tmp/../bpftrace"):
            with self.assertRaises(ValueError): runner.launch_spec(path, "/tmp/observer.bt")


if __name__ == "__main__": unittest.main()
