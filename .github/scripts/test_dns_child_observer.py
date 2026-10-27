"""Inert contract tests. No process, signal, attach, socket or network fixtures."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("observer", Path(__file__).with_name("dns-child-observer.py"))
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)

# Child exits before the parent reports spawn: must still correlate correctly.
SHORT = """STARTING 100 1
ATTACHED 100 1
BEGIN 7 100 2
FORK 7 123 3
EXIT 7 123 10 1 4 2 0
SPAWN 7 123 11
FINISH 7 123 12
DONE 13
"""
WAIT = """STARTING 100 1
ATTACHED 100 1
BEGIN 7 100 2
FORK 7 123 3
SPAWN 7 123 4
WAIT 7 123 5000000010 7 5000000000 1
EXIT 7 123 5000000010 1 5000000000 4999999990 1
FINISH 7 123 5000000020
DONE 5000000030
"""


class DnsObserverTests(unittest.TestCase):
    def test_short_lifetime_and_unfinished_wait(self):
        result = observer.parse_capture(SHORT, 100)[0]
        self.assertEqual((result["query_id"], result["child_pid"], result["lifetime_ns"]), (7, 123, 7))
        result = observer.parse_capture(WAIT, 100)[0]
        self.assertEqual(result["waits"], [dict(syscall=7, duration_ns=5_000_000_000, unfinished=True)])

    def test_wrong_child_missing_duplicate_reused_query_and_payload_refuse(self):
        bad = [
            SHORT.replace("SPAWN 7 123", "SPAWN 7 456"),
            SHORT.replace("FORK 7 123 3\n", ""),
            SHORT.replace("EXIT 7 123 10 1 4 2 0\n", ""),
            SHORT.replace("BEGIN 7 100 2", "BEGIN 7 100 2\nBEGIN 7 100 2"),
            SHORT.replace("ATTACHED 100", "ATTACHED 101"),
            SHORT.replace("BEGIN 7 100", "BEGIN 7 0"),
            SHORT.replace("DONE 13\n", ""),
            SHORT + "BAD 1 14\n",
            SHORT + "SECRET-SENTINEL\n",
            WAIT.replace("WAIT 7 123 5000000010 7 5000000000 1\n", ""),
            WAIT.replace("WAIT 7 123", "WAIT 8 123"),
            WAIT.replace("5000000000 1\n", "5000000000 2\n"),
            WAIT.replace("5000000010 7", "5000000010 65535"),
            SHORT.replace("10 1 4 2 0", "10 4097 4 2 0"),
        ]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(ValueError):
                observer.parse_capture(text, 100)

    def test_pid_reuse_is_a_separate_fork_lifetime_not_name_or_time_matching(self):
        text = SHORT.replace("DONE 13\n", "") + """BEGIN 8 100 14
FORK 8 123 15
SPAWN 8 123 16
EXIT 8 123 20 1 2 1 0
FINISH 8 123 21
DONE 22
"""
        result = observer.parse_capture(text, 100)
        self.assertEqual([r["query_id"] for r in result], [7, 8])
        self.assertEqual([r["lifetime_ns"] for r in result], [7, 5])

    def test_bounds_and_injection_refuse(self):
        for pid, exe, symbol in [(True, "/bin/sbxr", "dns_child_observer_hook"),
                                  (1, "/bin/sbxr", "dns_child_observer_hook"),
                                  (100, "/bin/*", "dns_child_observer_hook"),
                                  (100, "/bin/../sbxr", "dns_child_observer_hook"),
                                  (100, "/bin/sbxr", "dns_child_observer_hook*"),
                                  (100, "/bin/sbxr", "other")]:
            with self.assertRaises(ValueError): observer.render(exe, symbol, pid)
        with self.assertRaises(ValueError): observer.parse_capture("x" * 65537, 100)
        with self.assertRaises(ValueError): observer.parse_capture(SHORT.replace("7 123 3", "7 123 18446744073709551616"), 100)

    def test_query_and_wait_budgets_accept_boundary_and_refuse_overflow(self):
        def queries(count):
            rows = ["STARTING 100 1\nATTACHED 100 1"]
            for q in range(1, count + 1):
                base = q * 100
                rows += [f"BEGIN {q} 100 {base}", f"FORK {q} 123 {base+1}",
                         f"SPAWN {q} 123 {base+2}", f"EXIT {q} 123 {base+4} 0 0 0 0",
                         f"FINISH {q} 123 {base+5}"]
            return "\n".join(rows + [f"DONE {count*100+6}"])
        self.assertEqual(len(observer.parse_capture(queries(32), 100)), 32)
        with self.assertRaises(ValueError): observer.parse_capture(queries(33), 100)

        def waits(count):
            rows = ["STARTING 100 1\nATTACHED 100 1", "BEGIN 7 100 2", "FORK 7 123 3", "SPAWN 7 123 4"]
            for n in range(1, count + 1):
                rows.append(f"WAIT 7 123 {n*1000000+10} 7 1000000 0")
            end = count * 1000000 + 10
            rows += [f"EXIT 7 123 {end} {count} {count*1000000} 0 {count}",
                     f"FINISH 7 123 {end+1}", f"DONE {end+2}"]
            return "\n".join(rows)
        self.assertEqual(len(observer.parse_capture(waits(128), 100)[0]["waits"]), 128)
        with self.assertRaises(ValueError): observer.parse_capture(waits(129), 100)

    def test_review_impossible_accounting_and_duplicate_unfinished_refuse(self):
        bad = [
            SHORT.replace("10 1 4 2 0", "10 0 4 2 0"),
            SHORT.replace("EXIT 7 123 10 1 4 2 0", "EXIT 7 123 10000010 1 5000000 2 0")
                 .replace("123 11", "123 10000011").replace("123 12", "123 10000012")
                 .replace("DONE 13", "DONE 10000013"),
            SHORT.replace("EXIT 7 123 10 1 4 2 0", "WAIT 7 123 10 60 0 1\nWAIT 7 123 10 60 0 1\nEXIT 7 123 10 2 4 2 2"),
        ]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(ValueError):
                observer.parse_capture(text, 100)

    def test_review_parent_scope_overlap_refuses_even_with_distinct_children(self):
        text = SHORT.replace("DONE 13\n", "") + (
            "BEGIN 8 100 2\nFORK 8 124 4\nSPAWN 8 124 5\n"
            "EXIT 8 124 8 1 2 1 0\nFINISH 8 124 9\nDONE 13\n")
        for capture in (text, "\n".join(reversed(text.splitlines()))):
            with self.assertRaises(ValueError): observer.parse_capture(capture, 100)

    def test_review_early_ready_is_not_attachment(self):
        with self.assertRaises(ValueError):
            observer.parse_capture(SHORT.replace("STARTING", "READY").replace("ATTACHED 100 1\n", ""), 100)

    def test_review_accounting_threshold_and_scope_ordering_boundaries(self):
        text = SHORT.replace("EXIT 7 123 10 1 4 2 0", "EXIT 7 123 1000010 1 999999 2 0")
        text = text.replace("123 11", "123 1000011").replace("123 12", "123 1000012").replace("DONE 13", "DONE 1000013")
        self.assertEqual(observer.parse_capture(text, 100)[0]["syscall_ns"], 999999)
        with self.assertRaises(ValueError): observer.parse_capture(text.replace("999999", "1000000"), 100)
        single = SHORT.replace("EXIT 7 123 10 1 4 2 0", "WAIT 7 123 10 60 0 1\nEXIT 7 123 10 1 0 2 1")
        self.assertTrue(observer.parse_capture(single, 100)[0]["waits"][0]["unfinished"])
        self.assertEqual(observer.parse_capture("\n".join(reversed(SHORT.splitlines())), 100), observer.parse_capture(SHORT, 100))
        for invalid in (SHORT.replace("DONE 13", "DONE 1000000000001"),
                        SHORT.replace("ATTACHED 100 1\n", ""),
                        SHORT.replace("ATTACHED 100 1", "ATTACHED 100 3")):
            with self.assertRaises(ValueError): observer.parse_capture(invalid, 100)

    def test_template_is_payload_free_and_contains_fixed_bounds(self):
        rendered = observer.render("/opt/sbxr", "_ZN_dns_child_observer_hook_abc", 100)
        self.assertIn("uprobe:/opt/sbxr:_ZN_dns_child_observer_hook_abc", rendered)
        self.assertNotIn("TARGET_", rendered)
        self.assertNotIn('printf("READY', rendered)
        self.assertIn("missing_probes=error", rendered)
        self.assertIn("nsecs(monotonic)", rendered)
        for forbidden in ("str(", "buf(", "comm", "ustack", "kstack", "args.args", "args.filename", "system(", "signal(", "override("):
            self.assertNotIn(forbidden, rendered)
        for bound in ("max_map_keys=64", "perf_rb_pages=8", "@queries >= 32", "@rows >= 128", "@calls[tid] >= 4096", "interval:s:90"):
            self.assertIn(bound, rendered)


if __name__ == "__main__": unittest.main()
