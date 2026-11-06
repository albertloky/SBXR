#!/usr/bin/env python3
"""Exercise actual CLI, filesystem permissions, refusal, and publication."""
import datetime as dt
import json
import os
import shlex
import stat
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("mvp-observe.py")


class ObserveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.request = self.root / "request.json"
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.value = {"scenario_id": "mvp-install", "not_before": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "deadline_unix": int(now.timestamp())+1800, "scenario_limit_seconds": 1800,
                      "qualification_manifest_sha256": "a"*64,
                      "required_checks": ["packaged-install", "outside-proxy-traffic"]}
        self.save_request()
        self.draft, self.output = self.root / "draft.json", self.root / "observation.json"

    def save_request(self):
        self.request.write_text(json.dumps(self.value))
        self.request.chmod(0o600)

    def call(self, command, *args, ok=True):
        result = subprocess.run([sys.executable, str(SCRIPT), command, "--request", str(self.request),
                                 "--draft", str(self.draft), *args], capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, ok, result.stderr)
        self.assertFalse(list(self.root.glob(".mvp-observe-*")), "temporary publication file leaked")
        return result

    def test_explicit_observations_sealed_atomic_publication(self):
        self.call("start")
        self.assertEqual(self.draft.stat().st_mode & 0o777, 0o600)
        before = json.loads(self.draft.read_text())["observation"]
        self.assertIsNone(before["completed_at"])
        self.call("finish", "--output", str(self.output), ok=False)
        self.assertFalse(self.output.exists())
        for check in self.value["required_checks"]:
            self.call("observe", "--check", check)
        self.call("observe", "--check", "packaged-install", ok=False)
        self.call("finish", "--output", str(self.output))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        body = json.loads(self.output.read_text())
        self.assertEqual(set(body), {"scenario_id", "started_at", "completed_at", "checks"})
        self.assertEqual(body["started_at"], before["started_at"])
        self.assertTrue(all(c["result"] == "observed" for c in body["checks"]))
        self.output.unlink()  # Collector consumption cannot authorize resubmission.
        self.call("finish", "--output", str(self.output), ok=False)
        self.assertFalse(self.output.exists())

    def test_stale_request_missing_unknown_and_duplicate_checks_refuse(self):
        self.call("start")
        original = self.draft.read_bytes()
        self.call("observe", "--check", "all", ok=False)
        self.call("observe", ok=False)
        self.assertEqual(self.draft.read_bytes(), original)
        self.value["qualification_manifest_sha256"] = "b"*64
        self.save_request()
        self.call("observe", "--check", "packaged-install", ok=False)
        self.assertEqual(self.draft.read_bytes(), original)

    def test_deadline_cannot_be_backdated_or_extended(self):
        self.call("start")
        self.value["deadline_unix"] -= 1801
        self.save_request()
        self.call("observe", "--check", "packaged-install", ok=False)
        self.value["deadline_unix"] += 1802
        self.save_request()
        self.call("status", ok=False)
        self.assertFalse(self.output.exists())

    def test_permissions_symlinks_hardlinks_and_duplicate_json_refuse(self):
        self.request.chmod(0o644)
        self.call("start", ok=False)
        self.request.chmod(0o600)
        backup = self.root / "original"
        self.request.rename(backup)
        self.request.symlink_to(backup)
        self.call("start", ok=False)
        self.request.unlink()
        os.link(backup, self.request)
        self.call("start", ok=False)
        backup.unlink()
        self.request.write_text(self.request.read_text().replace('"scenario_id":', '"scenario_id":"duplicate", "scenario_id":'))
        self.call("start", ok=False)
        self.assertFalse(self.draft.exists())

    def test_collector_draft_read_handles_retirement_and_refuses_unsafe_files(self):
        source = SCRIPT.with_name("v3-recurring-evidence.sh").read_text()
        helper = "read_mvp_timing_draft() {" + source.split("read_mvp_timing_draft() {", 1)[1].split("# Timing transport helpers end.", 1)[0]
        helper = helper.replace("/root/mvp-observation-draft.json", str(self.draft))
        script = ("set -euo pipefail\numask 077\nremote=(bash -c)\ndirectory=" +
                  shlex.quote(str(self.root)) + "\n" + helper + "\nread_mvp_timing_draft\n")
        fetched = self.root / "mvp-timing-draft.json"
        def read(ok=True, env=None):
            result = subprocess.run(["bash", "-c", script], capture_output=True, timeout=5, env=env)
            self.assertEqual(result.returncode == 0, ok, result.stderr)
        read()
        self.assertFalse(fetched.exists())
        self.draft.write_bytes(b"original opened inode"); self.draft.chmod(0o600)
        read(); self.assertEqual(fetched.read_bytes(), self.draft.read_bytes())
        self.draft.chmod(0o644); read(False); self.draft.chmod(0o600)
        alias = self.root / "alias"
        os.link(self.draft, alias); read(False); alias.unlink()
        self.draft.rename(alias); self.draft.symlink_to(alias); read(False)
        self.draft.unlink(); alias.rename(self.draft)
        for body in (b"", b"x" * 1000001):
            self.draft.write_bytes(body); read(False)
        self.draft.unlink(); os.mkfifo(self.draft, 0o600); read(False); self.draft.unlink()
        self.draft.write_bytes(b"retired opened inode"); self.draft.chmod(0o600)
        hook = self.root / "hook"; hook.mkdir()
        (hook / "sitecustomize.py").write_text("""import os
original = os.open
def opening(path, *args, **kwargs):
    fd = original(path, *args, **kwargs)
    if path == os.environ['FIXTURE_DRAFT']:
        os.unlink(path)
    return fd
os.open = opening
""")
        read(env=dict(os.environ, PYTHONPATH=str(hook), FIXTURE_DRAFT=str(self.draft)))
        self.assertFalse(self.draft.exists())
        self.assertEqual(fetched.read_bytes(), b"retired opened inode")
        read(); self.assertFalse(fetched.exists())

    def enable_handoff(self, elapsed=0):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.value.update(scenario_id="source-v3.1.81-upgrade", not_before=(now-dt.timedelta(seconds=elapsed)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                          deadline_unix=int(now.timestamp())+1800-elapsed,
                          karing_response_limit_seconds=3600,
                          attended_finish_by=(now+dt.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.save_request()
        return now

    def ready(self, now, **kw):
        stamp = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
        return self.call("ready", "--phase", "http-profile-refresh", "--prepared-at", stamp(now-dt.timedelta(minutes=19)),
                         "--notified-at", stamp(now), **kw)

    def test_hour_starts_at_actual_notification_not_preparation(self):
        now = self.enable_handoff(elapsed=1200)
        self.call("start")
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.ready(now)
        status = json.loads(self.call("status").stdout)
        self.assertEqual(status["deadline"], (now+dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.assertGreaterEqual(status["seconds_remaining"],3597)
        collector = int(self.call("deadline").stdout)
        self.assertEqual(collector,int(now.timestamp())+3600)
        self.call("ready", "--phase", "source-profile-import", "--prepared-at", now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "--notified-at", now.strftime("%Y-%m-%dT%H:%M:%SZ"), ok=False)
        for check in self.value["required_checks"]: self.call("observe","--check",check)
        self.call("finish","--output",str(self.output),ok=False)
        self.call("responded")
        self.call("responded",ok=False)
        self.call("finish","--output",str(self.output))
        handoff=json.loads(self.output.read_text())["karing_handoffs"][0]
        self.assertIsNotNone(handoff["responded_at"])

    def test_undeclared_expired_wrong_phase_and_insufficient_attendance_refuse(self):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.call("start")
        self.ready(now,ok=False)
        self.draft.unlink()
        now=self.enable_handoff(elapsed=1801)
        self.call("start",ok=False)
        now=self.enable_handoff()
        self.call("start")
        self.call("ready","--phase","unrelated-profile","--prepared-at",now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "--notified-at",now.strftime("%Y-%m-%dT%H:%M:%SZ"),ok=False)
        self.value["attended_finish_by"]=(now+dt.timedelta(minutes=59)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.save_request();self.draft.unlink();self.call("start")
        self.ready(now,ok=False)

    def test_actual_cli_preserves_technical_budget_while_response_is_pending(self):
        now=self.enable_handoff(elapsed=80*60)
        import hashlib
        stamp=lambda t:t.strftime("%Y-%m-%dT%H:%M:%SZ")
        notified=now-dt.timedelta(minutes=59)
        draft={"request_sha256":hashlib.sha256(self.request.read_bytes()).hexdigest(),"observation":{
            "scenario_id":self.value["scenario_id"],"started_at":self.value["not_before"],"completed_at":None,
            "checks":[{"check":c,"observed_at":None,"result":None} for c in self.value["required_checks"]],
            "karing_handoffs":[{"phase":"http-profile-refresh","prepared_at":stamp(now-dt.timedelta(minutes=79)),
                                 "notified_at":stamp(notified),"responded_at":None}]}}
        self.draft.write_text(json.dumps(draft));self.draft.chmod(0o600)
        self.call("responded")
        status=json.loads(self.call("status").stdout)
        self.assertGreaterEqual(status["seconds_remaining"],539)
        self.assertLessEqual(status["seconds_remaining"],543)
        for check in self.value["required_checks"]:self.call("observe","--check",check)
        self.call("finish","--output",str(self.output))

    def test_collector_refuses_malformed_draft_before_waiting(self):
        now=self.enable_handoff();self.call("start")
        original=self.draft.read_bytes()
        for change in [lambda d:d.update(unknown=True),
                       lambda d:d["observation"].update(scenario_id="mvp-subscription"),
                       lambda d:d["observation"].update(started_at="1970-01-01T00:00:00Z"),
                       lambda d:d["observation"]["checks"][0].update(result="observed",observed_at="2999-01-01T00:00:00Z")]:
            draft=json.loads(original);change(draft);self.draft.write_text(json.dumps(draft))
            self.call("deadline",ok=False)
        self.draft.write_bytes(original)
        self.ready(dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
        self.call("deadline")

    def test_collector_and_recorder_refuse_late_response_and_request_replay(self):
        now=self.enable_handoff();self.call("start");now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0);self.ready(now)
        draft=json.loads(self.draft.read_text())
        earlier=now-dt.timedelta(seconds=3601)
        self.value["not_before"]=(earlier-dt.timedelta(seconds=100)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.value["deadline_unix"]=int(earlier.timestamp())+1700
        self.save_request()
        import hashlib
        draft["request_sha256"]=hashlib.sha256(self.request.read_bytes()).hexdigest()
        draft["observation"]["started_at"]=self.value["not_before"]
        for key in ["prepared_at","notified_at"]:draft["observation"]["karing_handoffs"][0][key]=earlier.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.draft.write_text(json.dumps(draft))
        self.call("responded",ok=False)
        self.assertEqual(int(self.call("deadline").stdout),int(earlier.timestamp())+3600)
        self.value["qualification_manifest_sha256"]="b"*64;self.save_request()
        self.call("deadline",ok=False)


    def test_start_and_finish_never_overwrite_existing_files(self):
        self.call("start")
        original = self.draft.read_bytes()
        self.call("start", ok=False)
        self.assertEqual(self.draft.read_bytes(), original)
        for check in self.value["required_checks"]:
            self.call("observe", "--check", check)
        self.output.write_text("retained evidence")
        self.call("finish", "--output", str(self.output), ok=False)
        self.assertEqual(self.output.read_text(), "retained evidence")


    def cleanup_history(self, *, completed=False, pending=False, elapsed=600,
                        period=1800, finish_after=7200):
        """Retain historical facts; exercise the real clock CLI against them."""
        import hashlib
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
        phases, scenario = ("credential-refresh", "rotated-link-refresh"), "mvp-credentials"
        if period == 7200:
            phases, scenario = ("profile-import", "profile-refresh"), "mvp-subscription"
        self.value.update(scenario_id=scenario, not_before=stamp(now-dt.timedelta(seconds=elapsed)),
                          deadline_unix=int(now.timestamp())+period-elapsed,
                          scenario_limit_seconds=period, karing_response_limit_seconds=3600,
                          attended_finish_by=stamp(now+dt.timedelta(seconds=finish_after)))
        self.save_request()
        handoffs = []
        if completed:
            handoffs.append({"phase": phases[0], "prepared_at": stamp(now-dt.timedelta(seconds=500)),
                             "notified_at": stamp(now-dt.timedelta(seconds=500)),
                             "responded_at": stamp(now-dt.timedelta(seconds=200))})
        if pending:
            handoffs.append({"phase": phases[1] if completed else phases[0],
                             "prepared_at": stamp(now-dt.timedelta(seconds=100)),
                             "notified_at": stamp(now-dt.timedelta(seconds=100)), "responded_at": None})
        draft = {"request_sha256": hashlib.sha256(self.request.read_bytes()).hexdigest(), "observation": {
            "scenario_id": scenario, "started_at": self.value["not_before"], "completed_at": None,
            "checks": [{"check": check, "observed_at": None, "result": None}
                       for check in self.value["required_checks"]], "karing_handoffs": handoffs}}
        self.draft.write_text(json.dumps(draft)); self.draft.chmod(0o600)
        return now

    def cleanup_snapshot(self):
        return {path.name: (path.lstat().st_ino, path.lstat().st_mode,
                            path.lstat().st_nlink, path.lstat().st_mtime_ns,
                            path.lstat().st_ctime_ns,
                            os.readlink(path) if path.is_symlink() else path.read_bytes())
                for path in self.root.iterdir()}

    def cleanup_call(self, *, ok=True):
        before = self.cleanup_snapshot()
        result = self.call("cleanup-deadline", ok=ok)
        self.assertEqual(self.cleanup_snapshot(), before, "cleanup clock changed retained evidence")
        if not ok:
            self.assertIn("Observation refused:", result.stderr)
            self.assertEqual(result.stdout, "")
        return result

    def test_cleanup_deadline_pending_counts_only_completed_waits(self):
        self.cleanup_history(completed=True, pending=True)
        before = self.cleanup_snapshot()
        self.call("operation-deadline", ok=False)
        self.assertEqual(int(self.cleanup_call().stdout), self.value["deadline_unix"]+300)
        draft = json.loads(self.draft.read_text())
        self.assertIsNone(draft["observation"]["karing_handoffs"][-1]["responded_at"])
        self.assertTrue(all(check["result"] is None for check in draft["observation"]["checks"]))
        self.assertEqual(self.cleanup_snapshot(), before)

    def test_cleanup_deadline_matches_operation_without_pending_response(self):
        self.call("start")
        self.assertEqual(self.cleanup_call().stdout, self.call("operation-deadline").stdout)
        self.cleanup_history(completed=True)
        expected = self.value["deadline_unix"]+300
        self.assertEqual(int(self.cleanup_call().stdout), expected)
        self.assertEqual(int(self.call("operation-deadline").stdout), expected)

    def test_cleanup_deadline_respects_attendance_and_pending_handoff_caps(self):
        now = self.cleanup_history(period=7200, finish_after=1000)
        self.assertEqual(int(self.cleanup_call().stdout), int(now.timestamp())+1000)
        now = self.cleanup_history(period=7200, pending=True)
        self.assertEqual(int(self.cleanup_call().stdout), int(now.timestamp())+3500)
        self.call("operation-deadline", ok=False)

    def test_cleanup_deadline_pending_does_not_rescue_expired_technical_budget(self):
        now = self.cleanup_history(elapsed=1810, pending=True)
        self.assertGreater(int(self.call("deadline").stdout), int(now.timestamp()))
        self.cleanup_call(ok=False)
        self.call("operation-deadline", ok=False)
        self.cleanup_history(elapsed=1800, pending=True)
        self.cleanup_call(ok=False)  # Exactly exhausted time is not a cleanup budget.

    def test_cleanup_deadline_refuses_expired_attendance_or_pending_response(self):
        self.cleanup_history(finish_after=-5)
        self.cleanup_call(ok=False)
        now = self.cleanup_history(period=7200, elapsed=4000, pending=True)
        draft = json.loads(self.draft.read_text())
        notified = (now-dt.timedelta(seconds=3700)).strftime("%Y-%m-%dT%H:%M:%SZ")
        draft["observation"]["karing_handoffs"][0].update(prepared_at=notified, notified_at=notified)
        self.draft.write_text(json.dumps(draft))
        self.assertGreater(self.value["deadline_unix"], int(now.timestamp()))
        self.cleanup_call(ok=False)

    def test_cleanup_deadline_requires_unsealed_current_private_draft(self):
        self.cleanup_call(ok=False)
        self.call("start")
        for check in self.value["required_checks"]:
            self.call("observe", "--check", check)
        self.call("finish", "--output", str(self.output))
        self.cleanup_call(ok=False)
        self.output.unlink()
        self.cleanup_history(pending=True)
        original = self.draft.read_bytes()
        self.value["qualification_manifest_sha256"] = "b"*64
        self.save_request()
        self.cleanup_call(ok=False)
        self.assertEqual(self.draft.read_bytes(), original)

    def test_cleanup_deadline_validates_original_handoff_and_observation_facts(self):
        mutations = {
            "unknown-draft-member": lambda d: d.update(unknown=True),
            "foreign-request": lambda d: d.update(request_sha256="b"*64),
            "wrong-scenario": lambda d: d["observation"].update(scenario_id="mvp-install"),
            "future-check": lambda d: d["observation"]["checks"][0].update(
                result="observed", observed_at="2999-01-01T00:00:00Z"),
            "unknown-phase": lambda d: d["observation"]["karing_handoffs"][1].update(phase="other"),
            "duplicate-phase": lambda d: d["observation"]["karing_handoffs"][1].update(phase="credential-refresh"),
            "response-before-notification": lambda d: d["observation"]["karing_handoffs"][0].update(
                responded_at=d["observation"]["started_at"]),
            "future-response": lambda d: d["observation"]["karing_handoffs"][0].update(
                responded_at="2999-01-01T00:00:00Z"),
            "pending-before-later-handoff": lambda d: d["observation"]["karing_handoffs"][0].update(responded_at=None),
            "invalid-pending-time": lambda d: d["observation"]["karing_handoffs"][1].update(notified_at="invalid"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.cleanup_history(completed=True, pending=True)
                draft = json.loads(self.draft.read_text()); mutate(draft)
                self.draft.write_text(json.dumps(draft))
                self.cleanup_call(ok=False)

    def test_clock_loader_refuses_fifos_without_blocking(self):
        self.call("start")
        for which in ("request", "draft"):
            for command in ("status", "cleanup-deadline"):
                with self.subTest(which=which, command=command):
                    path = self.request if which == "request" else self.draft
                    other = self.draft if which == "request" else self.request
                    original, other_original = path.read_bytes(), other.read_bytes()
                    path.unlink(); os.mkfifo(path, 0o600)
                    before = path.lstat()
                    try:
                        result = subprocess.run(
                            [sys.executable, str(SCRIPT), command, "--request", str(self.request),
                             "--draft", str(self.draft)], capture_output=True, text=True, timeout=2)
                        self.assertEqual(result.returncode, 1, result.stderr)
                        self.assertIn("input must be an owned, private, one-link regular file", result.stderr)
                        self.assertEqual(result.stdout, "")
                        self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))
                        self.assertEqual(path.lstat().st_ino, before.st_ino)
                        self.assertEqual(other.read_bytes(), other_original)
                    finally:
                        path.unlink(); path.write_bytes(original); path.chmod(0o600)

    def test_cleanup_deadline_refuses_unsafe_request_and_draft_files(self):
        for which in ("request", "draft"):
            for kind in ("mode", "symlink", "hardlink", "duplicate-json"):
                with self.subTest(which=which, kind=kind):
                    self.cleanup_history(pending=True)
                    path = self.request if which == "request" else self.draft
                    original = path.read_bytes(); alias = self.root / "alias"
                    try:
                        if kind == "mode":
                            path.chmod(0o644)
                        elif kind == "symlink":
                            path.rename(alias); path.symlink_to(alias)
                        elif kind == "hardlink":
                            os.link(path, alias)
                        else:
                            member = '"scenario_id"' if which == "request" else '"request_sha256"'
                            path.write_text(path.read_text().replace(member+":", member+':"duplicate",'+member+":", 1))
                        self.cleanup_call(ok=False)
                    finally:
                        if path.is_symlink(): path.unlink()
                        if alias.exists(): alias.unlink()
                        path.write_bytes(original); path.chmod(0o600)


if __name__ == "__main__":
    unittest.main()
