"""Offline request/clock regression; synthetic manifest is never release authority."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

binding = load("diagnostic-restoration")
collector = load("disclosure-diagnostic")

class DiagnosticRestoration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = int(time.time())
        self.window = dict(start_unix=self.now-10, test_until_unix=self.now-10+7200, finish_unix=self.now-10+10800)
        manifest = {"schema":"sbxr-qualification-manifest-v3", "v3_attempt":{
            "diagnostic":self.window, "required_scenarios":["mvp-install"], "attempt_id":"run-999001-attempt-1"}}
        self.raw = collector.canonical(manifest)
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.manifest = self.root / "manifest.json"
        self.manifest.write_bytes(self.raw)
        self.manifest.chmod(0o600)
        handoff = collector.prepare(self.root, self.manifest, self.now)
        self.directory = Path(handoff["directory"])
        self.q = json.loads((self.directory / "request.json").read_bytes())
        self.request_path = "/root/sbxr-diagnostic-run-999001-attempt-1/request.json"
        self.draft_path = "/root/sbxr-diagnostic-run-999001-attempt-1/observation-draft.json"

    def validate(self, q=None, raw=None, digest=None, request=None, draft=None, window=None):
        return binding.validate_request(self.q if q is None else q, self.raw if raw is None else raw,
            self.digest if digest is None else digest, self.request_path if request is None else request,
            self.draft_path if draft is None else draft, self.window if window is None else window)

    def test_real_collector_request_needs_no_attendance_claim(self):
        self.assertNotIn("attended_finish_by", self.q)
        self.assertEqual(self.validate(), self.window)
        with self.assertRaises(KeyError):
            _ = self.q["attended_finish_by"]  # Previous caller failed here.

    def test_real_recorder_keeps_removal_reserve(self):
        request = self.directory / "request.json"
        draft = self.directory / "observation-draft.json"
        def clock(command):
            return subprocess.run([sys.executable, "-B", str(HERE / "mvp-observe.py"), command,
                "--request", str(request), "--draft", str(draft)], capture_output=True, timeout=10)
        result = clock("start")
        self.assertEqual(result.returncode, 0, result.stderr)
        before = (request.read_bytes(), draft.read_bytes())
        ordinary, cleanup = clock("operation-deadline"), clock("cleanup-deadline")
        self.assertEqual((ordinary.returncode, cleanup.returncode), (0, 0))
        self.assertGreaterEqual(int(cleanup.stdout)-int(ordinary.stdout), 900)
        self.assertEqual(int(cleanup.stdout), self.q["deadline_unix"])
        self.assertEqual(before, (request.read_bytes(), draft.read_bytes()))

    def test_refuses_wrong_paths_digest_and_window(self):
        for change in ({"request":"/root/sbxr-qualification-evidence/request.json"},
                       {"draft":"/root/mvp-observation-draft.json"}, {"digest":"0"*64},
                       {"window":dict(self.window, finish_unix=self.window["finish_unix"]+1)}):
            with self.subTest(change=change), self.assertRaises(ValueError): self.validate(**change)

    def test_refuses_scope_or_reserve_changes(self):
        for key,value in (("attended_finish_by","2099-01-01T00:00:00Z"), ("deadline_unix",self.q["deadline_unix"]+1),
                          ("diagnostic_test_until_unix",self.q["diagnostic_test_until_unix"]+1),
                          ("required_checks",["packaged-install"]), ("scenario_id","mvp-removal"),
                          ("scenario_limit_seconds",True), ("qualification_manifest_sha256","f"*64)):
            q=copy.deepcopy(self.q);q[key]=value
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate(q=q)

    def test_refuses_nondiagnostic_or_attended_manifest(self):
        for key,value in (("required_scenarios",["mvp-install","mvp-removal"]),
                          ("attended_finish_by","2099-01-01T00:00:00Z"), ("karing_response_limit_seconds",3600),
                          ("proxy_profile","vless-vmess"), ("owner_exception","override")):
            m=json.loads(self.raw);m["v3_attempt"][key]=value;raw=collector.canonical(m)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(raw=raw,digest=hashlib.sha256(raw).hexdigest())

if __name__ == "__main__": unittest.main()
