"""Real private filesystem and recorder CLI; never contacts a host or runs SBXR."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("diagnostic", HERE / "disclosure-diagnostic.py")
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


class DiagnosticTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "root"
        self.root.mkdir(mode=0o700)
        self.now = int(time.time())
        self.transport = self.root / "sbxr-qualification-v3"
        self.transport.mkdir(mode=0o700)
        self.manifest = self.transport / "qualification-manifest.json"
        self.value = {"schema":"sbxr-qualification-manifest-v3", "v3_attempt":{
            "attempt_id":"run-123-attempt-1", "required_scenarios":["mvp-install"],
            "diagnostic":{"start_unix":self.now-1000, "test_until_unix":self.now+6200, "finish_unix":self.now+9800}}}
        diag.write_new(self.manifest, self.value)
        self.old = self.root / "sbxr-qualification-evidence"
        self.old.mkdir(mode=0o700)
        diag.write_new(self.old / "request.json", {"retained":"STOP"})
        diag.write_new(self.root / "mvp-observation-draft.json", {"retained":"observation"})
        self.before = diag.retained(self.root)

    def prepare(self, now=None):
        result = diag.prepare(self.root, self.manifest, self.now if now is None else now)
        self.target = Path(result["directory"])
        self.binding = result["state_sha256"]
        return result

    def status(self, now=None):
        return diag.status(self.root, self.manifest, self.binding, self.now if now is None else now)

    def test_preserves_old_paths_and_refuses_reuse(self):
        result = self.prepare()
        self.assertEqual(self.status(), "waiting")
        self.assertEqual(diag.retained(self.root), self.before)
        self.assertEqual(result["deadline_unix"]-result["test_until_unix"], 900)
        self.assertEqual(self.status(result["test_until_unix"]), "restore-now")
        with self.assertRaises(FileExistsError): self.prepare()
        with self.assertRaises(ValueError): self.status(result["deadline_unix"])
        self.assertEqual(diag.retained(self.root), self.before)

    def test_notice_never_proves_qualification_and_product_absence_required(self):
        self.prepare()
        state = json.loads(diag.read(self.target / "state.json"))
        diag.write_new(self.target / "operator-finished.json", {"manifest_sha256":state["manifest_sha256"],"request_sha256":state["request_sha256"],"status":"operator-finished"})
        product = self.root.parent / "var/lib/sbxr"
        product.mkdir(parents=True)
        with self.assertRaises(ValueError): self.status()
        product.rmdir()
        self.assertEqual(self.status(), "operator-finished")
        self.assertEqual(diag.retained(self.root), self.before)

    def test_retained_change_refuses_without_overwrite(self):
        self.prepare()
        old = self.old / "request.json"
        old.write_bytes(b"changed by fixture")
        with self.assertRaises(ValueError): self.status()
        self.assertEqual(old.read_bytes(), b"changed by fixture")

    def test_unsafe_old_input_refuses_before_creation(self):
        (self.old / "request.json").chmod(0o644)
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(list(self.root.glob("sbxr-diagnostic-*")))

    def test_wrong_binding_and_request_tampering_refuse(self):
        self.prepare()
        with self.assertRaises(ValueError): diag.status(self.root,self.manifest,"0"*64,self.now)
        (self.target / "request.json").write_bytes(b"changed")
        with self.assertRaises(ValueError): self.status()

    def test_symlinks_and_hardlinks_refuse(self):
        self.prepare()
        request = self.target / "request.json"
        request.unlink()
        request.symlink_to(self.old / "request.json")
        with self.assertRaises(OSError): self.status()
        request.unlink()
        os.link(self.old / "request.json", request)
        with self.assertRaises(ValueError): self.status()

    def test_real_clock_stops_actions_but_allows_cleanup(self):
        self.prepare(self.now-950)
        request = self.target / "request.json"
        draft = self.target / "observation-draft.json"
        value = json.loads(diag.read(request))
        diag.write_new(draft, {"request_sha256":diag.digest(diag.read(request)), "observation":{
            "scenario_id":"mvp-install", "started_at":value["not_before"], "completed_at":None,
            "checks":[{"check":"diagnostic-observation", "observed_at":None,"result":None}]}})
        for command, expected in (("operation-deadline",False),("cleanup-deadline",True)):
            result = subprocess.run([sys.executable,str(HERE / "mvp-observe.py"),command,"--request",str(request),"--draft",str(draft)],capture_output=True,text=True)
            self.assertEqual(result.returncode==0,expected,result.stderr)
            if expected: self.assertEqual(int(result.stdout),value["deadline_unix"])
        self.assertEqual(diag.retained(self.root), self.before)

    def test_ordinary_submit_refuses_diagnostic_before_ssh(self):
        stub = self.root / "bin"
        stub.mkdir()
        marker = self.root / "ssh-called"
        ssh = stub / "ssh"
        ssh.write_text('#!/bin/sh\ntouch "$SSH_MARKER"\nexit 9\n')
        ssh.chmod(0o700)
        env = dict(os.environ, PATH=str(stub)+os.pathsep+os.environ["PATH"], SSH_MARKER=str(marker))
        result = subprocess.run(["bash", str(HERE / "v3-recurring-evidence.sh"), "submit",
                                 "fixture.invalid", "unused-key", "unused-known-hosts", str(self.manifest), "unused-facts"],
                                env=env, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists(), "ordinary collector contacted the host for a diagnostic")
        self.assertEqual(diag.retained(self.root), self.before)

    def test_invalid_window_or_path_identifier_never_creates_evidence(self):
        for key, value in (("finish_unix", self.now+9900),("test_until_unix",self.now+9800)):
            changed = json.loads(diag.read(self.manifest))
            changed["v3_attempt"]["diagnostic"][key] = value
            self.manifest.write_bytes(diag.canonical(changed))
            with self.assertRaises(ValueError): self.prepare()
        self.value["v3_attempt"]["attempt_id"] = "../../evidence"
        self.manifest.write_bytes(diag.canonical(self.value))
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(list(self.root.glob("sbxr-diagnostic-*")))


if __name__ == "__main__": unittest.main()
