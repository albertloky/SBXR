"""Real private filesystem and recorder CLI; never contacts a host or runs SBXR."""
import base64
import importlib.util
import json
import os
import shlex
import stat
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
            "attempt_id":"run-123-attempt-1", "scenario_limit_seconds":1800, "required_scenarios":["mvp-install"],
            "diagnostic":{"start_unix":self.now-1000, "test_until_unix":self.now+6200, "finish_unix":self.now+9800}}}
        diag.write_new(self.manifest, self.value)
        self.old = self.root / "sbxr-qualification-evidence"
        self.old.mkdir(mode=0o700)
        diag.write_new(self.old / "request.json", {"retained":"STOP"})
        diag.write_new(self.root / "mvp-observation-draft.json", {"retained":"observation"})
        self.before = diag.retained(self.root)

    def clock_args(self):
        clock = (HERE / "mvp-observe.py").read_bytes()
        return dict(clock=clock, clock_sha256=diag.digest(clock))

    def prepare(self, now=None):
        window = self.value["v3_attempt"]["diagnostic"]
        args = self.clock_args() if isinstance(window, dict) and window.get("mode") == "karing-one-node" else {}
        result = diag.prepare(self.root, self.manifest, self.now if now is None else now, **args)
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

    def test_stages_pinned_private_recorder_before_readiness(self):
        attempt = self.value["v3_attempt"]
        attempt["diagnostic"]["mode"] = "karing-one-node"
        attempt["scenario_limit_seconds"] = 2700
        self.manifest.write_bytes(diag.canonical(self.value))
        args = self.clock_args()
        for bad in ({}, dict(args, clock=b"changed"), dict(args, clock=b"")):
            with self.subTest(bad=bad.keys()), self.assertRaises(ValueError):
                diag.prepare(self.root, self.manifest, self.now, **bad)
        self.assertFalse(list(self.root.glob("sbxr-diagnostic-*")))
        self.prepare()
        path = self.target / "mvp-observe.py"
        self.assertEqual(diag.read(path), args["clock"])
        info = path.stat()
        self.assertEqual((info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink), (os.geteuid(), 0o600, 1))
        state = json.loads(diag.read(self.target / "state.json"))
        self.assertEqual(state["clock_sha256"], args["clock_sha256"])
        self.assertFalse((self.target / "observation-draft.json").exists())
        self.assertEqual(self.status(), "waiting")
        path.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.status()

    def test_legacy_diagnostic_does_not_stage_a_recorder(self):
        with self.assertRaises(ValueError):
            diag.prepare(self.root, self.manifest, self.now, **self.clock_args())
        self.prepare()
        self.assertFalse((self.target / "mvp-observe.py").exists())
        self.assertNotIn("clock_sha256", json.loads(diag.read(self.target / "state.json")))

    def test_shell_reports_one_node_pin_before_first_status(self):
        scripts = HERE.resolve()
        stub_dir = self.root / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "ssh"
        stub.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
log = pathlib.Path(os.environ["LOG"])
if " prepare " in sys.argv[-1]:
    pathlib.Path("command").write_text(sys.argv[-1])
    print(json.dumps({"state_sha256":"f"*64}))
else:
    pathlib.Path("before-status").write_bytes(log.read_bytes())
    print("operator-finished")
""")
        stub.chmod(0o700)
        (self.root / ".github").mkdir()
        (self.root / ".github/scripts").symlink_to(scripts)
        handoff = self.root / "handoff"
        handoff.mkdir()
        log = self.root / "shell-log"
        env = dict(os.environ, PATH=str(stub_dir)+os.pathsep+os.environ["PATH"], LOG=str(log))
        for one_node in (False, True):
            if one_node:
                self.value["v3_attempt"]["diagnostic"]["mode"] = "karing-one-node"
                self.value["v3_attempt"]["scenario_limit_seconds"] = 2700
            (handoff / "qualification-manifest.json").write_bytes(diag.canonical(self.value))
            with log.open("wb") as output:
                proc = subprocess.run(["bash", str(scripts / "disclosure-diagnostic.sh"), "fixture.invalid", "fixture-key", "fixture-hosts"],
                                      cwd=self.root, env=env, stdout=output, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            early = (self.root / "before-status").read_text()
            command = shlex.split((self.root / "command").read_text())
            if one_node:
                self.assertEqual(early, "::notice::Karing diagnostic ready run-123-attempt-1 state_sha256=" + "f"*64 + "\n")
                args = self.clock_args()
                self.assertEqual(command[command.index("--clock-sha256")+1], args["clock_sha256"])
                self.assertEqual(base64.b64decode(command[command.index("--clock-base64")+1], validate=True), args["clock"])
            else:
                self.assertEqual(early, "")
                self.assertNotIn("--clock-base64", command)

    def test_nonobject_window_creates_no_namespace(self):
        self.value["v3_attempt"]["diagnostic"] = []
        self.manifest.write_bytes(diag.canonical(self.value))
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(list(self.root.glob("sbxr-diagnostic-*")))

    def test_one_node_scope_refuses_clock_mismatch_without_creating_namespace(self):
        attempt = self.value["v3_attempt"]
        for mode, limit in ((None, 2700), ("karing-one-node", 1800), ("karing-one-node", 7200),
                            ("other", 2700), ("", 1800)):
            if mode is not None:
                attempt["diagnostic"]["mode"] = mode
            attempt["scenario_limit_seconds"] = limit
            self.manifest.write_bytes(diag.canonical(self.value))
            with self.subTest(mode=mode, limit=limit), self.assertRaises(ValueError):
                self.prepare()
        self.assertFalse(list(self.root.glob("sbxr-diagnostic-*")))

    def test_one_node_stops_at_signed_test_cutoff_with_remaining_cleanup_time(self):
        attempt = self.value["v3_attempt"]
        attempt["diagnostic"]["mode"] = "karing-one-node"
        attempt["scenario_limit_seconds"] = 2700
        self.manifest.write_bytes(diag.canonical(self.value))
        cutoff = attempt["diagnostic"]["test_until_unix"]
        with self.assertRaises(ValueError):
            self.prepare(cutoff)
        handoff = self.prepare(cutoff - 90)
        self.assertEqual(handoff["test_until_unix"], cutoff)
        self.assertEqual(self.status(cutoff), "restore-now")
        self.assertGreaterEqual(handoff["deadline_unix"] - cutoff, 1500)

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
