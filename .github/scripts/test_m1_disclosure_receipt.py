"""Exercise the real disclosure driver and its failure-only metadata, offline."""
import hashlib
import io
import json
import runpy
from contextlib import redirect_stderr, redirect_stdout
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
LABEL = "Show client configuration"
CODE = "PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED"
CANARY = "SECRET-CANARY-injected-text"
FIXTURE = """#!/usr/bin/env python3
import os, sys, time
print("SBXR V3\\n3. Show client configuration\\n0. Exit", flush=True)
assert input() == "3"
print("Show client configuration? [y/N]", flush=True)
assert input() == "y"
print("SECRET-CANARY-injected-text", file=sys.stderr, flush=True)
print("SBXR_M1_DISCLOSURE label-missing exit 17", file=sys.stderr, flush=True)
mode=os.environ["SYNTHETIC_MODE"]
if mode == "silent": time.sleep(5)
if mode == "early": sys.exit(8)
print("Code: PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED", flush=True)
print("Press Enter to preserve this configuration in terminal scrollback and return to the menu.", flush=True)
assert input() == ""
print("SBXR V3\\n0. Exit", flush=True)
assert input() == "0"
"""

def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def run_driver(root, mode):
    executable = root / "synthetic-product"
    executable.write_text(FIXTURE)
    executable.chmod(0o700)
    argv = [sys.executable, "-I", "-B", str(SCRIPTS / "v3-menu-session.py"), "disclose", LABEL, CODE,
            "--executable", str(executable), "--timeout", "2"]
    env = dict(os.environ, SYNTHETIC_MODE=mode, SBXR_M1_DISCLOSURE_RECEIPT="1")
    return subprocess.run(argv, capture_output=True, env=env, timeout=8)


class DisclosureReceiptTest(unittest.TestCase):
    def test_only_bound_closed_fields_reach_failure(self):
        projection = runpy.run_path(str(SCRIPTS / "m1_disclosure_receipt.py"))
        h = digest
        request = b"fixture"
        intent = dict(run=321, attempt=1, job="654", operation="disclose", label="m1-client",
                      scenario="mvp-install", request_sha256=h(request), manifest_sha256="a"*64, window_sha256="b"*64)
        terminal = dict(binding_sha256=h(json.dumps(intent,sort_keys=True,separators=(",",":")).encode()),
                        command_exit=1, stdout_size=0, stdout_sha256=h(b""))
        raw = b"untrusted SECRET-CANARY\nSBXR_M1_DISCLOSURE output-deadline other 90004\n"
        projection["add_diagnostic"](terminal, intent, raw)
        result = dict(outcome="command-completed", no_retry=True, exit=1, stdout_size=0, stdout_sha256=h(b""), remote_terminal=terminal)
        failure = dict(attempt_id="run-321-attempt-1", scenario_id="mvp-install", operation_id="operation-1", actual_result="unexpected-failure")
        diag = projection["bound_diagnostic"](failure, intent, result, h(request), "a"*64, "b"*64)
        self.assertEqual(diag, dict(reason="output-deadline",last_input_class="other",elapsed_ms=90004))
        self.assertNotIn("CANARY", json.dumps(diag))
        for unsafe in (raw + raw, raw.replace(b"other", b"secret"), raw.replace(b"90004", b"120001"),
                       raw.replace(b"output-deadline", b"SECRET-CANARY")):
            t = {k:v for k,v in terminal.items() if k!="m1_disclosure"}
            projection["add_diagnostic"](t, intent, unsafe)
            self.assertNotIn("m1_disclosure", t)
        for bad in (dict(result, outcome="uncertain-remote-outcome"), dict(result, exit=0),
                    dict(result, remote_terminal=dict(terminal, m1_disclosure=dict(diag, raw=CANARY)))):
            with self.assertRaises(ValueError):
                projection["bound_diagnostic"](failure, intent, bad, h(request), "a"*64, "b"*64)
        with self.assertRaises(ValueError):
            projection["bound_diagnostic"](failure, intent, result, h(b"other"), "a"*64, "b"*64)

    def test_submission_and_staged_artifact(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            manifest = dict(workflow=dict(run_id="321", commit="f"*40), v3_attempt={})
            manifest_bytes = wire(manifest)
            request = wire(dict(scenario_id="mvp-install", deadline_unix=123, qualification_manifest_sha256=digest(manifest_bytes)))
            intent = dict(run=321, attempt=1, job="654", operation="disclose", label="m1-client",
                          scenario="mvp-install", request_sha256=digest(request), manifest_sha256=digest(manifest_bytes),
                          source="f"*40)
            outcome = run_driver(root, "early")
            self.assertEqual(outcome.returncode, 1)
            projection = runpy.run_path(str(SCRIPTS / "m1_disclosure_receipt.py"))
            terminal = dict(binding_sha256=digest(wire(intent)), command_exit=outcome.returncode,
                            stdout_size=len(outcome.stdout), stdout_sha256=digest(outcome.stdout))
            projection["add_diagnostic"](terminal, intent, outcome.stderr)
            diag = terminal["m1_disclosure"]
            self.assertEqual(diag["reason"], "exit-before-continuation")
            result = dict(outcome="command-completed", no_retry=True, exit=outcome.returncode, stdout_size=len(outcome.stdout),
                          stdout_sha256=digest(outcome.stdout), remote_terminal=terminal)
            facts = dict(schema="sbxr-release-qualification-facts-v1", stage="v3-scenario-failure", qualification_manifest=manifest,
                         failure=dict(attempt_id="run-321-attempt-1", scenario_id="mvp-install", operation_id="operation-1", actual_result="unexpected-failure"))
            for n, data in (("manifest",manifest_bytes), ("facts",wire(facts)), ("request",request),
                            ("m1-disclose-client-operation-intent.json",wire(intent)), ("m1-disclose-client-result.json",wire(result))):
                path = root/n
                path.write_bytes(data)
                path.chmod(0o600)
            # Only the SSH boundary is replaced; run the real shell submit and Python receipt projection.
            ssh = root/"ssh"
            ssh.write_text("#!/bin/sh\ncase \" $* \" in *' -n '*) sha256sum request | cut -d' ' -f1; cat request;; *) cat > received;; esac\n")
            ssh.chmod(0o700)
            def prepare():
                submission = projection["attach_to_failure"](facts, root, job="654", request_sha256=digest(request),
                                                             manifest_sha256=digest(manifest_bytes), window_sha256=None)
                (root / "prepared-facts").write_bytes(wire(submission))
            prepare()
            cmd = ["bash", str(SCRIPTS/"v3-recurring-evidence.sh"), "submit", "fixture.invalid", "key", "known", "manifest", "prepared-facts"]
            proc = subprocess.run(cmd, cwd=root, env=dict(os.environ, PATH=str(root)+os.pathsep+os.environ["PATH"]), capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual((root/"facts").read_bytes(), wire(facts))
            self.assertEqual((root/"received").read_bytes(), (root/"prepared-facts").read_bytes())
            delivered = json.loads((root/"received").read_bytes())
            self.assertEqual(delivered["failure"]["m1_disclosure"], diag)
            self.assertNotIn(CANARY.encode(), (root / "received").read_bytes() + proc.stderr + proc.stdout)
            # An independently bound fresh window has a different workflow from
            # the signed origin. Match both digests and the actual protected job.
            fresh_workflow = dict(manifest["workflow"], run_id="322")
            window_decision = {"window": {"workflow": fresh_workflow}}
            window_sha = digest(wire(window_decision))
            fresh_facts = dict(facts, fresh_window=dict(workflow=fresh_workflow, window_decision=window_decision),
                               failure=dict(facts["failure"], attempt_id="run-322-attempt-1"))
            fresh_intent = dict(intent, run=322, window_sha256=window_sha)
            fresh_terminal = dict(terminal, binding_sha256=digest(wire(fresh_intent)))
            (root / "m1-disclose-client-operation-intent.json").write_bytes(wire(fresh_intent))
            (root / "m1-disclose-client-result.json").write_bytes(wire(dict(result, remote_terminal=fresh_terminal)))
            inputs = dict(job=654, request_sha256=digest(request), manifest_sha256=digest(manifest_bytes), window_sha256=window_sha)
            self.assertEqual(projection["attach_to_failure"](fresh_facts,root,**inputs)["failure"]["m1_disclosure"], diag)
            for wrong in (dict(inputs, job=655), dict(inputs, window_sha256="0"*64)):
                self.assertEqual(projection["attach_to_failure"](fresh_facts,root,**wrong), fresh_facts)
            (root / "m1-disclose-client-result.json").write_bytes(wire(result))
            # An unavailable optional diagnostic must neither borrow another intent nor
            # prevent the original terminal failure from reaching the collector.
            (root / "m1-disclose-client-operation-intent.json").write_bytes(wire(dict(intent, run=322)))
            prepare()
            fallback = subprocess.run(cmd, cwd=root, env=dict(os.environ, PATH=str(root)+os.pathsep+os.environ["PATH"]),
                                      capture_output=True)
            self.assertEqual(fallback.returncode, 0)
            self.assertEqual((root / "received").read_bytes(), wire(facts))
            stage = runpy.run_path(str(SCRIPTS/"candidate-evidence.py"))["stage"]
            evidence = root/"handoff/failure-evidence/failure.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_bytes(wire(delivered))
            self.assertEqual(stage(root,root/"safe"),1)
            decision = dict(schema="sbxr-release-qualification-decision-v1", stage="v3-scenario-failure",
                            outcome="failed", stop_test_mutations=True, burn_required=True, failure=delivered["failure"])
            decision_path = evidence.with_name("failure-decision.json")
            decision_path.write_bytes(wire(decision))
            log = io.StringIO()
            with redirect_stdout(log):
                self.assertEqual(stage(root,root/"with-decision"),2)
            self.assertEqual(log.getvalue().splitlines(), [
                f"M1 disclosure: reason={diag['reason']} last_input_class={diag['last_input_class']} elapsed_ms={diag['elapsed_ms']}"])
            decision_path.unlink()
            for k, val in (("reason",CANARY), ("last_input_class",CANARY), ("elapsed_ms",False), ("free_text",CANARY)):
                evidence.write_bytes(wire(dict(delivered,failure=dict(delivered["failure"],m1_disclosure=dict(diag,**{k:val})))))
                log = io.StringIO()
                with redirect_stderr(log):
                    self.assertEqual(stage(root,root/k),0)
                self.assertNotIn(CANARY,log.getvalue())

    def test_native_disclosure_outcomes(self):
        for mode, expected in (("silent", "output-deadline"), ("early", "exit-before-continuation"), ("pass", None)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                result = run_driver(Path(tmp), mode)
                self.assertEqual(result.returncode, int(expected is not None))
                rows = [line.split() for line in result.stderr.splitlines() if line.startswith(b"SBXR_M1_DISCLOSURE ")]
                if expected is None:
                    self.assertEqual(rows, [])
                else:
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0][1:3], [expected.encode(), b"other"])
                    self.assertTrue(0 <= int(rows[0][3]) < 8000)
                    self.assertNotIn(CANARY.encode(), b" ".join(rows[0]))

if __name__ == "__main__":
    unittest.main()
