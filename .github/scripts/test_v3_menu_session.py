"""Focused subprocess tests for the shared same-process menu driver."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

DRIVER = Path(__file__).resolve().parent / "v3-menu-session.py"
FIXTURE = r'''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
root=Path(os.environ["FIXTURE_ROOT"]); spec=json.loads(os.environ["FIXTURE_SPEC"])
def event(value):
    with (root/"events.jsonl").open("a") as stream: stream.write(json.dumps(value)+"\n")
print("SBXR V3\nProxy status: Running\nCode: PROXY-INSTALLATION-STATUS-RUNNING")
print("2. Rotate Client Identity\n7. "+spec["label"]+"\n0. Exit",flush=True)
selected=sys.stdin.readline().strip(); event({"selected":selected})
if selected != "7": raise SystemExit(90)
if spec["kind"] in ("hang","leader-exit"):
    child=os.fork()
    if child == 0:
        if spec.get("escape"): os.setsid()
        (root/"descendant.pending").write_text(str(os.getpid()))
        (root/"descendant.pending").rename(root/"descendant.pid")
        while True: time.sleep(10)
    deadline=time.monotonic()+3
    while not (root/"descendant.pid").exists() and time.monotonic()<deadline: time.sleep(.01)
    if spec["kind"] == "leader-exit": os._exit(0)
    while True: time.sleep(10)
if spec.get("prompt"):
    print(spec["prompt"],flush=True); answer=sys.stdin.readline().rstrip("\n"); event({"answer":answer})
kind=spec["kind"]
if kind == "link":
    print("https://203.0.113.1:8443/s/"+"A"*43)
    print("Press Enter to preserve this link in terminal scrollback and return to the menu.",flush=True)
    event({"continue":sys.stdin.readline().rstrip("\n")})
if kind == "details":
    print("Detected fixture fact\nPress Enter to return to the menu.",flush=True)
    event({"continue":sys.stdin.readline().rstrip("\n")})
elif kind == "observe":
    print(spec["expected"],flush=True)
elif kind == "terminal":
    print("Code: "+spec["expected"],flush=True); raise SystemExit(0)
print("SBXR V3\nProxy status: Running\nCode: "+spec.get("actual",spec.get("expected","PROXY-INSTALLATION-STATUS-RUNNING")))
print("1. View details\n0. Exit",flush=True); event({"exit":sys.stdin.readline().strip()})
'''

class MenuSessionDriverTest(unittest.TestCase):
    def invoke(self,spec,*arguments):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); executable=root/"sbxr"
            executable.write_text(FIXTURE); executable.chmod(0o700)
            env=dict(os.environ,FIXTURE_ROOT=temporary,FIXTURE_SPEC=json.dumps(spec))
            result=subprocess.run([sys.executable,str(DRIVER),*arguments,"--executable",str(executable),"--timeout","5"],
                                  env=env,text=True,capture_output=True,timeout=10)
            events=[json.loads(line) for line in (root/"events.jsonl").read_text().splitlines()] if (root/"events.jsonl").exists() else []
            return result,events

    def test_setup_requires_exact_prompt_then_exits_returned_frame(self):
        spec={"label":"Start setup","prompt":"Start proxy setup? [y/N]","kind":"action","expected":"PROXY-INSTALLATION-SETUP-COMPLETE"}
        result,events=self.invoke(spec,"action","Start setup",spec["expected"],"--confirmation","yes")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"answer":"y"},{"exit":"0"}])

    def test_certificate_replacement_requires_its_prompt_and_exact_result(self):
        spec={"label":"Replace subscription certificate","prompt":"Replace subscription certificate? [y/N]","kind":"action","expected":"PROXY-INSTALLATION-SUBSCRIPTION-CERTIFICATE-REPLACED"}
        result,events=self.invoke(spec,"action",spec["label"],spec["expected"],"--confirmation","yes")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"answer":"y"},{"exit":"0"}])
        spec["actual"]="PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-INCOMPLETE"
        result,events=self.invoke(spec,"action",spec["label"],spec["expected"],"--confirmation","yes")
        self.assertNotEqual(result.returncode,0)
        self.assertIn("phase=result-mismatch",result.stderr)

    def test_details_waits_for_continue_in_same_process(self):
        spec={"label":"View details","kind":"details"}
        result,events=self.invoke(spec,"details","View details")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"continue":""},{"exit":"0"}])
        self.assertIn("Detected fixture fact",result.stdout)

    def test_complete_removal_uses_exact_phrase_and_terminal_result(self):
        spec={"label":"Complete removal","prompt":"Type REMOVE SBXR to confirm Complete removal. Any other input cancels.","kind":"terminal","expected":"SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"}
        result,events=self.invoke(spec,"action","Complete removal",spec["expected"],"--confirmation","remove")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"answer":"REMOVE SBXR"}])

    def test_complete_removal_expected_refusal_sends_no_confirmation(self):
        expected="PROXY-INSTALLATION-ACTION-REFUSED"
        spec={"label":"Complete removal","kind":"action","expected":expected}
        result,events=self.invoke(spec,"action","Complete removal",expected,"--confirmation","remove")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"exit":"0"}])

    def test_unexpected_removal_prompt_during_expected_refusal_gets_no_input(self):
        expected="PROXY-INSTALLATION-ACTION-REFUSED"
        spec={"label":"Complete removal","prompt":"Type REMOVE SBXR to confirm Complete removal. Any other input cancels.","kind":"action","expected":expected}
        result,events=self.invoke(spec,"action","Complete removal",expected,"--confirmation","remove")
        self.assertNotEqual(result.returncode,0)
        self.assertIn("phase=prompt-mismatch",result.stderr)
        self.assertEqual(events,[{"selected":"7"}])

    def test_promptless_finish_removal(self):
        spec={"label":"Finish removal","kind":"terminal","expected":"SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"}
        result,events=self.invoke(spec,"action","Finish removal",spec["expected"])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"}])

    def test_promptless_lifecycle_check_and_update(self):
        for label,code in (("Check","SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT"),("Update","SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT")):
            with self.subTest(label=label):
                spec={"label":label,"kind":"action","expected":code}
                result,events=self.invoke(spec,"action",label,code)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(events,[{"selected":"7"},{"exit":"0"}])

    def test_enable_subscription_consumes_exact_link_pause(self):
        spec={"label":"Enable subscription","prompt":"Enable subscription? [y/N]","kind":"link","expected":"PROXY-INSTALLATION-SUBSCRIPTION-ENABLED"}
        result,events=self.invoke(spec,"action",spec["label"],spec["expected"],"--confirmation","yes")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"answer":"y"},{"continue":""},{"exit":"0"}])

    def test_promptless_recover_branch(self):
        marker="No recovery is available. If a change is in progress, wait for it to finish."
        spec={"label":"Recover","kind":"observe","expected":marker}
        result,events=self.invoke(spec,"observe","Recover",marker)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(events,[{"selected":"7"},{"exit":"0"}])

    def test_result_mismatch_reports_only_phase_and_actual_code(self):
        spec={"label":"Check","kind":"action","expected":"SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT","actual":"SOFTWARE-LIFECYCLE-CHECK-FAILED"}
        result,events=self.invoke(spec,"action","Check",spec["expected"])
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stderr,"SBXR_MENU_SESSION_REFUSED phase=result-mismatch code=SOFTWARE-LIFECYCLE-CHECK-FAILED\n")
        self.assertEqual(events,[{"selected":"7"}])

    def test_expired_request_deadline_refuses_before_product_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); executable=root/"sbxr"; request=root/"request.json"
            executable.write_text(FIXTURE); executable.chmod(0o700)
            request.write_text(json.dumps({"deadline_unix":1}))
            spec={"label":"Check","kind":"action","expected":"SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT"}
            env=dict(os.environ,FIXTURE_ROOT=temporary,FIXTURE_SPEC=json.dumps(spec),SBXR_QUALIFICATION_REQUEST=str(request))
            result=subprocess.run([sys.executable,str(DRIVER),"action","Check",spec["expected"],"--executable",str(executable)],env=env,text=True,capture_output=True,timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stderr,"SBXR_MENU_SESSION_REFUSED phase=deadline-before-start\n")
            self.assertFalse((root/"events.jsonl").exists())

    @unittest.skipUnless(sys.platform.startswith("linux"),"subreaper cleanup requires Linux")
    def test_signal_cancellation_reaps_escaped_descendant(self):
        self.assert_owned_descendant_cleaned("hang",signal_driver=True,escape=True)

    @unittest.skipUnless(sys.platform.startswith("linux"),"subreaper cleanup requires Linux")
    def test_early_leader_exit_still_kills_owned_descendant(self):
        self.assert_owned_descendant_cleaned("leader-exit",signal_driver=False,escape=False)

    def assert_owned_descendant_cleaned(self,kind,*,signal_driver,escape):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); executable=root/"sbxr"
            executable.write_text(FIXTURE); executable.chmod(0o700)
            spec={"label":"Start setup","kind":kind,"escape":escape}
            env=dict(os.environ,FIXTURE_ROOT=temporary,FIXTURE_SPEC=json.dumps(spec))
            process=subprocess.Popen([sys.executable,str(DRIVER),"action","Start setup",
                                      "PROXY-INSTALLATION-SETUP-COMPLETE","--confirmation","yes",
                                      "--executable",str(executable),"--timeout","5"],
                                     env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
            try:
                deadline=time.monotonic()+3
                while not (root/"descendant.pid").exists() and time.monotonic()<deadline: time.sleep(.01)
                self.assertTrue((root/"descendant.pid").exists())
                descendant=int((root/"descendant.pid").read_text())
                if signal_driver: process.terminate()
                stderr=process.communicate(timeout=8)[1]
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=8)
            self.assertNotEqual(process.returncode,0); self.assertIn("SBXR_MENU_SESSION_REFUSED",stderr)
            with self.assertRaises(ProcessLookupError): os.kill(descendant,0)

if __name__ == "__main__": unittest.main()
