"""Regression coverage for process-bound numbered-menu confirmation."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

MODULE = Path(__file__).resolve().parent / "v3-packaged-live.sh"
CONFIGURATION = {"outbounds": [{"type": "fixture", "credential": "test-only"}]}

FIXTURE = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ["SBXR_MENU_FIXTURE_ROOT"])
mode = os.environ.get("SBXR_MENU_FIXTURE_MODE", "renumbered")
def event(value):
    with (root / "events.jsonl").open("a") as stream:
        stream.write(json.dumps(value) + "\n")
event({"event":"started","pid":os.getpid()})
print("SBXR V3\nProxy status: Running")
print("Subscription status: Problem detected" if mode == "missing" else "Subscription status: Available")
print("Code: PROXY-INSTALLATION-SETUP-COMPLETE")
print("1. View details\n2. Rotate Client Identity")
if mode != "missing": print("3. Show client configuration")
if mode == "duplicate": print("7. Show client configuration")
print("4. Check\n5. Update\n6. Recover\n0. Exit", flush=True)
number = sys.stdin.readline().strip(); event({"event":"selected","number":number})
if number == "0": raise SystemExit(0)
if number == "2":
    print("Rotate Client Identity? [y/N]", flush=True)
    event({"event":"rotation-answer","answer":sys.stdin.readline().strip()})
    raise SystemExit(0)
if number != "3" or mode == "missing": raise SystemExit(1)
print("Rotate Client Identity? [y/N]" if mode == "wrong-prompt" else "Show client configuration? [y/N]", flush=True)
answer=sys.stdin.readline().strip(); event({"event":"disclosure-answer","answer":answer})
if answer != "y" or mode == "wrong-prompt": raise SystemExit(0)
print("----- BEGIN SBXR CLIENT CONFIGURATION -----")
print(json.dumps({"outbounds":[{"type":"fixture","credential":"test-only"}]}))
print("----- END SBXR CLIENT CONFIGURATION -----")
if mode in ("rust", "wrong-result", "duplicate-result"):
    print("Code: " + ("PROXY-INSTALLATION-ACTION-REFUSED" if mode == "wrong-result" else "PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED"))
    if mode == "duplicate-result": print("Code: PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED")
print("Press Enter to preserve this configuration in terminal scrollback and return to the menu.", flush=True)
event({"event":"continue","value":sys.stdin.readline().strip()})
print("SBXR V3\nProxy status: Running\nSubscription status: Available")
print("Code: SOFTWARE-LIFECYCLE-STATUS-READY" if mode in ("rust", "missing-result") else "Code: PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED")
print("1. View details\n2. Show client configuration\n3. Rotate Client Identity\n0. Exit", flush=True)
event({"event":"exit","number":sys.stdin.readline().strip()})
'''

class MenuDisclosureTest(unittest.TestCase):
    def invoke(self, mode="renumbered"):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); fixture=root/"sbxr"
            fixture.write_text(FIXTURE); fixture.chmod(0o700)
            script=f'''set -euo pipefail
source {shlex.quote(str(MODULE))}
function /usr/local/bin/sbxr {{ {shlex.quote(str(fixture))}; }}
remote_outside_disclose
'''
            env=dict(os.environ,SBXR_MENU_FIXTURE_ROOT=temporary,
                     SBXR_MENU_FIXTURE_MODE=mode,SBXR_EXECUTABLE=str(fixture))
            result=subprocess.run(["/bin/bash","--noprofile","--norc","-c",script],
                                  env=env,text=True,capture_output=True,timeout=10)
            events=[json.loads(line) for line in (root/"events.jsonl").read_text().splitlines()]
            return result,events

    def test_uses_current_process_label_after_renumbering(self):
        result,events=self.invoke()
        self.assertEqual(result.returncode,0,(result.stderr,events))
        self.assertEqual(json.loads(result.stdout),CONFIGURATION)
        self.assertIn({"event":"selected","number":"3"},events)
        self.assertIn({"event":"disclosure-answer","answer":"y"},events)
        self.assertNotIn("rotation-answer",[item["event"] for item in events])
        self.assertIn({"event":"exit","number":"0"},events)

    def test_rust_result_before_continuation(self):
        result, events = self.invoke("rust")
        self.assertEqual(result.returncode, 0, (result.stderr, events))
        self.assertEqual(json.loads(result.stdout), CONFIGURATION)
        self.assertIn({"event": "exit", "number": "0"}, events)

    def test_wrong_or_duplicate_result_before_continuation_refuses(self):
        for mode in ("wrong-result", "duplicate-result"):
            with self.subTest(mode=mode):
                result, events = self.invoke(mode)
                self.assertNotEqual(result.returncode, 0)
                # Disclosure was explicitly confirmed; the wrapper may already
                # have streamed it, but must refuse the session result.
                self.assertNotIn("continue", [item["event"] for item in events])
                self.assertIn("phase=result-mismatch", result.stderr)

    def test_continuation_without_disclosure_result_refuses(self):
        result, events = self.invoke("missing-result")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("phase=result-mismatch", result.stderr)
        self.assertNotIn("exit", [item["event"] for item in events])

    def test_missing_label_never_confirms_rotation(self):
        result,events=self.invoke("missing")
        self.assertNotEqual(result.returncode,0); self.assertEqual(result.stdout,"")
        self.assertNotIn("rotation-answer",[item["event"] for item in events])
        self.assertNotIn("disclosure-answer",[item["event"] for item in events])
        self.assertIn("SBXR_MENU_SESSION_REFUSED phase=label-missing",result.stderr)

    def test_duplicate_label_never_selects_or_confirms(self):
        result,events=self.invoke("duplicate")
        self.assertNotEqual(result.returncode,0); self.assertEqual(result.stdout,"")
        self.assertNotIn("disclosure-answer",[item["event"] for item in events])
        self.assertIn("SBXR_MENU_SESSION_REFUSED phase=label-duplicate",result.stderr)

    def test_wrong_prompt_never_sends_confirmation(self):
        result,events=self.invoke("wrong-prompt")
        self.assertNotEqual(result.returncode,0); self.assertEqual(result.stdout,"")
        self.assertEqual([item for item in events if item["event"]=="selected"][-1]["number"],"3")
        self.assertNotIn("disclosure-answer",[item["event"] for item in events])
        self.assertNotIn("rotation-answer",[item["event"] for item in events])
        self.assertIn("SBXR_MENU_SESSION_REFUSED phase=prompt-mismatch",result.stderr)

if __name__ == "__main__": unittest.main()
