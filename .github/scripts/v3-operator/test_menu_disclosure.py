"""Exercise the real Bash menu helper with a temporary, lock-taking menu.

Only the absolute executable call is replaced by a shell function. No fixture
installs SBXR or touches its host paths.
"""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


MODULE = Path(__file__).resolve().parent.parent / "v3-packaged-live.sh"
CONFIGURATION = {"outbounds": [{"type": "fixture", "credential": "test-only"}]}

FIXTURE = r'''
import fcntl
import json
import os
from pathlib import Path
import sys
import time

root = Path(os.environ["SBXR_MENU_FIXTURE_ROOT"])
mode = os.environ.get("SBXR_MENU_FIXTURE_MODE", "normal")
def event(name):
    with (root / "events.jsonl").open("a") as stream:
        stream.write(json.dumps({"event": name, "pid": os.getpid()}) + "\n")

event("started")
with (root / "inspection.lock").open("a") as lock:
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        event("inspection-busy")
        available = False
    else:
        # Model an inspection that briefly excludes another menu's inspection.
        time.sleep(0.15)
        available = mode != "missing-menu"
        fcntl.flock(lock, fcntl.LOCK_UN)
print("Proxy status: Running")
print("Code: PROXY-INSTALLATION-SETUP-COMPLETE")
print("1. View details")
if available:
    print("2. Show client configuration")
print("0. Exit", flush=True)
number = sys.stdin.readline().strip()
if number == "2" and available and sys.stdin.readline().strip() == "y":
    print("----- BEGIN SBXR CLIENT CONFIGURATION -----")
    print(json.dumps({"outbounds": [{"type": "fixture", "credential": "test-only"}]}))
    print("----- END SBXR CLIENT CONFIGURATION -----", flush=True)
event("completed")
'''


class MenuDisclosureTest(unittest.TestCase):
    def invoke(self, mode="normal"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "menu.py"
            fixture.write_text(FIXTURE)
            script = f'''
set -euo pipefail
source {shlex.quote(str(MODULE))}
function /usr/local/bin/sbxr {{ {shlex.quote(sys.executable)} {shlex.quote(str(fixture))}; }}
remote_outside_disclose
'''
            env = dict(os.environ, SBXR_MENU_FIXTURE_ROOT=temporary,
                       SBXR_MENU_FIXTURE_MODE=mode)
            result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", script],
                                    env=env, text=True, capture_output=True, timeout=10)
            events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
            return result, events

    def test_discovery_finishes_before_confirmed_menu_starts(self):
        result, events = self.invoke()
        self.assertEqual(result.returncode, 0, (result.stderr, events))
        self.assertEqual(json.loads(result.stdout), CONFIGURATION)
        self.assertNotIn("inspection-busy", [event["event"] for event in events])
        active = set()
        for event in events:
            if event["event"] == "started":
                self.assertFalse(active, "menu discovery overlapped the action menu")
                active.add(event["pid"])
            elif event["event"] == "completed":
                active.remove(event["pid"])
        self.assertFalse(active)

    def test_missing_option_refuses_before_starting_an_action_menu(self):
        result, events = self.invoke("missing-menu")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(sum(event["event"] == "started" for event in events), 2)


if __name__ == "__main__":
    unittest.main()
