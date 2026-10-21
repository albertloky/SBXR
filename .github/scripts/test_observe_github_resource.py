#!/usr/bin/env python3
"""Exercise the observation command with real child CLI outcomes, without sockets."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("observe-github-resource.py")


class ObservationTests(unittest.TestCase):
    def test_command_classifies_only_explicit_absence(self):
        cases = [
            ("200", 0, '{"id":17}', "present"),
            ("404", 1, '{"message":"Not Found"}', "absent"),
            ("401", 1, '{"message":"Bad credentials"}', None),
            ("403", 1, '{"message":"Forbidden"}', None),
            ("500", 1, '{"message":"Server error"}', None),
            ("502", 1, '{}', None),
            ("200", 1, '{"id":17}', None),
            ("404", 0, '{}', None),
            ("200", 0, 'broken', None),
            ("", 1, 'transport error (HTTP 404)', None),
        ]
        with tempfile.TemporaryDirectory() as directory:
            cli = Path(directory) / "gh"
            cli.write_text("#!/bin/sh\n[ \"$1:$2\" = api:--include ] || exit 9\nprintf '%s' \"$SBXR_GH_RESPONSE\"\nexit \"$SBXR_GH_STATUS\"\n")
            cli.chmod(0o755)
            for code, status, body, expected in cases:
                with self.subTest(code=code, status=status):
                    response = f"HTTP/2.0 {code} Fixture\r\nContent-Type: application/json\r\n\r\n{body}" if code else body
                    env = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"], SBXR_GH_RESPONSE=response, SBXR_GH_STATUS=str(status))
                    result = subprocess.run([sys.executable, str(SCRIPT), "repos/albertloky/SBXR/releases/17"], env=env, capture_output=True, text=True)
                    if expected:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(json.loads(result.stdout)["state"], expected)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
