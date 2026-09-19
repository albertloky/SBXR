#!/usr/bin/env python3
"""Regression checks for the executable listener comparison in the VPS runbook."""

import copy
import json
import os
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[3]
RUNBOOK = ROOT / "docs/acceptance/v3.1.75-snapshot-recovery-runbook.md"
MARKER = "with open('listeners.before.json', 'rb') as stream:"
HEREDOC = "python3 - <<'PY'\n"


def listener_comparison_source():
    text = RUNBOOK.read_text(encoding="utf-8")
    marker = text.index(MARKER)
    start = text.rfind(HEREDOC, 0, marker)
    assert start >= 0, "listener comparison Python heredoc start missing"
    start += len(HEREDOC)
    end = text.index("\nPY\n", marker)
    source = text[start:end]
    assert source.count(MARKER) == 1
    return source


SSH = """MainPID=885
Result=success
ExecMainStartTimestampMonotonic=23201152
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=disabled
"""

BEFORE = [
    ["LISTEN", "0", "4096", "*:443", "*:*",
     'users:(("sing-box",pid=749,fd=8))'],
    ["LISTEN", "0", "4096", "0.0.0.0:22", "0.0.0.0:*",
     'users:(("sshd",pid=885,fd=3),("systemd",pid=1,fd=181))'],
    ["LISTEN", "0", "4096", "127.0.0.53%lo:53", "0.0.0.0:*",
     'users:(("systemd-resolve",pid=428,fd=15))'],
    ["LISTEN", "0", "4096", "127.0.0.54:53", "0.0.0.0:*",
     'users:(("systemd-resolve",pid=428,fd=17))'],
    ["LISTEN", "0", "128", "127.0.0.1:9999", "0.0.0.0:*",
     'users:(("systemd",pid=1,fd=99))'],
    ["LISTEN", "0", "4096", "[::]:22", "[::]:*",
     'users:(("sshd",pid=885,fd=4),("systemd",pid=1,fd=182))'],
]

AFTER = copy.deepcopy(BEFORE[1:])
AFTER[0][5] = 'users:(("sshd",pid=885,fd=3),("systemd",pid=1,fd=168))'
AFTER[4][5] = 'users:(("sshd",pid=885,fd=4),("systemd",pid=1,fd=169))'


def write_fixtures(directory, after, ssh_after=SSH):
    for name, value in (
        ("listeners.before.json", BEFORE),
        ("listeners.after.json", after),
    ):
        (directory / name).write_text(
            json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8"
        )
    (directory / "ssh.before").write_text(SSH, encoding="utf-8")
    (directory / "ssh.after").write_text(ssh_after, encoding="utf-8")


def run_comparison(source, after, ssh_after=SSH):
    supplied_tmp = pathlib.Path(os.environ["TMPDIR"])
    assert supplied_tmp.is_absolute() and supplied_tmp.is_dir()
    with tempfile.TemporaryDirectory(prefix="runbook-listeners-", dir=supplied_tmp) as raw:
        directory = pathlib.Path(raw)
        write_fixtures(directory, after, ssh_after)
        return subprocess.run(
            ["python3", "-c", source], cwd=directory, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )


def changed(base, row, field, value):
    result = copy.deepcopy(base)
    result[row][field] = value
    return result


def require_refusal(source, label, after, ssh_after=SSH):
    result = run_comparison(source, after, ssh_after)
    assert result.returncode != 0, (label, result.stdout, result.stderr)


def main():
    source = listener_comparison_source()

    # This is the old byte-exact predicate. It must reproduce the captured
    # failure before the executable runbook comparison is exercised.
    assert AFTER != BEFORE[1:]

    result = run_comparison(source, AFTER)
    assert result.returncode == 0, (result.stdout, result.stderr)

    require_refusal(source, "changed SSH PID", changed(
        AFTER, 0, 5,
        'users:(("sshd",pid=886,fd=3),("systemd",pid=1,fd=168))'))
    require_refusal(source, "changed endpoint", changed(
        AFTER, 0, 3, "127.0.0.1:22"))
    require_refusal(source, "changed queue", changed(AFTER, 0, 1, "1"))
    require_refusal(source, "changed non-PID1 fd", changed(
        AFTER, 0, 5,
        'users:(("sshd",pid=885,fd=30),("systemd",pid=1,fd=168))'))
    require_refusal(source, "changed systemd name", changed(
        AFTER, 0, 5,
        'users:(("sshd",pid=885,fd=3),("not-systemd",pid=1,fd=168))'))
    require_refusal(source, "changed systemd PID", changed(
        AFTER, 0, 5,
        'users:(("sshd",pid=885,fd=3),("systemd",pid=2,fd=168))'))
    require_refusal(source, "changed non-SSH systemd fd", changed(
        AFTER, 3, 5, 'users:(("systemd",pid=1,fd=100))'))
    require_refusal(source, "extra listener", AFTER + [[
        "LISTEN", "0", "1", "127.0.0.1:9", "0.0.0.0:*", ""
    ]])
    require_refusal(source, "missing listener", AFTER[1:])
    require_refusal(
        source, "changed SSH fingerprint", AFTER,
        SSH.replace("ExecMainStartTimestampMonotonic=23201152",
                    "ExecMainStartTimestampMonotonic=23201153"),
    )
    print("runbook listener comparison regression: PASS")


if __name__ == "__main__":
    main()
