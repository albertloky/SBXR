#!/usr/bin/env python3
"""Run frozen lifecycle tests THROUGH the real launcher and reviewed wrapper.

Input is a diagnostic Go test binary, not a released packaged SBXR executable.
Requires an explicitly marked disposable root Linux VM. No CA/network use.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

from test_mvp_protected_menu import identity, command, ROOT, PRODUCT, LOG, SHARED, STATE, SOURCE


def run(binary):
    assert sys.platform.startswith('linux') and os.geteuid() == 0
    marker = Path('/run/sbxr-isolated-test-host')
    assert marker.read_bytes() == b'disposable SBXR test VM\n'
    assert not marker.is_symlink() and identity(marker)[2:4] == (0, 0) and identity(marker)[5] == 0o600
    for path in (ROOT, PRODUCT, SHARED):
        assert not os.path.lexists(path), path
    baseline = identity(LOG)
    assert baseline[2] == 0 and baseline[5] == 0o775
    original = binary.read_bytes()
    ROOT.mkdir(mode=0o700)
    try:
        for source, target, mode in (
            (SOURCE / 'mvp-protected-menu.sh', ROOT / 'mvp-protected-menu.sh', 0o700),
            (SOURCE / 'sbxr-snapshot-recovery/with-protected-log-parent.sh', ROOT / 'with-protected-log-parent.sh', 0o700),
            (SOURCE / 'sbxr-snapshot-recovery/protected_command_supervisor.py', ROOT / 'protected_command_supervisor.py', 0o600),
            (binary, PRODUCT, 0o755),
        ):
            shutil.copyfile(source, target)
            target.chmod(mode)
        SHARED.mkdir(mode=0o700)
        # Preserve the existing Go tests' owning-package working directory and
        # relative fixture path; do not alter those released tests to pass.
        work = ROOT / 'frozen/internal/softwarelifecycle'
        work.mkdir(parents=True)
        fixture_dir = work.parent / 'proxyinstallation/testdata'
        fixture_dir.mkdir(parents=True)
        shutil.copyfile(SOURCE.parents[1] / 'internal/proxyinstallation/testdata/subscription-absent-schema2.json',
                        fixture_dir / 'subscription-absent-schema2.json')
        result = subprocess.run([str(ROOT / 'mvp-protected-menu.sh')], cwd=work,
                                capture_output=True, timeout=30)
        print(result.stdout.decode(), end='', flush=True)
        print('diagnostic binary SHA256=' + hashlib.sha256(original).hexdigest(), flush=True)
        assert result.returncode == 0, result.stderr.decode()
        assert b'Umask:\t0022' in result.stdout and result.stdout.count(b'--- PASS:') == 4
        assert PRODUCT.read_bytes() == original, 'test executable changed'
        assert not STATE.exists(), 'success left wrapper state'
    finally:
        if STATE.exists():
            command(['bash', str(ROOT / 'with-protected-log-parent.sh'), 'restore', str(STATE)])
        for path in (STATE, Path(str(STATE)+'.control'), Path(str(STATE)+'.result')):
            assert not os.path.lexists(path)
        assert PRODUCT.read_bytes() == original
        PRODUCT.unlink()
        SHARED.rmdir()
        assert identity(LOG) == baseline
        shutil.rmtree(ROOT)
        print('CLEANUP frozen-source-wrapper-test', flush=True)


if __name__ == '__main__':
    run(Path(sys.argv[1]).resolve())
