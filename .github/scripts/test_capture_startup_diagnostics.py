import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

spec=importlib.util.spec_from_file_location("capture_startup",Path(__file__).with_name("capture-startup-diagnostics.py"))
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.output=self.root/"captured.json"
    def rows(self, message=None, unit="sbxr-subscription.service"):
        return io.BytesIO((json.dumps({"MESSAGE":message or "SBXR_START_V1 role=serving stage=connect result=deadline first=peer elapsed_ms=100 stage_ms=2", "_SYSTEMD_UNIT":unit,"SECRET":"never-save-this"})+"\n").encode())
    def test_private_creation_under_permissive_umask_and_projection(self):
        previous=os.umask(0)
        try: module.capture(self.rows(),self.output)
        finally: os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode),0o600)
        self.assertNotIn("never-save-this",self.output.read_text())
        self.assertEqual(json.loads(self.output.read_text())["records"][0]["first"],"peer")
    def test_existing_or_symlink_never_overwritten(self):
        target=self.root/"target";target.write_text("keep")
        self.output.symlink_to(target)
        with self.assertRaises(OSError):module.capture(self.rows(),self.output)
        self.assertEqual(target.read_text(),"keep")
    def test_malformed_sensitive_or_foreign_rows_refuse_without_capture(self):
        for message,unit in [("SBXR_START_V1 token=secret","sbxr-subscription.service"),(None,"foreign.service"),("SBXR_START_V1 role=serving stage=secret result=deadline first=none elapsed_ms=1 stage_ms=1","sbxr-subscription.service"),("SBXR_START_V1 role=serving stage=connect result=deadline first=none elapsed_ms=1 stage_ms=2","sbxr-subscription.service")]:
            with self.assertRaises(ValueError): module.capture(self.rows(message,unit),self.output)
            self.assertFalse(self.output.exists())
    def test_arbitrary_logs_and_limits(self):
        for data in [b'{"MESSAGE":"secret arbitrary log"}\n', b'x'*(module.MAX_INPUT+1), self.rows().getvalue()*33]:
            with self.assertRaises(ValueError):module.capture(io.BytesIO(data),self.output)
            self.assertFalse(self.output.exists())
    def test_unit_filter_rejects_payloads_and_accepts_each_fixed_category(self):
        # Apply the exact source unit's POSIX ERE via grep -E, without a shell.
        import re
        import subprocess
        source=Path(__file__).resolve().parents[2]/"src/runtime_handoff.rs"
        pattern=re.search(r"LogFilterPatterns=(.*?)\\n",source.read_text()).group(1)
        for stage in module.STAGES:
            for outcome in ["ok","refused","busy","cancelled","deadline"]:
                message=f"SBXR_START_V1 role=serving stage={stage} result={outcome} first=none elapsed_ms=100 stage_ms=2"
                checked=subprocess.run(["grep","-E","-x",pattern],input=message+"\n",text=True,capture_output=True)
                self.assertEqual(checked.returncode,0)
                self.assertIsNotNone(module.RECORD.fullmatch(message))
        for message in ["panic: token=secret", "SBXR_START_V1 token=secret", "SBXR_START_V1 role=serving stage=public-ip result=refused first=none elapsed_ms=1 stage_ms=1 token=secret", "SBXR_START_V1 role=serving stage=secret result=refused first=none elapsed_ms=1 stage_ms=1"]:
            checked=subprocess.run(["grep","-E","-x",pattern],input=message+"\n",text=True,capture_output=True)
            self.assertEqual(checked.returncode,1)
            self.assertEqual(checked.stdout,"")
    def test_nonprivate_parent_refuses(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):module.capture(self.rows(),self.output)
        self.assertFalse(self.output.exists())
if __name__=="__main__":unittest.main()
