import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
import io


PATH = Path(__file__).with_name("assemble-evidence.py")
SPEC = importlib.util.spec_from_file_location("assemble_evidence", PATH)
assembler = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = assembler
SPEC.loader.exec_module(assembler)


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


class Fixture:
    def __init__(self, root):
        self.root = Path(root)
        self.now = int(time.time())
        self.paths = {}

    def write(self, name, raw, mode=0o600):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(mode)
        self.paths[name] = path
        return path

    def document(self, name, value, newline=False):
        return self.write(name, canon(value) + (b"\n" if newline else b""))

    def build(self):
        packages = {"snap":{"name":"snapd"}, "certbot":{"name":"certbot"}, "karing":{"name":"karing"}}
        candidate = {"commit":"a"*40,"release_identity":{"commit":"a"*40,"release_index_sha256":"b"*64,"repository":"owner/repo","tag":"v9.0.0"},"sequence":900,"tag":"v9.0.0"}
        required = ["baseline-clean","baseline-refusal","baseline-precommit","baseline-postcommit","baseline-drift","baseline-removal","identity-absent","enable-schema1","later"]
        attempt = {"attempt_id":"attempt-1","evidence_policy":assembler.POLICY,"packages":packages,"required_scenarios":required,
                   "runner":{"architecture":"amd64"},"scenario_limit_seconds":1800,"schema":"sbxr-v3-qualification-attempt-v3",
                   "started_at":stamp(self.now-500),"validation_limit_seconds":300,"vps_id":"vps-1","vps_identity_sha256":"c"*64}
        manifest = {"mode":"v3","releases":[candidate],"schema":"sbxr-qualification-manifest-v3","source_state":"v3-subscription-clean","v3_attempt":attempt}
        manifest_raw = canon(manifest); manifest_sha = sha(manifest_raw)
        boundary = {"fixture":"boundary"}; boundary_raw = canon(boundary)
        request = {"deadline_unix":self.now+120,"not_before":stamp(self.now-100),"qualification_manifest_sha256":manifest_sha,
                   "scenario_id":"enable-schema1","scenario_limit_seconds":1800}
        request_raw = canon(request)
        prefix=[]; previous=manifest_sha
        for index, scenario in enumerate(required[:7]):
            item={"attempt_id":"attempt-1","candidate":candidate,"completed_at":stamp(self.now-300+index*20),"operation_id":f"operation-{index+1}",
                  "packages_after":packages,"packages_before":packages,"prior_scenario_sha256":previous,"scenario_id":scenario,
                  "schema":"sbxr-v3-scenario-evidence-v3","started_at":stamp(self.now-310+index*20),"validated_at":stamp(self.now-295+index*20),
                  "vps_id":"vps-1","vps_identity_sha256":"c"*64}
            prefix.append(item); previous=sha(canon(item))
        prefix_raw=canon(prefix)
        state={"action_completed_at":stamp(self.now-30),"action_started_at":stamp(self.now-40),"authoritative_link_sha256":"d"*64,
               "config_sha256":"1"*64,"creation_provenance":[candidate["release_identity"]],"entry_started_at":stamp(self.now-49),"install_at":stamp(self.now-48),"key_sha256":"2"*64,
               "ownership_sha256":"3"*64,"proxy_pid":"123","proxy_start_tick":"456","release_identity":candidate["release_identity"],
               "setup_at":stamp(self.now-45),"started_at":stamp(self.now-50),"uuid_sha256":"4"*64}
        state_raw=canon(state)
        safe={"action_completed_at":state["action_completed_at"],"action_started_at":state["action_started_at"],"authoritative_link_sha256":"d"*64,
              "completed_at":stamp(self.now-5),"final_state":"Running","initial_state":"Running","link_id":"e"*32,"ownership_record_sha256":"f"*64,
              "ownership_schema":2,"private_state_sha256":sha(state_raw),"qualification_manifest_sha256":manifest_sha,"request_sha256":sha(request_raw),
              "scenario_id":"enable-schema1","schema":"sbxr-v4-enable-schema1-safe-state-v1","started_at":state["started_at"],"subscription_observed_at":"pending"}
        capture=b"operator capture bytes\n"
        rules=assembler.timing.scenario_rules("enable-schema1")
        operator_rows=[]
        for rule in rules:
            for anchor in rule.not_before:
                if anchor.source=="entry":
                    at=stamp(self.now-45 if anchor.event=="candidate_setup_origin_at" else self.now-20)
                    operator_rows.append({"capture_sha256":sha(capture),"check":rule.check,"event":anchor.event,"observed_at":at,"result":"observed"})
        operator={"capture_sha256":sha(capture),"observations":operator_rows,"qualification_manifest_sha256":manifest_sha,"request_sha256":sha(request_raw),
                  "scenario_id":"enable-schema1","schema":assembler.OPERATOR_SCHEMA}
        route={"check":"supported-effective-route-inspected","completed_at":stamp(self.now-44),"effective_exec_verified":True,"owned_artifacts_sha256":{},
               "qualification_manifest_sha256":manifest_sha,"record_sha256":"9"*64,"request_sha256":sha(request_raw),"route":"official-snap",
               "scenario_id":"enable-schema1","schema":"sbxr-v4-effective-route-v1","started_at":stamp(self.now-45),"timer_calendar_verified":True}
        trace=(canon({"check":1,"connection_id":"1"*32,"request_sha256":sha(request_raw),"same_connection":True,"schema":"sbxr-v3-connection-probe-v1","time":stamp(self.now-42)})+b"\n"+
               canon({"check":2,"connection_id":"1"*32,"request_sha256":sha(request_raw),"same_connection":True,"schema":"sbxr-v3-connection-probe-v1","time":stamp(self.now-10)})+b"\n")
        summary={"action_spanned":True,"checks":2,"same_connection":True,"trace_sha256":sha(trace)}
        subscription={"artifact_fields_and_name":True,"expected_status":True,"link_sha256":"d"*64,"certificate_der_sha256":"5"*64,"completed_at":stamp(self.now-30).replace("Z",".200000Z"),"configuration_sha256":"1"*64,"schema":"sbxr-v4-subscription-check-v2","qualification_manifest_sha256":manifest_sha,"request_sha256":sha(request_raw),"scenario_id":"enable-schema1","started_at":stamp(self.now-30).replace("Z",".100000Z"),"trusted_outside_tls":True}
        safe["subscription_observed_at"]=subscription["completed_at"]
        safe["subscription_receipt_sha256"]=sha(canon(subscription)+b"\n")
        validator = b'''#!/usr/bin/env python3
import hashlib,json,sys
raw=sys.stdin.buffer.read(); facts=json.loads(raw); prior=facts["prior_decision_sha256"]
value={"facts_sha256":hashlib.sha256(raw).hexdigest(),"outcome":"accepted","prior_decision_sha256":prior,"records":[],"schema":"sbxr-release-qualification-decision-v1","stage":"v3-scenario-result"}
sys.stdout.write(json.dumps(value,sort_keys=True,separators=(",",":")))
''' + b"#" + b"x" * (assembler.JSON_LIMIT + 100)
        validator_path=self.write("validator",validator,0o700); validator_sha=sha(validator)
        preparation={"accepted_prior_prefix_sha256":sha(prefix_raw),"prepared_at":stamp(self.now-49),"qualification_boundary_facts_sha256":sha(boundary_raw),
                     "qualification_manifest_sha256":manifest_sha,"request_sha256":sha(request_raw),"scenario_id":"enable-schema1","schema":assembler.PREPARATION_SCHEMA,
                     "validator_sha256":validator_sha,"verifications":[
                         {"artifact_sha256":manifest_sha,"check":"fresh-signed-manifest","observed_at":stamp(self.now-52),"result":"verified"},
                         {"artifact_sha256":sha(boundary_raw),"check":"qualification-boundary","observed_at":stamp(self.now-51),"result":"verified"},
                         {"artifact_sha256":validator_sha,"check":"pinned-validator","observed_at":stamp(self.now-50),"result":"verified"}]}
        source_events={"state":{"setup_at":state["setup_at"],"action_started_at":state["action_started_at"],"action_completed_at":state["action_completed_at"]},
                       "connection":{"last_at":stamp(self.now-10)},"subscription":{"observed_at":subscription["completed_at"]},
                       "entry":{row["event"]:row["observed_at"] for row in operator_rows},"route":{"completed_at":route["completed_at"]}}
        records=[]
        for rule in rules:
            lower=max(assembler.instant(source_events[a.source][a.event],"fixture") for a in rule.not_before)
            observed=stamp(lower.epoch_second + (1 if lower.nanosecond else 0))
            records.append({"check":rule.check,"observed_at":observed,"result":"observed"})
        proof={"completed_at":stamp(self.now-1),"link_id":"","observations":records,"operation_id":"operation-8","scenario_id":"enable-schema1","schema":assembler.PROOF_SCHEMA}
        values=(("manifest",manifest,False),("boundary",boundary,False),("request",request,False),("prefix",prefix,False),("preparation",preparation,True),
                ("operator",operator,True),("route",route,True),("state",state,False),("safe",safe,False),("summary",summary,True),("subscription",subscription,True),("proof",proof,True))
        for name,value,newline in values:self.document(name,value,newline)
        self.write("capture",capture); self.write("trace",trace)
        self.output=self.root/"output"
        self.command=[sys.executable,str(PATH),"enable-schema1","--manifest",str(self.paths["manifest"]),"--boundary",str(self.paths["boundary"]),
            "--request",str(self.paths["request"]),"--accepted-prior-prefix",str(self.paths["prefix"]),"--preparation-receipt",str(self.paths["preparation"]),
            "--operator-observations",str(self.paths["operator"]),"--operator-capture",str(self.paths["capture"]),"--effective-route",str(self.paths["route"]),"--state",str(self.paths["state"]),
            "--safe-state",str(self.paths["safe"]),"--connection-observation",str(self.paths["trace"]),"--connection-summary",str(self.paths["summary"]),
            "--subscription-observation",str(self.paths["subscription"]),"--proof",str(self.paths["proof"]),
            "--validator",str(validator_path),"--validator-sha256",validator_sha,"--output",str(self.output)]


class AssembleEvidenceTests(unittest.TestCase):
    def fixture(self):
        temporary=tempfile.TemporaryDirectory(); root=Path(temporary.name); root.chmod(0o700)
        fixture=Fixture(root); fixture.build(); return temporary,fixture

    def test_complete_08_path_writes_canonical_validator_accepted_facts(self):
        temporary,fixture=self.fixture()
        with temporary:
            result=subprocess.run(fixture.command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertGreater(fixture.paths["validator"].stat().st_size,assembler.JSON_LIMIT)
            facts=json.loads(fixture.output.read_bytes())
            self.assertTrue(facts["qualification_manifest_attested"])
            scenario=facts["detailed_evidence"]["scenarios"][-1]
            self.assertEqual((scenario["scenario_id"],scenario["initial_state"],scenario["final_state"]),("enable-schema1","Running","Running"))
            self.assertEqual(scenario["packages_before"],scenario["packages_after"])

    def test_changed_capture_bytes_are_refused(self):
        temporary,fixture=self.fixture()
        with temporary:
            fixture.paths["capture"].write_bytes(b"different\n")
            result=subprocess.run(fixture.command,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn("capture bytes SHA differs",result.stderr)
            self.assertFalse(fixture.output.exists())

    def test_preparation_cannot_attest_a_different_prefix(self):
        temporary,fixture=self.fixture()
        with temporary:
            value=json.loads(fixture.paths["preparation"].read_bytes()); value["accepted_prior_prefix_sha256"]="0"*64
            fixture.paths["preparation"].write_bytes(canon(value)+b"\n")
            result=subprocess.run(fixture.command,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn("artifact binding differs",result.stderr)
            self.assertFalse(fixture.output.exists())

    def test_subscription_receipt_refuses_stale_time_request_drift_and_byte_change(self):
        for case in ("backdated","request-drift","byte-change"):
            with self.subTest(case=case):
                temporary,fixture=self.fixture()
                with temporary:
                    subscription=json.loads(fixture.paths["subscription"].read_bytes())
                    if case=="backdated": subscription["started_at"]=stamp(fixture.now-31)
                    elif case=="request-drift": subscription["request_sha256"]="0"*64
                    else: subscription["certificate_der_sha256"]="6"*64
                    fixture.paths["subscription"].write_bytes(canon(subscription)+b"\n")
                    if case!="byte-change":
                        safe=json.loads(fixture.paths["safe"].read_bytes()); safe["subscription_observed_at"]=subscription["completed_at"]
                        safe["subscription_receipt_sha256"]=sha(canon(subscription)+b"\n")
                        fixture.paths["safe"].write_bytes(canon(safe))
                    result=subprocess.run(fixture.command,capture_output=True,text=True)
                    self.assertNotEqual(result.returncode,0)
                    self.assertFalse(fixture.output.exists())

    def test_required_checks_come_from_shared_timing_contract(self):
        result=subprocess.run([sys.executable,str(PATH),"required-checks","identity-absent"],capture_output=True,text=True,check=True)
        self.assertEqual(result.stdout.splitlines(),[rule.check for rule in assembler.timing.SCENARIO_07_RULES])

    def test_07_state_accepts_old_session_closure_during_rotation(self):
        times={"started_at":"2030-01-01T00:00:00Z","initial_at":"2030-01-01T00:00:01Z","entry_started_at":"2030-01-01T00:00:01.500000Z","install_at":"2030-01-01T00:00:02Z",
               "setup_at":"2030-01-01T00:00:03Z","old_established_at":"2030-01-01T00:00:04Z","rotation_started_at":"2030-01-01T00:00:05.000000000Z",
               "old_terminated_at":"2030-01-01T00:00:05.500000000Z","rotation_completed_at":"2030-01-01T00:00:06.123456789Z",
               "old_refused_at":"2030-01-01T00:00:07Z","replacement_at":"2030-01-01T00:00:08Z","reviewed_removal_at":"2030-01-01T00:00:09Z",
               "absence_at":"2030-01-01T00:00:10Z","completed_at":"2030-01-01T00:00:11Z"}
        state=dict(times,issuance_lines_before=0,replacement_disclosure_confirmed=True,replacement_pid="22",replacement_tick="33",
                   source_disclosure_confirmed=True,source_group="11",source_pid="12",source_tick="13")
        raw=canon(state)
        source=assembler.state_07_source(state,raw,"identity-absent","a"*64,"b"*64,
                                         {"not_before":"2030-01-01T00:00:00Z"})
        self.assertEqual(source.events["rotation_completed_at"],"2030-01-01T00:00:06.123456789Z")

    def test_controller_adapter_enforces_exact_monotonic_five_checkpoint_receipt(self):
        process={"cgroup":"/system.slice/sbxr-v4-identity-absent-123.service","executable_device":1,"executable_inode":2,"pid":123,"start_tick":456}
        checkpoints=("target prepared","startup integration published","systemd reloaded","startup route verified","source quiescent")
        checks=("startup-publication","reload","effective-route","source-only-before-gate","ordinary-start-denied-after-gate")
        rows=[]
        for index,(checkpoint,check) in enumerate(zip(checkpoints,checks)):
            details={"drop_in_sha256":"d"*64}
            if index>=1: details["loaded_condition_exact"]=True
            if index==3: details.update({"ordinary_active_start":"no-op","source_process":{"pid":99,"start_tick":100},"target_staged_only":True,"whole_host_owner":123})
            if index==4: details.update({"main_pid":0,"ordinary_requests_denied":["start","restart"],"owned_processes_and_descendants_absent":True})
            rows.append({"boundary_index":index,"boundary_process":process,"check":check,"checkpoint":checkpoint,"details":details,
                         "observed_at":f"2030-01-01T00:00:0{index+2}.123456Z","record_sha256":str(index)*64})
        receipt={"boundary_process":process,"completed_at":"2030-01-01T00:00:07.123456Z","final_record_sha256":"f"*64,"initial_record_sha256":"a"*64,
                 "observations":rows,"phase":"rotated","qualification_manifest_sha256":"b"*64,"request_sha256":"c"*64,
                 "result_code":"PROXY-INSTALLATION-CLIENT-IDENTITY-ROTATED","scenario":"identity-absent","schema":1,"started_at":"2030-01-01T00:00:01.123456Z"}
        state={"rotation_started_at":"2030-01-01T00:00:01Z","rotation_completed_at":"2030-01-01T00:00:08.123456789Z"}
        source=assembler.controller_source(receipt,canon(receipt),state,"identity-absent","b"*64,"c"*64)
        self.assertEqual(len(source.events),5)
        changed=json.loads(canon(receipt)); changed["observations"][3]["observed_at"]="2030-01-01T00:00:02Z"
        with self.assertRaisesRegex(assembler.Refusal,"monotonic"):
            assembler.controller_source(changed,canon(changed),state,"identity-absent","b"*64,"c"*64)

    def test_validator_has_separate_64_mib_bound_while_json_stays_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); root.chmod(0o700)
            large=b"x"*(assembler.JSON_LIMIT+1)
            document=root/"document"; document.write_bytes(large); document.chmod(0o600)
            with self.assertRaisesRegex(assembler.Refusal,"exceeded byte bound"):
                assembler.private_bytes(document,"document")
            validator=root/"validator"; validator.write_bytes(large); validator.chmod(0o700)
            self.assertEqual(assembler.private_bytes(validator,"validator",0o700,assembler.VALIDATOR_LIMIT),large)
            with self.assertRaisesRegex(assembler.Refusal,"exceeded byte bound"):
                assembler.private_bytes(validator,"validator",0o700,assembler.JSON_LIMIT)

    def test_boundary_accepts_existing_collector_size_without_raising_receipt_limits(self):
        temporary,fixture=self.fixture()
        with temporary:
            boundary={"history":"x"*(assembler.JSON_LIMIT+1)}
            boundary_raw=assembler.canonical(boundary)
            self.assertLess(len(boundary_raw),assembler.BOUNDARY_LIMIT)
            fixture.paths["boundary"].write_bytes(boundary_raw)
            preparation=json.loads(fixture.paths["preparation"].read_bytes())
            preparation["qualification_boundary_facts_sha256"]=sha(boundary_raw)
            preparation["verifications"][1]["artifact_sha256"]=sha(boundary_raw)
            fixture.paths["preparation"].write_bytes(canon(preparation)+b"\n")
            result=subprocess.run(fixture.command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue(fixture.output.exists())
            ordinary=fixture.root/"ordinary-receipt"
            ordinary.write_bytes(boundary_raw); ordinary.chmod(0o600)
            with self.assertRaisesRegex(assembler.Refusal,"exceeded byte bound"):
                assembler.load(ordinary,"ordinary receipt")

    def test_07_retention_preserves_exact_bytes_and_satisfies_collector_absence_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); root.chmod(0o700)
            expected={}
            for index,name in enumerate(assembler.RETAINED_07):
                raw=canon({"index":index,"name":name})
                path=root/name; path.write_bytes(raw); path.chmod(0o600); expected[name]=raw
            with redirect_stdout(io.StringIO()):
                assembler.retain_07(root)
            for name,raw in expected.items():
                self.assertFalse((root/name).exists())
                retained=root/("07-retained-"+name.removeprefix("07-"))
                self.assertEqual(retained.read_bytes(),raw)
                self.assertEqual(retained.stat().st_mode & 0o777,0o600)
            collector=(PATH.parent.parent/"v3-recurring-evidence.sh").read_text()
            for name in assembler.RETAINED_07:
                self.assertIn(name,collector)
                self.assertNotIn("07-retained-"+name.removeprefix("07-"),collector)

    @unittest.skipUnless(shutil.which("go") and (PATH.parents[3] / "go.mod").is_file(),
                         "Full repository and Go toolchain required for real validator integration")
    def test_real_go_validator_refuses_synthetic_non_authority_without_output(self):
        temporary,fixture=self.fixture()
        with temporary:
            real=fixture.root/"real-sbxr-release"
            build=subprocess.run([shutil.which("go"),"build","-o",str(real),"./cmd/sbxr-release"],
                                 cwd=PATH.parents[3],capture_output=True,text=True,timeout=120)
            self.assertEqual(build.returncode,0,build.stderr)
            real.chmod(0o700); real_sha=sha(real.read_bytes())
            preparation=json.loads(fixture.paths["preparation"].read_bytes())
            preparation["validator_sha256"]=real_sha
            preparation["verifications"][2]["artifact_sha256"]=real_sha
            fixture.paths["preparation"].write_bytes(canon(preparation)+b"\n")
            command=list(fixture.command)
            command[command.index("--validator")+1]=str(real)
            command[command.index("--validator-sha256")+1]=real_sha
            result=subprocess.run(command,capture_output=True,text=True,timeout=30)
            self.assertNotEqual(result.returncode,0)
            self.assertIn("validator",result.stderr)
            self.assertFalse(fixture.output.exists())


if __name__=="__main__": unittest.main()
