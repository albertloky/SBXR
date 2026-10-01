package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestHTTPRecurringQualificationRequiresHTTPProofAndPreservesReleasedReader(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build %v %s", err, out)
	}
	boundary, manifest, evidence := mvpRecurringQualificationFixtureFor(t, binary, true)
	document := recurringResultFixture(t, boundary, manifest, evidence)
	out, err := runQualificationCommand(binary, document)
	if err != nil {
		t.Fatalf("HTTP qualification refused: %v %s", err, out)
	}
	body := jsonObject(t, out)["records"].([]any)[0].(map[string]any)["body"].(string)
	if !strings.Contains(body, "Recurring evidence policy: mvp-http-recurring-live-v1\n") || !strings.Contains(body, "Subscription transport: "+softwarelifecycle.MVPHTTPTransportDisclosure+"\n") || !strings.Contains(body, "Journey: mvp-serving ") || strings.Contains(body, "Journey: mvp-renewal ") {
		t.Fatal("HTTP qualification misrepresented certificate/TLS evidence")
	}
	var m qualificationManifest
	if !decodeCanonical(manifest, &m) {
		t.Fatal("manifest")
	}
	r := m.Releases[0]
	support := m.V3Attempt.Support.lifecycle()
	public := softwarelifecycle.LatestRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: r.ReleaseIdentity.Repository, Tag: r.Tag, Commit: r.Commit, IndexSHA256: r.ReleaseIdentity.ReleaseIndexSHA256}, Sequence: r.Sequence, Support: &support}
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, []byte(qualificationDocument(t, map[string]any{"body": body, "release": public, "assets": r.Assets})), 0600); err != nil {
		t.Fatal(err)
	}
	check := exec.Command("go", "test", "../../internal/softwarelifecycle/adapter/github", "-run", "TestOrdinaryRecordCompatibility|TestFrozenV3181Reader", "-count=1")
	check.Env = append(os.Environ(), "SBXR_TEST_RECURRING_RECORD="+path)
	if result, err := check.CombinedOutput(); err != nil {
		t.Fatalf("HTTP released/current reader: %v %s", err, result)
	}
	assertOrdinaryPublicationGates(t, binary, boundary, manifest, document, out)
	for _, scenarioIndex := range []int{0, 1, 2, 4, 6, 7} {
		v := jsonObject(t, []byte(qualificationDocument(t, evidence)))
		scenario := v["scenarios"].([]any)[scenarioIndex].(map[string]any)
		checks := scenario["evidence"].([]any)
		scenario["evidence"] = checks[:len(checks)-1]
		rebindRecurringEvidence(t, v)
		assertQualificationRefused(t, binary, recurringResultFixture(t, boundary, manifest, v), "missing HTTP/source/removal proof")
	}
	bad := jsonObject(t, []byte(qualificationDocument(t, evidence)))
	bad["scenarios"].([]any)[6].(map[string]any)["scenario_id"] = "mvp-renewal"
	rebindRecurringEvidence(t, bad)
	assertQualificationRefused(t, binary, recurringResultFixture(t, boundary, manifest, bad), "legacy certificate journey substituted for HTTP serving")
}
