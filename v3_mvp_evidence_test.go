package architecture_test

import (
	"os/exec"
	"testing"
)

func TestMVPEvidenceAssemblyFixtures(t *testing.T) {
	if output, err := exec.Command("python3", ".github/scripts/test_mvp_operator_run.py").CombinedOutput(); err != nil {
		t.Fatalf("MVP operator launch regression: %v\n%s", err, output)
	}
	if output, err := exec.Command("python3", ".github/scripts/test_mvp_observe.py").CombinedOutput(); err != nil {
		t.Fatalf("MVP observation recorder regression: %v\n%s", err, output)
	}
	if output, err := exec.Command("python3", ".github/scripts/test_mvp_evidence.py").CombinedOutput(); err != nil {
		t.Fatalf("MVP evidence assembler regression: %v\n%s", err, output)
	}
}

func TestNativeKaringReceiptReadbacks(t *testing.T) {
	for _, path := range []string{".github/scripts/test_native_receipts.py", ".github/scripts/test_native_settings.py", ".github/scripts/test_native_profiles.py"} {
		if output, err := exec.Command("python3", "-B", path).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", path, err, output)
		}
	}
}

func TestSharedPackagedMenuDrivers(t *testing.T) {
	for _, path := range []string{
		".github/scripts/test_v3_menu_session.py",
		".github/scripts/test_v3_packaged_live_menu_disclosure.py",
	} {
		if output, err := exec.Command("python3", path).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", path, err, output)
		}
	}
}
