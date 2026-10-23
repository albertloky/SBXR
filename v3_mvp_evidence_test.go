package architecture_test

import (
	"bytes"
	"os/exec"
	"testing"

	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
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
	for _, path := range []string{".github/scripts/test_native_receipts.py", ".github/scripts/test_native_settings.py", ".github/scripts/test_native_profiles.py", ".github/scripts/test_capture_native.py"} {
		if output, err := exec.Command("python3", "-B", path).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", path, err, output)
		}
	}
}

func TestNativeTwoNodeContractMatchesProductSubscription(t *testing.T) {
	artifact, err := (singbox.Adapter{}).EncodeSubscriptionArtifact(singbox.ConnectionFacts{
		PublicIPv4: "198.51.100.10", UUID: "12345678-1234-4234-8234-123456789abc",
		ServerName: "example.com", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ShortID: "01020304", VMessHostname: "tunnel.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Reuse public native fixtures; execute only data validation, never Karing.
	script := `import importlib.util, pathlib, sys
p = pathlib.Path('.github/scripts/test_native_receipts.py')
s = importlib.util.spec_from_file_location('public_native_fixtures', p)
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)
case = m.NativeReadbackTests()
try:
    case.setUp()
    attempt, profile, _ = case.combined()
    profile['servers'][0]['tag'] = 'SBXR Proxy (198.51.100.10)'
    case.profile = profile
    case.write('expected-wire.private', sys.stdin.buffer.read())
    case.persist()
    m.RECEIPTS.readbacks(case.live, case.facts, 'expected-url.private',
                        'expected-wire.private', attempt=attempt)
finally:
    case.doCleanups()
`
	command := exec.Command("python3", "-B", "-c", script)
	command.Stdin = bytes.NewReader(artifact)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("product/native two-node contract: %v\n%s", err, output)
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
