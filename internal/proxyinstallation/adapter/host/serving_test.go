package host

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestServingAuthorityRejectsUnrecordedAndUnsafeMaterial(t *testing.T) {
	a := Adapter{root: t.TempDir()}
	if a.InspectServingFiles(ServingAuthority{}, false).Accepted {
		t.Fatal("empty serving authority accepted")
	}
	authority := ServingAuthority{LinkID: strings.Repeat("a", 32), CredentialSHA256: strings.Repeat("b", 64), CertificateGeneration: 1, CertificateSHA256: [4]string{strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64)}}
	if !authority.Valid() {
		t.Fatal("valid typed authority refused")
	}
	if a.InspectServingFiles(authority, false).Accepted {
		t.Fatal("missing active files accepted")
	}
	path := a.path("/var/lib/sbxr")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "unknown-secret"), []byte("test only"), 0600); err != nil {
		t.Fatal(err)
	}
	if a.InspectServingFiles(authority, true).Accepted {
		t.Fatal("unknown state accepted for removal")
	}
}

func servingFiles(t *testing.T) (Adapter, ServingAuthority) {
	t.Helper()
	a := Adapter{root: t.TempDir()}
	a.subscriptionCommand = func(context.Context, string, ...string) (string, int, bool) { return "", 0, true }
	for _, path := range certbotDirectoryLocks {
		if os.MkdirAll(filepath.Dir(a.path(path)), 0755) != nil || os.WriteFile(a.path(path), nil, 0600) != nil {
			t.Fatal("lock fixture failed")
		}
	}
	for _, dir := range []string{"/var/lib/sbxr", "/var/lib/sbxr/subscription-staging", servingLive, servingArchive} {
		if err := os.MkdirAll(a.path(dir), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(a.path(dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(a.path("/etc/systemd/system"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(a.path(ServingUnitWantsPath)), 0755); err != nil {
		t.Fatal(err)
	}
	token := []byte(strings.Repeat("A", 43) + "\n")
	authority := ServingAuthority{LinkID: strings.Repeat("a", 32), CredentialSHA256: digest(token[:43]), CertificateGeneration: 1}
	for i, name := range certificateNames {
		body := []byte(name + " test only\n")
		authority.CertificateSHA256[i] = digest(body)
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		if err := os.WriteFile(a.path(servingArchive+"/"+name+"1.pem"), body, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../archive/sbxr-subscription/"+name+"1.pem", a.path(servingLive+"/"+name+".pem")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(a.path(ServingUnitPath), []byte(ServingUnit), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../sbxr-subscription.service", a.path(ServingUnitWantsPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.path(ServingTokenPath), token, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.path(ServingStatePath), servingStateBytes(authority), 0600); err != nil {
		t.Fatal(err)
	}
	return a, authority
}

func removeServing(t *testing.T, a Adapter, authority ServingAuthority) bool {
	t.Helper()
	exclusion, ok := a.AcquireServingExclusion()
	if !ok {
		return false
	}
	defer exclusion.Release()
	return a.RemoveServingRuntime(t.Context(), authority, exclusion)
}

func TestServingFilesAndRemovalPreserveUnrelatedLineages(t *testing.T) {
	a, authority := servingFiles(t)
	if !a.InspectServingFiles(authority, false).Accepted {
		t.Fatal("protected serving files refused")
	}
	unrelated := a.path("/etc/letsencrypt/archive/unrelated")
	if err := os.Mkdir(unrelated, 0700); err != nil {
		t.Fatal(err)
	}
	if !removeServing(t, a, authority) || !a.ServingRuntimeAbsent(authority) {
		t.Fatal("runtime removal failed")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("unrelated lineage removed")
	}
	if !removeServing(t, a, authority) {
		t.Fatal("repeated removal failed")
	}
}

func TestServingRemovalResumesAfterEveryUnlinkSynchronizationFailure(t *testing.T) {
	for boundary := 1; boundary <= 13; boundary++ {
		t.Run("sync", func(t *testing.T) {
			a, authority := servingFiles(t)
			calls := 0
			a.syncDirectoryFault = func(string) error {
				calls++
				if calls == boundary {
					return os.ErrInvalid
				}
				return nil
			}
			if removeServing(t, a, authority) {
				t.Fatal("synchronization failure accepted")
			}
			a.syncDirectoryFault = nil
			if !removeServing(t, a, authority) || !a.ServingRuntimeAbsent(authority) {
				t.Fatal("removal recovery failed")
			}
		})
	}
}

func TestServingFilesRefuseUnsafeOwnershipLinksAndUnknownState(t *testing.T) {
	for _, mutate := range []func(Adapter){
		func(a Adapter) { os.Chmod(a.path(ServingTokenPath), 0644) },
		func(a Adapter) { os.Link(a.path(ServingTokenPath), a.path(ServingStagingPath+"/alias")) },
		func(a Adapter) { os.WriteFile(a.path(ServingStagingPath+"/candidate"), []byte("test only"), 0600) },
		func(a Adapter) { os.WriteFile(a.path(servingArchive+"/privkey2.pem"), []byte("test only"), 0600) },
		func(a Adapter) {
			os.Remove(a.path(servingLive + "/cert.pem"))
			os.Symlink("/outside", a.path(servingLive+"/cert.pem"))
		},
		func(a Adapter) { os.WriteFile(a.path(ServingUnitPath), []byte("untrusted unit\n"), 0644) },
	} {
		t.Run("unsafe", func(t *testing.T) {
			a, authority := servingFiles(t)
			mutate(a)
			if a.InspectServingFiles(authority, false).Accepted || removeServing(t, a, authority) {
				t.Fatal("unsafe serving material accepted")
			}
		})
	}
}

func TestServingRemovalDeletesProvedCertificateHistory(t *testing.T) {
	a, authority := servingFiles(t)
	for _, name := range certificateNames {
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		body, err := os.ReadFile(a.path(servingArchive + "/" + name + "1.pem"))
		if err != nil || os.Rename(a.path(servingArchive+"/"+name+"1.pem"), a.path(servingArchive+"/"+name+"2.pem")) != nil || os.WriteFile(a.path(servingArchive+"/"+name+"1.pem"), body, mode) != nil {
			t.Fatal("create proved certificate history")
		}
		live := a.path(servingLive + "/" + name + ".pem")
		if os.Remove(live) != nil || os.Symlink("../../archive/sbxr-subscription/"+name+"2.pem", live) != nil {
			t.Fatal("publish current generation")
		}
	}
	authority.CertificateGeneration = 2
	if err := os.WriteFile(a.path(ServingStatePath), servingStateBytes(authority), 0600); err != nil {
		t.Fatal(err)
	}
	if !removeServing(t, a, authority) || !a.ServingRuntimeAbsent(authority) {
		t.Fatal("proved certificate history prevented removal")
	}
}

func TestServingRemovalRefusesUnrecordedFutureGeneration(t *testing.T) {
	a, authority := servingFiles(t)
	for _, name := range certificateNames {
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		body, err := os.ReadFile(a.path(servingArchive + "/" + name + "1.pem"))
		if err != nil || os.WriteFile(a.path(servingArchive+"/"+name+"2.pem"), body, mode) != nil {
			t.Fatal("create unrecorded future generation")
		}
	}
	if removeServing(t, a, authority) {
		t.Fatal("unrecorded future generation was removed")
	}
}

func TestServingExclusionRefusesBusyOrMissingOfficialLockInodes(t *testing.T) {
	a, _ := servingFiles(t)
	path := a.path(certbotDirectoryLocks[0])
	child := exec.Command(os.Args[0], "-test.run=^TestSubscriptionCertbotLockChild$")
	child.Env = append(os.Environ(), "SBXR_TEST_CERTBOT_LOCK="+path)
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if child.Start() != nil {
		t.Fatal("lock child failed")
	}
	t.Cleanup(func() { input.Close(); child.Wait() })
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatal("lock readiness failed")
	}
	if exclusion, ok := a.AcquireServingExclusion(); ok {
		exclusion.Release()
		t.Fatal("active Certbot admitted")
	}
	input.Close()
	if child.Wait() != nil {
		t.Fatal("lock child exit failed")
	}
	exclusion, ok := a.AcquireServingExclusion()
	if !ok {
		t.Fatal("released Certbot locks refused")
	}
	exclusion.Release()
	if os.Remove(path) != nil {
		t.Fatal("lock removal fixture failed")
	}
	if exclusion, ok := a.AcquireServingExclusion(); ok {
		exclusion.Release()
		t.Fatal("missing lock authority accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing shared lock recreated")
	}
}

func TestCertificateActivationInspectionBindsOnePublishedGenerationAndLoadedState(t *testing.T) {
	a, accepted := servingFiles(t)
	renewal := RenewalAuthority{RecorderID: strings.Repeat("1", 32), Lineage: "sbxr-subscription", PublicIPv4: "8.8.8.8", Invocation: OfficialRenewalInvocation}
	a.publicIPv4 = func(context.Context) string { return renewal.PublicIPv4 }
	a.renewalCertificateValid = func(_ RenewalAuthority, generation int) bool { return generation == 2 }
	a.servingLoaded = func(context.Context, RenewalAuthority, ServingAuthority, ServingAuthority) (ServingAuthority, bool) {
		return accepted, true
	}
	for _, name := range certificateNames {
		body := []byte(name + " replacement\n")
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		if err := os.WriteFile(a.path(servingArchive+"/"+name+"2.pem"), body, mode); err != nil {
			t.Fatal(err)
		}
		path := a.path(servingLive + "/" + name + ".pem")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../archive/sbxr-subscription/"+name+"2.pem", path); err != nil {
			t.Fatal(err)
		}
	}
	inspection := a.InspectCertificateActivation(t.Context(), renewal, accepted)
	if !inspection.Observed || !inspection.Accepted || inspection.Published.CertificateGeneration != 2 || inspection.Loaded != accepted || inspection.Published.LinkID != accepted.LinkID || inspection.Published.CredentialSHA256 != accepted.CredentialSHA256 {
		t.Fatalf("InspectCertificateActivation() = %#v", inspection)
	}
	restarts := 0
	a.subscriptionCommand = func(_ context.Context, name string, arguments ...string) (string, int, bool) {
		if name == "systemctl" && strings.Join(arguments, " ") == "restart sbxr-subscription.service" {
			restarts++
			return "", 0, true
		}
		return "", 1, true
	}
	if !a.ActivateServing(t.Context(), renewal, inspection.Published) || restarts != 1 {
		t.Fatalf("ActivateServing() restarts=%d", restarts)
	}
	if err := os.Remove(a.path(servingLive + "/chain.pem")); err != nil || os.Symlink("../../archive/sbxr-subscription/chain1.pem", a.path(servingLive+"/chain.pem")) != nil {
		t.Fatal("mixed generation fixture failed")
	}
	if mixed := a.InspectCertificateActivation(t.Context(), renewal, accepted); !mixed.Observed || mixed.Accepted {
		t.Fatalf("mixed InspectCertificateActivation() = %#v", mixed)
	}
	if a.ActivateServing(t.Context(), renewal, inspection.Published) || restarts != 1 {
		t.Fatalf("mixed ActivateServing() restarts=%d", restarts)
	}
}
