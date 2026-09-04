package host

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestServingActivationWaitsForDelayedRuntimeReadiness(t *testing.T) {
	accepted := ServingAuthority{LinkID: strings.Repeat("a", 32), CredentialSHA256: strings.Repeat("b", 64), CertificateGeneration: 1, CertificateSHA256: [4]string{strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64)}}
	renewal := RenewalAuthority{RecorderID: strings.Repeat("1", 32), Lineage: "sbxr-subscription", PublicIPv4: "8.8.8.8", Invocation: OfficialRenewalInvocation}
	calls := 0
	a := Adapter{servingLoaded: func(context.Context, RenewalAuthority, ServingAuthority, ServingAuthority) (ServingAuthority, bool) {
		calls++
		if calls < 3 {
			return ServingAuthority{}, false
		}
		return accepted, true
	}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if !a.waitLoadedServingAuthority(ctx, renewal, accepted) || calls != 3 {
		t.Fatalf("delayed serving readiness was not accepted: calls=%d", calls)
	}
}

func TestServingUnitUsesStartablePrivateSystemControlDirectory(t *testing.T) {
	if !strings.Contains(ServingUnit, "TemporaryFileSystem=/run/systemd:ro,mode=000\n") {
		t.Fatal("system control directory is not replaced with a private unreadable filesystem")
	}
	inaccessible := "InaccessiblePaths=/var/lib/sbxr/subscription-token /var/lib/sbxr/subscription-staging -/var/lib/sbxr/client-identity-target.json -/var/lib/sbxr/client-identity-target.json.sbxr-next /proc /run/dbus\n"
	if !strings.Contains(ServingUnit, inaccessible) || strings.Contains(ServingUnit, "InaccessiblePaths=/run/systemd") || strings.Contains(ServingUnit, " /run/systemd ") {
		t.Fatal("system control directory remains in the unstartable inaccessible-path list")
	}
}

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

func TestServingFilesAcceptSystemdAbsoluteEnablementLink(t *testing.T) {
	a, authority := servingFiles(t)
	if err := os.Remove(a.path(ServingUnitWantsPath)); err != nil || os.Symlink(ServingUnitPath, a.path(ServingUnitWantsPath)) != nil {
		t.Fatal("absolute systemd enablement fixture failed")
	}
	if !a.InspectServingFiles(authority, false).Accepted {
		t.Fatal("systemd absolute enablement link was refused")
	}
	if !removeServing(t, a, authority) || !a.ServingRuntimeAbsent(authority) {
		t.Fatal("systemd absolute enablement link prevented removal")
	}
}

func TestServingAcceptsAndRemovesOnlyOfficialCertbotReadme(t *testing.T) {
	body, err := os.ReadFile("testdata/certbot-lineage-README")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0600, 0644} {
		a, authority := servingFiles(t)
		path := a.path(servingLive + "/README")
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
		if !a.InspectServingFiles(authority, false).Accepted {
			t.Fatalf("official Certbot README with mode %o refused", mode)
		}
		if !removeServing(t, a, authority) || !a.ServingRuntimeAbsent(authority) {
			t.Fatal("official Certbot README prevented complete removal")
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("owned README remained after removal")
		}
	}
	for _, mutate := range []func(string){
		func(path string) { os.WriteFile(path, []byte("unknown content"), 0644) },
		func(path string) { os.Chmod(path, 0666) },
		func(path string) { os.Link(path, path+".alias") },
		func(path string) { os.Remove(path); os.Symlink("/outside", path) },
		func(path string) { os.Remove(path); syscall.Mkfifo(path, 0600) },
	} {
		a, authority := servingFiles(t)
		path := a.path(servingLive + "/README")
		if err := os.WriteFile(path, body, 0644); err != nil {
			t.Fatal(err)
		}
		mutate(path)
		if a.InspectServingFiles(authority, false).Accepted || removeServing(t, a, authority) {
			t.Fatal("unproved README was accepted or removed")
		}
	}
}

func TestServingRemovalResumesAfterEveryUnlinkSynchronizationFailure(t *testing.T) {
	readme, err := os.ReadFile("testdata/certbot-lineage-README")
	if err != nil {
		t.Fatal(err)
	}
	for boundary := 1; boundary <= 16; boundary++ {
		t.Run("sync", func(t *testing.T) {
			a, authority := servingFiles(t)
			if err := os.WriteFile(a.path(servingLive+"/README"), readme, 0644); err != nil {
				t.Fatal(err)
			}
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

func TestServingExclusionRefusesBusyAndRestoresMissingOfficialLockInodes(t *testing.T) {
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
	// Model a contender locking our newly created inode before our lock call.
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	(&ServingExclusion{files: []*os.File{file}, created: []*os.File{file}}).Release()
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("failed acquisition removed another process's locked inode")
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
	exclusion, ok = a.AcquireServingExclusion()
	if !ok {
		t.Fatal("absent idle Certbot lock prevented exclusion")
	}
	exclusion.Release()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("temporary shared lock survived exclusion")
	}
}

func TestServingExclusionCreatesRealPOSIXLocksAndPreservesReplacement(t *testing.T) {
	a, authority := servingFiles(t)
	for _, path := range certbotDirectoryLocks {
		if err := os.Remove(a.path(path)); err != nil {
			t.Fatal(err)
		}
	}
	exclusion, ok := a.AcquireServingExclusion()
	if !ok {
		t.Fatal("Certbot's removed lock files prevented exclusion")
	}
	t.Cleanup(exclusion.Release)
	for _, path := range certbotDirectoryLocks {
		child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSubscriptionCertbotLockChild$")
		child.Env = append(os.Environ(), "SBXR_TEST_CERTBOT_LOCK="+a.path(path))
		if err := child.Run(); err == nil {
			t.Fatal("temporary inode did not exclude a real POSIX lock contender")
		}
	}
	path := a.path(certbotDirectoryLocks[0])
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if a.RemoveServingRuntime(t.Context(), authority, exclusion) {
		t.Fatal("replaced lock inode authorized removal")
	}
	exclusion.Release()
	if body, err := os.ReadFile(path); err != nil || string(body) != "replacement" {
		t.Fatal("replacement inode was changed by release")
	}
	for _, path := range certbotDirectoryLocks[1:] {
		if _, err := os.Lstat(a.path(path)); !os.IsNotExist(err) {
			t.Fatal("created lock file remained after release")
		}
	}
}

func TestCertificateActivationInspectionBindsOnePublishedGenerationAndLoadedState(t *testing.T) {
	a, accepted := servingFiles(t)
	renewal := RenewalAuthority{RecorderID: strings.Repeat("1", 32), Lineage: "sbxr-subscription", PublicIPv4: "8.8.8.8", Invocation: OfficialRenewalInvocation}
	a.publicIPv4 = func(context.Context) string { return renewal.PublicIPv4 }
	a.renewalCertificateValid = func(_ RenewalAuthority, generation int) bool { return generation == 2 }
	loaded := accepted
	a.servingLoaded = func(context.Context, RenewalAuthority, ServingAuthority, ServingAuthority) (ServingAuthority, bool) {
		return loaded, true
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
	loaded = inspection.Published
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
