package host

import (
	"context"
	"os"
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
	if err := os.WriteFile(a.path(ServingTokenPath), token, 0600); err != nil {
		t.Fatal(err)
	}
	return a, authority
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
	if !a.RemoveServingRuntime(t.Context(), authority) || !a.ServingRuntimeAbsent(authority) {
		t.Fatal("runtime removal failed")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("unrelated lineage removed")
	}
	if !a.RemoveServingRuntime(t.Context(), authority) {
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
			if a.RemoveServingRuntime(t.Context(), authority) {
				t.Fatal("synchronization failure accepted")
			}
			a.syncDirectoryFault = nil
			if !a.RemoveServingRuntime(t.Context(), authority) || !a.ServingRuntimeAbsent(authority) {
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
			if a.InspectServingFiles(authority, false).Accepted || a.RemoveServingRuntime(t.Context(), authority) {
				t.Fatal("unsafe serving material accepted")
			}
		})
	}
}
