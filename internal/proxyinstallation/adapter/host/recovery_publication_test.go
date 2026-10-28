package host

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationCleanupRecoversStaging(t *testing.T) {
	for _, kind := range []string{"exact", "foreign", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			a := Adapter{root: t.TempDir()}
			spec := testSetupSpec()
			path := a.path(spec.ConfigurationPath + ".sbxr-next")
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			body := []byte("{}\n")
			value := body
			if kind == "foreign" {
				value = []byte("foreign")
			}
			if err := os.WriteFile(path, value, 0640); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" || kind == "hardlink" {
				other := a.path("/other")
				if err := os.Rename(path, other); err != nil {
					t.Fatal(err)
				}
				link := os.Link
				if kind == "symlink" {
					link = os.Symlink
				}
				if err := link(other, path); err != nil {
					t.Fatal(err)
				}
				if kind == "hardlink" {
					if err := os.Link(other, a.path("/third")); err != nil {
						t.Fatal(err)
					}
				}
			}
			input := OperationInput{Operation: RemoveConfigurationState, Spec: spec, SHA256: digest(body)}
			for range 2 {
				result := a.Apply(t.Context(), input)
				if result.OK != (kind == "exact") {
					t.Fatalf("cleanup %s = %v", kind, result.OK)
				}
			}
			if kind != "exact" {
				if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, value) {
					t.Fatal("unowned staging changed")
				}
			}
		})
	}
}

func TestSubscriptionCandidateCleanupRecoversPublication(t *testing.T) {
	for _, stage := range []string{"staged", "linked", "published"} {
		t.Run(stage, func(t *testing.T) {
			a := Adapter{root: t.TempDir()}
			token := []byte(strings.Repeat("a", 43) + "\n")
			serving := ServingAuthority{HTTP: true, LinkID: strings.Repeat("1", 32), CredentialSHA256: digest(token[:43])}
			for _, item := range []struct {
				path string
				body []byte
			}{{SubscriptionCandidateTokenPath, token}, {SubscriptionCandidateStatePath, servingStateBytes(serving)}} {
				path := a.path(item.path)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path+".sbxr-next", item.body, 0600); err != nil {
					t.Fatal(err)
				}
				if stage != "staged" {
					if err := os.Link(path+".sbxr-next", path); err != nil {
						t.Fatal(err)
					}
				}
				if stage == "published" {
					if err := os.Remove(path + ".sbxr-next"); err != nil {
						t.Fatal(err)
					}
				}
				if stage == "linked" {
					if _, err := a.protectedServingFile(item.path, 0600, ""); err == nil {
						t.Fatal("ordinary read accepted hardlinks")
					}
				}
			}
			for range 2 {
				if !a.removeSubscriptionCandidates(&serving, serving.CredentialSHA256) {
					t.Fatal("candidate cleanup refused interruption")
				}
			}
			for _, path := range []string{SubscriptionCandidateTokenPath, SubscriptionCandidateStatePath} {
				if !a.safelyAbsent(path) || !a.safelyAbsent(path+".sbxr-next") {
					t.Fatal("publication residue")
				}
			}
		})
	}
}

func TestSubscriptionPublicationPreservesUnownedLinks(t *testing.T) {
	for _, kind := range []string{"foreign", "third-link", "mode", "symlink"} {
		for _, publish := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/publish=%t", kind, publish), func(t *testing.T) {
				a := Adapter{root: t.TempDir()}
				path := a.path(ServingTokenPath)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				body := []byte("expected\n")
				actual := body
				if kind == "foreign" {
					actual = []byte("foreign\n")
				}
				if err := os.WriteFile(path, actual, 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					if err := os.Rename(path, path+".other"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path+".other", path); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Link(path, path+".sbxr-next"); err != nil {
					t.Fatal(err)
				}
				if kind == "third-link" {
					if err := os.Link(path, path+".other"); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "mode" {
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				}
				ok := false
				if publish {
					ok = a.publishSubscriptionFile(ServingTokenPath, body, 0600)
				} else {
					ok = a.removeSubscriptionPublication(ServingTokenPath, body, 0600)
				}
				if ok {
					t.Fatal("unsafe publication accepted")
				}
				if _, err := os.Lstat(path + ".sbxr-next"); err != nil {
					t.Fatal("unowned link removed")
				}
			})
		}
	}
}

func TestHTTPSubscriptionCleanupRecoversLinkedPublication(t *testing.T) {
	for _, interrupted := range []string{SubscriptionCandidateTokenPath, SubscriptionCandidateStatePath, ServingTokenPath, ServingStatePath, ServingUnitPath} {
		t.Run(filepath.Base(interrupted), func(t *testing.T) {
			a, _ := httpSubscriptionFixture(t)
			credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
			serving := ServingAuthority{HTTP: true, LinkID: strings.Repeat("a", 32), CredentialSHA256: digest(credential)}
			resources := SubscriptionResourcesForEnablement("8.8.8.8", a.PreflightHTTPSubscription(t.Context(), "8.8.8.8"))
			injected := false
			a.syncDirectoryFault = func(string) error {
				info, err := os.Lstat(a.path(interrupted))
				staged, stagedErr := os.Lstat(a.path(interrupted + ".sbxr-next"))
				if err == nil && stagedErr == nil && os.SameFile(info, staged) {
					injected = true
					return errors.New("injected post-link synchronization interruption")
				}
				return nil
			}
			result := a.PrepareSubscription(t.Context(), SubscriptionEnableInput{PublicIPv4: "8.8.8.8", Credential: credential, Serving: serving, Resources: resources, Authorize: func(int, *ServingAuthority) bool { return true }})
			if result.Prepared || !injected {
				t.Fatal("did not interrupt real publication at hardlink boundary")
			}
			a.syncDirectoryFault = nil
			input := SubscriptionCleanupInput{LinkID: serving.LinkID, CredentialSHA256: serving.CredentialSHA256, Resources: &resources, Serving: &serving}
			for range 2 {
				if !a.CleanupPreparedSubscription(t.Context(), input) {
					t.Fatal("cleanup refused exact interrupted publication")
				}
			}
			if !a.safelyAbsent(interrupted) || !a.safelyAbsent(interrupted+".sbxr-next") {
				t.Fatal("publication residue")
			}
		})
	}
}
