package host

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func certificateStateFiles(t *testing.T) (Adapter, RenewalAuthority, ServingAuthority, ServingAuthority) {
	t.Helper()
	a, source := servingFiles(t)
	renewal := RenewalAuthority{RecorderID: strings.Repeat("1", 32), Lineage: "sbxr-subscription", PublicIPv4: "8.8.8.8", Invocation: OfficialRenewalInvocation}
	installRenewalCertificate(t, a, renewal.PublicIPv4)
	previous := map[string][]byte{}
	for i, name := range certificateNames {
		body, err := os.ReadFile(a.path(servingArchive + "/" + name + "1.pem"))
		if err != nil {
			t.Fatal(err)
		}
		previous[name], source.CertificateSHA256[i] = body, digest(body)
	}
	if err := os.WriteFile(a.path(ServingStatePath), servingStateBytes(source), 0600); err != nil {
		t.Fatal(err)
	}
	a.renewalTrustRoots = installRenewalCertificate(t, a, renewal.PublicIPv4)
	target := source
	target.CertificateGeneration = 2
	for i, name := range certificateNames {
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		body, err := os.ReadFile(a.path(servingArchive + "/" + name + "1.pem"))
		if err != nil {
			t.Fatal(err)
		}
		target.CertificateSHA256[i] = digest(body)
		if os.WriteFile(a.path(servingArchive+"/"+name+"2.pem"), body, mode) != nil || os.WriteFile(a.path(servingArchive+"/"+name+"1.pem"), previous[name], mode) != nil {
			t.Fatal("archive fixture failed")
		}
		path := a.path(servingLive + "/" + name + ".pem")
		if os.Remove(path) != nil || os.Symlink("../../archive/sbxr-subscription/"+name+"2.pem", path) != nil {
			t.Fatal("live fixture failed")
		}
	}
	return a, renewal, source, target
}

func TestCertificateStatePublicationRestoresRealLinkAndRemoval(t *testing.T) {
	a, renewal, source, target := certificateStateFiles(t)
	if a.InspectServingFiles(target, false).Accepted {
		t.Fatal("generation mismatch accepted")
	}
	if _, ok := a.ReadSubscriptionLink(target, renewal.PublicIPv4); ok {
		t.Fatal("obsolete state disclosed link")
	}
	if stored, ok := a.InspectCertificateServingState(target, false); !ok || stored != source {
		t.Fatal("proved historical snapshot refused")
	}
	before, err := os.ReadFile(a.path(ServingTokenPath))
	if err != nil {
		t.Fatal(err)
	}
	if !a.PublishCertificateServingState(renewal, source, target) {
		t.Fatal("state publication failed")
	}
	if !a.InspectServingFiles(target, false).Accepted {
		t.Fatal("accepted files refused")
	}
	if _, ok := a.ReadSubscriptionLink(target, renewal.PublicIPv4); !ok {
		t.Fatal("accepted link refused")
	}
	after, err := os.ReadFile(a.path(ServingTokenPath))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("credential changed")
	}
	unrelated := a.path("/etc/letsencrypt/archive/unrelated")
	if os.Mkdir(unrelated, 0700) != nil || os.WriteFile(filepath.Join(unrelated, "keep"), []byte("keep"), 0600) != nil {
		t.Fatal("unrelated fixture")
	}
	if !removeServing(t, a, target) || !a.ServingRuntimeAbsent(target) {
		t.Fatal("accepted serving removal failed")
	}
	if body, err := os.ReadFile(filepath.Join(unrelated, "keep")); err != nil || string(body) != "keep" {
		t.Fatal("unrelated lineage changed")
	}
}

func TestCertificateStatePublicationResumesStagingAndDirectorySyncFailures(t *testing.T) {
	for _, failure := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			a, renewal, source, target := certificateStateFiles(t)
			if failure == 0 {
				if err := os.WriteFile(a.path(SubscriptionCandidateStatePath), servingStateBytes(target), 0600); err != nil {
					t.Fatal(err)
				}
				if _, ok := a.InspectCertificateServingState(target, false); ok {
					t.Fatal("unjournalled staging admitted")
				}
				if _, ok := a.InspectCertificateServingState(target, true); !ok {
					t.Fatal("exact pending staging refused")
				}
			} else {
				calls := 0
				a.syncDirectoryFault = func(string) error {
					calls++
					if calls == failure {
						return errors.New("injected fsync failure")
					}
					return nil
				}
				if a.PublishCertificateServingState(renewal, source, target) {
					t.Fatal("unproved publication reported success")
				}
				a.syncDirectoryFault = nil
			}
			if !a.PublishCertificateServingState(renewal, source, target) || !a.PublishCertificateServingState(renewal, source, target) {
				t.Fatal("idempotent publication failed")
			}
			if !a.servingDirectory(ServingStagingPath, nil, false) || !a.InspectServingFiles(target, false).Accepted {
				t.Fatal("publication residue")
			}
		})
	}
}

func TestCertificateStatePublicationRefusesUnknownOrUntrustedMaterial(t *testing.T) {
	cases := map[string]func(Adapter, *ServingAuthority){
		"mode":    func(a Adapter, _ *ServingAuthority) { mustState(t, os.Chmod(a.path(ServingStatePath), 0644)) },
		"missing": func(a Adapter, _ *ServingAuthority) { mustState(t, os.Remove(a.path(ServingStatePath))) },
		"symlink": func(a Adapter, _ *ServingAuthority) {
			mustState(t, os.Remove(a.path(ServingStatePath)))
			mustState(t, os.Symlink(a.path(ServingTokenPath), a.path(ServingStatePath)))
		},
		"hardlink": func(a Adapter, _ *ServingAuthority) {
			mustState(t, os.Link(a.path(ServingStatePath), a.path(ServingStatePath)+".foreign"))
		},
		"unknown-field": func(a Adapter, _ *ServingAuthority) {
			mustState(t, os.WriteFile(a.path(ServingStatePath), []byte(`{"schema":1,"unknown":true}`), 0600))
		},
		"historical-hash": func(a Adapter, _ *ServingAuthority) {
			mustState(t, os.WriteFile(a.path(servingArchive+"/cert1.pem"), []byte("changed"), 0644))
		},
		"mixed-live": func(a Adapter, _ *ServingAuthority) {
			p := a.path(servingLive + "/chain.pem")
			mustState(t, os.Remove(p))
			mustState(t, os.Symlink("../../archive/sbxr-subscription/chain1.pem", p))
		},
		"foreign-stage": func(a Adapter, _ *ServingAuthority) {
			mustState(t, os.WriteFile(a.path(SubscriptionCandidateStatePath), []byte("foreign"), 0600))
		},
		"changed-link":        func(_ Adapter, target *ServingAuthority) { target.LinkID = strings.Repeat("e", 32) },
		"changed-credential":  func(_ Adapter, target *ServingAuthority) { target.CredentialSHA256 = strings.Repeat("e", 64) },
		"changed-target-hash": func(_ Adapter, target *ServingAuthority) { target.CertificateSHA256[0] = strings.Repeat("e", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a, renewal, source, target := certificateStateFiles(t)
			mutate(a, &target)
			if a.PublishCertificateServingState(renewal, source, target) {
				t.Fatal("unsafe state publication accepted")
			}
		})
	}
	t.Run("untrusted-certificate", func(t *testing.T) {
		a, renewal, source, target := certificateStateFiles(t)
		a.renewalTrustRoots = x509.NewCertPool()
		before, _ := os.ReadFile(a.path(ServingStatePath))
		if a.PublishCertificateServingState(renewal, source, target) {
			t.Fatal("untrusted certificate accepted")
		}
		after, _ := os.ReadFile(a.path(ServingStatePath))
		if !bytes.Equal(before, after) {
			t.Fatal("refusal changed state")
		}
	})
}

func mustState(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
