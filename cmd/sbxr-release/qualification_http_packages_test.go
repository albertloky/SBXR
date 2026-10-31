package main

import (
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestFreshHTTPPackageReceipts(t *testing.T) {
	attempt := v3QualificationAttempt{Schema: "sbxr-v3-qualification-attempt-v3", EvidencePolicy: softwarelifecycle.MVPHTTPEvidencePolicy, Support: &v3ReleaseSupport{Scope: softwarelifecycle.SubscriptionCleanInstallOnly}, Sources: []v3QualificationSource{}}
	packages := v3QualificationPackages{Karing: v3SoftwarePackage{Name: "karing", Repository: "https://github.com/KaringX/karing", Architecture: "macos-arm64", Version: "1.2.25.2802", Size: 100, SHA256: strings.Repeat("a", 64)}}
	if !validV3Packages(packages, attempt) {
		t.Fatal("HTTP-only preparation incorrectly requires unused TLS packages")
	}
	for _, name := range []string{"certbot", "snap", "karing"} {
		t.Run("partial-"+name, func(t *testing.T) {
			changed := packages
			switch name {
			case "certbot":
				changed.Certbot.Name = name
			case "snap":
				changed.Snap.Name = "snapd"
			case "karing":
				changed.Karing = v3SoftwarePackage{}
			}
			if validV3Packages(changed, attempt) {
				t.Fatal("partial or missing required receipt accepted")
			}
		})
	}
	for _, policy := range []string{softwarelifecycle.MVPLiveEvidencePolicy, softwarelifecycle.MVPHTTPRecurringEvidencePolicy, softwarelifecycle.RepairTwoIssuanceEvidencePolicy} {
		t.Run(policy, func(t *testing.T) {
			changed := attempt
			changed.EvidencePolicy = policy
			if validV3Packages(packages, changed) {
				t.Fatal("historical/source requirement weakened")
			}
		})
	}
	for _, mutate := range []func(*v3QualificationAttempt){func(a *v3QualificationAttempt) { a.Schema = "sbxr-v3-qualification-attempt-v2" }, func(a *v3QualificationAttempt) { a.Support = nil }, func(a *v3QualificationAttempt) {
		a.Support = &v3ReleaseSupport{Scope: softwarelifecycle.SubscriptionCleanInstallRepair}
	}, func(a *v3QualificationAttempt) { a.Sources = nil }, func(a *v3QualificationAttempt) { a.Sources = []v3QualificationSource{{}} }} {
		changed := attempt
		mutate(&changed)
		if validV3Packages(packages, changed) {
			t.Fatal("unused package receipts accepted outside exact fresh HTTP scope")
		}
	}
	packages.Certbot = v3SoftwarePackage{Name: "certbot", Repository: "https://snapcraft.io/certbot", Architecture: "amd64", Version: "5.8.0", Size: 100, SHA256: strings.Repeat("b", 64)}
	packages.Snap = v3SoftwarePackage{Name: "snapd", Repository: "https://snapcraft.io/snapd", Architecture: "amd64", Version: "2.77.1", Size: 100, SHA256: strings.Repeat("c", 64)}
	if !validV3Packages(packages, attempt) {
		t.Fatal("retained populated HTTP receipts refused")
	}
	packages.Certbot.Version = "5.3.0"
	if validV3Packages(packages, attempt) {
		t.Fatal("supplied invalid receipt ignored")
	}
}
