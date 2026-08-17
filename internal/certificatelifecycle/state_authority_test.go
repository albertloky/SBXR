package certificatelifecycle

import (
	"strings"
	"sync/atomic"
	"testing"
)

func TestFreshInstallContributionContainsOnlyIP(t *testing.T) {
	plan := &Plan{identity: "certificate-ip-plan", sha256: strings.Repeat("a", 64), used: &atomic.Bool{}, stateUsed: &atomic.Bool{}, request: PlanRequest{Lineage: IPLineage, ChangeSet: "install-0001", StartingRevision: 1, DesiredStateSHA256: strings.Repeat("b", 64)}}
	contribution, valid := NewFreshInstallContribution(plan)
	proof := contribution.SoftwareLifecycleInstallContribution()
	if !valid || proof.Name != "Certificate Lifecycle" || proof.Identity != plan.identity || proof.SHA256 != plan.sha256 {
		t.Fatalf("IP-only install contribution = (%+v, %t)", proof, valid)
	}
}

func TestStateProfileSetupCertificateIsExactAndOneUse(t *testing.T) {
	plan := &Plan{identity: "certificate-domain-plan", sha256: strings.Repeat("a", 64), used: &atomic.Bool{}, stateUsed: &atomic.Bool{}, request: PlanRequest{Lineage: DomainLineage, ChangeSet: "change-0008", StartingRevision: 7, StartingStateSHA256: strings.Repeat("b", 64), DesiredStateSHA256: strings.Repeat("c", 64)}}
	copyBeforeUse := *plan
	start, candidate, startingSHA, desiredSHA, changeSet, valid := plan.StateProfileSetupCertificate()
	if !valid || start != 7 || candidate != 8 || startingSHA != strings.Repeat("b", 64) || desiredSHA != strings.Repeat("c", 64) || changeSet != "change-0008" {
		t.Fatalf("StateProfileSetupCertificate() = (%d, %d, %q, %q, %q, %t)", start, candidate, startingSHA, desiredSHA, changeSet, valid)
	}
	if _, _, _, _, _, reused := copyBeforeUse.StateProfileSetupCertificate(); reused {
		t.Fatal("a copied Plan reused the shared State authority")
	}
	if _, _, _, _, _, reused := plan.StateProfileSetupCertificate(); reused {
		t.Fatal("StateProfileSetupCertificate() reused one Plan")
	}
}
