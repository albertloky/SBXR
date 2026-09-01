package softwarelifecycle

import (
	"os"
	"strings"
	"testing"
)

func TestUpdateRefusesChangedReviewedTarget(t *testing.T) {
	root := t.TempDir()
	prior := ReleaseIdentity{Repository: Repository, Tag: "v3.0.22", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	target := ReleaseIdentity{Repository: Repository, Tag: "v3.0.23", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	writeInstalledEvidence(t, root, installedEvidence(t, prior, 22, AMD64))
	source := &controlledUpdateSource{candidate: updateCandidateFromEvidence(t, target, 23, AMD64, installedEvidence(t, target, 23, AMD64))}
	lifecycle := newInstalledInterface(filesystemInspector{root: root, uid: uint32(os.Getuid())}, source)
	reviewed := lifecycle.Check(t.Context(), nil)
	target.Tag = "v3.0.24"
	source.candidate = updateCandidateFromEvidence(t, target, 24, AMD64, installedEvidence(t, target, 24, AMD64))
	got := lifecycle.Update(ConfirmReview(t.Context(), reviewed), nil)
	if got.Code != UpdateReleaseRefused || lifecycle.Status(t.Context()).Installed.Tag != prior.Tag {
		t.Fatalf("changed target admitted: %+v", got)
	}
}

func TestCleanInstallScopeCannotBeAnUpdateTarget(t *testing.T) {
	root := t.TempDir()
	prior := ReleaseIdentity{Repository: Repository, Tag: "v3.0.21", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	target := ReleaseIdentity{Repository: Repository, Tag: "v3.0.22", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	writeInstalledEvidence(t, root, installedEvidence(t, prior, 21, AMD64))
	candidate := updateCandidateFromEvidence(t, target, 22, AMD64, installedEvidence(t, target, 22, AMD64))
	candidate.cell.release.Support = &ReleaseSupport{Scope: FirstSubscriptionCleanInstall, Sources: []ReleaseIdentity{}, Contract: SubscriptionUpdateContract}
	source := &controlledUpdateSource{candidate: candidate}
	lifecycle := newInstalledInterface(filesystemInspector{root: root, uid: uint32(os.Getuid())}, source)
	if got := lifecycle.Check(t.Context(), nil); got.Code != CheckReleaseRefused {
		t.Fatalf("Check = %+v", got)
	}
	if got := lifecycle.Update(t.Context(), nil); got.Code != UpdateReleaseRefused {
		t.Fatalf("Update = %+v", got)
	}
	if got := lifecycle.Status(t.Context()); got.Installed == nil || *got.Installed != prior {
		t.Fatal("prior changed")
	}
}
