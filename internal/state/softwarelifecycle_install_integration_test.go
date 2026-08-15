package state

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	lifecyclecontract "github.com/albertloky/SBXR/internal/softwarelifecycle/contract"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type lifecycleReleaseSource struct {
	evidence softwarelifecycle.ReleaseEvidence
}

func (source lifecycleReleaseSource) Verify(context.Context, string) (softwarelifecycle.ReleaseEvidence, error) {
	return source.evidence, nil
}

type lifecycleStager struct {
	proof softwarelifecycle.StagedRelease
}

func (stager lifecycleStager) Stage(_ context.Context, request softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
	if !request.Authenticated() {
		return softwarelifecycle.StagedRelease{}, fmt.Errorf("unauthenticated")
	}
	return stager.proof, nil
}

type lifecycleContribution struct {
	proof lifecyclecontract.InstallContribution
}

func (value lifecycleContribution) SoftwareLifecycleInstallContribution() lifecyclecontract.InstallContribution {
	return value.proof
}

type lifecycleApproval struct {
	recheck softwarelifecycle.InstallRecheck
}

func (approval lifecycleApproval) AuthorizeAndRecheck(context.Context) (softwarelifecycle.InstallRecheck, error) {
	return approval.recheck, nil
}

func TestSoftwareLifecycleInstallPublishesRevisionOneOnlyAfterCompleteAgreement(t *testing.T) {
	const changeSet = "software-install-revision-1"
	evidence, staged := lifecycleRelease(t)
	module := softwarelifecycle.New(lifecycleReleaseSource{evidence}, softwarelifecycle.VerifierQualification{Version: "2.97.0", SigningFingerprint: "0123456789ABCDEF0123456789ABCDEF01234567"}, func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) }, lifecycleStager{staged})
	view := module.View(t.Context(), softwarelifecycle.ViewRequest{Tag: staged.Identity.Tag, Architecture: softwarelifecycle.AMD64, InstallationStatus: softwarelifecycle.NotInstalled})
	if view.Refusal != nil || view.InstallCandidate() == (softwarelifecycle.InstallCandidate{}) {
		t.Fatalf("View() = %+v", view)
	}

	candidate := completeDesiredState()
	template, err := marshalProtectedJSON(candidate)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(template)
	desired := hex.EncodeToString(digest[:])
	contributions := lifecycleContributions(t, changeSet, desired)
	plan, finding := softwarelifecycle.PlanInstall(softwarelifecycle.InstallPlanRequest{Candidate: view.InstallCandidate(), ChangeSet: changeSet, DesiredStateSHA256: desired, Contributions: contributions, Disk: systemchanges.DiskRequirement{PreparationBytes: 100, TemporaryBytes: 100, SnapshotBytes: 100, JournalBytes: 100, RollbackBytes: 100, OverheadBytes: 100}, SSHPreservation: testSSHPreservationAuthority(t)})
	if finding != nil {
		t.Fatal(finding)
	}

	storage := &mutableStateStorage{err: fs.ErrNotExist}
	stateModule := New(storage)
	loaded, err := stateModule.Load(LoadRequest{Baseline: CleanVPS})
	if err != nil {
		t.Fatal(err)
	}
	prepare := preparedRequest(t, loaded, candidate, changeSet)
	prepare.CandidateReleaseIdentity = ReleaseIdentity{Repository: staged.Identity.Repository, Tag: staged.Identity.Tag, Commit: staged.Identity.Commit, ReleaseIndexSHA256: staged.Identity.IndexSHA256}
	prepare.ReviewedInputs, err = NewReviewedInputs(PlanIdentity(plan.Identity()), plan.SHA256(), prepare.ReviewedInputs.managed)
	if err != nil {
		t.Fatal(err)
	}
	validator := prepare.SemanticValidators.ConnectionProfiles.(*validatingSeams)
	validator.planIdentity, validator.planSHA256 = plan.Identity(), plan.SHA256()
	prepared, err := stateModule.PrepareCommit(prepare)
	if err != nil {
		t.Fatal(err)
	}
	rechecked := lifecycleContributions(t, changeSet, desired)
	recheckedNetwork := rechecked[0].SoftwareLifecycleInstallContribution()
	recheckedNetwork.Privileged, recheckedNetwork.SHA256 = true, strings.Repeat("f", 64)
	recheckedNetwork.Identity = "network-install-" + recheckedNetwork.SHA256[:12]
	rechecked[0] = lifecycleContribution{recheckedNetwork}
	var fresh string
	for _, contribution := range rechecked {
		fresh += contribution.SoftwareLifecycleInstallContribution().SHA256
	}
	freshDigest := sha256.Sum256([]byte(fresh))
	observed := systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: hex.EncodeToString(freshDigest[:]), FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	adapter := &systemChangesAdapter{observation: observed, stateRecovery: stateModule}
	result := plan.Apply(t.Context(), softwarelifecycle.InstallApplyRequest{Approval: lifecycleApproval{softwarelifecycle.InstallRecheck{Candidate: view.InstallCandidate(), Contributions: rechecked, PrivilegedNetworkHealthy: true}}, PreparedState: prepared, SystemChanges: systemchanges.New(adapter)})
	if result.Outcome != systemchanges.Completed || result.NothingChanged {
		t.Fatalf("Apply() = %+v; events=%v", result, adapter.events)
	}
	if loaded, loadErr := stateModule.Load(LoadRequest{Baseline: ManagedEvidence, SupportedRelease: prepare.CandidateReleaseIdentity, Lineage: &LineageProof{Revision: 1, LastCompletedChangeSet: changeSet, ReleaseIdentity: prepare.CandidateReleaseIdentity}}); loadErr != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 1 {
		t.Fatalf("published revision 1 = (%+v, %v)", loaded, loadErr)
	}
	joined := strings.Join(adapter.events, "\n")
	if !strings.Contains(joined, string(systemchanges.PrePublicationHealthPassed)) || !strings.Contains(joined, string(systemchanges.StatePublished)) || !strings.Contains(joined, string(systemchanges.PostPublicationHealthPassed)) || !strings.Contains(joined, string(systemchanges.Complete)) {
		t.Fatalf("durable install order = %v", adapter.events)
	}
}

func lifecycleContributions(t *testing.T, changeSet, desired string) []softwarelifecycle.InstallContribution {
	t.Helper()
	definitions := []struct {
		name  string
		owner systemchanges.Module
	}{
		{"Network Policy", systemchanges.NetworkPolicyModule}, {"Connection Profiles", systemchanges.ConnectionProfilesModule}, {"Cloudflare Tunnel", systemchanges.CloudflareModule},
		{"Certificate Lifecycle", systemchanges.CertificateModule}, {"Subscription Publication", systemchanges.SubscriptionModule},
	}
	result := make([]softwarelifecycle.InstallContribution, 0, len(definitions))
	for index, definition := range definitions {
		step, err := systemchanges.NewStep(definition.owner, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
		ports, firewall := []string(nil), ""
		if definition.owner == systemchanges.NetworkPolicyModule {
			firewall = "table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  tcp dport 2222 accept\n }\n}"
			step, err = systemchanges.NewFirewallPolicyStep(firewall, 2222)
			ports = []string{"SSH preservation: public 2222/TCP"}
		}
		if err != nil {
			t.Fatal(err)
		}
		checks := []systemchanges.Check{{Owner: definition.owner, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: fmt.Sprintf("LIFECYCLE-%02d-PRE", index)}, {Owner: definition.owner, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: fmt.Sprintf("LIFECYCLE-%02d-POST", index)}}
		result = append(result, lifecycleContribution{lifecyclecontract.InstallContribution{Name: definition.name, Owner: definition.owner, Identity: fmt.Sprintf("lifecycle-plan-%d", index), SHA256: strings.Repeat(fmt.Sprintf("%x", index+1), 64), StableSHA256: strings.Repeat(fmt.Sprintf("%x", index+7), 64), ChangeSet: changeSet, DesiredStateSHA256: desired, Steps: []systemchanges.Step{step}, Checks: checks, Ports: ports, Firewall: firewall, Details: []string{definition.name + " exact install effects"}}})
	}
	return result
}

func lifecycleRelease(t *testing.T) (softwarelifecycle.ReleaseEvidence, softwarelifecycle.StagedRelease) {
	return lifecycleReleaseVersion(t, "v1.0.0", "1.0.0", 1, "0123456789abcdef0123456789abcdef01234567")
}

func lifecycleReleaseVersion(t *testing.T, tag, version string, sequence int, commit string) (softwarelifecycle.ReleaseEvidence, softwarelifecycle.StagedRelease) {
	t.Helper()
	archive := &bytes.Buffer{}
	compressed := gzip.NewWriter(archive)
	writer := tar.NewWriter(compressed)
	if err := writer.WriteHeader(&tar.Header{Name: "sbxr", Mode: 0o755, Size: 4, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write([]byte("ELF!"))
	if writer.Close() != nil || compressed.Close() != nil {
		t.Fatal("archive close")
	}
	amd64Archive, arm64Archive := archive.Bytes(), archive.Bytes()
	amd64Digest, arm64Digest := sha256.Sum256(amd64Archive), sha256.Sum256(arm64Archive)
	componentFiles := map[string][]byte{
		"xray": []byte("qualified xray"), "sing-box": []byte("qualified sing-box"), "cloudflared": []byte("qualified cloudflared"),
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(), "certbot/pyvenv.cfg": []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
	componentManifest, err := softwarelifecycle.NewComponentManifest(softwarelifecycle.AMD64, "5.4.0", componentFiles)
	if err != nil {
		t.Fatal(err)
	}
	components, err := softwarelifecycle.BuildComponentArchive(componentManifest, componentFiles)
	if err != nil {
		t.Fatal(err)
	}
	componentDigest := sha256.Sum256(components)
	armManifest, err := softwarelifecycle.NewComponentManifest(softwarelifecycle.ARM64, "5.4.0", componentFiles)
	if err != nil {
		t.Fatal(err)
	}
	armComponents, err := softwarelifecycle.BuildComponentArchive(armManifest, componentFiles)
	if err != nil {
		t.Fatal(err)
	}
	armComponentDigest := sha256.Sum256(armComponents)
	bootstrap := []byte("#!/bin/sh\nexit 1\n")
	bootstrapDigest := sha256.Sum256(bootstrap)
	type asset struct {
		Role   string `json:"role"`
		Name   string `json:"name"`
		Size   int    `json:"size"`
		SHA256 string `json:"sha256"`
	}
	index := struct {
		Schema               int     `json:"schema"`
		Product              string  `json:"product"`
		Repository           string  `json:"repository"`
		Version              string  `json:"version"`
		Sequence             int     `json:"sequence"`
		Tag                  string  `json:"tag"`
		Commit               string  `json:"commit"`
		StateSchema          int     `json:"state_schema"`
		MinimumUpdaterSchema int     `json:"minimum_updater_schema"`
		Assets               []asset `json:"assets"`
	}{Schema: 1, Product: "sbxr", Repository: softwarelifecycle.Repository, Version: version, Sequence: sequence, Tag: tag, Commit: commit, StateSchema: 1, MinimumUpdaterSchema: 1}
	index.Assets = []asset{{"application-linux-amd64", "sbxr-linux-amd64.tar.gz", len(amd64Archive), hex.EncodeToString(amd64Digest[:])}, {"application-linux-arm64", "sbxr-linux-arm64.tar.gz", len(arm64Archive), hex.EncodeToString(arm64Digest[:])}, {"components-linux-amd64", "sbxr-components-linux-amd64.tar.gz", len(components), hex.EncodeToString(componentDigest[:])}, {"components-linux-arm64", "sbxr-components-linux-arm64.tar.gz", len(armComponents), hex.EncodeToString(armComponentDigest[:])}, {"bootstrap", "install.sh", len(bootstrap), hex.EncodeToString(bootstrapDigest[:])}}
	indexBytes, _ := json.Marshal(index)
	indexDigest := sha256.Sum256(indexBytes)
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: index.Tag, Commit: index.Commit, IndexSHA256: hex.EncodeToString(indexDigest[:])}
	assets := []softwarelifecycle.DownloadedAsset{{Name: "sbxr-linux-amd64.tar.gz", Bytes: amd64Archive}, {Name: "sbxr-linux-arm64.tar.gz", Bytes: arm64Archive}, {Name: "sbxr-components-linux-amd64.tar.gz", Bytes: append([]byte(nil), components...)}, {Name: "sbxr-components-linux-arm64.tar.gz", Bytes: append([]byte(nil), armComponents...)}, {Name: "install.sh", Bytes: bootstrap}}
	attested := []softwarelifecycle.AttestedAsset{{Name: "release-index.json", SHA256: identity.IndexSHA256}, {Name: assets[0].Name, SHA256: hex.EncodeToString(amd64Digest[:])}, {Name: assets[1].Name, SHA256: hex.EncodeToString(arm64Digest[:])}, {Name: assets[2].Name, SHA256: hex.EncodeToString(componentDigest[:])}, {Name: assets[3].Name, SHA256: hex.EncodeToString(armComponentDigest[:])}, {Name: assets[4].Name, SHA256: hex.EncodeToString(bootstrapDigest[:])}}
	evidence := softwarelifecycle.ReleaseEvidence{Repository: softwarelifecycle.Repository, Tag: identity.Tag, Commit: identity.Commit, Index: indexBytes, Assets: assets, AttestedAssets: attested, Verifier: softwarelifecycle.VerifierEvidence{Version: "2.97.0", SigningFingerprint: "0123456789ABCDEF0123456789ABCDEF01234567", OfficialSignedDistribution: true, ReleaseVerified: true, VerifiedAssets: []string{"release-index.json", assets[0].Name, assets[1].Name, assets[2].Name, assets[3].Name, assets[4].Name}}}
	staged := softwarelifecycle.StagedRelease{Identity: identity, Build: softwarelifecycle.EmbeddedBuildIdentity{Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, PayloadSHA256: strings.Repeat("c", 64)}, Architecture: softwarelifecycle.AMD64, ExecutableSHA256: strings.Repeat("d", 64), ComponentsSHA256: hex.EncodeToString(componentDigest[:]), InstallPath: softwarelifecycle.ReleaseInstallPath(identity), StateSchema: 1}
	return evidence, staged
}
