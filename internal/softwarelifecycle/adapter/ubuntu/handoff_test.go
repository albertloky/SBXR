package ubuntu

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
)

func TestInstallApplyHandoffIsOneBoundedStrictRequestAndOneUseApproval(t *testing.T) {
	request := installHandoffFixture()
	parent, child := socketPair(t)
	defer parent.Close()
	defer child.Close()
	executable := reviewedInstallExecutable(t, &request)
	defer executable.Close()

	prepared, applied := false, false
	done := make(chan error, 1)
	go func() {
		done <- serveInstallApply(t.Context(), child, executable, func(*os.File, *os.File) error { return nil }, func(_ context.Context, got InstallHandoffRequest) (func() error, error) {
			if !reflect.DeepEqual(got, request) {
				return nil, errors.New("request changed")
			}
			prepared = true
			return func() error { applied = true; return nil }, nil
		})
	}()
	if err := writeInstallHandoffRequest(parent, request); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(parent)
	if ready, err := reader.ReadString('\n'); err != nil || ready != installReady {
		t.Fatalf("ready = %q, %v", ready, err)
	}
	if !prepared || applied {
		t.Fatalf("prepared=%v applied=%v before final approval", prepared, applied)
	}
	if _, err := parent.Write([]byte(installApply)); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Shutdown(int(parent.Fd()), syscall.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil || !applied {
		t.Fatalf("serveInstallApply() = %v, applied=%v", err, applied)
	}
}

func TestInstallApplyHandoffRefusesMalformedOversizeEOFAndParentDeath(t *testing.T) {
	valid, _ := encodeInstallHandoffRequest(installHandoffFixture())
	cases := map[string][]byte{
		"unknown":   append(valid[:len(valid)-1], []byte(`,"operation":"anything"}`)...),
		"duplicate": []byte(strings.Replace(string(valid), `"schema":1`, `"schema":1,"schema":1`, 1)),
		"trailing":  append(append([]byte(nil), valid...), []byte("{}")...),
	}
	header := make([]byte, 8)
	binary.BigEndian.PutUint64(header, uint64(maxInstallHandoffBytes)+1)
	if _, err := readInstallHandoffRequest(bytes.NewReader(header)); err == nil {
		t.Fatal("oversized declared handoff accepted")
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeInstallHandoffRequest(body); err == nil {
				t.Fatal("hostile handoff accepted")
			}
		})
	}

	request := installHandoffFixture()
	parent, child := socketPair(t)
	executable := reviewedInstallExecutable(t, &request)
	done := make(chan error, 1)
	go func() {
		done <- serveInstallApply(t.Context(), child, executable, func(*os.File, *os.File) error { return nil }, func(context.Context, InstallHandoffRequest) (func() error, error) {
			return func() error { t.Error("Apply ran after parent death"); return nil }, nil
		})
	}()
	if err := writeInstallHandoffRequest(parent, request); err != nil {
		t.Fatal(err)
	}
	if ready, err := bufio.NewReader(parent).ReadString('\n'); err != nil || ready != installReady {
		t.Fatalf("ready = %q, %v", ready, err)
	}
	parent.Close()
	if err := <-done; err == nil {
		t.Fatal("parent death accepted")
	}
	child.Close()
	executable.Close()

	request = installHandoffFixture()
	parent, child = socketPair(t)
	executable = reviewedInstallExecutable(t, &request)
	done = make(chan error, 1)
	go func() {
		done <- serveInstallApply(t.Context(), child, executable, func(*os.File, *os.File) error { return nil }, func(context.Context, InstallHandoffRequest) (func() error, error) {
			return func() error { t.Error("Apply ran after replay"); return nil }, nil
		})
	}()
	if err := writeInstallHandoffRequest(parent, request); err != nil {
		t.Fatal(err)
	}
	if ready, err := bufio.NewReader(parent).ReadString('\n'); err != nil || ready != installReady {
		t.Fatalf("ready = %q, %v", ready, err)
	}
	if _, err := parent.Write([]byte(installApply + installApply)); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Shutdown(int(parent.Fd()), syscall.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("replayed approval accepted")
	}
	parent.Close()
	child.Close()
	executable.Close()
}

func TestInstallApplyUsesOnlyTheApprovedSudoCommandAndInheritedDescriptors(t *testing.T) {
	parent, child := socketPair(t)
	defer parent.Close()
	defer child.Close()
	executable, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	command := installApplyCommand(t.Context(), child, executable)
	want := []string{"/usr/bin/sudo", "--preserve-fds=3", "--", "/proc/self/fd/3", "private", "install-apply"}
	if command.Path != want[0] || strings.Join(command.Args, "\x00") != strings.Join(want, "\x00") || command.Stdin != child || len(command.ExtraFiles) != 1 || command.ExtraFiles[0] != executable {
		t.Fatalf("sudo command = path %q args %q stdin=%v extra=%v", command.Path, command.Args, command.Stdin, command.ExtraFiles)
	}
}

func TestInstallExecutableMustMatchTheReviewedCandidate(t *testing.T) {
	metadata := installHandoffMetadata(t, softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("1", 40)}, softwarelifecycle.AMD64)
	raw := []byte("reviewed executable")
	stamped, err := softwarelifecycle.StampPayload(raw, metadata)
	if err != nil {
		t.Fatal(err)
	}
	name := t.TempDir() + "/sbxr"
	if err := os.WriteFile(name, stamped, 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	digest := sha256.Sum256(stamped)
	payloadDigest := sha256.Sum256(raw)
	metadata.Build.PayloadSHA256 = hex.EncodeToString(payloadDigest[:])
	staged := softwarelifecycle.StagedRelease{Build: metadata.Build, Architecture: metadata.Architecture, StateSchema: metadata.StateSchema, ExecutableSHA256: hex.EncodeToString(digest[:])}
	if err := verifyInstallExecutableCandidate(executable, staged); err != nil {
		t.Fatal(err)
	}
	staged.Build.Tag = "v2.0.0"
	if err := verifyInstallExecutableCandidate(executable, staged); err == nil {
		t.Fatal("different reviewed executable identity accepted")
	}
}

func reviewedInstallExecutable(t *testing.T, request *InstallHandoffRequest) *os.File {
	t.Helper()
	metadata := installHandoffMetadata(t, request.Candidate.Staged.Build, request.Candidate.Staged.Architecture)
	raw := []byte("reviewed executable")
	stamped, err := softwarelifecycle.StampPayload(raw, metadata)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(raw)
	request.Candidate.Staged.Build.PayloadSHA256 = hex.EncodeToString(payloadDigest[:])
	digest := sha256.Sum256(stamped)
	request.Candidate.Staged.ExecutableSHA256 = hex.EncodeToString(digest[:])
	name := t.TempDir() + "/sbxr"
	if err := os.WriteFile(name, stamped, 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	return executable
}

func installHandoffMetadata(t *testing.T, identity softwarelifecycle.EmbeddedBuildIdentity, architecture softwarelifecycle.Architecture) softwarelifecycle.PayloadMetadata {
	t.Helper()
	definitions, err := state.ReleaseDefinitions()
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := subscriptionpublication.QualificationArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	artifacts["cloudflared.yml"] = cloudflaretunnel.QualificationConfiguration()
	units := []map[string]string{{"cloudflared.service": cloudflaretunnel.CloudflaredServiceUnit()}, {"sbxr-subscription.service": subscriptionserving.ServiceUnit()}, connectionprofiles.SystemdUnits(), softwarelifecycle.SystemdUnits()}
	for _, read := range []func() (map[string]string, error){certificatelifecycle.SystemdUnits, healthdiagnostics.SystemdUnits} {
		set, err := read()
		if err != nil {
			t.Fatal(err)
		}
		units = append(units, set)
	}
	metadata, err := softwarelifecycle.NewPayloadMetadata(identity, architecture, softwarelifecycle.PayloadMaterial{StateDefinitions: definitions, StateMigrations: state.ReleaseMigrations(), UnitSets: units, ArtifactSets: []map[string][]byte{artifacts}})
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

func installHandoffFixture() InstallHandoffRequest {
	application := []byte("application")
	applicationDigest := sha256.Sum256(application)
	componentFiles := map[string][]byte{
		"xray": []byte("xray"), "sing-box": []byte("sing-box"), "cloudflared": []byte("cloudflared"),
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(), "certbot/pyvenv.cfg": []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
	manifest, _ := softwarelifecycle.NewComponentManifest(softwarelifecycle.AMD64, "5.4.0", componentFiles)
	components, _ := softwarelifecycle.BuildComponentArchive(manifest, componentFiles)
	componentDigest := sha256.Sum256(components)
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("1", 40), IndexSHA256: strings.Repeat("2", 64)}
	applicationAsset := softwarelifecycle.AssetProof{Role: softwarelifecycle.ApplicationAMD64, Name: "sbxr-linux-amd64.tar.gz", Size: int64(len(application)), SHA256: hex.EncodeToString(applicationDigest[:])}
	componentAsset := softwarelifecycle.AssetProof{Role: softwarelifecycle.ComponentsAMD64, Name: "sbxr-components-linux-amd64.tar.gz", Size: int64(len(components)), SHA256: hex.EncodeToString(componentDigest[:])}
	verified := softwarelifecycle.VerifiedRelease{Identity: identity, Version: "1.0.0", Sequence: 1, StateSchema: 2, MinimumUpdaterSchema: 1, Assets: []softwarelifecycle.AssetProof{applicationAsset, componentAsset}}
	staged := softwarelifecycle.StagedRelease{Identity: identity, Build: softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: identity.Tag, Commit: identity.Commit, PayloadSHA256: strings.Repeat("3", 64)}, Architecture: softwarelifecycle.AMD64, ExecutableSHA256: strings.Repeat("4", 64), ComponentsSHA256: componentAsset.SHA256, InstallPath: softwarelifecycle.ReleaseInstallPath(identity), StateSchema: 2}
	return InstallHandoffRequest{
		Schema: 1, Session: strings.Repeat("a", 64), Tag: "v1.0.0", Architecture: softwarelifecycle.AMD64,
		Draft:               softwarelifecycle.InstallationDraft{Domain: "example.com", OwnerEmail: "owner@example.com", PublicIPv4: "192.0.2.10", PrimaryAddress: "192.0.2.10", SSHPort: 22, RealityPort: 443, Hysteria2Port: 443, TUICPort: 8443, AnyTLSPort: 9443, SubscriptionPort: 10443},
		CloudflareAccountID: strings.Repeat("b", 32), CloudflareZoneID: strings.Repeat("c", 32), CloudflareToken: "cfat_" + strings.Repeat("d", 40),
		RealityTarget: "www.example.net:443", RealityServerName: "www.example.net", ReviewedPlanSHA256: strings.Repeat("e", 64),
		Candidate: softwarelifecycle.InstallCandidateHandoff{Verified: verified, Staged: staged, ApplicationAsset: applicationAsset, ComponentAsset: componentAsset, ApplicationArchive: application, ComponentArchive: components},
	}
}

func socketPair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(descriptors[0]), "parent"), os.NewFile(uintptr(descriptors[1]), "child")
}
