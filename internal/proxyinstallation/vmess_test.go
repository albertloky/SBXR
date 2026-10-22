package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type vmessSetupReviewer interface {
	ReviewVMessSetup(context.Context, string) Review
}

type managedVMessHost struct {
	*controlledHost
	prerequisiteProblem, probeProblem  string
	failInstall, failStart, failRemove bool
	installedTunnel, removedTunnel     bool
	probes                             int
}

func (h *managedVMessHost) PreflightTunnel(context.Context) (hostadapter.TunnelAuthority, string) {
	return hostadapter.TunnelAuthority{TunnelID: "12345678-1234-4234-8234-123456789abc", TokenSHA256: strings.Repeat("a", 64), BinarySHA256: strings.Repeat("b", 64)}, h.prerequisiteProblem
}
func (h *managedVMessHost) InstallTunnel(context.Context, hostadapter.TunnelAuthority) bool {
	h.installedTunnel = !h.failInstall
	return !h.failInstall
}
func (h *managedVMessHost) StartTunnel(context.Context, hostadapter.TunnelAuthority) bool {
	return !h.failStart
}
func (h *managedVMessHost) RemoveTunnel(context.Context, hostadapter.TunnelAuthority) bool {
	h.removedTunnel = !h.failRemove
	return !h.failRemove
}
func (h *managedVMessHost) TunnelRemovalSafe(context.Context, hostadapter.TunnelAuthority) bool {
	return !h.failRemove
}
func (h *managedVMessHost) ProbeVMess(context.Context, []byte, string) string {
	h.probes++
	return h.probeProblem
}

func TestOptionalVMessSetupSubscriptionRotationAndRemoval(t *testing.T) {
	host := &managedVMessHost{controlledHost: acceptedHost()}
	installation := newInstalledInterface(&controlledRemovalLifecycle{ready: true}, host, singboxadapter.New())
	reviewer, ok := installation.(vmessSetupReviewer)
	if !ok {
		t.Fatal("VMess setup is not wired into the installed module")
	}
	for _, invalid := range []string{"", "https://unsafe.example.com", "tunnel.example.com\n"} {
		if r := reviewer.ReviewVMessSetup(t.Context(), invalid); r.Prepared != nil || r.Result.Code != ActionRefused {
			t.Fatal("invalid hostname prepared setup")
		}
	}
	review := reviewer.ReviewVMessSetup(t.Context(), "tunnel.example.com")
	if review.Prepared == nil || !strings.Contains(strings.Join(review.Plan, "\n"), "http://127.0.0.1:10000") {
		t.Fatal("missing reviewed VMess origin")
	}
	if r := installation.Execute(t.Context(), *review.Prepared, Declined, nil); r.Code != ActionCancelled || len(host.operations) != 0 {
		t.Fatal("decline mutated the host")
	}
	review = reviewer.ReviewVMessSetup(t.Context(), "tunnel.example.com")
	if r := installation.Execute(t.Context(), *review.Prepared, Approved, nil); r.Code != VMessConnectionReady || host.probes != 1 || !host.installedTunnel {
		t.Fatalf("setup: %#v", r)
	}
	first, err := singboxadapter.New().CurrentConnectionFacts(host.configuration, "8.8.8.8")
	if err != nil || first.VMessHostname != "tunnel.example.com" {
		t.Fatal("setup lost optional VMess", err)
	}
	source := testInstalledIdentity()
	target := &softwarelifecycle.UpdateTarget{Identity: source, Executable: []byte(expandedProxyAuthorityCapability + " " + hostadapter.LockProvisioningCapability()), Support: &softwarelifecycle.ReleaseSupport{Scope: softwarelifecycle.RecurringSubscriptionUpgrade, Contract: softwarelifecycle.SubscriptionUpdateContract, Sources: []softwarelifecycle.ReleaseIdentity{source}}}
	if AdmitSoftwareUpdate(host.ownership, source, target) {
		t.Fatal("update target without connector recovery capability admitted")
	}
	target.Executable = append(target.Executable, []byte(" "+hostadapter.TunnelCapability())...)
	if !AdmitSoftwareUpdate(host.ownership, source, target) {
		t.Fatal("compatible connector-aware target refused")
	}
	if review := reviewer.ReviewVMessSetup(t.Context(), "other.example.com"); review.Prepared != nil {
		t.Fatal("existing installation accepted another setup")
	}
	enable := installation.Review(t.Context(), EnableSubscriptionAction)
	if enable.Prepared == nil {
		t.Fatalf("enable refused: %#v", enable.Result)
	}
	if r := installation.Execute(t.Context(), *enable.Prepared, Approved, func(Progress) {}); r.Code != SubscriptionEnabled {
		t.Fatalf("enable: %#v", r)
	}
	oldArtifact, _, valid := clientArtifact(host.configuration, "8.8.8.8")
	if !valid || !bytes.Contains(oldArtifact, []byte("vmess://")) {
		t.Fatal("subscription omitted VMess")
	}
	rotation := installation.Review(t.Context(), RotateClientIdentityAction)
	if rotation.Prepared == nil {
		t.Fatalf("rotation refused: %#v", rotation.Result)
	}
	if r := installation.Execute(t.Context(), *rotation.Prepared, Approved, nil); r.Code != ClientIdentityRotated {
		t.Fatalf("rotate: %#v", r)
	}
	fresh, err := singboxadapter.New().CurrentConnectionFacts(host.configuration, "8.8.8.8")
	if err != nil || fresh.UUID == first.UUID || fresh.VMessHostname != first.VMessHostname {
		t.Fatal("VMess identity was not rotated", err)
	}
	artifact, _, _ := clientArtifact(host.configuration, "8.8.8.8")
	sum := sha256.Sum256(artifact)
	selected := false
	for _, checkpoint := range host.checkpoints {
		record, ok := decodeOwnership(checkpoint)
		if ok && record.ClientRotation != nil && record.ClientRotation.Subscription != nil && record.ClientRotation.Subscription.TargetArtifactSHA256 == hex.EncodeToString(sum[:]) {
			selected = true
		}
	}
	if bytes.Equal(oldArtifact, artifact) || !selected || len(host.clientSubscriptionArtifact) != 0 {
		t.Fatal("subscription did not select the rotated nodes")
	}
	removal := installation.Review(t.Context(), CompleteRemovalAction)
	if removal.Prepared == nil {
		t.Fatalf("removal refused: %#v", removal.Result)
	}
	if r := installation.Execute(t.Context(), *removal.Prepared, Approved, nil); r.Code != CompleteRemovalCompleted {
		t.Fatalf("remove: %#v", r)
	}
	if !host.removedTunnel {
		t.Fatal("dedicated connector was not removed")
	}
}

type occupiedVMessHost struct {
	*managedVMessHost
	occupied bool
	unknown  bool
}

func (h *occupiedVMessHost) Inspect(ctx context.Context, requested []hostadapter.Resource) hostadapter.Inspection {
	if len(requested) == 1 && requested[0].Kind == hostadapter.TCPListenerResource && requested[0].Name == "10000" {
		return hostadapter.Inspection{Complete: true, Resources: []hostadapter.Resource{{Kind: hostadapter.TCPListenerResource, Name: "10000", Observed: !h.unknown, Present: h.occupied}}}
	}
	return h.controlledHost.Inspect(ctx, requested)
}

func TestVMessOriginPortIsCheckedDuringReviewAndExecution(t *testing.T) {
	host := &occupiedVMessHost{managedVMessHost: &managedVMessHost{controlledHost: acceptedHost()}, occupied: true}
	installation := newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	reviewer, ok := installation.(vmessSetupReviewer)
	if !ok {
		t.Fatal("missing optional setup review")
	}
	if r := reviewer.ReviewVMessSetup(t.Context(), "tunnel.example.com"); r.Prepared != nil {
		t.Fatal("prepared an occupied origin")
	}
	host.occupied = false
	host.unknown = true
	if r := reviewer.ReviewVMessSetup(t.Context(), "tunnel.example.com"); r.Prepared != nil {
		t.Fatal("prepared an unobserved origin")
	}
	host.unknown = false
	r := reviewer.ReviewVMessSetup(t.Context(), "tunnel.example.com")
	if r.Prepared == nil {
		t.Fatal("free origin refused")
	}
	host.occupied = true
	if result := installation.Execute(t.Context(), *r.Prepared, Approved, nil); result.Code != ActionRefused || len(host.operations) != 0 {
		t.Fatal("port drift was not refused before mutation")
	}
}

func TestVMessPrerequisitesAndForwardRecoveryKeepPublicReadinessHonest(t *testing.T) {
	host := &managedVMessHost{controlledHost: acceptedHost(), prerequisiteProblem: "protected token missing"}
	installation := newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	reviewer := installation.(vmessSetupReviewer)
	if r := reviewer.ReviewVMessSetup(t.Context(), "tunnel.example.com"); r.Prepared != nil || len(host.operations) != 0 || !strings.Contains(r.Result.Correction, "protected token missing") {
		t.Fatal("missing prerequisite was accepted")
	}
	host.prerequisiteProblem = ""
	r := reviewer.ReviewVMessSetup(t.Context(), "tunnel.example.com")
	host.prerequisiteProblem = "token changed"
	if result := installation.Execute(t.Context(), *r.Prepared, Approved, nil); result.Code != ActionRefused || len(host.operations) != 0 {
		t.Fatal("prerequisite drift mutated host")
	}
	host.prerequisiteProblem = ""
	host.failStart = true
	r = reviewer.ReviewVMessSetup(t.Context(), "tunnel.example.com")
	if result := installation.Execute(t.Context(), *r.Prepared, Approved, nil); result.Code != SetupNeedsCompletion || host.probes != 0 {
		t.Fatal("connector failure falsely completed setup", result)
	}
	record, valid := decodeOwnership(host.ownership)
	if !valid || record.Direction != setupRequired || record.Phase != serviceStarted || record.Tunnel == nil {
		t.Fatal("lost forward recovery authority")
	}
	host.failStart = false
	host.probeProblem = "public WebSocket unavailable"
	installation = newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	r = installation.Review(t.Context(), FinishSetupAction)
	if r.Prepared == nil {
		t.Fatal("forward recovery refused", r.Result)
	}
	if result := installation.Execute(t.Context(), *r.Prepared, Approved, nil); result.Code != VMessConnectionPending || result.Status != Running || !strings.Contains(result.Correction, "public WebSocket unavailable") {
		t.Fatal("unverified public connection was reported complete", result)
	}
	before := bytes.Clone(host.ownership)
	operations := len(host.operations)
	probes := host.probes
	if status := installation.Review(t.Context(), StatusAction); status.Result.Code != VMessConnectionPending || !strings.Contains(status.Result.Message, "not verified") || host.probes != probes {
		t.Fatal("ordinary status claimed public setup success or ran a network probe", status.Result)
	}
	host.probeProblem = ""
	check := installation.Review(t.Context(), CheckVMessTunnelAction)
	if check.Result.Code != VMessConnectionReady || !bytes.Equal(before, host.ownership) || len(host.operations) != operations || check.Prepared != nil {
		t.Fatal("repeatable connection check changed durable state", check.Result)
	}
	host.busy = true
	if check := installation.Review(t.Context(), CheckVMessTunnelAction); check.Result.Code != VMessConnectionPending || check.Result.ProxyTraffic == ProvedWorking {
		t.Fatal("busy check claimed fresh local readiness", check.Result)
	}
	host.busy = false
	host.active = false
	record, _ = decodeOwnership(host.ownership)
	if checked := installation.(*installedInterface).checkVMessConnection(t.Context(), record, host.ownership); checked.ProxyTraffic == ProvedWorking || checked.Code != VMessConnectionPending {
		t.Fatal("stopped runtime claimed fresh local readiness", checked)
	}
}

func TestVMessConnectorPrecommitFailureCleansOnlyRecordedConnector(t *testing.T) {
	host := &managedVMessHost{controlledHost: acceptedHost(), failInstall: true, failRemove: true}
	installation := newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	r := installation.(vmessSetupReviewer).ReviewVMessSetup(t.Context(), "tunnel.example.com")
	if result := installation.Execute(t.Context(), *r.Prepared, Approved, nil); result.Code != SetupNeedsCleanup {
		t.Fatal("missing cleanup authority", result)
	}
	host.failInstall = false
	host.failRemove = false
	installation = newInstalledInterface(readyLifecycle{}, host, singboxadapter.New())
	r = installation.Review(t.Context(), FinishCleanupAction)
	if r.Prepared == nil {
		t.Fatal("cleanup review refused", r.Result)
	}
	if result := installation.Execute(t.Context(), *r.Prepared, Approved, nil); result.Code != SetupCleanedUp || !host.removedTunnel || len(host.ownership) != 0 {
		t.Fatal("cleanup did not recover", result)
	}
}

type unrelatedTunnelHost struct{ *controlledHost }

func (h *unrelatedTunnelHost) Inspect(ctx context.Context, requested []hostadapter.Resource) hostadapter.Inspection {
	facts := h.controlledHost.Inspect(ctx, requested)
	for i := range facts.Resources {
		if facts.Resources[i].Name == hostadapter.TunnelUnitPath || facts.Resources[i].Name == hostadapter.TunnelWantsPath {
			facts.Resources[i].Present = true
		}
	}
	return facts
}

func TestVLESSSetupAndRemovalPreserveUnrelatedTunnelService(t *testing.T) {
	host := &unrelatedTunnelHost{acceptedHost()}
	installation := newInstalledInterface(&controlledRemovalLifecycle{ready: true}, host, singboxadapter.New())
	r := installation.Review(t.Context(), StartSetupAction)
	if r.Prepared == nil {
		t.Fatal("unrelated tunnel blocked VLESS setup", r.Result)
	}
	if result := installation.Execute(t.Context(), *r.Prepared, Approved, nil); result.Code != SetupComplete {
		t.Fatal(result)
	}
	r = installation.Review(t.Context(), CompleteRemovalAction)
	if r.Prepared == nil {
		t.Fatal("unrelated tunnel blocked VLESS removal", r.Result)
	}
	if result := installation.Execute(t.Context(), *r.Prepared, Approved, nil); result.Code != CompleteRemovalCompleted {
		t.Fatal(result)
	}
	foreign := host.Inspect(t.Context(), []hostadapter.Resource{{Kind: hostadapter.PathResource, Name: hostadapter.TunnelUnitPath}})
	if len(foreign.Resources) != 1 || !foreign.Resources[0].Present {
		t.Fatal("unrelated connector was changed")
	}
}
