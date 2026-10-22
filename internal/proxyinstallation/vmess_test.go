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
)

type vmessSetupReviewer interface {
	ReviewVMessSetup(context.Context, string) Review
}

func TestOptionalVMessSetupSubscriptionRotationAndRemoval(t *testing.T) {
	host := acceptedHost()
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
	if r := installation.Execute(t.Context(), *review.Prepared, Approved, nil); r.Code != SetupComplete {
		t.Fatalf("setup: %#v", r)
	}
	first, err := singboxadapter.New().CurrentConnectionFacts(host.configuration, "8.8.8.8")
	if err != nil || first.VMessHostname != "tunnel.example.com" {
		t.Fatal("setup lost optional VMess", err)
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
}

type occupiedVMessHost struct {
	*controlledHost
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
	host := &occupiedVMessHost{controlledHost: acceptedHost(), occupied: true}
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
