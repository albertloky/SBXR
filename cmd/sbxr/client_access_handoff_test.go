package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
)

func TestClientAccessHandoffAcceptsOnlyExactTypedRequests(t *testing.T) {
	valid := clientAccessHandoffRequest{Schema: 1, Mode: "change", Action: clientAccessRotateProfile, Profile: string(connectionprofiles.AnyTLSProfileID), ChangeSet: "client-access-0001"}
	if !validClientAccessHandoff(valid) || !validClientAccessHandoff(clientAccessHandoffRequest{Schema: 1, Mode: "view"}) || !validClientAccessHandoff(clientAccessHandoffRequest{Schema: 1, Mode: "recover", ChangeSet: valid.ChangeSet}) {
		t.Fatal("exact Client Access requests were refused")
	}
	for _, changed := range []clientAccessHandoffRequest{
		{Schema: 1, Mode: "change", Action: clientAccessRotateProfile, ChangeSet: valid.ChangeSet},
		{Schema: 1, Mode: "change", Action: clientAccessRotateAllProfiles, Profile: valid.Profile, ChangeSet: valid.ChangeSet},
		{Schema: 1, Mode: "change", Action: "run-command", Profile: valid.Profile, ChangeSet: valid.ChangeSet},
		{Schema: 1, Mode: "view", ChangeSet: valid.ChangeSet},
		{Schema: 1, Mode: "view", DiagnosticsAction: "view"},
		{Schema: 1, Mode: "recover", Action: clientAccessRotateProfile, ChangeSet: valid.ChangeSet},
		{Schema: 1, Mode: "change", Action: clientAccessRotateAllProfiles, ChangeSet: valid.ChangeSet, BundleReplacement: ownerconsole.BundleReplacement{Archive: "sbxr-support-20260810T120000Z.tar.gz"}},
	} {
		if validClientAccessHandoff(changed) {
			t.Fatalf("unsafe request accepted: %+v", changed)
		}
	}
	var encoded bytes.Buffer
	if err := writeClientAccessMessage(&encoded, valid); err != nil {
		t.Fatal(err)
	}
	var decoded clientAccessHandoffRequest
	if err := readClientAccessMessage(&encoded, &decoded); err != nil || decoded != valid {
		t.Fatalf("strict round trip failed: %+v %v", decoded, err)
	}
	unknown := []byte(`{"schema":1,"mode":"view","command":"id"}`)
	framed := make([]byte, 4)
	binary.BigEndian.PutUint32(framed, uint32(len(unknown)))
	if err := readClientAccessMessage(bytes.NewReader(append(framed, unknown...)), &decoded); err == nil {
		t.Fatal("unknown privileged field was accepted")
	}
	if strings.Contains(valid.String(), "client-access") {
		t.Fatal("request rendering exposed privileged facts")
	}
}

func TestClientAccessHandoffPreservesOnlyTypedSSHFailureCause(t *testing.T) {
	firewallRequest := clientAccessHandoffRequest{Schema: 1, Mode: "change", Action: clientAccessEnableProfile, Profile: string(connectionprofiles.AnyTLSProfileID), ChangeSet: "client-access-0001"}
	for _, cause := range []networkpolicy.SSHPreservationFailureCause{networkpolicy.SSHLaunchIdentityInvalid, networkpolicy.SSHOriginalSessionLost, networkpolicy.SSHObservationUnavailable} {
		var encoded bytes.Buffer
		if err := writeClientAccessMessage(&encoded, clientAccessHandoffReview{SSHFailureCause: cause}); err != nil {
			t.Fatal(err)
		}
		var decoded clientAccessHandoffReview
		if err := readClientAccessMessage(&encoded, &decoded); err != nil || decoded.SSHFailureCause != cause || !validClientAccessSSHFailureReview(firewallRequest, decoded) {
			t.Fatalf("typed SSH failure round trip for %q was refused", cause)
		}
	}
	invalid := clientAccessHandoffReview{SSHFailureCause: networkpolicy.SSHOriginalSessionLost}
	rotation := firewallRequest
	rotation.Action = clientAccessRotateProfile
	for _, request := range []clientAccessHandoffRequest{rotation, {Schema: 1, Mode: "software-review", SoftwareAction: "repair", ChangeSet: "repair-0001"}} {
		if validClientAccessSSHFailureReview(request, invalid) {
			t.Fatal("SSH failure response was accepted for non-firewall work")
		}
	}
	invalid.SSHFailureCause = "different session"
	if validClientAccessSSHFailureReview(firewallRequest, invalid) {
		t.Fatal("unknown SSH failure cause was accepted")
	}
}

func TestManagedProviderHandoffAcceptsOnlyExactReviewedActions(t *testing.T) {
	requests := []clientAccessHandoffRequest{
		{Schema: 1, Mode: "provider", ProviderAction: managedCloudflareReplace, ChangeSet: "provider-0001", Token: "sbxr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DedicatedBroadPolicyConfirmed: true},
		{Schema: 1, Mode: "provider", ProviderAction: managedCloudflareRemove, ChangeSet: "provider-0002"},
		{Schema: 1, Mode: "provider", ProviderAction: managedCloudflareRotate, ChangeSet: "provider-0003"},
		{Schema: 1, Mode: "provider", ProviderAction: managedCloudflareRotateManagement, ChangeSet: "provider-0006"},
		{Schema: 1, Mode: "provider", ProviderAction: managedCertificateIP, ChangeSet: "provider-0004", OwnerEmail: "owner@example.com", Agreement: true},
		{Schema: 1, Mode: "provider", ProviderAction: managedCertificateDomain, ChangeSet: "provider-0005", OwnerEmail: "owner@example.com", Agreement: true},
	}
	for _, request := range requests {
		if !validClientAccessHandoff(request) {
			t.Fatalf("exact managed provider request was refused: %+v", request)
		}
		request.Action = clientAccessRotateAllProfiles
		if validClientAccessHandoff(request) {
			t.Fatalf("mixed Client Access/provider authority was accepted: %+v", request)
		}
	}
	for _, request := range []clientAccessHandoffRequest{
		{Schema: 1, Mode: "provider", ProviderAction: managedCloudflareReplace, ChangeSet: "provider-0001", Token: "short"},
		{Schema: 1, Mode: "provider", ProviderAction: managedCloudflareRemove, ChangeSet: "provider-0002", Token: "sbxr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Schema: 1, Mode: "provider", ProviderAction: managedCertificateIP, ChangeSet: "provider-0004", OwnerEmail: "owner@example.com"},
		{Schema: 1, Mode: "provider", ProviderAction: "shell", ChangeSet: "provider-0006"},
	} {
		if validClientAccessHandoff(request) {
			t.Fatalf("unsafe managed provider request was accepted: %+v", request)
		}
	}
}

func TestDiagnosticsHandoffAcceptsOnlyViewOrReviewedBundleReplacement(t *testing.T) {
	view := clientAccessHandoffRequest{Schema: 1, Mode: "diagnostics", DiagnosticsAction: "view"}
	bundle := clientAccessHandoffRequest{Schema: 1, Mode: "diagnostics", DiagnosticsAction: "bundle", BundleReplacement: ownerconsole.BundleReplacement{Archive: "sbxr-support-20260810T120000Z.tar.gz"}}
	if !validClientAccessHandoff(view) || !validClientAccessHandoff(bundle) {
		t.Fatal("exact diagnostics request was refused")
	}
	for _, request := range []clientAccessHandoffRequest{
		{Schema: 1, Mode: "diagnostics"},
		{Schema: 1, Mode: "diagnostics", DiagnosticsAction: "shell"},
		{Schema: 1, Mode: "diagnostics", DiagnosticsAction: "view", ChangeSet: "client-access-0001"},
		{Schema: 1, Mode: "diagnostics", DiagnosticsAction: "bundle", Action: clientAccessRotateAllProfiles},
	} {
		if validClientAccessHandoff(request) {
			t.Fatalf("unsafe diagnostics request was accepted: %+v", request)
		}
	}
}

func TestSoftwareLifecycleHandoffAcceptsOnlyExactTypedActions(t *testing.T) {
	update := clientAccessHandoffRequest{Schema: 1, Mode: "software-review", SoftwareAction: "update", ReleaseTag: "v1.5.0", ChangeSet: "update-0001"}
	repair := clientAccessHandoffRequest{Schema: 1, Mode: "software-review", SoftwareAction: "repair", ChangeSet: "repair-0001"}
	downgrade := clientAccessHandoffRequest{Schema: 1, Mode: "software-review", SoftwareAction: "downgrade", ReleaseTag: "v1.4.0", ChangeSet: "downgrade-0001"}
	apply := update
	apply.Mode, apply.ReviewedPlanIdentity, apply.ReviewedPlanSHA256 = "software-apply", "update-0001-plan-abcdef123456", strings.Repeat("a", 64)
	if !validClientAccessHandoff(update) || !validClientAccessHandoff(downgrade) || !validClientAccessHandoff(repair) || !validClientAccessHandoff(apply) {
		t.Fatal("exact Software Lifecycle request was refused")
	}
	for _, request := range []clientAccessHandoffRequest{
		{Schema: 1, Mode: "software-review"},
		{Schema: 1, Mode: "software-review", SoftwareAction: "apply"},
		{Schema: 1, Mode: "software-review", SoftwareAction: "view"},
		{Schema: 1, Mode: "software-review", SoftwareAction: "downgrade", ChangeSet: "downgrade-0001"},
		{Schema: 1, Mode: "software-apply", SoftwareAction: "update", ReleaseTag: "v1.5.0", ChangeSet: "update-0001"},
		{Schema: 1, Mode: "software-review", SoftwareAction: "update", ReleaseTag: "v1.5.0", ChangeSet: "update-0001", ReviewedPlanIdentity: "unexpected", ReviewedPlanSHA256: strings.Repeat("a", 64)},
		{Schema: 1, Mode: "software-review", SoftwareAction: "downgrade", ReleaseTag: "../v1.4.0", ChangeSet: "downgrade-0001"},
		{Schema: 1, Mode: "software-review", SoftwareAction: "downgrade", ReleaseTag: "v1.4.0-rc.1", ChangeSet: "downgrade-0001"},
		{Schema: 1, Mode: "software-review", SoftwareAction: "downgrade", ReleaseTag: "vX.Y.Z", ChangeSet: "downgrade-0001"},
	} {
		if validClientAccessHandoff(request) {
			t.Fatalf("unsafe Software Lifecycle view accepted: %+v", request)
		}
	}
}

func TestCompleteRemovalHandoffRequiresSeparateBoundReviewAndApprovedApply(t *testing.T) {
	review := clientAccessHandoffRequest{Schema: 1, Mode: "removal-review", ChangeSet: "complete-removal-0001"}
	apply := clientAccessHandoffRequest{Schema: 1, Mode: "removal-apply", ChangeSet: review.ChangeSet, ReviewedPlanIdentity: "complete-removal-0001-plan-abcdef123456", ReviewedPlanSHA256: strings.Repeat("a", 64)}
	if !validClientAccessHandoff(review) || !validClientAccessHandoff(apply) {
		t.Fatal("exact Complete removal review/apply requests were refused")
	}
	for _, request := range []clientAccessHandoffRequest{
		{Schema: 1, Mode: "removal-apply", ChangeSet: review.ChangeSet},
		{Schema: 1, Mode: "removal-apply", ChangeSet: review.ChangeSet, ReviewedPlanIdentity: apply.ReviewedPlanIdentity, ReviewedPlanSHA256: apply.ReviewedPlanSHA256, SoftwareAction: "repair"},
	} {
		if validClientAccessHandoff(request) {
			t.Fatalf("unsafe Complete removal request was accepted: %+v", request)
		}
	}
}

func TestSoftwareLifecycleHandoffCarriesOneBoundedCancellationRequest(t *testing.T) {
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(descriptors[0]), "parent"), os.NewFile(uintptr(descriptors[1]), "child")
	defer child.Close()
	ready := make(chan struct{})
	go func() {
		approval := make([]byte, 6)
		_, _ = io.ReadFull(child, approval)
		close(ready)
		cancel := make([]byte, 7)
		_, _ = io.ReadFull(child, cancel)
		_, _ = child.Write([]byte{'R'})
	}()
	session := &clientAccessHandoffSession{socket: parent, wait: func() error { return nil }, cancellable: true}
	result := make(chan byte, 1)
	go func() { terminal, _ := session.apply(); result <- terminal }()
	<-ready
	if err := session.cancel(); err != nil {
		t.Fatal(err)
	}
	if terminal := <-result; terminal != 'R' {
		t.Fatalf("terminal = %q", terminal)
	}
	if err := session.cancel(); err == nil {
		t.Fatal("second cancellation request was accepted")
	}
}

func TestCompleteRemovalApplyCarriesBothPostReviewOwnerActs(t *testing.T) {
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(descriptors[0]), "parent"), os.NewFile(uintptr(descriptors[1]), "child")
	defer child.Close()
	message := "COMPLETE REMOVAL\nPERMANENTLY REMOVE SBXR\nAPPLY\n"
	seen := make(chan string, 1)
	go func() {
		body := make([]byte, len(message))
		_, _ = io.ReadFull(child, body)
		seen <- string(body)
		_, _ = child.Write([]byte{'R'})
	}()
	session := &clientAccessHandoffSession{socket: parent, wait: func() error { return nil }, removalApproved: true}
	if terminal, err := session.apply(); err != nil || terminal != 'R' {
		t.Fatalf("terminal = %q, err = %v", terminal, err)
	}
	if got := <-seen; got != message {
		t.Fatalf("approval protocol = %q", got)
	}
}

func TestCompleteRemovalOutcomeWiresBothOwnerActsToApplyHandoff(t *testing.T) {
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(descriptors[0]), "parent"), os.NewFile(uintptr(descriptors[1]), "child")
	defer child.Close()
	message := "COMPLETE REMOVAL\nPERMANENTLY REMOVE SBXR\nAPPLY\n"
	seen := make(chan string, 1)
	go func() {
		body := make([]byte, len(message))
		_, _ = io.ReadFull(child, body)
		seen <- string(body)
		_, _ = child.Write([]byte{'R'})
	}()
	identity := ownerconsole.PlanIdentity("complete-removal-0001-plan-abcdef123456")
	request := clientAccessHandoffRequest{Schema: 1, Mode: "removal-apply", ChangeSet: "complete-removal-0001", ReviewedPlanIdentity: string(identity), ReviewedPlanSHA256: strings.Repeat("a", 64)}
	outcome := &clientAccessOutcome{
		loaded: true, request: request, removalReview: &deferredRemovalReview{identity: identity},
		presentation: clientAccessPresentation{Installation: ownerconsole.InstallationManaged, StateRevision: 7},
		softwareLaunch: func(context.Context, clientAccessHandoffRequest) (*clientAccessHandoffSession, error) {
			return &clientAccessHandoffSession{socket: parent, wait: func() error { return nil }, review: clientAccessHandoffReview{Identity: string(identity), SHA256: request.ReviewedPlanSHA256, StartingRevision: 7, TotalSteps: completeRemovalTotalSteps}}, nil
		},
	}
	if result := outcome.Apply(t.Context(), identity); result.Kind != ownerconsole.ChangeStarted {
		t.Fatalf("apply result = %+v", result)
	}
	if got := <-seen; got != message {
		t.Fatalf("approval protocol = %q", got)
	}
}
