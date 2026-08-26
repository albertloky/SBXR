package terminal

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
)

type journeyInstallation struct {
	actions       []proxyinstallation.Action
	confirmations []proxyinstallation.Confirmation
	statusReviews int
}

func (installation *journeyInstallation) Review(_ context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	installation.actions = append(installation.actions, action)
	base := proxyinstallation.Review{
		Version: "v3.0.0", Status: proxyinstallation.NotSetUp,
		LegalActions: []proxyinstallation.Action{proxyinstallation.StartSetupAction, proxyinstallation.ViewDetailsAction, proxyinstallation.CompleteRemovalAction},
		Result:       proxyinstallation.Result{Status: proxyinstallation.NotSetUp, Message: "Proxy setup has not started.", Code: proxyinstallation.StatusNotSetUp},
	}
	if action == proxyinstallation.StatusAction {
		installation.statusReviews++
	}
	if action == proxyinstallation.StartSetupAction {
		base.Plan = []string{"Host: Ubuntu 24.04 amd64", "SBXR will not change SSH, firewall, routing, or provider settings."}
		base.Prepared = &proxyinstallation.PreparedAction{}
	}
	return base
}

func (installation *journeyInstallation) Execute(_ context.Context, _ proxyinstallation.PreparedAction, confirmation proxyinstallation.Confirmation, _ proxyinstallation.ProgressReporter) proxyinstallation.Result {
	installation.confirmations = append(installation.confirmations, confirmation)
	return proxyinstallation.Result{Status: proxyinstallation.NotSetUp, Message: "No changes were made.", Code: proxyinstallation.ActionCancelled}
}

func TestRunPresentsAndCancelsTheRealNotSetUpJourney(t *testing.T) {
	installation := &journeyInstallation{}
	var output bytes.Buffer

	status := Run(t.Context(), nil, bytes.NewBufferString("1\n\n0\n"), &output, &output, installation)

	if status != 0 || !reflect.DeepEqual(installation.actions, []proxyinstallation.Action{proxyinstallation.StatusAction, proxyinstallation.StartSetupAction, proxyinstallation.StatusAction}) || !reflect.DeepEqual(installation.confirmations, []proxyinstallation.Confirmation{proxyinstallation.Declined}) || installation.statusReviews != 2 {
		t.Fatalf("status=%d actions=%v confirmations=%v statusReviews=%d", status, installation.actions, installation.confirmations, installation.statusReviews)
	}
	want := "SBXR V3\nVersion: v3.0.0\nProxy status: Not set up\nResult: Proxy setup has not started.\nCode: PROXY-INSTALLATION-STATUS-NOT-SET-UP\n\n1. Start setup\n2. View details\n3. Complete removal\n0. Exit\n"
	if !bytes.Contains(output.Bytes(), []byte(want)) {
		t.Fatalf("initial frame missing:\n%s", output.String())
	}
	for _, required := range []string{
		"Host: Ubuntu 24.04 amd64",
		"Start proxy setup? [y/N]",
		"Result: No changes were made.\nCode: PROXY-INSTALLATION-ACTION-CANCELLED",
	} {
		if !bytes.Contains(output.Bytes(), []byte(required)) {
			t.Errorf("output missing %q:\n%s", required, output.String())
		}
	}
}

func TestRunAcceptsOnlyYOrNConfirmation(t *testing.T) {
	installation := &journeyInstallation{}
	var output bytes.Buffer

	status := Run(t.Context(), nil, bytes.NewBufferString("1\nmaybe\ny\n0\n"), &output, &output, installation)

	if status != 0 || !reflect.DeepEqual(installation.confirmations, []proxyinstallation.Confirmation{proxyinstallation.Approved}) || !bytes.Contains(output.Bytes(), []byte("Enter y or n.\nStart proxy setup? [y/N]")) {
		t.Fatalf("status=%d confirmations=%v output:\n%s", status, installation.confirmations, output.String())
	}
}

func TestRunRejectsNonCanonicalMenuNumbers(t *testing.T) {
	installation := &journeyInstallation{}
	var output bytes.Buffer

	status := Run(t.Context(), nil, bytes.NewBufferString("+1\n01\n1\n\n0\n"), &output, &output, installation)

	if status != 0 || len(installation.confirmations) != 1 || bytes.Count(output.Bytes(), []byte("Enter one of the displayed numbers.")) != 2 {
		t.Fatalf("status=%d confirmations=%v output:\n%s", status, installation.confirmations, output.String())
	}
}
