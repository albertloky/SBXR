package terminal

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
)

type vmessInstallation struct {
	journeyInstallation
	hostname string
}

func (v *vmessInstallation) Review(ctx context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	r := v.journeyInstallation.Review(ctx, action)
	r.LegalActions = append(r.LegalActions, proxyinstallation.StartVMessSetupAction)
	return r
}

func (v *vmessInstallation) ReviewVMessSetup(_ context.Context, hostname string) proxyinstallation.Review {
	v.hostname = hostname
	v.actions = append(v.actions, proxyinstallation.StartVMessSetupAction)
	return proxyinstallation.Review{Prepared: &proxyinstallation.PreparedAction{}, Plan: []string{"VMess origin for " + hostname}}
}

func TestMenuReviewsVMessHostnameBeforeConfirmation(t *testing.T) {
	for _, confirmation := range []struct {
		input    string
		expected proxyinstallation.Confirmation
	}{{"y", proxyinstallation.Approved}, {"n", proxyinstallation.Declined}} {
		t.Run(confirmation.input, func(t *testing.T) {
			v := &vmessInstallation{}
			var output bytes.Buffer
			if code := Run(t.Context(), nil, strings.NewReader("4\ntunnel.example.com\n"+confirmation.input+"\n0\n"), &output, &output, v, nil); code != 0 {
				t.Fatal("menu failed")
			}
			if v.hostname != "tunnel.example.com" || !reflect.DeepEqual(v.confirmations, []proxyinstallation.Confirmation{confirmation.expected}) || len(v.actions) != 3 || v.actions[1] != proxyinstallation.StartVMessSetupAction {
				t.Fatal("VMess review/confirmation was not wired correctly")
			}
			if !strings.Contains(output.String(), "VMess origin for tunnel.example.com\nStart proxy setup? [y/N]") {
				t.Fatal("confirmation omitted the reviewed origin")
			}
			for _, guidance := range []string{"your own Cloudflare domain", "dedicated unused tunnel", "leave route path blank", "/etc/cloudflared/sbxr.token", "never paste it here", "sbxr-tunnel.service"} {
				if !strings.Contains(output.String(), guidance) {
					t.Fatalf("guide omitted %q", guidance)
				}
			}
		})
	}
}

func TestVMessGuideBlankHostnameCancelsBeforeReview(t *testing.T) {
	v := &vmessInstallation{}
	var output bytes.Buffer
	if code := Run(t.Context(), nil, strings.NewReader("4\n\n0\n"), &output, &output, v, nil); code != 0 || v.hostname != "" || len(v.confirmations) != 0 || len(v.actions) != 1 {
		t.Fatal("blank hostname did not cancel safely")
	}
}

func TestMenuDoesNotPrepareVMessAfterMissingOrOversizedHostname(t *testing.T) {
	for _, input := range []string{"4\n", "4\n" + strings.Repeat("a", 257) + "\n"} {
		v := &vmessInstallation{}
		var output bytes.Buffer
		Run(t.Context(), nil, strings.NewReader(input), &output, &output, v, nil)
		if v.hostname != "" || len(v.confirmations) != 0 || len(v.actions) != 1 {
			t.Fatal("invalid hostname input reached setup")
		}
	}
}
