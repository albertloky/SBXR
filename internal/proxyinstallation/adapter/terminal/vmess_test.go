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
	return proxyinstallation.Review{Prepared: &proxyinstallation.PreparedAction{}, Plan: []string{"VMess origin for " + hostname, "Selected tunnel ID: 12345678-1234-4234-8234-123456789abc"}}
}

func TestMenuReviewsVMessHostnameBeforeConfirmation(t *testing.T) {
	for _, answer := range []string{"y", "n", "", "c"} {
		t.Run("answer="+answer, func(t *testing.T) {
			v := &vmessInstallation{}
			var output bytes.Buffer
			if code := Run(t.Context(), nil, strings.NewReader("1\n2\n\ntunnel.example.com\n"+answer+"\n0\n"), &output, &output, v, nil); code != 0 {
				t.Fatal("menu failed")
			}
			if v.hostname != "tunnel.example.com" || len(v.actions) != 3 || v.actions[1] != proxyinstallation.StartVMessSetupAction {
				t.Fatal("VMess review was not wired correctly")
			}
			if answer == "y" && !reflect.DeepEqual(v.confirmations, []proxyinstallation.Confirmation{proxyinstallation.Approved}) || answer != "y" && len(v.confirmations) != 0 {
				t.Fatal("only explicit Apply may execute")
			}
			text := output.String()
			if !strings.Contains(text, "VMess origin for tunnel.example.com") || strings.Index(text, "VMess origin for tunnel.example.com") > strings.Index(text, "Apply setup? [y/N]") {
				t.Fatal("confirmation preceded review")
			}
			if !strings.Contains(text, "Selected tunnel ID: 12345678-1234-4234-8234-123456789abc") || strings.Index(text, "Selected tunnel ID:") > strings.Index(text, "Apply setup? [y/N]") {
				t.Fatal("confirmation omitted the reviewed tunnel ID")
			}
			for _, guidance := range []string{"your own Cloudflare account", "domain is a name you own", "tunnel connects that hostname", "dedicated unused", "leave route path blank", "/etc/cloudflared/sbxr.token", "never paste it here", "do not overwrite it", "never account API credentials", "sbxr-tunnel.service"} {
				if !strings.Contains(text, guidance) {
					t.Fatalf("guide omitted %q", guidance)
				}
			}
		})
	}
}

func TestWizardCancelAndEOFNeverPrepareOrExecuteSetup(t *testing.T) {
	for _, input := range []string{"1\nc\n", "1\n2\nc\n", "1\n2\n\nc\n", "1\n", "1\n2\n", "1\n2\n\n", "1\n2\n\n" + strings.Repeat("a", 257) + "\nc\n"} {
		v := &vmessInstallation{}
		var output bytes.Buffer
		if code := Run(t.Context(), nil, strings.NewReader(input), &output, &output, v, nil); code != 0 || v.hostname != "" || len(v.confirmations) != 0 {
			t.Fatalf("Cancel/EOF reached setup: code=%d installation=%+v", code, v)
		}
		for _, action := range v.actions {
			if action != proxyinstallation.StatusAction {
				t.Fatal("Cancel/EOF reached preparation")
			}
		}
	}
}
