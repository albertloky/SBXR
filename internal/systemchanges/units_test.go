package systemchanges_test

import (
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestRecoveryUnitRunsThePrivateRollbackBeforeManagedServices(t *testing.T) {
	unit := systemchanges.SystemdUnits()["sbxr-recovery.service"]
	for _, required := range []string{"After=network-online.target", "Before=xray.service sing-box.service cloudflared.service sbxr-subscription.service", "ExecStart=/usr/local/bin/sbxr private recover"} {
		if !strings.Contains(unit, required) {
			t.Fatalf("recovery unit omitted %q: %s", required, unit)
		}
	}
}
