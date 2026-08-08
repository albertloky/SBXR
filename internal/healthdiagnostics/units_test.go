package healthdiagnostics_test

import (
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
)

func TestScheduledHealthUnitsUseOneWeeklyPersistentCheckEntry(t *testing.T) {
	units, err := healthdiagnostics.SystemdUnits()
	service, timer := units["sbxr-health-check.service"], units["sbxr-health-check.timer"]
	if err != nil || len(units) != 2 || strings.Count(service, "ExecStart=/usr/local/bin/sbxr private health-check") != 1 || strings.Contains(service, "ExecStartPre=") || strings.Contains(service, "ExecStartPost=") {
		t.Fatalf("scheduled service = %q, %v", service, err)
	}
	if strings.Count(timer, "OnCalendar=weekly") != 1 || strings.Count(timer, "Persistent=true") != 1 || strings.Count(timer, "Unit=sbxr-health-check.service") != 1 {
		t.Fatalf("scheduled timer = %q", timer)
	}
	for _, competing := range []string{"OnActiveSec=", "OnBootSec=", "OnUnitActiveSec=", "OnUnitInactiveSec=", "RandomizedDelaySec="} {
		if strings.Contains(timer, competing) {
			t.Fatalf("scheduled timer contains competing trigger %q: %q", competing, timer)
		}
	}
}
