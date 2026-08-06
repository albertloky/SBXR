package certificatelifecycle_test

import (
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
)

func TestSystemdUnitsOwnOnePersistentRandomizedTwiceDailyRenewal(t *testing.T) {
	units, err := certificatelifecycle.SystemdUnits()
	if err != nil || len(units) != 2 || units["sbxr-certificate-renewal.service"] == "" || strings.Count(units["sbxr-certificate-renewal.timer"], "OnCalendar=") != 1 || !strings.Contains(units["sbxr-certificate-renewal.timer"], "00,12:00:00") || !strings.Contains(units["sbxr-certificate-renewal.timer"], "RandomizedDelaySec=") || !strings.Contains(units["sbxr-certificate-renewal.timer"], "Persistent=true") {
		t.Fatalf("persistent renewal units = %+v, %v", units, err)
	}
}
