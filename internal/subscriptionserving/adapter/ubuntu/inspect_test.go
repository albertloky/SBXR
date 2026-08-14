package ubuntu

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/subscriptionserving"
)

func TestInspectorSuppliesExactUbuntuRuntimeFacts(t *testing.T) {
	var observed subscriptionserving.RuntimeObservation
	inspector := Inspector{
		run: func(_ context.Context, name string, arguments ...string) (string, error) {
			command := name + " " + strings.Join(arguments, " ")
			switch command {
			case "/usr/bin/systemctl cat sbxr-subscription.service":
				return "# /etc/systemd/system/sbxr-subscription.service\n" + subscriptionserving.ServiceUnit(), nil
			case "/usr/bin/systemctl show --property=User --value sbxr-subscription.service", "/usr/bin/systemctl show --property=Group --value sbxr-subscription.service":
				return "root\n", nil
			case "/usr/bin/systemctl show --property=ActiveState --value sbxr-subscription.service":
				return "active\n", nil
			case "/usr/bin/systemctl show --property=MainPID --value sbxr-subscription.service":
				return "42\n", nil
			case "/usr/bin/ps -o uid= -o gid= -p 42":
				return "0 0\n", nil
			case "/usr/bin/ss -H -ltnp sport = :10443":
				return `LISTEN 0 4096 198.51.100.10:10443 0.0.0.0:* users:(("sbxr",pid=42,fd=3))`, nil
			default:
				return "", fmt.Errorf("unexpected command: %s", command)
			}
		},
		inspect: func(value subscriptionserving.RuntimeObservation) subscriptionserving.HealthResult {
			observed = value
			return subscriptionserving.HealthResult{Status: subscriptionserving.Healthy, Code: "SUBSCRIPTION-SERVING-HTTPS"}
		},
	}
	result := inspector.Inspect(t.Context())
	if result.Status != subscriptionserving.Healthy || observed.Unit != subscriptionserving.ServiceUnit() || observed.User != "root" || observed.Group != "root" || observed.ActiveState != "active" || observed.MainPID != 42 || observed.ListenerPID != 42 || observed.ProcessUID != 0 || observed.ProcessGID != 0 || observed.Listener.String() != "198.51.100.10:10443" {
		t.Fatalf("Inspect() = %+v, observation=%+v", result, observed)
	}
}

func TestInspectorRefusesAmbiguousListenerFacts(t *testing.T) {
	inspected := false
	inspector := Inspector{
		run: func(_ context.Context, name string, arguments ...string) (string, error) {
			if name == "/usr/bin/ss" {
				return "LISTEN 0 4096 198.51.100.10:10443 0.0.0.0:* users:((\"sbxr\",pid=42,fd=3))\nLISTEN 0 4096 [::]:10443 [::]:* users:((\"sbxr\",pid=42,fd=4))", nil
			}
			command := strings.Join(arguments, " ")
			switch command {
			case "cat sbxr-subscription.service":
				return subscriptionserving.ServiceUnit(), nil
			case "show --property=MainPID --value sbxr-subscription.service":
				return "42", nil
			case "show --property=ActiveState --value sbxr-subscription.service":
				return "active", nil
			case "-o uid= -o gid= -p 42":
				return "0 0", nil
			default:
				return "root", nil
			}
		},
		inspect: func(subscriptionserving.RuntimeObservation) subscriptionserving.HealthResult {
			inspected = true
			return subscriptionserving.HealthResult{Status: subscriptionserving.Healthy}
		},
	}
	if result := inspector.Inspect(t.Context()); result.Status != subscriptionserving.Unknown || inspected {
		t.Fatalf("ambiguous listener = %+v, inspected=%v", result, inspected)
	}
}
