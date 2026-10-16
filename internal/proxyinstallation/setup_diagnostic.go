package proxyinstallation

import (
	"fmt"
	"reflect"
	"strings"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// Keep the existing refusal code and correction boundary; never format raw facts.
func setupDiagnosticRefused(status Status, check, code, expected, observed, correction string) Result {
	return refused(status, check, fmt.Sprintf("Diagnostic: %s; expected=%s; observed=%s. %s", code, expected, observed, correction))
}

func setupPreflightRefused(status Status, facts hostadapter.Preflight, check, correction string) Result {
	code, expected, observed := "FACTS", "accepted setup preflight", "preflight refused"
	switch check {
	case "Proxy footprint inspection", "Clean proxy footprint":
		code, expected = "FOOTPRINT", "every fixed proxy resource observed absent"
		observed = fmt.Sprintf("all_observed=%t, any_present=%t, resource_count=%d", resourcesObserved(facts.Resources), resourcesPresent(facts.Resources), len(facts.Resources))
		for _, resource := range facts.Resources {
			if resource.Observed && !resource.Present {
				continue
			}
			name := "unrecognized resource"
			for _, known := range footprint {
				if resource.Kind == known.Kind && resource.Name == known.Name {
					name = known.Name
					break
				}
			}
			observed += fmt.Sprintf(", resource=%s, inspected=%t, present=%t", name, resource.Observed, resource.Present)
			break
		}
	case "Ubuntu version":
		code, expected, observed = "OS", "Ubuntu 24.04", fmt.Sprintf("ubuntu=%t, version_24.04=%t", facts.OSID == "ubuntu", facts.OSVersion == "24.04")
	case "Architecture":
		code, expected, observed = "ARCHITECTURE", "amd64", "amd64=false"
	case "Public IPv4":
		code, expected, observed = "IPV4", "valid public IPv4 from api.ipify.org", "public IPv4 missing or invalid"
	case "Synchronized clock":
		code, expected, observed = "CLOCK", "NTPSynchronized=yes", "synchronized=false or unobserved"
	case "Public TCP port 443":
		code, expected, observed = "TCP443", "successful bind and close on public TCP 443", "bind or close failed"
	case "SBXR mutation lock":
		code, expected, observed = "MUTATION-LOCK", "available protected SBXR lock", "busy or unsafe lock"
	case "Ubuntu package locks":
		code, expected, observed = "PACKAGE-LOCKS", "all APT and dpkg locks available", "at least one lock busy or unobservable"
	case "REALITY destination":
		code, expected = "DESTINATION", "accepted destination with DNS/TCP/TLS13/HTTP2/certificate=true"
		var probes []string
		for _, known := range destinations {
			probe := known.Address + " unobserved"
			for _, fact := range facts.Destinations {
				if fact.Destination == known {
					probe = fmt.Sprintf("%s DNS=%t TCP=%t TLS13=%t HTTP2=%t certificate=%t", known.Address, fact.DNS, fact.TCP, fact.TLS13, fact.HTTP2, fact.CertificateName)
					break
				}
			}
			probes = append(probes, probe)
		}
		observed = strings.Join(probes, "; ")
	}
	return setupDiagnosticRefused(status, check, "SETUP-PREFLIGHT-"+code, expected, observed, correction)
}

func setupLifecycleState(state softwarelifecycle.LifecycleState) string {
	switch state {
	case softwarelifecycle.Ready, softwarelifecycle.RecoveryRequiredState, softwarelifecycle.UpdateInProgress:
		return string(state)
	default:
		return "unavailable"
	}
}

func changedSetupFact(before, after hostadapter.Preflight) string {
	switch {
	case !reflect.DeepEqual(before.Resources, after.Resources):
		return "Proxy footprint observations changed"
	case before.OSID != after.OSID || before.OSVersion != after.OSVersion:
		return "Ubuntu version changed"
	case before.Architecture != after.Architecture:
		return "Architecture changed"
	case before.PublicIPv4 != after.PublicIPv4:
		return "Public IPv4 changed"
	case before.ClockSynchronized != after.ClockSynchronized:
		return "Synchronized clock changed"
	case before.TCP443Available != after.TCP443Available:
		return "Public TCP port 443 changed"
	case before.MutationLockAvailable != after.MutationLockAvailable:
		return "SBXR mutation lock changed"
	case before.PackageLocksAvailable != after.PackageLocksAvailable:
		return "Ubuntu package locks changed"
	case !reflect.DeepEqual(before.Destinations, after.Destinations):
		return "REALITY destination observations changed"
	default:
		return "Preflight facts changed"
	}
}
