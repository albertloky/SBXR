package proxyinstallation

import (
	"context"
	"fmt"
	"slices"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func (module *installedInterface) ownershipProblem(ctx context.Context, review Review, installed softwarelifecycle.ReleaseIdentity, installedReady bool, lock, ownership, detail, correction string) Review {
	review.Status = ProblemDetected
	review.LegalActions = []Action{ViewDetailsAction}
	review.Result = Result{Status: ProblemDetected, Message: "A proxy problem was detected. View details before continuing.", Code: StatusProblemDetected}
	review.Details = module.problemDetails(ctx, installed, installedReady, ProblemDetected, lock, ownership, detail, correction)
	if installedReady {
		review.Version = installed.Tag
	}
	return review
}

func (module *installedInterface) problemDetails(ctx context.Context, installed softwarelifecycle.ReleaseIdentity, installedReady bool, status Status, lock, ownership, detail, correction string) []string {
	inspection := module.host.Inspect(ctx, slices.Clone(footprint))
	facts := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, nil, "", "")
	configurationPresent := resourcePresent(inspection.Resources, "/etc/sing-box")
	overrides := &detailOverrides{
		direction: "Unavailable", lock: lock, ownership: ownership,
		clientIdentity: present(configurationPresent), publicEndpoint: "Unavailable",
		destination: "Unavailable", serverName: "Unavailable",
	}
	details := inspectionDetails(installed, installedReady, status, inspection, &facts, overrides, false)
	return append(details, "Detected mismatch: "+detail, "Safe correction: "+correction)
}

func ownedDetails(installed softwarelifecycle.ReleaseIdentity, installedReady bool, status Status, record ownershipRecord, facts hostadapter.RunningInspection, lock string) []string {
	version, release := "Unavailable", "Unavailable"
	if installedReady {
		version = installed.Tag
		release = fmt.Sprintf("%s %s %s %s", installed.Repository, installed.Tag, installed.Commit, installed.IndexSHA256)
	}
	details := []string{
		"SBXR version: " + version,
		"Release Identity: " + release,
		"Ubuntu: " + ubuntu(facts),
		"Proxy Installation Status: " + string(status),
		"Required unfinished direction: " + string(record.Direction),
		"Mutation lock: " + lock,
		fmt.Sprintf("Ownership Record: Valid; phase %s; cleanup checkpoint %d", record.Phase, record.CleanupCheckpoint),
		"Proxy Package Identity: " + proxyPackageIdentity() + "; " + observationMatch(all(facts.APTKey, facts.APTSource, facts.Package)),
		"Package hold: " + observationPresence(facts.Hold),
		"Protected configuration identity: /etc/sing-box/config.json SHA-256 " + record.ConfigurationSHA256 + "; " + observationMatch(facts.Configuration),
		"Packaged validation result: " + observationAcceptance(facts.Validation),
		"systemd unit provenance: /usr/lib/systemd/system/sing-box.service from sing-box; " + observationMatch(facts.ServiceProvenance),
		"Service enabled: " + observationYesNo(facts.ServiceEnabled),
		"Service active: " + observationYesNo(facts.ServiceActive),
		"Expected public listener ownership: sing-box on TCP " + record.PublicIPv4 + ":443; " + observationMatch(facts.Listener),
		"Public endpoint: " + record.PublicIPv4 + ":443",
		"Selected destination: " + record.DestinationAddress,
		"Server name: " + record.DestinationName,
		"Client Identity: " + present(facts.Configuration.Accepted),
		"Running is local VPS truth only; outside-client traffic is not claimed.",
	}
	if status != ProblemDetected {
		return details
	}
	checks := []struct {
		fact        hostadapter.Observation
		unavailable string
		accepted    bool
		mismatch    string
		correction  string
		observe     string
	}{
		{facts.Host, "Ubuntu version and architecture", facts.Host.Accepted, "the host is not Ubuntu 24.04 amd64", "Use the V3 installation only on Ubuntu Server 24.04 amd64, then inspect again.", "Restore read-only access to /etc/os-release, then inspect again."},
		{facts.PublicIPv4Matches, "public IPv4", facts.PublicIPv4Matches.Accepted, "the current public IPv4 does not match the Ownership Record", "Restore the recorded public IPv4 to this VPS, then inspect again.", "Restore HTTPS access to https://api.ipify.org, then inspect again."},
		{facts.Ownership, "Ownership Record", facts.Ownership.Accepted, "the Ownership Record changed during inspection", "Restore the exact valid Ownership Record checkpoint, then inspect again.", "Restore read-only access to /var/lib/sbxr/proxy-ownership.json, then inspect again."},
		{facts.TransactionFilesAbsent, "transaction files", facts.TransactionFilesAbsent.Accepted, "unfinished transaction material is present after Running", "Remove only the proved V3 transaction files, then inspect again.", "Restore read-only access to the four fixed V3 transaction paths, then inspect again."},
		{facts.APTKey, "APT signing key", facts.APTKey.Accepted, "the SagerNet signing key identity does not match", "Restore /etc/apt/keyrings/sagernet.asc from the qualified package identity, then inspect again.", "Restore read-only access to /etc/apt/keyrings/sagernet.asc, then inspect again."},
		{facts.APTSource, "APT source", facts.APTSource.Accepted, "the SagerNet APT source identity does not match", "Restore /etc/apt/sources.list.d/sagernet.sources to the exact qualified source, then inspect again.", "Restore read-only access to /etc/apt/sources.list.d/sagernet.sources, then inspect again."},
		{facts.Package, "proxy package", facts.Package.Accepted, "the sing-box package identity does not match", "Restore sing-box 1.13.19 amd64 from the qualified DEB, then inspect again.", "Restore working dpkg-query inspection for sing-box, then inspect again."},
		{facts.Hold, "package hold", facts.Hold.Accepted, "the sing-box package hold is absent", "Apply the package hold to sing-box 1.13.19, then inspect again.", "Restore working apt-mark inspection for sing-box, then inspect again."},
		{facts.PackageIdentity, "package user and group", facts.PackageIdentity.Accepted, "the sing-box user or group identity does not match", "Restore the package-created sing-box user and group ownership, then inspect again.", "Restore working getent inspection for the sing-box user and group, then inspect again."},
		{facts.Configuration, "protected configuration", facts.Configuration.Accepted, "the protected configuration identity does not match", "Restore /etc/sing-box/config.json with the recorded SHA-256 and protected ownership, then inspect again.", "Restore read-only access to /etc/sing-box/config.json, then inspect again."},
		{facts.State, "protected state", facts.State.Accepted, "the protected sing-box state identity does not match", "Restore /var/lib/sing-box with the package-created sing-box ownership and native systemd mode 0755, then inspect again.", "Restore read-only access to /var/lib/sing-box, then inspect again."},
		{facts.Validation, "packaged validation", facts.Validation.Accepted, "the packaged configuration validation was refused", "Restore the recorded protected configuration until packaged sing-box check accepts it, then inspect again.", "Restore execution of the packaged sing-box check command, then inspect again."},
		{facts.ServiceProvenance, "systemd unit provenance", facts.ServiceProvenance.Accepted, "sing-box.service does not have package provenance", "Restore /usr/lib/systemd/system/sing-box.service from sing-box 1.13.19, then inspect again.", "Restore working dpkg-query provenance inspection for sing-box.service, then inspect again."},
		{facts.ServiceEnabled, "service enabled state", facts.ServiceEnabled.Accepted, "sing-box.service is not enabled", "Enable the package-owned sing-box.service, then inspect again.", "Restore working systemctl enabled-state inspection for sing-box.service, then inspect again."},
		{facts.ServiceActive, "service active state", facts.ServiceActive.Accepted, "sing-box.service is not active", "Start sing-box.service from the exact installed package, then inspect again.", "Restore working systemctl active-state inspection for sing-box.service, then inspect again."},
		{facts.Listener, "public listener ownership", facts.Listener.Accepted, "TCP port 443 is not owned by the expected sing-box service", "Restore the sing-box listener on the recorded public endpoint, then inspect again.", "Restore working ss inspection for TCP port 443, then inspect again."},
	}
	for _, check := range checks {
		if !check.fact.Observed {
			details = append(details, "Detected mismatch: "+check.unavailable+" could not be inspected", "Safe correction: "+check.observe)
		} else if !check.accepted {
			details = append(details, "Detected mismatch: "+check.mismatch, "Safe correction: "+check.correction)
		}
	}
	return details
}

func match(ok bool) string {
	if ok {
		return "Matches"
	}
	return "Mismatch"
}

func present(ok bool) string {
	if ok {
		return "Present"
	}
	return "Absent"
}

func accepted(ok bool) string {
	if ok {
		return "Accepted"
	}
	return "Refused"
}

func yesNo(ok bool) string {
	if ok {
		return "Yes"
	}
	return "No"
}

type detailOverrides struct {
	direction, lock, ownership, clientIdentity string
	publicEndpoint, destination, serverName    string
}

func inspectionDetails(installed softwarelifecycle.ReleaseIdentity, installedReady bool, status Status, inspection hostadapter.Inspection, facts *hostadapter.RunningInspection, overrides *detailOverrides, reportResourceMismatches bool) []string {
	version, identity := "Unavailable", "Unavailable"
	if installedReady {
		version = installed.Tag
		identity = fmt.Sprintf("%s %s %s %s", installed.Repository, installed.Tag, installed.Commit, installed.IndexSHA256)
	}
	ownership := "Absent"
	if slices.ContainsFunc(inspection.Resources, func(resource hostadapter.Resource) bool {
		return resource.Name == "/var/lib/sbxr/proxy-ownership.json" && resource.Present
	}) {
		ownership = "Present"
	}
	direction, lock := "none", "Available"
	clientIdentity, publicEndpoint := "Absent", "Absent"
	destination, serverName := "Absent", "Absent"
	if overrides != nil {
		direction, lock, ownership = overrides.direction, overrides.lock, overrides.ownership
		clientIdentity, publicEndpoint = overrides.clientIdentity, overrides.publicEndpoint
		destination, serverName = overrides.destination, overrides.serverName
	}
	details := []string{
		"SBXR version: " + version,
		"Release Identity: " + identity,
		"Proxy Installation Status: " + string(status),
		"Required unfinished direction: " + direction,
		"Mutation lock: " + lock,
		"Ownership Record: " + ownership,
		"Client Identity: " + clientIdentity,
	}
	if facts != nil {
		configuration := resourcePresent(inspection.Resources, "/etc/sing-box")
		listener := resourcePresent(inspection.Resources, "443")
		packagePresent := resourcePresent(inspection.Resources, hostSetupSpec.PackageName)
		details = slices.Insert(details, 2,
			"Ubuntu: "+ubuntu(*facts),
		)
		details = append(details,
			"Proxy Package Identity: "+proxyPackageIdentity()+"; "+present(packagePresent),
			"Package hold: "+observationPresence(facts.Hold),
			"Protected configuration identity: "+present(configuration),
			"Packaged validation result: "+validationState(facts, configuration),
			"systemd unit provenance: "+observationPresence(facts.ServiceProvenance),
			"Service enabled: "+observationYesNo(facts.ServiceEnabled),
			"Service active: "+observationYesNo(facts.ServiceActive),
			"Expected public listener ownership: "+listenerState(facts, listener),
			"Public endpoint: "+publicEndpoint,
			"Selected destination: "+destination,
			"Server name: "+serverName,
		)
	}
	if !reportResourceMismatches {
		return details
	}
	for _, resource := range inspection.Resources {
		if !resource.Observed {
			details = append(details, "Detected mismatch: "+resource.Name+" could not be inspected", "Safe correction: Restore read-only inspection of "+resource.Name+", then inspect again.")
		} else if resource.Present {
			details = append(details, "Detected mismatch: "+resource.Name+" is present", "Safe correction: Remove only the conflicting "+resource.Name+" resource after proving it is not Owner data, then inspect again.")
		}
	}
	return details
}

func resourcePresent(resources []hostadapter.Resource, name string) bool {
	return slices.ContainsFunc(resources, func(resource hostadapter.Resource) bool { return resource.Name == name && resource.Present })
}

func validationState(facts *hostadapter.RunningInspection, applicable bool) string {
	if !applicable {
		return "Not applicable"
	}
	return observationAcceptance(facts.Validation)
}

func listenerState(facts *hostadapter.RunningInspection, present bool) string {
	if !facts.Listener.Observed {
		return "Unavailable"
	}
	if !present {
		return "Absent"
	}
	return match(facts.Listener.Accepted)
}

func observationPresence(fact hostadapter.Observation) string {
	if !fact.Observed {
		return "Unavailable"
	}
	return present(fact.Accepted)
}

func ubuntu(facts hostadapter.RunningInspection) string {
	if !facts.Host.Observed {
		return "Unavailable"
	}
	return facts.OSVersion + " " + facts.Architecture
}

func observationYesNo(fact hostadapter.Observation) string {
	if !fact.Observed {
		return "Unavailable"
	}
	return yesNo(fact.Accepted)
}

func observationMatch(fact hostadapter.Observation) string {
	if !fact.Observed {
		return "Unavailable"
	}
	return match(fact.Accepted)
}

func observationAcceptance(fact hostadapter.Observation) string {
	if !fact.Observed {
		return "Unavailable"
	}
	return accepted(fact.Accepted)
}

func all(facts ...hostadapter.Observation) hostadapter.Observation {
	combined := hostadapter.Observation{Observed: true, Accepted: true}
	for _, fact := range facts {
		combined.Observed = combined.Observed && fact.Observed
		combined.Accepted = combined.Accepted && fact.Accepted
	}
	return combined
}

func setupPlan(facts hostadapter.Preflight, selected hostadapter.Destination) []string {
	return []string{
		"Host: Ubuntu 24.04 amd64",
		"Public endpoint: " + facts.PublicIPv4 + ":443",
		"Port preflight: " + facts.PublicIPv4 + ":443 accepted a local bind; SBXR does not claim firewall or provider reachability before setup",
		"REALITY destination: " + selected.Address + " with server_name " + selected.ServerName,
		"Proxy Package Identity: " + proxyPackageIdentity(),
		"APT resources: /etc/apt/keyrings/sagernet.asc and /etc/apt/sources.list.d/sagernet.sources",
		"Protected resources: /etc/sing-box/config.json, /var/lib/sing-box, sing-box.service, and the package-created sing-box user and group",
		"Ownership Record: /var/lib/sbxr/proxy-ownership.json",
		"Identity: one generated Client Identity; no Owner-supplied proxy value is accepted",
		"Secret boundary: the VLESS UUID is disclosed only in an explicitly requested Client Configuration; the REALITY private key is an Infrastructure Secret and is never disclosed",
		"Owned resource groups: exact repository key and source, qualified package and hold, protected configuration and state, service state, and package-created identity",
		"SBXR will not change SSH, firewall, routing, or provider settings. It preserves every unrelated host resource.",
	}
}

func completeRemovalPlan(record *ownershipRecord) []string {
	groups := "No V3 proxy resource is present; SBXR executable and Installed Record only"
	if record != nil {
		groups = "Ownership Record; exact proxy package and hold; protected configuration and state; package-owned service, user, and group; APT source and signing key; SBXR executable and Installed Record"
	}
	plan := []string{
		"Complete removal deletes SBXR, proxy credentials, and every proved V3-owned resource from this VPS.",
		"Proved removal inventory: " + groups + ".",
		"Proved SBXR executable: /usr/local/bin/sbxr",
		"Proved Installed Record: /var/lib/sbxr/installed.json",
		"Outside copies of the Client Configuration cannot be deleted by SBXR.",
		"SBXR preserves SSH, firewall, routing, forwarding, provider settings, shared package-manager state, and every unrelated resource.",
		"There is no adoption, repair, recursive deletion, force path, or Owner override.",
		"Exact confirmation required: REMOVE SBXR",
	}
	if record != nil {
		for _, resource := range record.Resources {
			plan = append(plan, "Proved V3-owned resource: "+resource)
		}
	}
	return plan
}

func removalCorrection(facts hostadapter.RemovalInspection) string {
	checks := []struct {
		fact hostadapter.Observation
		name string
	}{
		{facts.PackageLocks, "Ubuntu package locks"},
		{facts.ConfigurationEntries, "/etc/sing-box directory membership"},
		{facts.StateEntries, "/var/lib/sing-box directory membership"},
		{facts.IdentityExclusive, "sing-box user and group ownership"},
		{facts.ProcessExclusive, "sing-box process identity"},
		{facts.ServiceSafe, "sing-box service, process, and listener state"},
	}
	for _, check := range checks {
		if !check.fact.Observed {
			return "Restore read-only inspection of " + check.name + ", then review Complete removal again."
		}
		if !check.fact.Accepted {
			return "Remove the unproved use or restore the exact proved " + check.name + ", then review Complete removal again."
		}
	}
	return "Restore every changed V3 ownership, package, service, process, listener, directory, and system fact, then review Complete removal again."
}

func removalMismatchDetails(facts hostadapter.RemovalInspection) []string {
	checks := []struct {
		fact       hostadapter.Observation
		mismatch   string
		correction string
		observe    string
	}{
		{facts.PackageLocks, "Ubuntu package locks are in use", "Wait for APT and dpkg to finish, then review Complete removal again.", "Restore safe inspection of every Ubuntu package lock, then inspect again."},
		{facts.ConfigurationEntries, "/etc/sing-box has changed metadata or unexpected directory entries", "Restore the exact root-owned mode-0755 directory containing only config.json, then inspect again.", "Restore read-only directory and metadata inspection of /etc/sing-box, then inspect again."},
		{facts.StateEntries, "/var/lib/sing-box has changed metadata or unexpected directory entries", "Remove only unproved entries after preserving Owner data, and restore the exact empty package-owned native systemd mode-0755 state directory, then inspect again.", "Restore read-only directory and metadata inspection of /var/lib/sing-box, then inspect again."},
		{facts.IdentityExclusive, "the sing-box user or group owns resources outside the proved V3 paths", "Reassign or preserve every outside resource before reviewing Complete removal again.", "Restore complete local ownership inspection for the sing-box user and group, then inspect again."},
		{facts.ProcessExclusive, "the sing-box user, group, or process name is used by an outside process", "Stop or reassign only the outside process after proving its ownership, then inspect again.", "Restore complete process inspection for the sing-box user, group, and process name, then inspect again."},
		{facts.ServiceSafe, "the service, process, or TCP 443 listener is neither exact Running state nor a harmless stopped reduction", "Stop the outside process or listener, or restore the exact package-owned sing-box service, then inspect again.", "Restore systemd, process, and TCP 443 listener inspection, then inspect again."},
	}
	var details []string
	for _, check := range checks {
		if !check.fact.Observed {
			details = append(details, "Detected mismatch: the Complete removal fact could not be inspected", "Safe correction: "+check.observe)
		} else if !check.fact.Accepted {
			details = append(details, "Detected mismatch: "+check.mismatch, "Safe correction: "+check.correction)
		}
	}
	return details
}

func proxyPackageIdentity() string {
	return fmt.Sprintf("https://deb.sagernet.org/; signing-key bytes SHA-256 %s; %s %s %s; DEB %d bytes; DEB SHA-256 %s", hostSetupSpec.APTKeySHA256, hostSetupSpec.PackageName, hostSetupSpec.PackageVersion, hostSetupSpec.Architecture, hostSetupSpec.PackageSize, hostSetupSpec.PackageSHA256)
}
