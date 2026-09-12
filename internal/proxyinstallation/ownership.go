package proxyinstallation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type unfinishedDirection string

const (
	cleanupRequired unfinishedDirection = "cleanup required"
	setupRequired   unfinishedDirection = "setup required"
	noDirection     unfinishedDirection = "none"
	removalRequired unfinishedDirection = "removal required"
)

type setupPhase string

const (
	ownershipRecorded      setupPhase = "Ownership recorded"
	aptKeyInstalled        setupPhase = "APT key installed"
	aptSourceInstalled     setupPhase = "APT source installed"
	serviceMasked          setupPhase = "Service masked"
	packageInstalled       setupPhase = "Package installed"
	packageHeld            setupPhase = "Package held"
	stateDirectoryCreated  setupPhase = "State directory created"
	configurationInstalled setupPhase = "Configuration installed"
	configurationValidated setupPhase = "Configuration validated"
	serviceUnmasked        setupPhase = "Service unmasked"
	activationCommitted    setupPhase = "Activation committed"
	serviceEnabled         setupPhase = "Service enabled"
	serviceStarted         setupPhase = "Service started"
	runningPhase           setupPhase = "Running"
	removalCommitted       setupPhase = "Removal committed"
)

type ownershipRecord struct {
	Schema                   int                                        `json:"schema"`
	Phase                    setupPhase                                 `json:"phase"`
	Direction                unfinishedDirection                        `json:"unfinished_direction"`
	Release                  softwarelifecycle.ReleaseIdentity          `json:"release_identity"`
	Package                  string                                     `json:"proxy_package_identity"`
	PublicIPv4               string                                     `json:"public_ipv4"`
	DestinationAddress       string                                     `json:"destination_address"`
	DestinationName          string                                     `json:"destination_server_name"`
	ConfigurationSHA256      string                                     `json:"configuration_sha256"`
	Resources                []string                                   `json:"permitted_resources"`
	CleanupCheckpoint        int                                        `json:"cleanup_checkpoint"`
	RemovalCheckpoint        int                                        `json:"removal_checkpoint"`
	ResourceCreatingReleases []softwarelifecycle.ReleaseIdentity        `json:"resource_creating_releases,omitempty"`
	FinishingRelease         *softwarelifecycle.ReleaseIdentity         `json:"finishing_release_identity,omitempty"`
	Serving                  *hostadapter.ServingAuthority              `json:"serving,omitempty"`
	Renewal                  *hostadapter.RenewalAuthority              `json:"renewal,omitempty"`
	Activation               *certificateActivation                     `json:"certificate_activation,omitempty"`
	Enablement               *subscriptionEnablement                    `json:"subscription_enablement,omitempty"`
	Rotation                 *subscriptionRotation                      `json:"subscription_rotation,omitempty"`
	Repair                   *subscriptionRepair                        `json:"subscription_repair,omitempty"`
	SubscriptionCompromised  bool                                       `json:"subscription_compromised,omitempty"`
	SubscriptionResources    *hostadapter.SubscriptionResourceAuthority `json:"subscription_resources,omitempty"`
	Startup                  *hostadapter.ProxyStartupAuthority         `json:"proxy_startup,omitempty"`
	ClientRotation           *clientIdentityRotation                    `json:"client_identity_rotation,omitempty"`
}

type clientIdentityRotation struct {
	OperationID  string                                  `json:"operation_id"`
	Direction    string                                  `json:"direction"`
	Effects      []string                                `json:"effects"`
	Completed    []string                                `json:"completed_effects"`
	Source       string                                  `json:"source_configuration_sha256"`
	Target       string                                  `json:"target_configuration_sha256"`
	Checkpoint   clientIdentityRotationCheckpoint        `json:"checkpoint"`
	Subscription *hostadapter.ClientIdentitySubscription `json:"subscription,omitempty"`
}

type clientIdentityRotationCheckpoint string

const (
	clientRotationAuthorized           clientIdentityRotationCheckpoint = "rotation authorized"
	clientRotationTargetPrepared       clientIdentityRotationCheckpoint = "target prepared"
	clientRotationIntegrationPublished clientIdentityRotationCheckpoint = "startup integration published"
	clientRotationReloaded             clientIdentityRotationCheckpoint = "systemd reloaded"
	clientRotationRouteVerified        clientIdentityRotationCheckpoint = "startup route verified"
	clientRotationGated                clientIdentityRotationCheckpoint = "cutover gated"
	clientRotationStopped              clientIdentityRotationCheckpoint = "source stopped"
	clientRotationQuiescent            clientIdentityRotationCheckpoint = "source quiescent"
	clientRotationRevoked              clientIdentityRotationCheckpoint = "source revoked"
	clientRotationTargetPublished      clientIdentityRotationCheckpoint = "target published"
	clientRotationTargetStarted        clientIdentityRotationCheckpoint = "target started"
)

type clientIdentityCheckpointPolicy struct {
	checkpoint      clientIdentityRotationCheckpoint
	effect          string
	targetRequired  bool
	startupRequired bool
	ordinaryStart   bool
	forward         bool
	targetCanonical bool
	verifyRoute     bool
}

func clientIdentityPolicy(checkpoint clientIdentityRotationCheckpoint) (clientIdentityCheckpointPolicy, int, bool) {
	index := slices.IndexFunc(clientIdentityCheckpointPolicies, func(policy clientIdentityCheckpointPolicy) bool { return policy.checkpoint == checkpoint })
	if index < 0 {
		return clientIdentityCheckpointPolicy{}, -1, false
	}
	return clientIdentityCheckpointPolicies[index], index, true
}

type subscriptionEnablement struct {
	Checkpoint       int                                        `json:"checkpoint"`
	LinkID           string                                     `json:"link_id"`
	CredentialSHA256 string                                     `json:"credential_sha256"`
	RecorderID       string                                     `json:"recorder_id"`
	Serving          *hostadapter.ServingAuthority              `json:"serving,omitempty"`
	Renewal          *hostadapter.RenewalAuthority              `json:"renewal,omitempty"`
	Resources        *hostadapter.SubscriptionResourceAuthority `json:"resources,omitempty"`
}

type subscriptionRotation struct {
	OperationID string                         `json:"operation_id"`
	Kind        string                         `json:"kind"`
	Direction   string                         `json:"direction"`
	Effects     []string                       `json:"effects"`
	Completed   []string                       `json:"completed_effects"`
	Source      hostadapter.ServingAuthority   `json:"source"`
	Target      hostadapter.ServingAuthority   `json:"target"`
	Checkpoint  subscriptionRotationCheckpoint `json:"checkpoint"`
}

type subscriptionRotationCheckpoint string

const (
	rotationTargetAuthorized subscriptionRotationCheckpoint = "target authorized"
	rotationStopAuthorized   subscriptionRotationCheckpoint = "stop authorized"
	rotationCommitted        subscriptionRotationCheckpoint = "committed"
)

type certificateActivation struct {
	Source     hostadapter.ServingAuthority    `json:"source"`
	Target     hostadapter.ServingAuthority    `json:"target"`
	Checkpoint certificateActivationCheckpoint `json:"checkpoint"`
}

type certificateActivationCheckpoint string

const (
	activationTargetRecorded certificateActivationCheckpoint = "target recorded"
	activationTargetAccepted certificateActivationCheckpoint = "target accepted"
)

type subscriptionRepair struct {
	OperationID string                        `json:"operation_id"`
	Kind        string                        `json:"kind"`
	Direction   string                        `json:"direction"`
	Correction  subscriptionRepairCorrection  `json:"correction"`
	Effects     []string                      `json:"effects"`
	Completed   []string                      `json:"completed_effects"`
	Checkpoint  subscriptionRepairCheckpoint  `json:"checkpoint"`
	Source      hostadapter.ServingAuthority  `json:"source"`
	Target      *hostadapter.ServingAuthority `json:"target,omitempty"`
}

type subscriptionRepairCorrection string

const (
	repairCertificate subscriptionRepairCorrection = "renew owned certificate"
	repairRuntime     subscriptionRepairCorrection = "restart owned serving runtime"
)

type subscriptionRepairCheckpoint string

const (
	repairPrepared  subscriptionRepairCheckpoint = "prepared"
	repairCommitted subscriptionRepairCheckpoint = "committed"
	repairAccepted  subscriptionRepairCheckpoint = "accepted"
)

func newOwnershipRecord(release softwarelifecycle.ReleaseIdentity, facts hostadapter.Preflight, destination hostadapter.Destination, configuration []byte) ownershipRecord {
	digest := sha256.Sum256(configuration)
	return ownershipRecord{
		Schema: 1, Phase: ownershipRecorded, Direction: cleanupRequired, Release: release,
		Package:    "https://deb.sagernet.org/ sing-box 1.13.19 amd64 24597120 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf",
		PublicIPv4: facts.PublicIPv4, DestinationAddress: destination.Address, DestinationName: destination.ServerName,
		ConfigurationSHA256: hex.EncodeToString(digest[:]),
		Resources:           ownershipResources(hex.EncodeToString(digest[:])),
	}
}

func ownershipBytes(record ownershipRecord) []byte {
	body, _ := json.Marshal(record)
	return append(body, '\n')
}

func newRemovalOwnershipRecord(release softwarelifecycle.ReleaseIdentity) ownershipRecord {
	return ownershipRecord{
		Schema: 1, Phase: removalCommitted, Direction: removalRequired, Release: release,
		Resources: []string{
			"/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-1",
			finalOwnershipPath + " root:root 0600 one-link finalization authority",
			"/usr/local/bin/sbxr exact committed Release Identity",
			"/var/lib/sbxr/installed.json exact committed Release Identity",
		},
	}
}

func decodeOwnership(body []byte) (ownershipRecord, bool) {
	if len(body) > 64<<10 || softwarelifecycle.ValidateUniqueJSON(body) != nil {
		return ownershipRecord{}, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return ownershipRecord{}, false
	}
	for _, name := range []string{"schema", "phase", "unfinished_direction", "release_identity", "proxy_package_identity", "public_ipv4", "destination_address", "destination_server_name", "configuration_sha256", "permitted_resources", "cleanup_checkpoint", "removal_checkpoint"} {
		if len(fields[name]) == 0 {
			return ownershipRecord{}, false
		}
	}
	for name, value := range fields {
		if !slices.Contains([]string{"schema", "phase", "unfinished_direction", "release_identity", "proxy_package_identity", "public_ipv4", "destination_address", "destination_server_name", "configuration_sha256", "permitted_resources", "cleanup_checkpoint", "removal_checkpoint", "resource_creating_releases", "finishing_release_identity", "serving", "renewal", "certificate_activation", "subscription_enablement", "subscription_rotation", "subscription_repair", "subscription_compromised", "subscription_resources", "proxy_startup", "client_identity_rotation"}, name) {
			return ownershipRecord{}, false
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ownershipRecord{}, false
		}
	}
	if raw, exists := fields["serving"]; exists {
		var serving map[string]json.RawMessage
		var hashes []string
		if json.Unmarshal(raw, &serving) != nil || len(serving) != 4 || json.Unmarshal(serving["certificate_sha256"], &hashes) != nil || len(hashes) != 4 {
			return ownershipRecord{}, false
		}
		for _, name := range []string{"link_id", "credential_sha256", "certificate_generation", "certificate_sha256"} {
			if len(serving[name]) == 0 || bytes.Equal(bytes.TrimSpace(serving[name]), []byte("null")) {
				return ownershipRecord{}, false
			}
		}
	}
	if raw, exists := fields["renewal"]; exists {
		var renewal map[string]json.RawMessage
		if json.Unmarshal(raw, &renewal) != nil || len(renewal) != 4 {
			return ownershipRecord{}, false
		}
		for _, name := range []string{"recorder_id", "lineage", "public_ipv4", "invocation"} {
			if len(renewal[name]) == 0 || bytes.Equal(bytes.TrimSpace(renewal[name]), []byte("null")) {
				return ownershipRecord{}, false
			}
		}
	}
	if raw, exists := fields["certificate_activation"]; exists {
		var activation map[string]json.RawMessage
		if json.Unmarshal(raw, &activation) != nil || len(activation) != 3 || len(activation["source"]) == 0 || len(activation["target"]) == 0 || len(activation["checkpoint"]) == 0 {
			return ownershipRecord{}, false
		}
	}
	if raw, exists := fields["subscription_enablement"]; exists {
		var enablement map[string]json.RawMessage
		if json.Unmarshal(raw, &enablement) != nil {
			return ownershipRecord{}, false
		}
		for _, name := range []string{"link_id", "credential_sha256", "recorder_id"} {
			if len(enablement[name]) == 0 || bytes.Equal(bytes.TrimSpace(enablement[name]), []byte("null")) {
				return ownershipRecord{}, false
			}
		}
	}
	if raw, exists := fields["subscription_rotation"]; exists {
		var rotation map[string]json.RawMessage
		if json.Unmarshal(raw, &rotation) != nil || len(rotation["source"]) == 0 || len(rotation["target"]) == 0 || len(rotation["checkpoint"]) == 0 {
			return ownershipRecord{}, false
		}
	}
	if raw, exists := fields["subscription_repair"]; exists {
		var repair map[string]json.RawMessage
		if json.Unmarshal(raw, &repair) != nil || len(repair) < 8 || len(repair) > 9 {
			return ownershipRecord{}, false
		}
		for _, name := range []string{"operation_id", "kind", "direction", "correction", "checkpoint", "source"} {
			if len(repair[name]) == 0 || bytes.Equal(bytes.TrimSpace(repair[name]), []byte("null")) {
				return ownershipRecord{}, false
			}
		}
		for _, name := range []string{"effects", "completed_effects"} {
			if len(repair[name]) == 0 {
				return ownershipRecord{}, false
			}
		}
		for name, value := range repair {
			if !slices.Contains([]string{"operation_id", "kind", "direction", "correction", "effects", "completed_effects", "checkpoint", "source", "target"}, name) || name == "target" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return ownershipRecord{}, false
			}
		}
	}
	if raw, exists := fields["proxy_startup"]; exists {
		var startup map[string]json.RawMessage
		if json.Unmarshal(raw, &startup) != nil || len(startup) != 2 || len(startup["drop_in_sha256"]) == 0 || len(startup["directory_created"]) == 0 {
			return ownershipRecord{}, false
		}
	}
	if raw, exists := fields["client_identity_rotation"]; exists {
		var rotation map[string]json.RawMessage
		if json.Unmarshal(raw, &rotation) != nil || len(rotation) != 7 && len(rotation) != 8 {
			return ownershipRecord{}, false
		}
		for _, name := range []string{"operation_id", "direction", "effects", "completed_effects", "source_configuration_sha256", "target_configuration_sha256", "checkpoint"} {
			if len(rotation[name]) == 0 || bytes.Equal(bytes.TrimSpace(rotation[name]), []byte("null")) {
				return ownershipRecord{}, false
			}
		}
		if raw, exists := rotation["subscription"]; exists {
			var sub map[string]json.RawMessage
			if json.Unmarshal(raw, &sub) != nil || len(sub) != 4 {
				return ownershipRecord{}, false
			}
		}
	}
	if !exactIdentityFields(fields["release_identity"]) {
		return ownershipRecord{}, false
	}
	if finishing, exists := fields["finishing_release_identity"]; exists && !exactIdentityFields(finishing) {
		return ownershipRecord{}, false
	}
	if origins, exists := fields["resource_creating_releases"]; exists {
		var identities []json.RawMessage
		if json.Unmarshal(origins, &identities) != nil {
			return ownershipRecord{}, false
		}
		for _, identity := range identities {
			if !exactIdentityFields(identity) {
				return ownershipRecord{}, false
			}
		}
	}
	var record ownershipRecord
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !validOwnership(record) {
		return ownershipRecord{}, false
	}
	return record, true
}

func exactIdentityFields(body []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != 4 {
		return false
	}
	for _, name := range []string{"Repository", "Tag", "Commit", "IndexSHA256"} {
		var value string
		if json.Unmarshal(fields[name], &value) != nil || value == "" {
			return false
		}
	}
	return true
}

func validOwnership(record ownershipRecord) bool {
	if record.Schema != 1 && record.Schema != 2 || !validReleaseIdentity(record.Release) {
		return false
	}
	if record.Schema == 1 {
		if record.ResourceCreatingReleases != nil || record.FinishingRelease != nil || record.Serving != nil || record.Renewal != nil || record.Activation != nil || record.Enablement != nil || record.Rotation != nil || record.Repair != nil || record.SubscriptionResources != nil || record.Startup != nil || record.ClientRotation != nil {
			return false
		}
	} else {
		if len(record.ResourceCreatingReleases) != len(record.Resources) {
			return false
		}
		for _, release := range record.ResourceCreatingReleases {
			if !validReleaseIdentity(release) {
				return false
			}
		}
		if record.Direction == removalRequired {
			if record.FinishingRelease == nil || !validReleaseIdentity(*record.FinishingRelease) {
				return false
			}
		} else if record.Phase != runningPhase || record.Direction != noDirection || record.FinishingRelease != nil {
			return false
		}
	}
	if record.Serving != nil && (!record.Serving.Valid() || record.Package == "" || record.Phase != runningPhase && record.Phase != removalCommitted) {
		return false
	}
	if record.Renewal != nil && (record.Serving == nil || !record.Renewal.Valid() || record.Renewal.PublicIPv4 != record.PublicIPv4 || record.Phase != runningPhase && record.Phase != removalCommitted) {
		return false
	}
	if record.Activation != nil && (record.Schema != 2 || record.Serving == nil || record.Renewal == nil || record.Direction != noDirection || record.Phase != runningPhase || record.Activation.Checkpoint == activationTargetRecorded && record.Activation.Source != *record.Serving || record.Activation.Checkpoint == activationTargetAccepted && record.Activation.Target != *record.Serving || !validCertificateActivation(*record.Activation)) {
		return false
	}
	if record.Enablement != nil && (record.Schema != 2 || record.Serving != nil || record.Renewal != nil || record.Activation != nil || record.Direction != noDirection && record.Direction != removalRequired || record.Phase != runningPhase && record.Phase != removalCommitted || !validSubscriptionEnablement(*record.Enablement)) {
		return false
	}
	if record.Rotation != nil && (record.Schema != 2 || record.Serving == nil || record.Renewal == nil || record.Enablement != nil || record.Activation != nil || record.Direction != noDirection && record.Direction != removalRequired || record.Phase != runningPhase && record.Phase != removalCommitted || !validSubscriptionRotation(*record.Rotation) || record.Rotation.Checkpoint != rotationCommitted && *record.Serving != record.Rotation.Source || record.Rotation.Checkpoint == rotationCommitted && *record.Serving != record.Rotation.Target) {
		return false
	}
	if record.Repair != nil && (record.Schema != 2 || record.Serving == nil || record.Renewal == nil || record.Enablement != nil || record.Rotation != nil || record.Activation != nil || record.Direction != noDirection && record.Direction != removalRequired || record.Phase != runningPhase && record.Phase != removalCommitted || !validSubscriptionRepair(*record.Repair) || record.Repair.Checkpoint != repairAccepted && *record.Serving != record.Repair.Source || record.Repair.Checkpoint == repairAccepted && (record.Repair.Target == nil || *record.Serving != *record.Repair.Target)) {
		return false
	}
	if record.SubscriptionCompromised && (record.Schema != 2 || record.Serving == nil) {
		return false
	}
	if record.SubscriptionResources != nil && (record.Schema != 2 || !record.SubscriptionResources.Valid() || record.SubscriptionResources.PublicIPv4 != record.PublicIPv4 || record.Serving == nil || record.Renewal == nil) {
		return false
	}
	if record.Startup != nil && (record.Schema != 2 || !record.Startup.Valid() || record.Phase != runningPhase && record.Phase != removalCommitted) {
		return false
	}
	if record.ClientRotation != nil && (record.Schema != 2 || record.Enablement != nil || record.Rotation != nil || record.Repair != nil || record.Activation != nil || record.Direction != noDirection && record.Direction != removalRequired || record.Phase != runningPhase && record.Phase != removalCommitted || !validClientIdentityRotation(*record.ClientRotation, record.Startup, record.ConfigurationSHA256)) {
		return false
	}
	if record.ClientRotation != nil {
		sub := record.ClientRotation.Subscription
		if (sub == nil) != (record.Serving == nil) || sub != nil && (!sub.Valid() || record.Renewal == nil || *record.Serving != sub.Source && *record.Serving != sub.Target) {
			return false
		}
	}
	if record.Direction == removalRequired {
		if record.Phase != removalCommitted || record.CleanupCheckpoint != 0 || record.RemovalCheckpoint < 0 || record.RemovalCheckpoint > removalCheckpointLimit(record) {
			return false
		}
		if record.Package == "" {
			return record.PublicIPv4 == "" && record.DestinationAddress == "" && record.DestinationName == "" && record.ConfigurationSHA256 == "" && slices.Equal(record.Resources, recordResources(record, true))
		}
		return validOwnedProxyFields(record)
	}
	if !validPhase(record.Phase) || record.Direction != cleanupRequired && record.Direction != setupRequired && record.Direction != noDirection || record.CleanupCheckpoint < 0 || record.CleanupCheckpoint > 8 || record.RemovalCheckpoint != 0 || record.Direction != cleanupRequired && record.CleanupCheckpoint != 0 || !validOwnedProxyFields(record) {
		return false
	}
	if record.Phase == runningPhase && record.Direction != noDirection || phaseAtOrAfter(record.Phase, activationCommitted) && record.Phase != runningPhase && record.Direction != setupRequired || !phaseAtOrAfter(record.Phase, activationCommitted) && record.Direction != cleanupRequired {
		return false
	}
	return true
}

// Schema 2 supports the original proxy footprint and the fixed serving-only
// footprint. Pending capability operations remain unsupported.
func recordResources(record ownershipRecord, softwareOnly bool) []string {
	resources := ownershipResources(record.ConfigurationSHA256)
	if softwareOnly {
		resources = newRemovalOwnershipRecord(record.Release).Resources
	}
	if record.Schema == 2 {
		resources[0] = "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-2"
	}
	if record.Serving != nil {
		resources = append(resources, record.Serving.Resources()...)
	}
	if record.Renewal != nil {
		resources = append(resources, record.Renewal.Resources()...)
	}
	if record.SubscriptionResources != nil {
		resources = append(resources, record.SubscriptionResources.Resources()...)
	}
	if record.Repair != nil {
		additional := record.Repair.Target
		replaceShared := additional != nil && *record.Serving == record.Repair.Source
		if *record.Serving != record.Repair.Source {
			additional = &record.Repair.Source
		}
		if additional != nil && *additional != *record.Serving {
			for _, resource := range additional.Resources() {
				path, _, _ := strings.Cut(resource, " ")
				replaced := false
				for index, current := range resources {
					currentPath, _, _ := strings.Cut(current, " ")
					if currentPath == path {
						if replaceShared {
							resources[index] = resource
						}
						replaced = true
						break
					}
				}
				if !replaced {
					resources = append(resources, resource)
				}
			}
		}
	}
	if record.Enablement != nil {
		if record.Enablement.Serving == nil {
			resources = append(resources,
				hostadapter.ServingTokenPath+" root:root 0600 one-link provisional credential",
				hostadapter.ServingStagingPath+" root:root 0700 provisional material",
				hostadapter.ServingUnitPath+" root:root 0644 one-link fixed-serving-v1",
				hostadapter.ServingUnitWantsPath+" root-owned provisional enablement symlink",
				"/etc/letsencrypt/archive/sbxr-subscription owned provisional lineage",
				"/etc/letsencrypt/live/sbxr-subscription owned provisional lineage",
				"/etc/letsencrypt/renewal/sbxr-subscription.conf owned provisional lineage",
				hostadapter.RenewalDropInPath+" root:root 0644 provisional recorder route",
				hostadapter.RenewalDeployHookPath+" root:root 0700 provisional hook",
				hostadapter.RenewalPostHookPath+" root:root 0700 provisional hook",
				hostadapter.RenewalEvidencePath+" root:root 0600 provisional evidence",
			)
		} else {
			resources = append(resources, record.Enablement.Serving.Resources()...)
		}
		if record.Enablement.Renewal != nil {
			resources = append(resources, record.Enablement.Renewal.Resources()...)
		}
		if record.Enablement.Resources != nil {
			resources = append(resources, record.Enablement.Resources.Resources()...)
		}
		if record.Enablement.Checkpoint >= hostadapter.SubscriptionServingCheckpoint && record.Enablement.Checkpoint <= 14 {
			resources = append(resources, hostadapter.SubscriptionCandidateTokenPath+" root:root 0600 one-link provisional credential")
		}
		if record.Enablement.Checkpoint >= hostadapter.SubscriptionServingCheckpoint && record.Enablement.Checkpoint <= 15 {
			resources = append(resources, hostadapter.SubscriptionCandidateStatePath+" root:root 0600 immutable provisional serving state")
		}
		for _, path := range []string{hostadapter.SubscriptionCandidateTokenPath, hostadapter.SubscriptionCandidateStatePath, hostadapter.ServingTokenPath, hostadapter.ServingStatePath, hostadapter.ServingUnitPath} {
			resources = append(resources, path+".sbxr-next root-owned synchronized no-replace publication")
		}
		for _, path := range []string{hostadapter.SubscriptionFirewallUnitPath, hostadapter.RenewalDropInPath, hostadapter.RenewalDeployHookPath, hostadapter.RenewalPostHookPath, hostadapter.RenewalAdmissionPath, hostadapter.RenewalWriterPath, hostadapter.RenewalEvidencePath} {
			resources = append(resources, path+".sbxr-next root-owned synchronized no-replace publication")
		}
	}
	if record.Rotation != nil {
		resources = append(resources,
			hostadapter.SubscriptionCandidateTokenPath+" root:root 0600 one-link replacement credential",
			hostadapter.SubscriptionCandidateStatePath+" root:root 0600 immutable replacement serving state",
		)
	}
	if record.Startup != nil {
		resources = append(resources, record.Startup.Resources()...)
	}
	if record.ClientRotation != nil {
		resources = append(resources, hostadapter.ClientIdentityTargetPath+" root:root 0600 one-link sha256:"+record.ClientRotation.Target)
		resources = append(resources,
			hostadapter.ClientIdentityTargetPath+".sbxr-next root-owned Client Identity target publication",
			hostadapter.ClientIdentityConfigurationNextPath+" root:sing-box 0640 one-link sha256:"+record.ClientRotation.Target,
			hostadapter.ProxyStartupDropInPath+".sbxr-next root-owned Client Identity startup publication")
		if sub := record.ClientRotation.Subscription; sub != nil {
			for _, serving := range []hostadapter.ServingAuthority{sub.Source, sub.Target} {
				for _, resource := range serving.Resources() {
					path, _, _ := strings.Cut(resource, " ")
					if !slices.ContainsFunc(resources, func(existing string) bool {
						existingPath, _, _ := strings.Cut(existing, " ")
						return existingPath == path
					}) {
						resources = append(resources, resource)
					}
				}
			}
			resources = append(resources, hostadapter.ClientIdentityArtifactPath+" root:root 0600 one-link sha256:"+sub.TargetArtifactSHA256,
				hostadapter.SubscriptionCandidateStatePath+" root:root 0600 immutable Client Identity serving state",
				hostadapter.ClientIdentityArtifactPath+".sbxr-next root-owned Client Identity artifact publication",
				hostadapter.SubscriptionCandidateStatePath+".sbxr-next root-owned Client Identity state publication",
				hostadapter.ServingUnitPath+".sbxr-next root-owned Client Identity serving startup publication",
				hostadapter.ServingUnitPath+".sbxr-next.sbxr-next root-owned Client Identity serving startup publication")
		}
	}
	return resources
}

func validClientIdentityRotation(rotation clientIdentityRotation, startup *hostadapter.ProxyStartupAuthority, configurationSHA256 string) bool {
	policy, index, known := clientIdentityPolicy(rotation.Checkpoint)
	id, err := hex.DecodeString(rotation.OperationID)
	validDigest := regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString
	if !known || err != nil || len(id) != 16 || rotation.OperationID == strings.Repeat("0", 32) || !validDigest(rotation.Source) || !validDigest(rotation.Target) || rotation.Source == rotation.Target || !slices.Equal(rotation.Effects, clientIdentityRotationEffects) || !slices.Equal(rotation.Completed, clientIdentityRotationEffects[:index]) {
		return false
	}
	direction := map[bool]string{false: "cleanup", true: "forward"}[policy.forward]
	if rotation.Direction != direction || startup == nil {
		return false
	}
	if policy.targetCanonical {
		return configurationSHA256 == rotation.Target
	}
	return configurationSHA256 == rotation.Source
}

func validSubscriptionEnablement(enablement subscriptionEnablement) bool {
	validHex := func(value string, size int) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == size && hex.EncodeToString(decoded) == value && value != strings.Repeat("0", size*2)
	}
	if enablement.Checkpoint < 0 || enablement.Checkpoint > hostadapter.SubscriptionActivationCheckpoint || !validHex(enablement.LinkID, 16) || !validHex(enablement.CredentialSHA256, 32) || !validHex(enablement.RecorderID, 16) || (enablement.Serving == nil) != (enablement.Renewal == nil) || enablement.Serving != nil && enablement.Resources == nil {
		return false
	}
	if enablement.Resources != nil && !enablement.Resources.Valid() {
		return false
	}
	return enablement.Serving == nil || enablement.Serving.Valid() && enablement.Renewal.Valid() && enablement.Serving.LinkID == enablement.LinkID && enablement.Serving.CredentialSHA256 == enablement.CredentialSHA256 && enablement.Renewal.RecorderID == enablement.RecorderID && enablement.Resources.PublicIPv4 == enablement.Renewal.PublicIPv4
}

func validSubscriptionRotation(rotation subscriptionRotation) bool {
	completed := map[subscriptionRotationCheckpoint][]string{
		rotationTargetAuthorized: nil,
		rotationStopAuthorized:   {"target prepared"},
		rotationCommitted:        {"target prepared", "source stopped"},
	}
	wantCompleted, checkpointOK := completed[rotation.Checkpoint]
	direction := "cleanup"
	if rotation.Checkpoint == rotationCommitted {
		direction = "forward"
	}
	operationID, err := hex.DecodeString(rotation.OperationID)
	return checkpointOK && err == nil && len(operationID) == 16 && hex.EncodeToString(operationID) == rotation.OperationID && rotation.OperationID != strings.Repeat("0", 32) && rotation.Kind == "rotate subscription link" && rotation.Direction == direction && slices.Equal(rotation.Effects, subscriptionRotationEffects) && slices.Equal(rotation.Completed, wantCompleted) && rotation.Source.Valid() && rotation.Target.Valid() && rotation.Source.LinkID != rotation.Target.LinkID && rotation.Source.CredentialSHA256 != rotation.Target.CredentialSHA256 && rotation.Source.CertificateGeneration == rotation.Target.CertificateGeneration && rotation.Source.CertificateSHA256 == rotation.Target.CertificateSHA256
}

func validCertificateActivation(activation certificateActivation) bool {
	return (activation.Checkpoint == activationTargetRecorded || activation.Checkpoint == activationTargetAccepted) && compatibleCertificateTarget(activation.Source, activation.Target)
}

func validSubscriptionRepair(repair subscriptionRepair) bool {
	id, err := hex.DecodeString(repair.OperationID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != repair.OperationID || repair.OperationID == strings.Repeat("0", 32) || !repair.Source.Valid() {
		return false
	}
	if repair.Kind != "repair subscription" || repair.Correction != repairCertificate && repair.Correction != repairRuntime || repair.Checkpoint != repairPrepared && repair.Checkpoint != repairCommitted && repair.Checkpoint != repairAccepted {
		return false
	}
	effects := []string{"restart owned serving runtime"}
	completed := []string(nil)
	if repair.Correction == repairCertificate {
		effects = []string{"renew owned certificate", "activate published certificate", "resolve renewal evidence"}
		if repair.Target != nil {
			completed = []string{"certificate published"}
		}
	}
	direction := "cleanup"
	if repair.Checkpoint != repairPrepared {
		direction = "forward"
	}
	if repair.Checkpoint == repairAccepted {
		completed = slices.Clone(effects)
	}
	if repair.Direction != direction || !slices.Equal(repair.Effects, effects) || !slices.Equal(repair.Completed, completed) || repair.Target != nil && !compatibleCertificateTarget(repair.Source, *repair.Target) {
		return false
	}
	if repair.Checkpoint == repairPrepared && repair.Target != nil || repair.Checkpoint == repairAccepted && repair.Target == nil {
		return false
	}
	return repair.Target == nil || repair.Correction == repairRuntime && *repair.Target == repair.Source || repair.Correction == repairCertificate && repair.Target.CertificateGeneration > repair.Source.CertificateGeneration
}

func compatibleOwnership(record ownershipRecord, installed softwarelifecycle.ReleaseIdentity) bool {
	if !validOwnership(record) || !validReleaseIdentity(installed) {
		return false
	}
	if record.Direction == removalRequired {
		return finishingRelease(record) == installed
	}
	if record.Phase != runningPhase {
		return record.Schema == 1 && record.Release == installed
	}
	if record.Schema == 2 {
		return true
	}
	if record.Release != installed && record.Release != legacyProxyCreator {
		return false
	}
	for _, creator := range record.ResourceCreatingReleases {
		if creator != installed && creator != legacyProxyCreator {
			return false
		}
	}
	return true
}

// AdmitSoftwareUpdate keeps Proxy Installation's exact durable-record rules
// out of Software Lifecycle. A target must understand every creating release.
const expandedProxyAuthorityCapability = "SBXR-PROXY-AUTHORITY-SCHEMA-2-CLIENT-IDENTITY-ROTATION-V1"

func AdmitSoftwareUpdate(body []byte, source softwarelifecycle.ReleaseIdentity, target *softwarelifecycle.UpdateTarget) bool {
	record, ok := decodeOwnership(body)
	if !ok || record.Phase != runningPhase || record.Direction != noDirection || record.FinishingRelease != nil || record.Activation != nil || record.Enablement != nil || record.Rotation != nil || record.Repair != nil || record.ClientRotation != nil || !compatibleOwnership(record, source) {
		return false
	}
	if target == nil {
		return true
	}
	if !validReleaseIdentity(target.Identity) || target.Support == nil || target.Support.Scope != softwarelifecycle.RecurringSubscriptionUpgrade || target.Support.Contract != softwarelifecycle.SubscriptionUpdateContract || !slices.Contains(target.Support.Sources, source) || !bytes.Contains(target.Executable, []byte(expandedProxyAuthorityCapability)) {
		return false
	}
	return true
}

func finishingRelease(record ownershipRecord) softwarelifecycle.ReleaseIdentity {
	if record.Schema == 2 && record.FinishingRelease != nil {
		return *record.FinishingRelease
	}
	return record.Release
}

func removalAuthority(record ownershipRecord, installed softwarelifecycle.ReleaseIdentity) ownershipRecord {
	if record.Schema == 1 {
		record.Schema = 2
		record.Resources = recordResources(record, record.Package == "")
		record.ResourceCreatingReleases = make([]softwarelifecycle.ReleaseIdentity, len(record.Resources))
		for i := range record.ResourceCreatingReleases {
			record.ResourceCreatingReleases[i] = record.Release
		}
	}
	record.FinishingRelease = &installed
	return record
}

func removalCheckpointLimit(record ownershipRecord) int {
	if record.Package == "" {
		return 3
	}
	return 11
}

func validOwnedProxyFields(record ownershipRecord) bool {
	if record.Package != "https://deb.sagernet.org/ sing-box 1.13.19 amd64 24597120 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(record.ConfigurationSHA256) || !slices.Equal(record.Resources, recordResources(record, false)) {
		return false
	}
	_, acceptedDestination := acceptedDestination(record.DestinationAddress, record.DestinationName)
	ip, ipErr := netip.ParseAddr(record.PublicIPv4)
	return ipErr == nil && isPublicIPv4(ip) && acceptedDestination
}

func validReleaseIdentity(release softwarelifecycle.ReleaseIdentity) bool {
	return release.Repository == softwarelifecycle.Repository && regexp.MustCompile(`^v[1-9][0-9]*\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`).MatchString(release.Tag) && regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(release.Commit) && regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(release.IndexSHA256)
}

func ownershipResources(configurationDigest string) []string {
	return []string{
		"/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-1",
		finalOwnershipPath + " root:root 0600 one-link finalization authority",
		"/var/lib/sbxr/.proxy-ownership.json.next root:root 0600 one-link transaction material",
		"/var/lib/sbxr/sing-box_1.13.19_amd64.deb root-owned one-link verified package artifact",
		"/etc/apt/keyrings/sagernet.asc sha256:803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1",
		"/etc/apt/keyrings/sagernet.asc.sbxr-next root-owned transaction material",
		"/etc/apt/sources.list.d/sagernet.sources https://deb.sagernet.org/ signed-by sagernet.asc",
		"/etc/apt/sources.list.d/sagernet.sources.sbxr-next root-owned transaction material",
		"sing-box package 1.13.19 amd64 deb-sha256:fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf",
		"sing-box package hold",
		"/etc/sing-box/config.json sha256:" + configurationDigest,
		"/var/lib/sing-box package state",
		"sing-box.service package provenance stopped-disabled-before-commit",
		"sing-box package-created user and group",
		"tcp/443 local listener",
	}
}

func acceptedDestination(address, name string) (hostadapter.Destination, bool) {
	for _, destination := range destinations {
		if destination.Address == address && destination.ServerName == name {
			return destination, true
		}
	}
	return hostadapter.Destination{}, false
}

func validPhase(phase setupPhase) bool { return slices.Contains(setupPhaseOrder, phase) }

func phaseAtOrAfter(phase, boundary setupPhase) bool {
	return slices.Index(setupPhaseOrder, phase) >= slices.Index(setupPhaseOrder, boundary)
}
