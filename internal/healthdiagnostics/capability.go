package healthdiagnostics

type ConnectionProfile string

const (
	VLESSRealityVision ConnectionProfile = "VLESS REALITY Vision"
	VLESSXHTTP         ConnectionProfile = "VLESS XHTTP"
	VLESSWebSocket     ConnectionProfile = "VLESS WebSocket"
	Hysteria2          ConnectionProfile = "Hysteria2"
	TUIC               ConnectionProfile = "TUIC"
	AnyTLS             ConnectionProfile = "AnyTLS"
)

type ProfileLifecycle string

const (
	ProfileNotSetUp ProfileLifecycle = "Not set up"
	ProfileEnabled  ProfileLifecycle = "Enabled"
	ProfileDisabled ProfileLifecycle = "Disabled"
)

type CapabilityFact struct {
	Name      ConnectionProfile
	Lifecycle ProfileLifecycle
}

type CapabilityInspection struct {
	CommittedRevision uint64
	CapabilityRows    []CapabilityFact
}

type CapabilityResult struct {
	Name                ConnectionProfile `json:"connection_profile"`
	Lifecycle           ProfileLifecycle  `json:"lifecycle"`
	HealthResultOmitted bool              `json:"health_result_omitted"`
	PublicationOmitted  bool              `json:"publication_omitted"`
	Explanation         string            `json:"explanation"`
}

type CapabilitySummary struct {
	CommittedRevision uint64             `json:"committed_revision"`
	CapabilityRows    []CapabilityResult `json:"capability_rows"`
}

var connectionProfiles = [...]ConnectionProfile{
	VLESSRealityVision, VLESSXHTTP, VLESSWebSocket, Hysteria2, TUIC, AnyTLS,
}

func capabilitySummary(inspection CapabilityInspection) *CapabilitySummary {
	if inspection.CommittedRevision == 0 || len(inspection.CapabilityRows) != len(connectionProfiles) {
		return nil
	}
	result := &CapabilitySummary{CommittedRevision: inspection.CommittedRevision, CapabilityRows: make([]CapabilityResult, len(connectionProfiles))}
	for index, profile := range inspection.CapabilityRows {
		if profile.Name != connectionProfiles[index] {
			return nil
		}
		row := CapabilityResult{Name: profile.Name, Lifecycle: profile.Lifecycle}
		switch profile.Lifecycle {
		case ProfileEnabled:
			row.Explanation = "Set up and Enabled."
		case ProfileDisabled:
			row.PublicationOmitted = true
			row.Explanation = "Set up and Disabled; no publication entry."
		case ProfileNotSetUp:
			row.HealthResultOmitted, row.PublicationOmitted = true, true
			row.Explanation = "No individual Health Result; Cloudflare Profile Setup is required."
		default:
			return nil
		}
		result.CapabilityRows[index] = row
	}
	return result
}

func cloneCapability(summary *CapabilitySummary) *CapabilitySummary {
	if summary == nil {
		return nil
	}
	copy := *summary
	copy.CapabilityRows = append([]CapabilityResult(nil), summary.CapabilityRows...)
	return &copy
}

func validCapability(summary *CapabilitySummary) bool {
	if summary == nil {
		return true
	}
	facts := make([]CapabilityFact, len(summary.CapabilityRows))
	for index, profile := range summary.CapabilityRows {
		facts[index] = CapabilityFact{Name: profile.Name, Lifecycle: profile.Lifecycle}
	}
	want := capabilitySummary(CapabilityInspection{CommittedRevision: summary.CommittedRevision, CapabilityRows: facts})
	if want == nil || len(want.CapabilityRows) != len(summary.CapabilityRows) {
		return false
	}
	for index := range want.CapabilityRows {
		if want.CapabilityRows[index] != summary.CapabilityRows[index] {
			return false
		}
	}
	return true
}
