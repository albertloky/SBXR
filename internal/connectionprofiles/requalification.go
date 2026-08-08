package connectionprofiles

import (
	"bytes"
	"context"
	"fmt"
)

type AcceptanceStatus string

const AcceptancePending AcceptanceStatus = "Pending"

type CoreUpdateRequalificationRequest struct {
	Registry                    RegistryViewRequest
	XrayVersion, SingBoxVersion string
}

type CoreUpdateRequalificationResult struct {
	NativeConfigurationPassed                            bool
	AutomatedAcceptance, LiveAcceptance, OwnerAcceptance AcceptanceStatus
	ReplacementAllowed                                   bool
	Health                                               Health
}

// RequalifyCoreUpdate checks the complete current profile artifact with the
// candidate binaries. A successful native check deliberately resets every
// acceptance stage; it never promotes a candidate to known-good by itself.
func (module Interface) RequalifyCoreUpdate(ctx context.Context, request CoreUpdateRequalificationRequest) CoreUpdateRequalificationResult {
	pending := CoreUpdateRequalificationResult{AutomatedAcceptance: AcceptancePending, LiveAcceptance: AcceptancePending, OwnerAcceptance: AcceptancePending}
	if module.ViewRegistry(ctx, request.Registry).Health.Outcome != Healthy || request.XrayVersion == "" || !supportedSingBoxUpdate(request.SingBoxVersion) || request.XrayVersion == request.Registry.Reality.XrayVersion && request.SingBoxVersion == request.Registry.AnyTLS.SingBoxVersion {
		pending.Health = registryPlanFailure("UPDATE", "the candidate core versions or current six-profile registry are not qualified")
		return pending
	}
	xray, singBox, _ := registryConfigurations(reviewedRegistryRequest(request.Registry))
	validator, ok := module.host.(SingBoxValidator)
	if module.host.ValidateReality(ctx, request.XrayVersion, bytes.NewReader(xray)) != nil || !ok || validator.ValidateSingBox(ctx, request.SingBoxVersion, bytes.NewReader(singBox)) != nil {
		pending.Health = registryPlanFailure("UPDATE-NATIVE", "the complete six-profile candidate configuration failed a native validator")
		return pending
	}
	pending.NativeConfigurationPassed = true
	pending.Health = blockedHealth(Health{Module: "Connection Profiles", Profile: "Registry", Outcome: NeedsAttention, Code: "CONNECTION-PROFILES-CORE-UPDATE-ACCEPTANCE-PENDING", Problem: "The candidate binaries passed native configuration validation", Required: "fresh automated, live, and Owner acceptance before known-good replacement", WhyStopped: "a core update resets prior acceptance evidence", NextActions: []string{"Run automated acceptance", "Back"}})
	return pending
}

func supportedSingBoxUpdate(version string) bool {
	var major, minor, patch int
	n, err := fmt.Sscanf(version, "%d.%d.%d", &major, &minor, &patch)
	return err == nil && n == 3 && (major > 1 || major == 1 && minor >= 12)
}
