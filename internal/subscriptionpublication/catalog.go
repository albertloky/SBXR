package subscriptionpublication

import (
	"encoding/hex"
	"net/netip"
	"net/url"
	"strconv"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
)

type RepresentationIdentity string

const (
	Base64Representation       RepresentationIdentity = "/base64"
	RawRepresentation          RepresentationIdentity = "/raw"
	V2RayNRepresentation       RepresentationIdentity = "/v2rayn"
	ShadowrocketRepresentation RepresentationIdentity = "/shadowrocket"
	KaringRepresentation       RepresentationIdentity = "/karing"
	MihomoRepresentation       RepresentationIdentity = "/mihomo"
	SingBoxRepresentation      RepresentationIdentity = "/sing-box"
)

type CompatibilityDefinition string

const CurrentCompatibilityDefinition CompatibilityDefinition = "sbxr-subscription-representations-v1"

type PublicationStatus string

const (
	PublicationCurrent           PublicationStatus = "Current"
	PublicationNotPublished      PublicationStatus = "Not published"
	PublicationNeedsRegeneration PublicationStatus = "Needs regeneration"
	PublicationUnavailable       PublicationStatus = "Unavailable"
)

type ViewRequest struct {
	Source                                          connectionprofiles.PublicationSource
	SubscriptionAddress                             string
	DesiredStateRevision, PublishedRevision         uint64
	DesiredStateSHA256, PublishedStateSHA256        string
	CompatibilityDefinition, PublishedCompatibility CompatibilityDefinition
}

type RepresentationView struct {
	Identity               RepresentationIdentity
	Name                   string
	ProfileCount           int
	Omissions              []RepresentationOmission
	Candidate              bool
	OwnerAcceptancePending []connectionprofiles.ProfileID
}

type ViewResult struct {
	Status                      PublicationStatus
	SubscriptionAddress         string
	CompatibilityDefinition     CompatibilityDefinition
	AgreesWithDesiredState      bool
	UnknownClientFallback       RepresentationIdentity
	UnknownClientFallbackReason string
	Representations             []RepresentationView
}

// RepresentationBody returns a copy of the validated body for one catalog identity.
func (artifacts Artifacts) RepresentationBody(identity RepresentationIdentity) ([]byte, bool) {
	var body []byte
	switch identity {
	case Base64Representation:
		body = artifacts.Base64
	case RawRepresentation:
		body = artifacts.Raw
	case V2RayNRepresentation:
		body = artifacts.V2RayN
	case ShadowrocketRepresentation:
		body = artifacts.Shadowrocket
	case KaringRepresentation:
		body = artifacts.Karing.Body
	case MihomoRepresentation:
		body = artifacts.Mihomo
	case SingBoxRepresentation:
		body = artifacts.SingBox.Body
	default:
		return nil, false
	}
	return append([]byte(nil), body...), true
}

// View returns the token-free publication status and named representation catalog.
func (Interface) View(request ViewRequest) ViewResult {
	profiles, disabled := request.Source.Profiles(), request.Source.Omissions()
	if len(profiles)+len(disabled) != 6 || !validSubscriptionAddress(request.SubscriptionAddress) || request.DesiredStateRevision == 0 || !validDigest(request.DesiredStateSHA256) {
		return ViewResult{Status: PublicationUnavailable}
	}
	enabledIDs := make([]connectionprofiles.ProfileID, 0, len(profiles))
	supportedIDs := make([]connectionprofiles.ProfileID, 0, len(profiles))
	for _, profile := range profiles {
		enabledIDs = append(enabledIDs, profile.ID)
		if profile.ID != connectionprofiles.VLESSXHTTPProfileID {
			supportedIDs = append(supportedIDs, profile.ID)
		}
	}
	allOmissions := disabledOmissions(disabled)
	singBoxOmissions := representationOmissions(disabled, singBoxXHTTPReason)
	karingOmissions := representationOmissions(disabled, karingXHTTPReason)
	result := ViewResult{
		Status:                      PublicationNeedsRegeneration,
		SubscriptionAddress:         request.SubscriptionAddress,
		CompatibilityDefinition:     CurrentCompatibilityDefinition,
		UnknownClientFallback:       Base64Representation,
		UnknownClientFallbackReason: "Unknown or ambiguous clients receive Base64; User-Agent is convenience only, not authentication, authorization, or compatibility proof",
		Representations: []RepresentationView{
			{Identity: Base64Representation, Name: "Base64", ProfileCount: len(profiles), Omissions: append([]RepresentationOmission(nil), allOmissions...)},
			{Identity: RawRepresentation, Name: "Raw", ProfileCount: len(profiles), Omissions: append([]RepresentationOmission(nil), allOmissions...)},
			{Identity: V2RayNRepresentation, Name: "v2rayN", ProfileCount: len(profiles), Omissions: append([]RepresentationOmission(nil), allOmissions...)},
			{Identity: ShadowrocketRepresentation, Name: "Shadowrocket", ProfileCount: len(profiles), Omissions: append([]RepresentationOmission(nil), allOmissions...), Candidate: true, OwnerAcceptancePending: enabledIDs},
			{Identity: KaringRepresentation, Name: "Karing", ProfileCount: len(supportedIDs), Omissions: karingOmissions, OwnerAcceptancePending: supportedIDs},
			{Identity: MihomoRepresentation, Name: "Mihomo", ProfileCount: len(profiles), Omissions: append([]RepresentationOmission(nil), allOmissions...)},
			{Identity: SingBoxRepresentation, Name: "sing-box", ProfileCount: len(supportedIDs), Omissions: singBoxOmissions},
		},
	}
	if request.PublishedRevision == 0 && request.PublishedStateSHA256 == "" && request.PublishedCompatibility == "" {
		result.Status = PublicationNotPublished
	} else if request.DesiredStateRevision == request.PublishedRevision && request.DesiredStateSHA256 == request.PublishedStateSHA256 && request.CompatibilityDefinition == CurrentCompatibilityDefinition && request.PublishedCompatibility == CurrentCompatibilityDefinition {
		result.Status, result.AgreesWithDesiredState = PublicationCurrent, true
	}
	return result
}

func disabledOmissions(disabled []connectionprofiles.PublicationOmission) []RepresentationOmission {
	omissions := make([]RepresentationOmission, 0, len(disabled))
	for _, omission := range disabled {
		omissions = append(omissions, RepresentationOmission{ID: omission.ID, Status: Disabled, Reason: "The Connection Profile is deliberately disabled"})
	}
	return omissions
}

func validSubscriptionAddress(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return false
	}
	address, addressErr := netip.ParseAddr(parsed.Hostname())
	port, portErr := strconv.ParseUint(parsed.Port(), 10, 16)
	return parsed.Scheme == "https" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && addressErr == nil && address.IsGlobalUnicast() && portErr == nil && port != 0
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
