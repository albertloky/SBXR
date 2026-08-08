package subscriptionpublication

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
)

type ClientAccessAction string

const (
	RotateSubscriptionToken ClientAccessAction = "Rotate subscription token"
	RevokeAllClientAccess   ClientAccessAction = "Revoke all client access"
)

type ClientAccessMutation struct {
	subscription       state.SubscriptionSettings
	connectionProfiles state.ConnectionProfiles
	source             connectionprofiles.PublicationSource
	address            string
	action             ClientAccessAction
	rotation           *connectionprofiles.RegistryRotation
	token              string
	effect             string
	used               atomic.Bool
}

func PrepareClientAccessMutation(action ClientAccessAction, address string, subscription state.SubscriptionSettings, profiles state.ConnectionProfiles, source connectionprofiles.PublicationSource) (*ClientAccessMutation, error) {
	parsedAddress, addressErr := netip.ParseAddr(address)
	if addressErr != nil || !parsedAddress.IsGlobalUnicast() || subscription.ListenPort != 10443 || subscription.Token == (state.ClientAccessValue{}) || !connectionprofiles.PublicationInputsMatch(source, profiles) || !publicationUsesAddress(source, address) {
		return nil, errors.New("current Subscription settings are invalid")
	}
	effect, valid := clientAccessEffect(action)
	if !valid || action == "" {
		return nil, errors.New("Client Access action is invalid")
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return nil, errors.New("subscription token generation failed")
	}
	token := hex.EncodeToString(tokenBytes)
	subscription.Token = state.NewClientAccessValue(token)
	switch action {
	case RotateSubscriptionToken:
	case RevokeAllClientAccess:
		rotation, err := connectionprofiles.RotateRegistryCredentials(profiles, source)
		if err != nil {
			return nil, errors.New("all Client Access Values could not be replaced")
		}
		profiles, source = rotation.ConnectionProfiles(), rotation.PublicationSource()
		return &ClientAccessMutation{subscription: subscription, connectionProfiles: profiles, source: source, address: address, action: action, rotation: rotation, token: token, effect: effect}, nil
	}
	return &ClientAccessMutation{subscription: subscription, connectionProfiles: profiles, source: source, address: address, action: action, token: token, effect: effect}, nil
}

func clientAccessEffect(action ClientAccessAction) (string, bool) {
	switch action {
	case "":
		return "", true
	case RotateSubscriptionToken:
		return "future downloads at the prior URL are revoked; already downloaded Connection Profile credentials remain valid", true
	case RevokeAllClientAccess:
		return "future downloads and all six prior Connection Profile credentials are revoked together", true
	default:
		return "", false
	}
}

func (mutation *ClientAccessMutation) Subscription() state.SubscriptionSettings {
	if mutation == nil {
		return state.SubscriptionSettings{}
	}
	return mutation.subscription
}
func (mutation *ClientAccessMutation) ConnectionProfiles() state.ConnectionProfiles {
	if mutation == nil {
		return state.ConnectionProfiles{}
	}
	return mutation.connectionProfiles
}
func (mutation *ClientAccessMutation) PublicationSource() connectionprofiles.PublicationSource {
	if mutation == nil {
		return connectionprofiles.PublicationSource{}
	}
	return mutation.source
}
func (mutation *ClientAccessMutation) Effect() string {
	if mutation == nil {
		return ""
	}
	return mutation.effect
}

type clientAccessPlanReader struct {
	mutation  *ClientAccessMutation
	generated state.ClientAccessReader
	fallback  state.ClientAccessReader
}

func (reader clientAccessPlanReader) ReadClientAccessValue(value state.ClientAccessValue) string {
	if value == reader.mutation.subscription.Token {
		return reader.mutation.token
	}
	if reader.generated != nil {
		if secret := reader.generated.ReadClientAccessValue(value); secret != "" {
			return secret
		}
	}
	return reader.fallback.ReadClientAccessValue(value)
}

// Route returns the one authenticated base route or one of the seven approved
// named representation routes. Calling it is an explicit secret-bearing action.

func (mutation *ClientAccessMutation) Route(suffix string) (string, error) {
	if mutation == nil {
		return "", errors.New("subscription route inputs are invalid")
	}
	parsed, err := netip.ParseAddr(mutation.address)
	if err != nil || !parsed.IsGlobalUnicast() || mutation.subscription.ListenPort != 10443 || len(mutation.token) != 64 {
		return "", errors.New("subscription route inputs are invalid")
	}
	if suffix != "" && !validRepresentationSuffix(RepresentationIdentity(suffix)) {
		return "", errors.New("subscription representation is invalid")
	}
	return "https://" + net.JoinHostPort(mutation.address, "10443") + "/s/" + mutation.token + suffix, nil
}

func publicationUsesAddress(source connectionprofiles.PublicationSource, address string) bool {
	for _, profile := range source.Profiles() {
		switch profile.ID {
		case connectionprofiles.VLESSRealityVisionProfileID, connectionprofiles.Hysteria2ProfileID, connectionprofiles.TUICProfileID, connectionprofiles.AnyTLSProfileID:
			if profile.Address != address {
				return false
			}
		}
	}
	return true
}

func validRepresentationSuffix(identity RepresentationIdentity) bool {
	switch identity {
	case Base64Representation, RawRepresentation, V2RayNRepresentation, ShadowrocketRepresentation, KaringRepresentation, MihomoRepresentation, SingBoxRepresentation:
		return true
	default:
		return false
	}
}

func (*ClientAccessMutation) String() string {
	return "Client Access mutation: protected values and routes redacted"
}
func (*ClientAccessMutation) GoString() string {
	return "Client Access mutation: protected values and routes redacted"
}
func (*ClientAccessMutation) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Client Access mutation cannot be rendered")
}
