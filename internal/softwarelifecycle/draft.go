package softwarelifecycle

import (
	"net/mail"
	"net/netip"
)

type InstallationDraft struct {
	OwnerEmail                  string `json:"owner_email"`
	SubscriberAgreementReviewed bool   `json:"subscriber_agreement_reviewed"`
	PublicIPv4                  string `json:"public_ipv4"`
	PublicIPv6                  string `json:"public_ipv6"`
	PrimaryAddress              string `json:"primary_address"`
	SSHPort                     uint16 `json:"ssh_port"`
	RealityPort                 uint16 `json:"reality_port"`
	SubscriptionPort            uint16 `json:"subscription_port"`
}

func (draft InstallationDraft) Valid() bool {
	address, err := mail.ParseAddress(draft.OwnerEmail)
	if err != nil || address.Name != "" || address.Address != draft.OwnerEmail || !draft.SubscriberAgreementReviewed || draft.SSHPort == 0 || draft.RealityPort == 0 || draft.SubscriptionPort == 0 {
		return false
	}
	v4, v4Err := netip.ParseAddr(draft.PublicIPv4)
	v6, v6Err := netip.ParseAddr(draft.PublicIPv6)
	if draft.PublicIPv4 != "" && (v4Err != nil || !v4.Is4() || !v4.IsGlobalUnicast()) || draft.PublicIPv6 != "" && (v6Err != nil || !v6.Is6() || !v6.IsGlobalUnicast()) || draft.PublicIPv4 == "" && draft.PublicIPv6 == "" {
		return false
	}
	return draft.PrimaryAddress == draft.PublicIPv4 || draft.PrimaryAddress == draft.PublicIPv6
}
