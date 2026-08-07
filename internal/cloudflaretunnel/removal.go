// Package cloudflaretunnel owns Cloudflare inventory and scoped-token observations.
package cloudflaretunnel

import (
	"errors"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type RemovalObservation struct {
	ReviewID              string
	Resource              string
	ImmutableID           string
	OwnedBySBXR           bool
	TokenActive           bool
	TokenAvailableLocally bool
	Inventory             map[string][]string
}

type RemovalObserver interface {
	ObserveRemovalResource(reviewID, resource, immutableID string) (RemovalObservation, error)
}

type RemovalInterface struct{ observer RemovalObserver }

// RemovalAuthority is opaque proof produced from a fresh owning-Module observation.
type RemovalAuthority struct{ observation RemovalObservation }

func NewRemoval(observer RemovalObserver) RemovalInterface {
	return RemovalInterface{observer: observer}
}

func (i RemovalInterface) ProveRemovalResource(reviewID, resource, immutableID string) (RemovalAuthority, error) {
	if i.observer == nil {
		return RemovalAuthority{}, errors.New("Cloudflare removal observer unavailable")
	}
	observed, err := i.observer.ObserveRemovalResource(reviewID, resource, immutableID)
	if err != nil || observed.ReviewID != reviewID || observed.Resource != resource || observed.ImmutableID != immutableID || !observed.OwnedBySBXR || !observed.TokenActive || !observed.TokenAvailableLocally {
		return RemovalAuthority{}, errors.New("Cloudflare ownership or scoped-token authority is unproved")
	}
	observed.Inventory = copyInventory(observed.Inventory)
	return RemovalAuthority{observation: observed}, nil
}

func (authority RemovalAuthority) SystemChangesCloudflareRemovalAuthority() systemchanges.CloudflareRemovalProof {
	o := authority.observation
	return systemchanges.CloudflareRemovalProof{ReviewID: o.ReviewID, Resource: systemchanges.RemovalResource(o.Resource), ImmutableID: o.ImmutableID, Inventory: copyInventory(o.Inventory), TokenActive: o.TokenActive, TokenAvailable: o.TokenAvailableLocally, Valid: o.OwnedBySBXR && o.ReviewID != "" && o.Resource != "" && o.ImmutableID != ""}
}

func copyInventory(source map[string][]string) map[string][]string {
	copy := make(map[string][]string, len(source))
	for category, identities := range source {
		copy[category] = append([]string(nil), identities...)
	}
	return copy
}
