// Package cloudflaretunnel owns Cloudflare inventory and scoped-token observations.
package cloudflaretunnel

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type RemovalRecoveryAuthority struct {
	AccountID, ZoneID, ZoneName, TunnelID string
	DNSRecordIDs                          []string
	Routes                                []Route
}

type removalRecoveryRecord struct {
	Authority RemovalRecoveryAuthority `json:"authority"`
	Token     string                   `json:"token"`
}

// WriteRemovalRecovery keeps the scoped token inside the protected transaction snapshot.
func WriteRemovalRecovery(token ManagementToken, authority RemovalRecoveryAuthority, write func(io.Reader) error) error {
	if write == nil || token.value == "" || !validRemovalRecoveryAuthority(authority) {
		return errors.New("Cloudflare removal recovery authority unavailable")
	}
	body, err := json.Marshal(removalRecoveryRecord{Authority: authority, Token: token.value})
	if err != nil {
		return err
	}
	return write(bytes.NewReader(body))
}

// ReadRemovalRecovery opens only the typed root-only snapshot record.
func ReadRemovalRecovery(source io.Reader) (RemovalRecoveryAuthority, ManagementToken, error) {
	var record removalRecoveryRecord
	decoder := json.NewDecoder(io.LimitReader(source, 1<<20))
	if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validRemovalRecoveryAuthority(record.Authority) {
		return RemovalRecoveryAuthority{}, ManagementToken{}, errors.New("Cloudflare removal recovery authority unavailable")
	}
	token, err := NewManagementToken(record.Token)
	return record.Authority, token, err
}

func validRemovalRecoveryAuthority(authority RemovalRecoveryAuthority) bool {
	if !immutableID.MatchString(authority.AccountID) || !immutableID.MatchString(authority.ZoneID) || !validZoneName(authority.ZoneName) || !tunnelUUID.MatchString(authority.TunnelID) || len(authority.DNSRecordIDs) < 2 || len(authority.DNSRecordIDs) > 4 || len(authority.Routes) == 0 {
		return false
	}
	for _, id := range authority.DNSRecordIDs {
		if !immutableID.MatchString(id) {
			return false
		}
	}
	for _, route := range authority.Routes {
		if !safeObservedRoute(route) {
			return false
		}
	}
	return true
}

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
