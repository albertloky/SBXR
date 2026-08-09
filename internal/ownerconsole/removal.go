// Package ownerconsole owns the two distinct Owner acts that authorize Complete removal.
package ownerconsole

import (
	"errors"
	"slices"
	"sync/atomic"
)

const completeRemovalPhrase = "COMPLETE REMOVAL"

var removalCategories = []string{
	"desired-state",
	"client-access-values",
	"infrastructure-secrets",
	"certificates-and-acme",
	"transaction-journal",
	"rollback-snapshot",
	"installed-release",
	"verified-update-candidate",
	"services-and-timers",
	"service-identities",
	"prepared-artifacts",
	"subscription-artifacts",
	"firewall-table",
	"public-listener",
	"public-service",
	"cloudflare-dns-record",
	"cloudflare-route",
	"cloudflare-tunnel",
	"certificate-transparency-remnant",
	"dns-cache-remnant",
}

type RemovalObserver interface {
	ReviewedCategories(reviewID string) ([]string, error)
	TypedPhrase(reviewID string) (phrase string, typedInteractively bool, err error)
	PermanentRemovalSelected(reviewID string) (bool, error)
}

type Interface struct{ observer RemovalObserver }

func New(observer RemovalObserver) Interface { return Interface{observer: observer} }

// RemovalReview is an opaque record that the Owner Console observed every category.
type RemovalReview struct {
	identity   string
	categories []string
}

// TypedRemovalConfirmation and PermanentRemovalSelection are separate opaque authorities.
type typedRemovalConfirmationCell struct {
	review, phrase string
	selected       atomic.Bool
}
type TypedRemovalConfirmation struct{ cell *typedRemovalConfirmationCell }
type PermanentRemovalSelection struct {
	review     string
	categories []string
}

func (i Interface) StartRemovalReview(identity string) (RemovalReview, error) {
	if i.observer == nil {
		return RemovalReview{}, errors.New("Owner Console removal observer unavailable")
	}
	categories, err := i.observer.ReviewedCategories(identity)
	want := append([]string(nil), removalCategories...)
	got := append([]string(nil), categories...)
	slices.Sort(want)
	slices.Sort(got)
	if err != nil || identity == "" || !slices.Equal(got, want) {
		return RemovalReview{}, errors.New("every Complete removal category must be reviewed")
	}
	return RemovalReview{identity: identity, categories: append([]string(nil), removalCategories...)}, nil
}

func (review RemovalReview) SoftwareLifecycleCompleteRemovalReview() (string, bool) {
	return review.identity, review.identity != "" && len(review.categories) == len(removalCategories)
}

func (i Interface) RecordTypedPhrase(review RemovalReview) (TypedRemovalConfirmation, error) {
	if i.observer == nil {
		return TypedRemovalConfirmation{}, errors.New("Owner Console removal observer unavailable")
	}
	phrase, typedInteractively, err := i.observer.TypedPhrase(review.identity)
	if err != nil || review.identity == "" || phrase != completeRemovalPhrase || !typedInteractively {
		return TypedRemovalConfirmation{}, errors.New("exact COMPLETE REMOVAL typing is required")
	}
	return TypedRemovalConfirmation{cell: &typedRemovalConfirmationCell{review: review.identity, phrase: phrase}}, nil
}

func (i Interface) SelectPermanentRemoval(review RemovalReview, confirmation TypedRemovalConfirmation) (PermanentRemovalSelection, error) {
	if i.observer == nil || confirmation.cell == nil || confirmation.cell.review != review.identity || confirmation.cell.phrase != completeRemovalPhrase || !confirmation.cell.selected.CompareAndSwap(false, true) {
		return PermanentRemovalSelection{}, errors.New("Owner Console removal observer unavailable")
	}
	selected, err := i.observer.PermanentRemovalSelected(review.identity)
	if err != nil || review.identity == "" || !selected {
		return PermanentRemovalSelection{}, errors.New("Complete removal review is required")
	}
	return PermanentRemovalSelection{review: review.identity, categories: append([]string(nil), removalCategories...)}, nil
}

func (confirmation TypedRemovalConfirmation) SystemChangesTypedRemovalConfirmation() (review, phrase string, valid bool) {
	if confirmation.cell == nil {
		return "", "", false
	}
	return confirmation.cell.review, confirmation.cell.phrase, confirmation.cell.review != "" && confirmation.cell.phrase == completeRemovalPhrase && confirmation.cell.selected.Load()
}

func (selection PermanentRemovalSelection) SystemChangesPermanentRemovalSelection() (review string, valid bool) {
	return selection.review, selection.review != "" && len(selection.categories) == len(removalCategories)
}
