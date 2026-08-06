// Package ownerconsole owns the two distinct Owner acts that authorize Complete removal.
package ownerconsole

import (
	"errors"
	"slices"
)

const completeRemovalPhrase = "COMPLETE REMOVAL"

var removalCategories = []string{
	"firewall-table",
	"public-listener",
	"public-service",
	"cloudflare-dns-record",
	"cloudflare-route",
	"cloudflare-tunnel",
}

type RemovalObserver interface {
	ReviewedCategories(reviewID string) ([]string, error)
	TypedPhrase(reviewID string) (phrase string, typedInteractively bool, err error)
	PermanentRemovalSelected(reviewID string) (bool, error)
}

type Interface struct{ observer RemovalObserver }

func New(observer RemovalObserver) Interface { return Interface{observer: observer} }

// RemovalReview is an opaque record that the Owner Console observed every category.
type RemovalReview struct{ identity string }

// TypedRemovalConfirmation and PermanentRemovalSelection are separate opaque authorities.
type TypedRemovalConfirmation struct{ review, phrase string }
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
	return RemovalReview{identity: identity}, nil
}

func (i Interface) RecordTypedPhrase(review RemovalReview) (TypedRemovalConfirmation, error) {
	if i.observer == nil {
		return TypedRemovalConfirmation{}, errors.New("Owner Console removal observer unavailable")
	}
	phrase, typedInteractively, err := i.observer.TypedPhrase(review.identity)
	if err != nil || review.identity == "" || phrase != completeRemovalPhrase || !typedInteractively {
		return TypedRemovalConfirmation{}, errors.New("exact COMPLETE REMOVAL typing is required")
	}
	return TypedRemovalConfirmation{review: review.identity, phrase: phrase}, nil
}

func (i Interface) SelectPermanentRemoval(review RemovalReview) (PermanentRemovalSelection, error) {
	if i.observer == nil {
		return PermanentRemovalSelection{}, errors.New("Owner Console removal observer unavailable")
	}
	selected, err := i.observer.PermanentRemovalSelected(review.identity)
	if err != nil || review.identity == "" || !selected {
		return PermanentRemovalSelection{}, errors.New("Complete removal review is required")
	}
	return PermanentRemovalSelection{review: review.identity, categories: append([]string(nil), removalCategories...)}, nil
}

func (confirmation TypedRemovalConfirmation) SystemChangesTypedRemovalConfirmation() (review, phrase string, valid bool) {
	return confirmation.review, confirmation.phrase, confirmation.review != "" && confirmation.phrase == completeRemovalPhrase
}

func (selection PermanentRemovalSelection) SystemChangesPermanentRemovalSelection() (review string, categories []string, valid bool) {
	return selection.review, append([]string(nil), selection.categories...), selection.review != "" && len(selection.categories) == len(removalCategories)
}
