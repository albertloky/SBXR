package ownerconsole

type controlledRemovalObserver struct{}

func (controlledRemovalObserver) ReviewedCategories(string) ([]string, error) {
	return CompleteRemovalCategories(), nil
}
func (controlledRemovalObserver) TypedPhrase(string) (string, bool, error) {
	return completeRemovalPhrase, true, nil
}
func (controlledRemovalObserver) PermanentRemovalSelected(string) (bool, error) { return true, nil }

// ControlledRemovalReview returns the genuine reviewed-category authority.
func ControlledRemovalReview(identity string) (RemovalReview, error) {
	return New(controlledRemovalObserver{}).StartRemovalReview(identity)
}
