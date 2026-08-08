//go:build !linux || (!amd64 && !arm64)

package filesystem

import (
	"errors"
	"os"
)

func exchangeDirectories(root *os.Root, first, second string) error {
	const temporary = ".subscription-exchange"
	if _, err := root.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		return errors.New("unresolved subscription exchange")
	}
	if err := root.Rename(first, temporary); err != nil {
		return err
	}
	if err := root.Rename(second, first); err != nil {
		_ = root.Rename(temporary, first)
		return err
	}
	if err := root.Rename(temporary, second); err != nil {
		return err
	}
	return nil
}
