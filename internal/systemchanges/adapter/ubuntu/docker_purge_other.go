//go:build !linux

package ubuntu

import "errors"

func enterDockerPurgeNamespace(string, []string) error {
	return errors.New("Docker purge requires Linux")
}
