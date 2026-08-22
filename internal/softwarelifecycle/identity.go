package softwarelifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const Repository = "albertloky/SBXR"

const (
	MaxIndexBytes = 1 << 20
	MaxAssetBytes = 256 << 20
)

type Architecture string

const (
	AMD64 Architecture = "amd64"
	ARM64 Architecture = "arm64"
)

type ReleaseIdentity struct {
	Repository, Tag, Commit, IndexSHA256 string
}

var (
	immutableReleaseTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	commitPattern       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hashPattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidateUniqueJSON rejects duplicate object keys at every nesting level.
func ValidateUniqueJSON(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate JSON key")
				}
				seen[name] = true
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
