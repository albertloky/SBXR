package ubuntu

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// CandidateHost validates generated configurations with the authenticated
// staged proxy cores before the install Change Set writes either executable.
type CandidateHost struct {
	xray, singBox               []byte
	xrayVersion, singBoxVersion string
}

func (CandidateHost) String() string   { return "Connection Profiles candidate host: redacted" }
func (CandidateHost) GoString() string { return "Connection Profiles candidate host: redacted" }
func (CandidateHost) MarshalJSON() ([]byte, error) {
	return []byte(`"Connection Profiles candidate host: redacted"`), nil
}

func NewCandidateHost(candidate softwarelifecycle.InstallCandidate) (CandidateHost, error) {
	xray, xrayVersion, xrayOK := candidate.QualifiedComponent("xray")
	singBox, singBoxVersion, singBoxOK := candidate.QualifiedComponent("sing-box")
	if !xrayOK || !singBoxOK {
		return CandidateHost{}, errors.New("qualified candidate proxy cores unavailable")
	}
	return CandidateHost{xray: xray, singBox: singBox, xrayVersion: xrayVersion, singBoxVersion: singBoxVersion}, nil
}

func (CandidateHost) ObserveReality(context.Context, connectionprofiles.RealityTarget) connectionprofiles.RealityObservation {
	return connectionprofiles.RealityObservation{}
}

func (host CandidateHost) ValidateReality(ctx context.Context, version string, configuration io.Reader) error {
	if version != host.xrayVersion {
		return errors.New("qualified Xray version changed")
	}
	return runCandidate(ctx, host.xray, configuration, "run", "-test", "-config", "stdin:")
}

func (host CandidateHost) ValidateSingBox(ctx context.Context, version string, configuration io.Reader) error {
	if version != host.singBoxVersion {
		return errors.New("qualified sing-box version changed")
	}
	return runCandidate(ctx, host.singBox, configuration, "check", "-c", "/dev/stdin")
}

func runCandidate(ctx context.Context, executable []byte, configuration io.Reader, arguments ...string) error {
	if len(executable) == 0 || configuration == nil {
		return errors.New("candidate validation unavailable")
	}
	directory, err := os.MkdirTemp("", "sbxr-component-")
	if err != nil {
		return errors.New("candidate validation unavailable")
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return errors.New("candidate validation unavailable")
	}
	path := filepath.Join(directory, "component")
	if err := os.WriteFile(path, executable, 0o700); err != nil {
		return errors.New("candidate validation unavailable")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Stdin = configuration
	if err := command.Run(); err != nil {
		return errors.New("candidate configuration validation failed")
	}
	return nil
}
