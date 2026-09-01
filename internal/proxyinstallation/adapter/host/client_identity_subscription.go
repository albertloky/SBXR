package host

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

const ClientIdentityArtifactPath = ServingStagingPath + "/client-artifact"

type ClientIdentitySubscription struct {
	Source               ServingAuthority `json:"source"`
	Target               ServingAuthority `json:"target"`
	SourceArtifactSHA256 string           `json:"source_artifact_sha256"`
	TargetArtifactSHA256 string           `json:"target_artifact_sha256"`
}

func (ClientIdentitySubscription) String() string {
	return "Client Identity subscription authority (redacted)"
}
func (ClientIdentitySubscription) GoString() string {
	return "Client Identity subscription authority (redacted)"
}

func (s ClientIdentitySubscription) Valid() bool {
	validDigest := func(value string) bool {
		b, err := hex.DecodeString(value)
		return err == nil && len(b) == 32 && hex.EncodeToString(b) == value && value != strings.Repeat("0", 64)
	}
	return s.Source.Valid() && s.Target.Valid() && s.Source.LinkID == s.Target.LinkID && s.Source.CredentialSHA256 == s.Target.CredentialSHA256 &&
		(s.Source == s.Target || s.Target.CertificateGeneration > s.Source.CertificateGeneration) &&
		validDigest(s.SourceArtifactSHA256) && validDigest(s.TargetArtifactSHA256) && s.SourceArtifactSHA256 != s.TargetArtifactSHA256
}

func (a Adapter) ClientIdentitySubscriptionReady(ctx context.Context, source ServingAuthority, renewal RenewalAuthority) bool {
	if !a.ServingPublicIPv4(ctx, renewal.PublicIPv4) || !a.renewalFiles(renewal) {
		return false
	}
	if _, ok := a.ReadSubscriptionLink(source, renewal.PublicIPv4); !ok {
		return false
	}
	if a.InspectServingFiles(source, false).Accepted {
		return true
	}
	// A complete, trusted, newer canonical publication can be incorporated into
	// this operation. The accepted source state and credential remain unchanged.
	published, ok := a.publishedCertificateAuthority(renewal, source)
	return ok && published.CertificateGeneration > source.CertificateGeneration && a.inspectServingFiles(published, false, false, source).Accepted
}

func (a Adapter) PrepareClientIdentitySubscription(s ClientIdentitySubscription, artifact []byte) bool {
	return s.Valid() && digest(artifact) == s.TargetArtifactSHA256 && len(artifact) <= 4096 &&
		a.publishSubscriptionFile(ClientIdentityArtifactPath, artifact, 0600) &&
		a.publishSubscriptionFile(SubscriptionCandidateStatePath, servingStateBytes(s.Target), 0600)
}

func (a Adapter) InspectClientIdentitySubscription(s ClientIdentitySubscription, ipv4 string, required, forward bool) Observation {
	if !s.Valid() || !a.servingDirectory(ServingStagingPath, []string{"client-artifact", "serving.json", "client-artifact.sbxr-next", "serving.json.sbxr-next"}, false) {
		return observation(false, true)
	}
	_, source := a.ReadSubscriptionLink(s.Source, ipv4)
	_, target := a.ReadSubscriptionLink(s.Target, ipv4)
	unit, err := a.protectedServingFile(ServingUnitPath, 0644, "")
	if err != nil || !knownServingUnit(unit) || !source && !(forward && target) {
		return observation(false, true)
	}
	for _, item := range []struct{ path, hash string }{
		{ClientIdentityArtifactPath, s.TargetArtifactSHA256},
		{SubscriptionCandidateStatePath, digest(servingStateBytes(s.Target))},
	} {
		_, err := a.clientPublicationFile(item.path, 0600, item.hash)
		if err != nil && !(errors.Is(err, os.ErrNotExist) && (!required || !forward && source || forward && target && item.path == SubscriptionCandidateStatePath)) {
			return observation(false, true)
		}
	}
	return observation(true, true)
}

func (a Adapter) StopClientIdentitySubscription(ctx context.Context) bool {
	unit, err := a.protectedServingFile(ServingUnitPath, 0644, "")
	return err == nil && knownServingUnit(unit) && a.servingCommand(ctx, "stop", "sbxr-subscription.service") && a.ServingQuiescent()
}

func (a Adapter) UpgradeClientIdentityServingStartup() bool {
	current, err := a.protectedServingFile(ServingUnitPath, 0644, "")
	if err != nil || !knownServingUnit(current) {
		return false
	}
	if string(current) == ServingUnit {
		return a.removeClientPublication(ServingUnitPath+".sbxr-next", 0644, digest([]byte(ServingUnit)))
	}
	if !a.publishSubscriptionFile(ServingUnitPath+".sbxr-next", []byte(ServingUnit), 0644) {
		return false
	}
	return a.replaceSubscriptionFile(ServingUnitPath, ServingUnitPath+".sbxr-next", []byte(ServingUnit), 0644, digest([]byte(legacyServingUnit))) && a.removeClientPublication(ServingUnitPath+".sbxr-next", 0644, digest([]byte(ServingUnit)))
}

func (a Adapter) VerifyClientIdentityServingStartup(ctx context.Context) bool {
	body, err := a.protectedServingFile(ServingUnitPath, 0644, "")
	if err != nil || string(body) != ServingUnit {
		return false
	}
	for property, want := range map[string]string{"FragmentPath": ServingUnitPath, "DropInPaths": "", "KillMode": "control-group"} {
		result := a.command(ctx, "systemctl", "show", "--property="+property, "--value", "sbxr-subscription.service")
		if !result.OK || strings.TrimSpace(result.Fact) != want {
			return false
		}
	}
	return true
}

func (a Adapter) PublishClientIdentitySubscription(source, target ServingAuthority) bool {
	if !source.Valid() || !target.Valid() || source.LinkID != target.LinkID || source.CredentialSHA256 != target.CredentialSHA256 {
		return false
	}
	state := servingStateBytes(target)
	if !a.publishSubscriptionFile(SubscriptionCandidateStatePath, state, 0600) {
		return false
	}
	return a.replaceSubscriptionFile(ServingStatePath, SubscriptionCandidateStatePath, state, 0600, digest(servingStateBytes(source)))
}

func (a Adapter) RemoveClientIdentitySubscription(s ClientIdentitySubscription) bool {
	if !s.Valid() {
		return false
	}
	for _, item := range []struct{ path, hash string }{{ClientIdentityArtifactPath, s.TargetArtifactSHA256}, {SubscriptionCandidateStatePath, digest(servingStateBytes(s.Target))}} {
		if !a.removeClientPublication(item.path, 0600, item.hash) {
			return false
		}
	}
	return a.removeClientPublication(ServingUnitPath+".sbxr-next", 0644, digest([]byte(ServingUnit)))
}

func (a Adapter) clientPublicationFile(path string, mode os.FileMode, expected string) ([]byte, error) {
	destination, err := os.Lstat(a.path(path))
	staged, stagedErr := os.Lstat(a.path(path + ".sbxr-next"))
	if err == nil && stagedErr == nil && os.SameFile(destination, staged) {
		return a.protectedServingFileWithLinks(path, mode, expected, 2)
	}
	if errors.Is(err, os.ErrNotExist) {
		return a.protectedServingFile(path+".sbxr-next", mode, expected)
	}
	body, err := a.protectedServingFile(path, mode, expected)
	if stagedErr == nil {
		if _, stagedErr = a.protectedServingFile(path+".sbxr-next", mode, expected); stagedErr != nil {
			return nil, stagedErr
		}
	} else if !errors.Is(stagedErr, os.ErrNotExist) {
		return nil, stagedErr
	}
	return body, err
}

func (a Adapter) removeClientPublication(path string, mode os.FileMode, expected string) bool {
	if _, err := a.clientPublicationFile(path, mode, expected); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false
	}
	for _, name := range []string{path + ".sbxr-next", path} {
		if err := os.Remove(a.path(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false
		}
		if !a.syncAbsentPath(name) {
			return false
		}
	}
	return true
}

func (a Adapter) ClientIdentitySubscriptionArtifactMatches(s ClientIdentitySubscription, artifact []byte) bool {
	if !s.Valid() || digest(artifact) != s.TargetArtifactSHA256 {
		return false
	}
	staged, err := a.protectedServingFile(ClientIdentityArtifactPath, 0600, s.TargetArtifactSHA256)
	return err == nil && bytes.Equal(staged, artifact) || errors.Is(err, os.ErrNotExist)
}
