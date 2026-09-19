package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

// InspectCertificateServingState proves an existing snapshot, never authority
// to adopt unknown material. An older snapshot must name this same link and
// match all four protected files in the owned certificate archive. Historical
// certificates need not still be valid; the selected certificate is checked
// separately, with normal trust and validity checks.
func (a Adapter) InspectCertificateServingState(target ServingAuthority, pending bool) (ServingAuthority, bool) {
	if !pending && !a.servingDirectory(ServingStagingPath, nil, false) {
		return ServingAuthority{}, false
	}
	body, err := a.protectedServingFile(ServingStatePath, 0600, "")
	var state struct {
		Schema  int              `json:"schema"`
		Serving ServingAuthority `json:"serving"`
	}
	if err != nil || json.Unmarshal(body, &state) != nil || state.Schema != 1 || !bytes.Equal(body, servingStateBytes(state.Serving)) {
		return ServingAuthority{}, false
	}
	source := state.Serving
	if !source.Valid() || !target.Valid() || source.LinkID != target.LinkID || source.CredentialSHA256 != target.CredentialSHA256 || source.CertificateGeneration > target.CertificateGeneration || source.CertificateGeneration == target.CertificateGeneration && source != target {
		return ServingAuthority{}, false
	}
	for i, name := range certificateNames {
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		if _, err := a.protectedServingFile(servingArchive+"/"+name+strconv.Itoa(source.CertificateGeneration)+".pem", mode, source.CertificateSHA256[i]); err != nil {
			return ServingAuthority{}, false
		}
	}
	return source, a.inspectCertificateServingFiles(target, source).Accepted
}

func (a Adapter) certificateStateStaging(target ServingAuthority) bool {
	if !a.servingDirectory(ServingStagingPath, []string{filepath.Base(SubscriptionCandidateStatePath)}, false) {
		return false
	}
	body, err := a.protectedServingFile(SubscriptionCandidateStatePath, 0600, digest(servingStateBytes(target)))
	return errors.Is(err, os.ErrNotExist) || err == nil && bytes.Equal(body, servingStateBytes(target))
}

// PublishCertificateServingState runs only after the caller has durably recorded
// source/target authority under the whole-host lock. A deploy hook can still
// belong to a live Certbot attempt; this does not acquire its writer locks. Keep
// that checkpoint until this expected-current publication and staging cleanup
// are durable, including after a previous rename succeeded but fsync failed.
func (a Adapter) PublishCertificateServingState(renewal RenewalAuthority, source, target ServingAuthority) bool {
	if !source.Valid() || !target.Valid() || source.LinkID != target.LinkID || source.CredentialSHA256 != target.CredentialSHA256 || source.CertificateGeneration > target.CertificateGeneration || source.CertificateGeneration == target.CertificateGeneration && source != target {
		return false
	}
	published, valid := a.publishedServingAuthority(renewal, target)
	stored, safe := a.InspectCertificateServingState(target, true)
	if !valid || published != target || !safe || stored != source && stored != target {
		return false
	}
	body := servingStateBytes(target)
	if stored != target {
		if a.PublishOwnership(ServingStatePath, SubscriptionCandidateStatePath, servingStateBytes(source), body) != nil {
			return false
		}
	} else {
		if a.SyncOwnership(ServingStatePath, body) != nil {
			return false
		}
		if !a.removeClientPublication(SubscriptionCandidateStatePath, 0600, digest(body)) {
			return false
		}
	}
	return a.syncOwnershipDirectory(a.path(ServingStagingPath)) == nil && a.InspectServingFiles(target, false).Accepted
}
