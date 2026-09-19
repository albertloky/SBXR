//go:build linux && amd64 && sbxr_snapshot_recovery

package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// SnapshotRecoveryPlan is a private, one-time maintenance handoff, not product
// authority. The target is always derived from the complete accepted record.
// Build-tag isolation keeps this entry point out of released SBXR executables.
type SnapshotRecoveryPlan struct {
	Schema           int                          `json:"schema"`
	ServiceMode      string                       `json:"service_mode"`
	ExecutableSHA256 string                       `json:"executable_sha256"`
	InstalledSHA256  string                       `json:"installed_sha256"`
	OwnershipSHA256  string                       `json:"ownership_sha256"`
	SourceSHA256     string                       `json:"source_sha256"`
	TargetSHA256     string                       `json:"target_sha256"`
	Source           hostadapter.ServingAuthority `json:"source"`
}

const RecoveryExecutableSHA256 = "3499451e3f9ff0aaca3209fd96d1c1e822b2bc331b7f242591dd40b543a5c14c"

const (
	RecoveryServiceActiveServing = "active-serving-v1"
	RecoveryServicePostReboot    = "post-reboot-quiescent-v1"
)

var recoveryRelease = softwarelifecycle.ReleaseIdentity{
	Repository: softwarelifecycle.Repository, Tag: "v3.1.75",
	Commit:      "cf2e89aae5cfa56ae316505d24f16d50b8a25069",
	IndexSHA256: "3b4026ca92c6af03367c6b638df2e574e9a607dde5f09c613b6e6da1763b34b9",
}

func recoveryDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
func recoveryState(authority hostadapter.ServingAuthority) []byte {
	body, _ := json.Marshal(struct {
		Schema  int                          `json:"schema"`
		Serving hostadapter.ServingAuthority `json:"serving"`
	}{1, authority})
	return append(body, '\n')
}
func recoveryHash(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s && s != string(bytes.Repeat([]byte{'0'}, 64))
}

// RecoverCertificateSnapshot checks or completes exactly the pinned 1 -> 2
// transaction. It never installs software, changes authority, restarts a unit,
// runs Certbot, repairs unrelated files, or rolls the snapshot backward.
func RecoverCertificateSnapshot(ctx context.Context, planPath string, apply bool) (string, error) {
	refuse := func(check string) (string, error) { return "", errors.New("snapshot recovery refused: " + check) }
	if os.Geteuid() != 0 || ctx.Err() != nil {
		return refuse("root/context")
	}
	host := hostadapter.New()
	body, err := host.ReadOwnership(planPath)
	var plan SnapshotRecoveryPlan
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&plan) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return refuse("protected plan")
	}
	canonical, _ := json.Marshal(plan)
	postReboot := plan.ServiceMode == RecoveryServicePostReboot
	if !bytes.Equal(body, append(canonical, '\n')) || plan.Schema != 1 || plan.ServiceMode != RecoveryServiceActiveServing && !postReboot || plan.ExecutableSHA256 != RecoveryExecutableSHA256 || !recoveryHash(plan.InstalledSHA256) || !recoveryHash(plan.OwnershipSHA256) || !recoveryHash(plan.TargetSHA256) || !plan.Source.Valid() || plan.Source.CertificateGeneration != 1 || plan.SourceSHA256 != recoveryDigest(recoveryState(plan.Source)) || plan.SourceSHA256 == plan.TargetSHA256 {
		return refuse("plan identities")
	}
	lockPresent, lockSafe := host.SnapshotRecoveryWholeHostLock(hostSetupSpec.LockPath)
	if !lockSafe {
		return refuse("whole-host lock state")
	}
	if postReboot && !apply && !lockPresent {
		return refuse("post-reboot whole-host lock absent; apply required")
	}
	// The post-reboot plan alone authorizes recreation of the exact volatile
	// lock. Check remains read-only and therefore requires an existing retry lock.
	var preLockServices string
	if postReboot && apply {
		if !host.SnapshotRecoveryIdentity(plan.ExecutableSHA256, plan.InstalledSHA256, plan.OwnershipSHA256) {
			return refuse("post-reboot identity precheck")
		}
		var ok bool
		if preLockServices, ok = host.SnapshotRecoveryServices(ctx, true); !ok {
			return refuse("post-reboot service precheck")
		}
	}
	var lock *hostadapter.MutationLock
	var busy bool
	if postReboot && apply {
		lock, busy, err = host.AcquireMutationLock(hostSetupSpec.LockPath)
	} else {
		lock, busy, err = host.AcquireSubscriptionReviewLock(hostSetupSpec.LockPath)
	}
	if err != nil || busy || lock == nil {
		return refuse("whole-host lock acquisition")
	}
	defer lock.Release()
	if postReboot && apply && !host.SnapshotRecoveryWholeHostLockHeld(hostSetupSpec.LockPath, lock) {
		return refuse("created whole-host lock identity")
	}
	// The protected plan is the one-time completion authority. Make its exact
	// source/target binding durable before any publication can survive a crash.
	if apply && host.SyncOwnership(planPath, body) != nil {
		return refuse("plan durability")
	}
	lifecycle := softwarelifecycle.NewInstalledWithUpdateRuntime(nil, AdmitSoftwareUpdate, SoftwareUpdateRuntime()).(mutationLifecycle)
	inspect := func() (ownershipRecord, string, bool) {
		status := lifecycle.StatusUnderMutationLock(ctx, lock)
		installed, e1 := host.ReadOwnership("/var/lib/sbxr/installed.json")
		ownership, e2 := host.ReadOwnership(hostSetupSpec.OwnershipPath)
		record, valid := decodeOwnership(ownership)
		var installedDigest struct {
			ExecutableSHA256 string `json:"executable_sha256"`
		}
		if ctx.Err() != nil || !host.SnapshotRecoveryWholeHostLockHeld(hostSetupSpec.LockPath, lock) || status.State != softwarelifecycle.Ready || status.Installed == nil || *status.Installed != recoveryRelease || e1 != nil || e2 != nil || json.Unmarshal(installed, &installedDigest) != nil || installedDigest.ExecutableSHA256 != plan.ExecutableSHA256 || recoveryDigest(installed) != plan.InstalledSHA256 || recoveryDigest(ownership) != plan.OwnershipSHA256 || !valid || !compatibleOwnership(record, *status.Installed) || record.Release != recoveryRelease || record.Schema != 2 || record.Phase != runningPhase || record.Direction != noDirection || record.FinishingRelease != nil || record.Activation != nil || record.Enablement != nil || record.Rotation != nil || record.Repair != nil || record.ClientRotation != nil || record.SubscriptionCompromised || record.Serving == nil || record.Renewal == nil || record.Startup == nil || record.SubscriptionResources == nil || record.Serving.CertificateGeneration != 2 || record.Serving.LinkID != plan.Source.LinkID || record.Serving.CredentialSHA256 != plan.Source.CredentialSHA256 || recoveryDigest(recoveryState(*record.Serving)) != plan.TargetSHA256 {
			return record, "", false
		}
		for _, path := range []string{hostSetupSpec.OwnershipNextPath, finalOwnershipPath, hostadapter.RenewalEvidenceNextPath, hostadapter.ClientIdentityTargetPath, hostadapter.ClientIdentityTargetPath + ".sbxr-next", hostadapter.ClientIdentityConfigurationNextPath} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				return record, "", false
			}
		}
		if _, err := host.ReadConfiguration(ctx, hostSetupSpec, record.ConfigurationSHA256); err != nil || !host.VerifyProxyStartupIntegration(ctx, *record.Startup) || !host.SnapshotRecoveryFirewall(*record.SubscriptionResources) {
			return record, "", false
		}
		if !host.SnapshotRecoverySourceValid(plan.Source) {
			return record, "", false
		}
		stored, safe := host.InspectCertificateServingState(*record.Serving, true)
		if !safe || stored != plan.Source && stored != *record.Serving {
			return record, "", false
		}
		if postReboot {
			activation := host.InspectCertificateActivation(ctx, *record.Renewal, *record.Serving)
			if !activation.Observed || !activation.Accepted || activation.Published != *record.Serving || activation.Loaded != (hostadapter.ServingAuthority{}) || !host.ServingQuiescent() {
				return record, "", false
			}
		} else {
			activation := host.InspectCertificateActivation(ctx, *record.Renewal, *record.Serving)
			if !activation.Observed || !activation.Accepted || activation.Published != *record.Serving || activation.Loaded != *record.Serving {
				return record, "", false
			}
		}
		current := "source"
		if stored == *record.Serving {
			current = "target"
		}
		return record, current, true
	}
	record, current, ok := inspect()
	if !ok {
		return refuse("installed/ownership/configuration/certificate state")
	}
	// Observe renewal health before taking its writer lock, then bind the exact
	// evidence bytes and recheck the route under retained exclusion below.
	renewal := host.InspectRenewal(*record.Renewal)
	evidence, err := host.ReadOwnership(hostadapter.RenewalEvidencePath)
	if err != nil || !renewal.Accepted || !renewal.Observed || renewal.State != hostadapter.RenewalAttemptHealthy {
		return refuse("healthy idle renewal")
	}
	services, ok := host.SnapshotRecoveryServices(ctx, postReboot)
	if !ok || postReboot && apply && services != preLockServices || !host.SnapshotRecoveryReadOnlyLocks() {
		return refuse("service state or Certbot contention")
	}
	renewalLock, ok := host.AcquireRenewalExclusion(*record.Renewal)
	if !ok {
		return refuse("renewal exclusion")
	}
	defer renewalLock.Release()
	if !apply {
		return "snapshot recovery checked: " + current, nil
	}
	certbotLock, ok := host.AcquireServingExclusion()
	if !ok {
		return refuse("Certbot exclusion")
	}
	defer certbotLock.Release()
	recheck := func() bool {
		after, _, valid := inspect()
		now, readErr := host.ReadOwnership(hostadapter.RenewalEvidencePath)
		observed, serviceOK := host.SnapshotRecoveryServices(ctx, postReboot)
		return valid && after.Serving != nil && *after.Serving == *record.Serving && readErr == nil && bytes.Equal(now, evidence) && serviceOK && observed == services && host.SnapshotRecoveryExclusionValid(*record.Renewal, renewalLock, certbotLock)
	}
	if !recheck() {
		return refuse("changed inputs under exclusion")
	}
	if !host.PublishCertificateServingState(*record.Renewal, plan.Source, *record.Serving) {
		return refuse("publication incomplete; preserve plan and retry only after check")
	}
	if !recheck() || !host.InspectServingFiles(*record.Serving, false).Accepted {
		return refuse("post-publication verification; preserve target and investigate")
	}
	if _, ok := host.ReadSubscriptionLink(*record.Serving, record.PublicIPv4); !ok {
		return refuse("post-publication link inspection")
	}
	return "snapshot recovery complete: target durable; original identities and services preserved", nil
}
